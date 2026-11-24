//! Mihomo MRS v1 uses a Zstandard frame containing either a succinct domain
//! trie or inclusive IP ranges. Expand only when preparing an import preview.
use std::{io::Read, net::Ipv6Addr};

use anyhow::{Context, Result, bail, ensure};
use ipnet::{Ipv4Subnets, Ipv6Subnets};

use super::{MAX_RULE_LIST_BYTES, MAX_RULE_LIST_RULES, RuleListPreview};
use crate::config::rules_batch::{DOMAIN_SET_SIZE, format_rule_clash_line, make_typed_rule};

fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    let (part, rest) = input.split_at_checked(n).context("MRS 数据不完整")?;
    *input = rest;
    Ok(part)
}

fn length(input: &mut &[u8]) -> Result<usize> {
    let value = u64::from_be_bytes(take(input, 8)?.try_into()?);
    usize::try_from(value).context("MRS 长度超出范围")
}

fn array<'a>(input: &mut &'a [u8], width: usize) -> Result<&'a [u8]> {
    let bytes = length(input)?
        .checked_mul(width)
        .context("MRS 长度超出范围")?;
    take(input, bytes)
}

pub(super) fn preview(bytes: &[u8], target: &str, group: &str) -> Result<RuleListPreview> {
    let mut decoder = zstd::stream::read::Decoder::new(bytes)?;
    decoder.window_log_max(23)?;
    let mut decoded = Vec::new();
    decoder
        .take(MAX_RULE_LIST_BYTES as u64 + 1)
        .read_to_end(&mut decoded)?;
    ensure!(
        decoded.len() <= MAX_RULE_LIST_BYTES,
        "MRS 解压后超过 2 MiB 限制"
    );
    let mut input = decoded.as_slice();
    ensure!(take(&mut input, 4)? == b"MRS\x01", "MRS 文件标识或版本无效");
    let behavior = take(&mut input, 1)?[0];
    // Source count precedes deduplication and merging. Bound the actual output.
    let source_count = length(&mut input)?;
    ensure!(source_count > 0, "MRS 规则集为空");
    array(&mut input, 1)?; // reserved metadata
    ensure!(take(&mut input, 1)? == [1], "不支持的 MRS 数据版本");
    let mut result = RuleListPreview {
        text: String::new(),
        count: 0,
        packed_domains: 0,
        skipped: Default::default(),
    };
    let mut emit = |kind: &str, pattern: &str| -> Result<()> {
        ensure!(
            result.count < MAX_RULE_LIST_RULES,
            "一次最多导入 32768 条规则"
        );
        let rule = make_typed_rule(kind, pattern, target, group).map_err(anyhow::Error::msg)?;
        let line = format_rule_clash_line(&rule);
        if result.count > 0 {
            result.text.push('\n');
        }
        ensure!(
            result.text.len() + line.len() <= MAX_RULE_LIST_BYTES,
            "展开后的规则列表超过 2 MiB 限制"
        );
        result.text.push_str(&line);
        result.count += 1;
        Ok(())
    };
    match behavior {
        0 => {
            let skipped = if source_count > MAX_RULE_LIST_RULES {
                let mut members = Vec::with_capacity(DOMAIN_SET_SIZE);
                let skipped = domains(&mut input, |kind, name| {
                    // Validate a member before introducing the set separator.
                    ensure!(!name.contains('|'), "MRS 域名包含无效字符");
                    let name = if kind == "domain-suffix" {
                        format!("+.{name}")
                    } else {
                        name.to_owned()
                    };
                    members.push(name);
                    result.packed_domains += 1;
                    if members.len() == DOMAIN_SET_SIZE {
                        emit("domain-set", &members.join("|"))?;
                        members.clear();
                    }
                    Ok(())
                })?;
                if !members.is_empty() {
                    emit("domain-set", &members.join("|"))?;
                }
                skipped
            } else {
                domains(&mut input, &mut emit)?
            };
            if skipped > 0 {
                result.skipped.insert("MRS 域名通配规则", skipped);
            }
        }
        1 => ip_ranges(&mut input, emit)?,
        _ => bail!("仅支持 domain 和 ipcidr 类型的 MRS"),
    }
    ensure!(input.is_empty(), "MRS 包含多余数据");
    ensure!(
        result.count > 0,
        "MRS 中没有可导入的规则（空集或仅包含不支持的通配规则）"
    );
    Ok(result)
}

fn ip_ranges(input: &mut &[u8], mut emit: impl FnMut(&str, &str) -> Result<()>) -> Result<()> {
    for pair in array(input, 32)?.as_chunks::<32>().0 {
        let from = Ipv6Addr::from(<[u8; 16]>::try_from(&pair[..16])?);
        let to = Ipv6Addr::from(<[u8; 16]>::try_from(&pair[16..])?);
        ensure!(from <= to, "MRS IP 地址范围无效");
        match (from.to_ipv4_mapped(), to.to_ipv4_mapped()) {
            (Some(a), Some(b)) => {
                for net in Ipv4Subnets::new(a, b, 0) {
                    emit("ip-cidr", &net.to_string())?;
                }
            }
            (None, None) => {
                for net in Ipv6Subnets::new(from, to, 0) {
                    emit("ip-cidr", &net.to_string())?;
                }
            }
            _ => bail!("MRS IP 地址族不一致"),
        }
    }
    Ok(())
}

// Words are big endian, but bit indices within each word run from LSB to MSB.
fn bit(words: &[u8], index: usize) -> bool {
    words[(index / 64) * 8 + 7 - (index % 64) / 8] & (1 << (index % 8)) != 0
}

fn domains(input: &mut &[u8], mut emit: impl FnMut(&str, &str) -> Result<()>) -> Result<usize> {
    let leaves = array(input, 8)?;
    let edges = array(input, 8)?;
    let labels = array(input, 1)?;
    let nodes = labels.len() + 1;
    ensure!(
        leaves.len() == nodes.div_ceil(64) * 8
            && edges.len() == (nodes + labels.len()).div_ceil(64) * 8,
        "MRS 域名索引长度无效"
    );
    ensure!(!bit(leaves, 0), "MRS 域名不能为空");
    // A suffix rule can have two terminals. Include unsupported patterns in
    // the traversal budget too, before walking their parent chains.
    let terminals: usize = leaves.iter().map(|b| b.count_ones() as usize).sum();
    ensure!(terminals <= 2 * 262_144, "MRS 域名条目过多");

    // Nodes are numbered breadth first. Each zero bit adds a child with the
    // next label, and each one bit terminates the current node's child list.
    let mut parents = Vec::with_capacity(nodes);
    parents.push(0u32);
    let mut parent = 0;
    let mut covers_children = vec![false; nodes];
    let mut skipped = 0;
    for index in 0..nodes + labels.len() {
        ensure!(parent < parents.len(), "MRS 域名树无效");
        if bit(edges, index) {
            parent += 1;
        } else {
            let id = parents.len();
            ensure!(id < nodes, "MRS 域名树超出索引");
            parents.push(parent as u32);
            // "+.example" stores two terminals: "example" and "+.example".
            // A lone wildcard terminal covers subdomains only.
            if labels[id - 1] == b'+' && bit(leaves, id) && parent > 0 && labels[parent - 1] == b'.'
            {
                let base = parents[parent] as usize;
                if bit(leaves, base) {
                    covers_children[base] = true;
                } else {
                    skipped += 1;
                }
            }
        }
    }
    ensure!(
        parent == nodes && parents.len() == nodes,
        "MRS 域名树不完整"
    );
    for (id, &suffix) in covers_children.iter().enumerate().skip(1) {
        if !bit(leaves, id) {
            continue;
        }
        let mut path = Vec::new();
        let mut node = id;
        while node != 0 {
            ensure!(path.len() < 1024, "MRS 域名过长");
            path.push(labels[node - 1]);
            node = parents[node] as usize;
        }
        // The trie stores the domain reversed by Unicode scalar, not by byte.
        path.reverse();
        let name: String = std::str::from_utf8(&path)?.chars().rev().collect();
        if name.starts_with("+.") {
            continue;
        }
        if name.contains(['*', '+']) || name.starts_with('.') {
            skipped += 1;
            continue;
        }
        emit(if suffix { "domain-suffix" } else { "domain" }, &name)?;
    }
    Ok(skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    // MetaCubeX/meta-rules-dat, geo/{geosite/github,geoip/telegram}.mrs.
    // Git blob IDs: 7f7bf0424bb914217b7767f5629382c613683d42 and
    // fb30975e15cc4e220abd1725145db819c868d4c2.
    const GITHUB: &[u8] = include_bytes!("../../../tests/fixtures/mrs/github.mrs");
    const TELEGRAM: &[u8] = include_bytes!("../../../tests/fixtures/mrs/telegram.mrs");

    #[test]
    fn upstream_mrs_preserves_matching_and_outbound() {
        let domains = super::super::preview_rule_list_bytes(GITHUB, "group:Japan", "Dev").unwrap();
        assert_eq!(domains.count, 66);
        assert!(domains.skipped.is_empty());
        let batch =
            crate::config::rules_batch::parse_batch_rules_in_group(&domains.text, "proxy", "Dev");
        assert!(batch.errors.is_empty());
        assert_eq!(batch.rules.len(), domains.count);
        assert!(
            batch
                .rules
                .iter()
                .all(|rule| rule.group == "Dev" && rule.target == "group:Japan")
        );
        assert!(
            domains
                .text
                .lines()
                .any(|s| s == "DOMAIN-SUFFIX,github.com,group:Japan")
        );
        assert!(
            domains
                .text
                .lines()
                .any(|s| s == "DOMAIN,github-api.arkoselabs.com,group:Japan")
        );
        let ips = super::super::preview_rule_list_bytes(TELEGRAM, "direct", "Telegram").unwrap();
        assert_eq!(ips.count, 12);
        for cidr in [
            "91.108.4.0/22",
            "91.108.8.0/21",
            "91.108.16.0/21",
            "2001:b28:f23c::/47",
        ] {
            assert!(
                ips.text
                    .lines()
                    .any(|s| s == format!("IP-CIDR,{cidr},DIRECT"))
            );
        }
    }

    #[test]
    fn subdomain_only_and_label_wildcards_do_not_widen_to_suffix_matches() {
        // Breadth-first labels for ".a", "*.b" and exact "c".
        // Only the "c", "+" and "*" nodes are terminal.
        let mut tree = Vec::new();
        for word in [1u64, 0b11001000, 1, 0b111010110101000] {
            tree.extend(word.to_be_bytes());
        }
        tree.extend(7u64.to_be_bytes());
        tree.extend(b"abc..+*");
        let mut rules = Vec::new();
        let skipped = domains(&mut tree.as_slice(), |kind, host| {
            rules.push((kind.to_owned(), host.to_owned()));
            Ok(())
        })
        .unwrap();
        assert_eq!(skipped, 2);
        assert_eq!(rules, [("domain".to_owned(), "c".to_owned())]);
    }

    fn repack(raw: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(raw, 1).unwrap()
    }

    #[test]
    fn rejects_invalid_and_oversized_mrs() {
        let raw = zstd::stream::decode_all(GITHUB).unwrap();
        for n in [0, 3, 19, 33, raw.len() - 1] {
            assert!(preview(&repack(&raw[..n]), "proxy", "Dev").is_err());
        }
        for offset in [0, 4, 13, 21, 22] {
            let mut bad = raw.clone();
            bad[offset] = 0xff;
            assert!(preview(&repack(&bad), "proxy", "Dev").is_err());
        }
        let mut oversized = raw;
        oversized.resize(MAX_RULE_LIST_BYTES + 1, 0);
        assert!(preview(&repack(&oversized), "proxy", "Dev").is_err());
    }
}
