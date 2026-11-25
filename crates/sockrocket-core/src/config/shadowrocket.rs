//! Local nodes in the [Proxy] section of a Shadowrocket configuration.
use super::{clash, model::Node, v2ray};
use anyhow::{Context, Result, bail, ensure};
use serde_json::json;

pub(super) fn is_config(text: &str) -> bool {
    let mut lines = text.lines().map(str::trim).filter(|line| {
        !line.is_empty() && !line.starts_with(['#', ';']) && !line.starts_with("//")
    });
    let Some(first) = lines.next() else {
        return false;
    };
    first.starts_with('[')
        && first.ends_with(']')
        && (first.eq_ignore_ascii_case("[Proxy]")
            || lines.any(|line| line.eq_ignore_ascii_case("[Proxy]")))
}

pub(super) fn entries(text: &str) -> impl Iterator<Item = &str> {
    let mut in_proxy = false;
    text.lines().map(str::trim).filter(move |line| {
        if line.starts_with('[') && line.ends_with(']') {
            in_proxy = line.eq_ignore_ascii_case("[Proxy]");
            return false;
        }
        in_proxy && !line.is_empty() && !line.starts_with(['#', ';']) && !line.starts_with("//")
    })
}

pub(super) fn parse(text: &str) -> Vec<Node> {
    entries(text)
        .filter_map(|line| parse_entry(line).ok())
        .collect()
}

fn flag(text: &str) -> Result<bool> {
    match text.to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => bail!("Invalid boolean"),
    }
}

fn parse_entry(line: &str) -> Result<Node> {
    let (name, definition) = line.split_once('=').context("Missing node definition")?;
    let name = name.trim();
    ensure!(!name.is_empty(), "Missing node name");
    let definition = definition.trim();
    if definition
        .split_once("://")
        .is_some_and(|(scheme, _)| scheme.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        let mut node = v2ray::parse_proxy_uri(definition)?;
        node.name = name.into();
        return Ok(node);
    }
    let mut fields = definition.split(',').map(str::trim);
    let kind = fields.next().unwrap_or_default().to_ascii_lowercase();
    let kind = match kind.as_str() {
        "ss" | "shadowsocks" => "ss",
        "hy2" | "hysteria2" => "hysteria2",
        "wg" | "wireguard" => "wireguard",
        "trojan" | "vmess" | "vless" | "tuic" | "anytls" => kind.as_str(),
        _ => bail!("Unsupported protocol"),
    };
    let server = fields
        .next()
        .filter(|s| !s.is_empty())
        .context("Missing address")?;
    let port: u16 = fields.next().context("Missing port")?.parse()?;
    ensure!(port != 0, "Invalid port");
    let mut proxy = json!({"name":name, "type":kind, "server":server, "port":port});
    for field in fields {
        let (key, value) = field.split_once('=').context("Invalid proxy option")?;
        let value = value.trim();
        match (kind, key.trim().to_ascii_lowercase().as_str()) {
            ("vmess" | "vless", "password" | "uuid") | ("tuic", "user" | "uuid") => {
                proxy["uuid"] = json!(value)
            }
            ("hysteria2", "auth")
            | ("ss" | "hysteria2" | "anytls" | "trojan" | "tuic", "password") => {
                proxy["password"] = json!(value)
            }
            ("vmess" | "ss", "method") => proxy["cipher"] = json!(value),
            ("vmess", "alterid") => proxy["alterId"] = json!(value.parse::<u32>()?),
            ("vless", "flow") => proxy["flow"] = json!(value),
            (_, "udp" | "udp-relay") => proxy["udp"] = json!(flag(value)?),
            ("vmess" | "vless", "tls") => proxy["tls"] = json!(flag(value)?),
            (_, "peer" | "sni") => proxy["servername"] = json!(value),
            (_, "allowinsecure" | "skip-cert-verify") => {
                proxy["skip-cert-verify"] = json!(flag(value)?)
            }
            (_, "ech") => {
                let options = match value {
                    "0" | "false" => json!({"enable":false}),
                    "1" | "true" => json!({"enable":true}),
                    _ if value.contains('.') && !value.contains(['+', '/', ':']) => {
                        json!({"enable":true, "query-server-name":value})
                    }
                    _ => json!({"enable":true, "config":value}),
                };
                proxy["ech-opts"] = options;
            }
            (_, "alpn") => proxy["alpn"] = json!(value.split('|').collect::<Vec<_>>()),
            ("vless" | "vmess" | "trojan", "obfs") if value == "websocket" || value == "ws" => {
                proxy["network"] = json!("ws")
            }
            ("vless" | "vmess" | "trojan", "obfs-host") => {
                proxy["ws-opts"]["headers"]["Host"] = json!(value)
            }
            ("vless" | "vmess" | "trojan", "obfs-uri") => proxy["ws-opts"]["path"] = json!(value),
            ("hysteria2", "obfsparam") if value.is_empty() => {}
            ("hysteria2", "obfsparam") => {
                proxy["obfs"] = json!("salamander");
                proxy["obfs-password"] = json!(value);
            }
            ("hysteria2", "upmbps") => proxy["up"] = json!(value),
            ("hysteria2", "downmbps") => proxy["down"] = json!(value),
            ("wireguard", "privatekey") => proxy["private-key"] = json!(value),
            ("wireguard", "publickey") => proxy["public-key"] = json!(value),
            ("wireguard", "presharedkey") => proxy["pre-shared-key"] = json!(value),
            ("wireguard", key @ ("ip" | "ipv6" | "dns" | "mtu")) => proxy[key] = json!(value),
            ("wireguard", "keepalive") => proxy["persistent-keepalive"] = json!(value),
            ("wireguard", "reserved") => {
                let bytes = value
                    .split('/')
                    .map(str::parse::<u8>)
                    .collect::<Result<Vec<_>, _>>()?;
                proxy["reserved"] = json!(bytes);
            }
            (_, "obfs" | "plugin") if value == "none" || value.is_empty() => {}
            (_, "tfo") => {
                flag(value)?;
            } // Optional TCP Fast Open hint.
            _ => bail!("Unsupported proxy option"),
        }
    }
    ensure!(
        proxy.get("ws-opts").is_none() || proxy["network"] == "ws",
        "WebSocket options require WebSocket transport"
    );
    clash::parse_proxy_entry(serde_yaml::to_value(proxy)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::subscription::{parse_subscription_content, subscription_entry_count};

    #[test]
    fn ech_nodes_preserve_the_key_source_and_reject_unusable_options() {
        let profile = format!(
            "[Proxy]\na = anytls, inner.example, 443, password=local, ech=keys.example\nb = hysteria2, inner.example, 443, auth=local, ech={}\nc = vmess, inner.example, 443, password=00000000-0000-4000-8000-000000000001, tls=1, ech=keys.example+https://dns.example/query",
            crate::config::ech::TEST_CONFIG
        );
        let nodes = parse(&profile);
        assert_eq!(nodes.len(), 2);
        assert!(
            matches!(crate::config::ech::EchSource::from_node(&nodes[0]).unwrap(),Some(crate::config::ech::EchSource::Dns(name)) if name=="keys.example")
        );
        assert!(matches!(
            crate::config::ech::EchSource::from_node(&nodes[1]).unwrap(),
            Some(crate::config::ech::EchSource::Inline(_))
        ));
    }

    #[test]
    fn mixed_profile_preserves_wire_options_and_skips_unknown_entries() {
        let profile = r#"# sample
[General]
dns-server = system
[Proxy]
ss = ss, example.invalid, 8388, password=sample, method=aes-128-gcm
vm = vmess, example.invalid, 443, password=00000000-0000-4000-8000-000000000001, method=auto, tls=1, obfs=websocket, obfs-host=cert.invalid, obfs-uri=/web
vl = vless, example.invalid, 443, password=00000000-0000-4000-8000-000000000002, tls=true, peer=cert.invalid
tr = trojan, example.invalid, 443, password=sample, allowInsecure=0
hy = hysteria2, example.invalid, 443, auth=sample, obfsParam=padding, udp=1, alpn=h3
tu = tuic, example.invalid, 443, password=sample, user=00000000-0000-4000-8000-000000000003, alpn=h3
at = anytls, example.invalid, 443, password=sample, peer=cert.invalid
wg = wireguard, example.invalid, 51820, privateKey=CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws=, publicKey=DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw=, ip=192.0.2.10, reserved=1/2/3
reject = ss, example.invalid, 443, password=sample, method=aes-128-gcm, plugin=unsupported
[Rule]
bogus = trojan, example.invalid, 443, password=sample
"#;
        assert!(is_config(profile));
        assert_eq!(subscription_entry_count(profile), 9);
        let nodes = parse_subscription_content(profile, "auto").unwrap();
        assert_eq!(
            nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            ["ss", "vm", "vl", "tr", "hy", "tu", "at", "wg"]
        );
        for node in &nodes {
            crate::create_outbound_unwarmed(node).unwrap();
        }
        let transport = nodes[1].transport.as_ref().unwrap();
        let ws = transport.ws.as_ref().unwrap();
        assert_eq!(ws.path.as_deref(), Some("/web"));
        assert_eq!(ws.host.as_deref(), Some("cert.invalid"));
        assert!(transport.tls.is_some());
    }
}
