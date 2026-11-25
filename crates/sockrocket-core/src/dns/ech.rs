//! Discover the ECHConfigList in HTTPS service records via node bootstrap DNS.
use super::{runtime, wire};
use anyhow::{Context, Result, bail, ensure};
use rustls::client::EchConfig;
use std::collections::HashSet;

pub(crate) async fn resolve_ech(name: &str) -> Result<EchConfig> {
    let resolver = runtime::bootstrap_resolver(name)
        .map(|(resolver, _)| resolver)
        .unwrap_or_default();
    let mut owner = name.to_owned();
    let mut seen = HashSet::new();
    for _ in 0..8 {
        ensure!(seen.insert(owner.clone()), "ECH DNS alias cycle");
        let query = wire::build_dns_query(&owner, 65);
        let reply = resolver.exchange_raw(&query).await?;
        wire::validate_response(&query, &reply)?;
        match answer(&reply, &owner)? {
            Answer::Config(config) => return Ok(config),
            Answer::Alias(target) => owner = target,
        }
    }
    bail!("Too many ECH DNS aliases")
}

enum Answer {
    Config(EchConfig),
    Alias(String),
}

fn word(data: &[u8], pos: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(
        data.get(pos..pos + 2)
            .context("Truncated HTTPS record")?
            .try_into()?,
    ))
}

fn name(packet: &[u8], pos: &mut usize) -> Result<String> {
    let mut cursor = *pos;
    let mut jumped = false;
    let mut labels = Vec::new();
    let mut length = 0;
    for _ in 0..128 {
        let len = *packet.get(cursor).context("Truncated DNS name")?;
        if len & 0xc0 == 0xc0 {
            let ptr = usize::from(word(packet, cursor)? & 0x3fff);
            ensure!(ptr < cursor, "Invalid DNS pointer");
            if !jumped {
                *pos = cursor + 2;
                jumped = true;
            }
            cursor = ptr;
            continue;
        }
        ensure!(len <= 63, "Invalid DNS label");
        cursor += 1;
        if len == 0 {
            if !jumped {
                *pos = cursor;
            }
            return Ok(labels.join("."));
        }
        let end = cursor + usize::from(len);
        let label = packet.get(cursor..end).context("Truncated DNS label")?;
        ensure!(
            label.is_ascii() && !label.contains(&b'.'),
            "Invalid DNS label"
        );
        labels.push(std::str::from_utf8(label)?);
        length += 1 + label.len();
        ensure!(length <= 254, "DNS name too long");
        cursor = end;
    }
    bail!("DNS name too complex")
}

fn answer(packet: &[u8], owner: &str) -> Result<Answer> {
    ensure!(
        packet.len() >= 12 && packet[3] & 15 == 0 && word(packet, 4)? == 1,
        "ECH DNS lookup failed"
    );
    let mut pos = 12;
    name(packet, &mut pos)?;
    pos += 4;
    let mut best = None;
    for _ in 0..word(packet, 6)? {
        let rr_name = name(packet, &mut pos)?;
        let kind = word(packet, pos)?;
        let class = word(packet, pos + 2)?;
        let len = usize::from(word(packet, pos + 8)?);
        pos += 10;
        let start = pos;
        pos += len;
        let data = packet.get(start..pos).context("Truncated HTTPS record")?;
        if class != 1 || !rr_name.eq_ignore_ascii_case(owner) {
            continue;
        }
        if kind == 5 || (kind == 65 && word(data, 0)? == 0) {
            let mut target = start + if kind == 5 { 0 } else { 2 };
            let alias = name(packet, &mut target)?;
            ensure!(target == pos && !alias.is_empty(), "Invalid ECH alias");
            rustls::pki_types::DnsName::try_from(alias.as_str())?;
            return Ok(Answer::Alias(alias.to_ascii_lowercase()));
        }
        if kind != 65 {
            continue;
        }
        let priority = word(data, 0)?;
        let mut offset = 2;
        name(data, &mut offset)?;
        let mut config = None;
        let mut supported = true;
        let mut last_key = None;
        while offset < data.len() {
            let key = word(data, offset)?;
            ensure!(
                last_key.is_none_or(|prev| prev < key),
                "Invalid HTTPS parameter order"
            );
            last_key = Some(key);
            let len = usize::from(word(data, offset + 2)?);
            offset += 4;
            let value = data
                .get(offset..offset + len)
                .context("Invalid HTTPS service parameter")?;
            if key == 0 {
                // Endpoint, port and ALPN are fixed by the node configuration.
                supported = value == [0, 5];
            } else if key == 5 {
                config = crate::config::ech::decode_list(value).ok();
            }
            offset += len;
        }
        if supported
            && let Some(config) = config
            && best.as_ref().is_none_or(|(p, _)| priority < *p)
        {
            best = Some((priority, config));
        }
    }
    best.map(|(_, config)| Answer::Config(config))
        .context("No compatible ECH configuration in HTTPS records")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};

    fn response(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut packet = wire::build_dns_query("keys.example", 65);
        packet[2] |= 0x80;
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 12]);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);
        packet
    }

    #[test]
    fn https_record_requires_matching_owner_and_complete_ech_config() {
        let ech = STANDARD.decode(crate::config::ech::TEST_CONFIG).unwrap();
        let mut data = vec![0, 1, 0, 0, 5];
        data.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        data.extend(ech);
        let packet = response(65, &data);
        assert!(matches!(
            answer(&packet, "keys.example"),
            Ok(Answer::Config(_))
        ));
        assert!(answer(&packet, "unrelated.example").is_err());
        for end in 0..packet.len() {
            assert!(answer(&packet[..end], "keys.example").is_err());
        }
        let cname = response(5, b"\x03alt\x07example\0");
        assert!(
            matches!(answer(&cname,"keys.example"),Ok(Answer::Alias(name)) if name == "alt.example")
        );
    }
}
