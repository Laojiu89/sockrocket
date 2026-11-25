//! Canonical ECH input shared by file imports, stored nodes and transports.
use super::model::{Node, ProxyProtocol, TransportType};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::client::EchConfig;
use serde::{Deserialize, Serialize};

pub(crate) const KEY: &str = "tls_ech";

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(super) struct Options {
    #[serde(default, alias = "enable")]
    enabled: bool,
    #[serde(default, alias = "query-server-name")]
    query_server_name: Option<String>,
    #[serde(default)]
    config: Option<ConfigText>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ConfigText {
    One(String),
    Lines(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EchSource {
    Inline(String),
    Dns(String),
}

impl Options {
    pub(super) fn attach(&self, node: &mut Node) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let tls = node
            .transport
            .as_ref()
            .and_then(|t| t.tls.as_ref())
            .context("ECH requires TLS")?;
        let source = if let Some(text) = &self.config {
            let text = match text {
                ConfigText::One(s) => s.clone(),
                ConfigText::Lines(v) => v.join("\n"),
            };
            let text = text.trim();
            let body = if text.starts_with("-----BEGIN") {
                text.strip_prefix("-----BEGIN ECH CONFIGS-----")
                    .and_then(|t| t.trim_end().strip_suffix("-----END ECH CONFIGS-----"))
                    .context("Invalid ECH PEM")?
            } else {
                text
            };
            let bytes =
                super::decode_base64(body.split_ascii_whitespace().collect::<String>().as_bytes())
                    .context("Invalid ECH encoding")?;
            decode_list(&bytes)?;
            EchSource::Inline(STANDARD.encode(bytes))
        } else {
            let name = self
                .query_server_name
                .as_deref()
                .filter(|n| !n.is_empty())
                .or(tls.sni.as_deref())
                .unwrap_or(&node.server);
            EchSource::Dns(name.trim_end_matches('.').to_ascii_lowercase())
        };
        // Both formats use a fixed interval when no upper bound is specified.
        if matches!(node.protocol, ProxyProtocol::Hysteria2 { .. })
            && let Some(interval) = node.extra.get(super::v2ray::HY2_HOP_INTERVAL).cloned()
        {
            node.extra
                .entry(super::v2ray::HY2_HOP_MAX.into())
                .or_insert(interval);
        }
        node.extra
            .insert(KEY.into(), serde_json::to_string(&source)?);
        EchSource::from_node(node)?;
        Ok(())
    }
}

pub(crate) fn decode_list(bytes: &[u8]) -> Result<EchConfig> {
    ensure!(
        bytes.len() >= 2 && bytes.len() - 2 == u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
        "Invalid ECHConfigList length"
    );
    Ok(EchConfig::new(
        bytes.into(),
        crate::proxy::ech_hpke::SUITES,
    )?)
}

impl EchSource {
    pub(crate) fn from_node(node: &Node) -> Result<Option<Self>> {
        let Some(value) = node.extra.get(KEY) else {
            return Ok(None);
        };
        let transport = node
            .transport
            .as_ref()
            .context("ECH requires TLS transport")?;
        let tls = transport.tls.as_ref().context("ECH requires TLS")?;
        ensure!(
            transport.reality.is_none()
                && matches!(
                    node.protocol,
                    ProxyProtocol::AnyTls { .. }
                        | ProxyProtocol::Hysteria2 { .. }
                        | ProxyProtocol::VMess { .. }
                )
                && !matches!(
                    transport.transport_type,
                    TransportType::Xhttp | TransportType::Reality
                ),
            "Unsupported ECH protocol or transport"
        );
        validate_name(tls.sni.as_deref().unwrap_or(&node.server))?;
        let source: Self = serde_json::from_str(value)?;
        match &source {
            Self::Dns(name) => validate_name(name)?,
            Self::Inline(data) => {
                decode_list(&STANDARD.decode(data)?)?;
            }
        }
        Ok(Some(source))
    }

    pub(crate) async fn resolve(&self) -> Result<EchConfig> {
        match self {
            Self::Inline(data) => decode_list(&STANDARD.decode(data)?),
            Self::Dns(name) => crate::dns::resolve_ech(name).await,
        }
    }
}

fn validate_name(name: &str) -> Result<()> {
    rustls::pki_types::DnsName::try_from(name).context("ECH requires a DNS name")?;
    ensure!(
        name.parse::<std::net::IpAddr>().is_err(),
        "ECH requires a DNS name"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) const TEST_CONFIG: &str = "AEX+DQBBBwAgACAGZMVaJiJ687LG59qTwtJ30n31zx+XNDanrl5HRgJJPQAIAAEAAQABAANADnB1YmxpYy5leGFtcGxlAAA=";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{clash, dedup, export, singbox};
    use serde_json::json;

    #[test]
    fn inline_and_dns_nodes_roundtrip_without_losing_ech() {
        for ech in [
            json!({"enabled":true,"config":["-----BEGIN ECH CONFIGS-----",TEST_CONFIG,"-----END ECH CONFIGS-----"]}),
            json!({"enabled":true,"query_server_name":"KEY.Example."}),
        ] {
            let mut input = json!({"type":"anytls","tag":"test","server":"private.example","server_port":443,"password":"test","tls":{"enabled":true,"ech":ech}});
            let node = singbox::parse_singbox_outbound(&input.to_string())
                .unwrap()
                .unwrap();
            let output = export::export_clash_config(std::slice::from_ref(&node));
            let restored = clash::parse_clash_config(&output).unwrap().pop().unwrap();
            assert_eq!(node.extra[KEY], restored.extra[KEY]);
            assert_eq!(
                dedup::node_fingerprint(&node),
                dedup::node_fingerprint(&restored)
            );
            input["tls"]["ech"] = json!({"enabled":false});
            let plain = singbox::parse_singbox_outbound(&input.to_string())
                .unwrap()
                .unwrap();
            assert!(!plain.extra.contains_key(KEY));
            assert_ne!(
                dedup::node_fingerprint(&plain),
                dedup::node_fingerprint(&node)
            );
        }
    }
}
