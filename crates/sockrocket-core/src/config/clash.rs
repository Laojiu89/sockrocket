use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

use super::model::*;

fn deserialize_scalar<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    let value = Option::<serde_yaml::Value>::deserialize(deserializer)?;
    value
        .map(|value| {
            let text = match value {
                serde_yaml::Value::String(s) => s,
                serde_yaml::Value::Number(n) => n.to_string(),
                _ => {
                    return Err(serde::de::Error::custom("Expected a number or string"));
                }
            };
            Ok(text)
        })
        .transpose()
}

fn deserialize_port<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u16>, D::Error> {
    deserialize_scalar(deserializer)?
        .map(|s| s.parse::<u16>())
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn deserialize_bandwidth<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    deserialize_scalar(deserializer)?
        .map(|s| super::bandwidth::canonical_mbps(&s))
        .transpose()
        .map_err(serde::de::Error::custom)
}

/// Clash YAML configuration top-level structure
#[derive(Debug, Deserialize)]
struct ClashConfig {
    // Deserialized entry-by-entry as raw values first: one malformed proxy
    // (missing port, wrong scalar type, …) must not fail the whole import.
    #[serde(default)]
    proxies: Vec<serde_yaml::Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ClashProxy {
    #[serde(default, rename = "reduce-rtt")]
    reduce_rtt: bool,
    #[serde(default, rename = "sockrocket-udp-only")]
    udp_only: bool,
    #[serde(default, rename = "global-padding")]
    global_padding: bool,
    #[serde(default, rename = "authenticated-length")]
    authenticated_length: bool,
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    server: String,
    // Optional: Hysteria2 port-hopping configs carry `ports: "a-b"` instead.
    #[serde(default, deserialize_with = "deserialize_port")]
    port: Option<u16>,
    /// Hysteria2 port-hopping range, e.g. "40001-50000".
    #[serde(default, deserialize_with = "deserialize_scalar")]
    ports: Option<String>,
    #[serde(
        rename = "hop-interval",
        default,
        deserialize_with = "deserialize_scalar"
    )]
    hop_interval: Option<String>,
    // Shadowsocks fields
    #[serde(rename = "udp-over-tcp", default)]
    udp_over_tcp: bool,
    cipher: Option<String>,
    #[serde(default, deserialize_with = "deserialize_scalar")]
    password: Option<String>,
    // VMess fields
    uuid: Option<String>,
    #[serde(rename = "alterId", default)]
    alter_id: Option<u32>,
    // VLESS fields
    flow: Option<String>,
    encryption: Option<String>,
    #[serde(rename = "ss-opts")]
    trojan_ss: Option<TrojanSsOpts>,
    // TLS
    #[serde(default)]
    tls: bool,
    servername: Option<String>,
    sni: Option<String>,
    #[serde(rename = "skip-cert-verify", default)]
    skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify")]
    name_cert_verify: Option<String>,
    certificate: Option<String>,
    #[serde(rename = "private-key")]
    private_key: Option<String>,
    #[serde(rename = "ech-opts")]
    ech_opts: Option<ClashSwitch>,
    #[serde(rename = "realm-opts")]
    realm_opts: Option<ClashSwitch>,
    alpn: Option<Vec<String>>,
    #[serde(rename = "client-fingerprint")]
    client_fingerprint: Option<String>,
    fingerprint: Option<String>,
    // Network/Transport
    network: Option<String>,
    #[serde(rename = "ws-opts")]
    ws_opts: Option<ClashWsOpts>,
    #[serde(rename = "grpc-opts")]
    grpc_opts: Option<GrpcConfig>,
    #[serde(rename = "xhttp-opts")]
    xhttp_opts: Option<XhttpConfig>,
    #[serde(rename = "idle-session-check-interval")]
    idle_check_secs: Option<u64>,
    #[serde(rename = "idle-session-timeout")]
    idle_timeout_secs: Option<u64>,
    #[serde(default, rename = "min-idle-session")]
    min_idle: usize,
    #[serde(default, rename = "disable-reuse")]
    disable_reuse: bool,
    // TUIC
    #[serde(rename = "congestion-controller")]
    congestion_controller: Option<String>,
    #[serde(rename = "udp-relay-mode")]
    udp_relay_mode: Option<String>,
    #[serde(rename = "heartbeat-interval")]
    heartbeat_ms: Option<u64>,
    #[serde(default, rename = "udp-over-stream")]
    udp_over_stream: bool,
    #[serde(rename = "udp-over-stream-version")]
    udp_over_stream_version: Option<u8>,
    // Reality
    #[serde(rename = "reality-opts")]
    reality_opts: Option<ClashRealityOpts>,
    // UDP
    #[serde(default)]
    udp: Option<bool>,
    // SS plugin (e.g. shadow-tls)
    plugin: Option<String>,
    #[serde(rename = "plugin-opts")]
    plugin_opts: Option<serde_yaml::Value>,
    // Hysteria2 bandwidth
    #[serde(default, deserialize_with = "deserialize_bandwidth")]
    up: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bandwidth")]
    down: Option<String>,
    #[serde(rename = "fast-open")]
    fast_open: Option<bool>,
    obfs: Option<String>,
    #[serde(
        rename = "obfs-password",
        default,
        deserialize_with = "deserialize_scalar"
    )]
    obfs_password: Option<String>,
    #[serde(rename = "obfs-min-packet-size")]
    min_packet_size: Option<u16>,
    #[serde(rename = "obfs-max-packet-size")]
    max_packet_size: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct ClashSwitch {
    #[serde(default)]
    enable: bool,
}

#[derive(Debug, Deserialize)]
struct TrojanSsOpts {
    #[serde(default)]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct ClashWsOpts {
    #[serde(default, rename = "v2ray-http-upgrade")]
    http_upgrade: bool,
    path: Option<String>,
    headers: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct ClashRealityOpts {
    #[serde(rename = "public-key")]
    public_key: Option<String>,
    #[serde(rename = "short-id")]
    short_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ClashMieru {
    name: String,
    server: String,
    port: u16,
    username: String,
    password: String,
    transport: Option<String>,
    multiplexing: Option<String>,
    handshake_mode: Option<String>,
    traffic_pattern: Option<String>,
    #[serde(default)]
    udp: bool,
    #[serde(default, rename = "sockrocket-udp-only")]
    udp_only: bool,
    fingerprint: Option<String>,
}

fn mieru_from_clash(value: serde_yaml::Value) -> Result<Node> {
    for key in ["port-range", "ports", "network", "reality-opts", "ws-opts"] {
        anyhow::ensure!(
            value.get(key).is_none(),
            "Unsupported Mieru transport option"
        );
    }
    anyhow::ensure!(
        value.get("tls").is_none_or(|v| v.as_bool() == Some(false)),
        "Unsupported Mieru TLS option"
    );
    let p: ClashMieru = serde_yaml::from_value(value)?;
    anyhow::ensure!(
        p.fingerprint.is_none(),
        "Mieru does not support certificate pinning"
    );
    super::model::validate_mieru_endpoint(&p.server, p.port, &p.username, &p.password)?;
    anyhow::ensure!(
        !p.udp
            && !p.udp_only
            && p.transport
                .as_deref()
                .unwrap_or("TCP")
                .eq_ignore_ascii_case("TCP")
            && p.multiplexing
                .as_deref()
                .is_none_or(|s| s == "MULTIPLEXING_OFF")
            && p.handshake_mode
                .as_deref()
                .is_none_or(|s| s == "HANDSHAKE_STANDARD")
            && p.traffic_pattern.as_deref().unwrap_or("").is_empty(),
        "Unsupported Mieru session mode"
    );
    Ok(Node {
        name: super::model::decode_display_name(&p.name),
        server: p.server,
        port: p.port,
        protocol: ProxyProtocol::Mieru {
            username: p.username,
            password: p.password,
        },
        transport: None,
        latency_ms: None,
        tags: vec![],
        extra: Default::default(),
    })
}

/// Parse a Clash YAML configuration string into a list of nodes
pub fn parse_clash_config(yaml_str: &str) -> Result<Vec<Node>> {
    let root = super::storage::parse_yaml_document(yaml_str)
        .map_err(|_| anyhow::anyhow!("Invalid Clash configuration"))?;
    let server_dns = super::server_dns::import(&root)?
        .map(|p| serde_json::to_string(&p))
        .transpose()?;
    let config: ClashConfig = serde_yaml::from_value(root).context("Failed to parse Clash YAML")?;
    let mut nodes = Vec::new();
    for mut value in config.proxies {
        // Mihomo configurations often share TLS and authentication settings
        // through YAML anchors. Expand each entry before checking its type.
        if value.apply_merge().is_err() {
            tracing::warn!("Skipping malformed proxy entry");
            continue;
        }
        if value.get("type").and_then(serde_yaml::Value::as_str) == Some("mieru") {
            match mieru_from_clash(value) {
                Ok(node) => nodes.push(node),
                Err(_) => tracing::warn!("Skipping invalid or unsupported Mieru entry"),
            }
            continue;
        }
        if value.get("type").and_then(serde_yaml::Value::as_str) == Some("wireguard") {
            match super::wireguard::from_clash(&value) {
                Ok(node) => nodes.push(node),
                Err(_) => tracing::warn!("Skipping invalid or unsupported WireGuard entry"),
            }
            continue;
        }
        if value.get("type").and_then(serde_yaml::Value::as_str) == Some("tuic")
            && normalize_tuic_endpoint(&mut value).is_err()
        {
            tracing::warn!("Skipping unsupported TUIC endpoint or TLS configuration");
            continue;
        }
        // Per-entry deserialization: a single malformed proxy is skipped
        // instead of failing the entire subscription.
        let proxy: ClashProxy = match serde_yaml::from_value(value) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!("Skipping malformed proxy entry");
                continue;
            }
        };
        match convert_clash_proxy(&proxy) {
            Ok(node) => nodes.push(node),
            Err(_) => {
                tracing::warn!("Skipping unsupported or invalid proxy entry");
            }
        }
    }

    if let Some(policy) = server_dns {
        for node in &mut nodes {
            node.extra
                .insert(super::server_dns::KEY.into(), policy.clone());
        }
    }
    Ok(nodes)
}

fn normalize_tuic_endpoint(value: &mut serde_yaml::Value) -> Result<()> {
    use serde_yaml::Value;
    let fields = value
        .as_mapping_mut()
        .context("Invalid TUIC configuration")?;
    let string = |key: &str| {
        fields
            .get(key)
            .map(|v| v.as_str().context("Invalid TUIC text field"))
            .transpose()
    };
    anyhow::ensure!(
        string("token")?.unwrap_or("").is_empty(),
        "TUIC v4 token is unsupported"
    );
    anyhow::ensure!(
        fields
            .get("disable-sni")
            .is_none_or(|v| v.as_bool() == Some(false)),
        "Disabling TLS SNI is not supported"
    );
    let server = string("server")?.context("Missing TUIC server")?;
    let sni = string("servername")?
        .or(string("sni")?)
        .filter(|s| !s.is_empty())
        .unwrap_or(server);
    if let Some(ip) = string("ip")?.filter(|ip| !ip.is_empty()) {
        let endpoint: std::net::IpAddr = ip.parse().context("Invalid TUIC server IP override")?;
        // Dial the given IP but continue to use the configured TLS identity.
        let sni = sni.to_owned();
        fields.insert(Value::from("server"), Value::from(endpoint.to_string()));
        fields.insert(Value::from("servername"), Value::from(sni));
    }
    Ok(())
}

/// Resolve the connect port: `port` first, otherwise the first port of a
/// Hysteria2 `ports` hopping range ("40001-50000" / "40001,40002").
fn resolve_port(proxy: &ClashProxy) -> Result<u16> {
    if let Some(p) = proxy.port {
        return Ok(p);
    }
    if let Some(ref range) = proxy.ports {
        let first = range
            .split(['-', ','])
            .next()
            .unwrap_or("")
            .trim()
            .parse::<u16>();
        if let Ok(p) = first {
            return Ok(p);
        }
    }
    anyhow::bail!("missing port (and no usable ports range)")
}

/// Parse the SS `plugin` / `plugin-opts` fields.
///
/// `shadow-tls` v3 is supported and becomes `Some(ShadowTlsConfig)`; no
/// plugin at all is `None`; anything else is rejected.
fn parse_shadow_tls_plugin(proxy: &ClashProxy) -> Result<Option<ShadowTlsConfig>> {
    let Some(plugin) = proxy.plugin.as_deref() else {
        return Ok(None);
    };
    if plugin != "shadow-tls" {
        anyhow::bail!(
            "SS node '{}' uses unsupported plugin '{}'",
            proxy.name,
            plugin
        );
    }

    #[derive(Debug, Deserialize)]
    struct ShadowTlsOpts {
        host: Option<String>,
        password: Option<String>,
        version: Option<u32>,
        #[serde(rename = "skip-cert-verify", default)]
        skip_cert_verify: bool,
    }

    let opts: ShadowTlsOpts = match proxy.plugin_opts {
        Some(ref value) => serde_yaml::from_value(value.clone())
            .context("SS shadow-tls plugin-opts are malformed")?,
        None => anyhow::bail!(
            "SS node '{}' shadow-tls plugin is missing plugin-opts",
            proxy.name
        ),
    };
    if opts.version.unwrap_or(3) != 3 {
        anyhow::bail!(
            "SS node '{}' shadow-tls version {:?} is unsupported (only v3)",
            proxy.name,
            opts.version
        );
    }
    Ok(Some(ShadowTlsConfig {
        host: opts
            .host
            .context("SS shadow-tls plugin-opts missing host")?,
        password: opts
            .password
            .context("SS shadow-tls plugin-opts missing password")?,
        skip_cert_verify: opts.skip_cert_verify,
    }))
}

/// Check if a YAML string looks like Clash config
pub fn is_clash_config(content: &str) -> bool {
    (content.contains("proxies") || content.contains("proxy-groups"))
        && super::storage::parse_yaml_document(content)
            .is_ok_and(|root| root.get("proxies").is_some() || root.get("proxy-groups").is_some())
}

fn convert_clash_proxy(proxy: &ClashProxy) -> Result<Node> {
    let udp = proxy.udp.unwrap_or(false);

    let protocol = match proxy.proxy_type.as_str() {
        "anytls" => ProxyProtocol::AnyTls {
            password: proxy.password.clone().context("AnyTLS missing password")?,
            pool: AnyTlsPool {
                check_interval_ms: proxy
                    .idle_check_secs
                    .map(|v| {
                        v.checked_mul(1000)
                            .context("AnyTLS check interval exceeds range")
                    })
                    .transpose()?,
                idle_timeout_ms: proxy
                    .idle_timeout_secs
                    .map(|v| v.checked_mul(1000).context("AnyTLS timeout exceeds range"))
                    .transpose()?,
                min_idle: proxy.min_idle,
                disable_reuse: proxy.disable_reuse,
            }
            .checked()?,
            udp: proxy.udp.unwrap_or(true),
        },
        "ss" => {
            anyhow::ensure!(
                !proxy.udp_over_tcp,
                "Shadowsocks UDP over TCP is unsupported"
            );
            let cipher = proxy.cipher.as_ref().context("SS missing cipher")?.clone();
            let password = proxy
                .password
                .as_ref()
                .context("SS missing password")?
                .clone();
            let shadow_tls = if proxy.plugin.as_deref() == Some("shadow-tls") {
                parse_shadow_tls_plugin(proxy)?
            } else {
                None
            };
            ProxyProtocol::Shadowsocks {
                cipher,
                password,
                udp,
                shadow_tls,
            }
        }
        "vmess" => {
            let uuid = proxy.uuid.as_ref().context("VMess missing uuid")?.clone();
            let alter_id = proxy.alter_id.unwrap_or(0);
            let cipher = proxy.cipher.clone().unwrap_or_else(|| "auto".to_string());
            ProxyProtocol::VMess {
                uuid,
                alter_id,
                cipher,
                udp,
            }
        }
        "vless" => {
            let uuid = proxy.uuid.as_ref().context("VLESS missing uuid")?.clone();
            ProxyProtocol::VLess {
                uuid,
                flow: proxy.flow.clone(),
                udp,
            }
        }
        "tuic" => {
            let uuid = proxy.uuid.as_ref().context("TUIC missing uuid")?.clone();
            uuid::Uuid::parse_str(&uuid).context("Invalid TUIC v5 UUID")?;
            let password = proxy
                .password
                .as_ref()
                .context("TUIC missing password")?
                .clone();
            let congestion_control = proxy
                .congestion_controller
                .clone()
                .unwrap_or_else(|| "bbr".to_string());
            ProxyProtocol::Tuic {
                uuid,
                password,
                congestion_control,
                heartbeat_ms: proxy.heartbeat_ms,
                relay: TuicRelay::parse(
                    if proxy.udp_over_stream {
                        None
                    } else {
                        proxy.udp_relay_mode.as_deref()
                    },
                    proxy
                        .udp_over_stream
                        .then_some(match proxy.udp_over_stream_version {
                            None | Some(0) => 1,
                            Some(v) => v,
                        }),
                )?,
                udp: proxy.udp.unwrap_or(true),
            }
        }
        "trojan" => {
            anyhow::ensure!(
                !proxy.trojan_ss.as_ref().is_some_and(|opts| opts.enabled),
                "Trojan-Go Shadowsocks wrapping is unsupported"
            );
            let password = proxy
                .password
                .as_ref()
                .context("Trojan missing password")?
                .clone();
            ProxyProtocol::Trojan { password, udp }
        }
        "hysteria2" | "hy2" => {
            anyhow::ensure!(
                !proxy.realm_opts.as_ref().is_some_and(|o| o.enable),
                "Hysteria2 Realms is unsupported"
            );
            let password = proxy
                .password
                .as_ref()
                .context("Hysteria2 missing password")?
                .clone();
            let obfs = match proxy.obfs.as_deref() {
                None | Some("") => None,
                kind => Hy2Obfs::from_parts(
                    kind,
                    proxy.obfs_password.as_deref(),
                    proxy.min_packet_size,
                    proxy.max_packet_size,
                )?,
            };
            ProxyProtocol::Hysteria2 {
                password,
                udp: proxy.udp.unwrap_or(true),
                obfs,
            }
        }
        other => anyhow::bail!("Unsupported proxy type: {}", other),
    };

    let hopping_ports = if matches!(protocol, ProxyProtocol::Hysteria2 { .. }) {
        proxy
            .ports
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| s.replace('/', ","))
    } else {
        None
    };
    let port = match &hopping_ports {
        Some(ports) => super::v2ray::hysteria2_initial_port(ports, proxy.port.unwrap_or_default())?,
        None => resolve_port(proxy)?,
    };
    if matches!(protocol, ProxyProtocol::Hysteria2 { .. }) {
        anyhow::ensure!(port != 0, "Hysteria2 requires a nonzero port");
    }
    let mut extra = HashMap::new();
    if proxy.proxy_type == "ss"
        && let Some(name) = proxy.plugin.as_deref().filter(|v| *v != "shadow-tls")
    {
        let opts = proxy
            .plugin_opts
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .unwrap_or_else(|| serde_json::json!({}));
        super::ss_plugin::Plugin::parse(
            name,
            opts.as_object()
                .context("Expected plugin options map")?
                .clone(),
            &proxy.server,
        )?
        .save(&mut extra)?;
    }
    if matches!(protocol, ProxyProtocol::VLess { .. }) {
        super::v2ray::set_vless_encryption(&mut extra, proxy.encryption.as_deref())?;
    }
    if proxy.proxy_type == "tuic" && proxy.reduce_rtt {
        extra.insert(super::v2ray::TUIC_ZERO_RTT.into(), "true".into());
    }
    if proxy.udp_only {
        anyhow::ensure!(
            proxy.proxy_type == "trojan" && udp,
            "Invalid UDP-only restriction"
        );
        extra.insert(super::v2ray::UDP_ONLY.into(), "true".into());
    }
    if proxy.proxy_type == "vmess" {
        super::v2ray::vmess_framing_options(
            &mut extra,
            proxy.global_padding,
            proxy.authenticated_length,
        );
    }
    if let Some(pin) = &proxy.fingerprint {
        let key = match proxy.proxy_type.as_str() {
            "tuic" => super::v2ray::TUIC_CERT_PIN,
            "hysteria2" | "hy2" | "anytls" => super::v2ray::TLS_CERT_PIN,
            _ => anyhow::bail!("Certificate pinning unsupported for this protocol"),
        };
        let pin = super::v2ray::parse_tuic_certificate_pin(pin)?;
        extra.insert(key.into(), pin.iter().map(|b| format!("{b:02x}")).collect());
    }
    if matches!(proxy.proxy_type.as_str(), "hysteria2" | "hy2") {
        if let Some(v) = &proxy.hop_interval {
            let (start, end) = v.split_once('-').unwrap_or((v, v));
            let lo = start.parse::<u64>()?;
            let lo = if lo == 0 { 30 } else { lo.max(5) };
            let hi = end.parse::<u64>()?.max(lo);
            for (n, k) in [
                (lo, super::v2ray::HY2_HOP_INTERVAL),
                (hi, super::v2ray::HY2_HOP_MAX),
            ] {
                extra.insert(
                    k.into(),
                    n.checked_mul(1000)
                        .context("Hysteria2 hop interval out of range")?
                        .to_string(),
                );
            }
        }
        if let Some(ports) = hopping_ports {
            extra.insert(super::v2ray::HY2_MPORT.into(), ports);
        }
        for (value, key) in [
            (&proxy.up, super::v2ray::HY2_UP),
            (&proxy.down, super::v2ray::HY2_DOWN),
        ] {
            if let Some(value) = value {
                // deserialize_bandwidth already normalized the imported value.
                extra.insert(key.into(), value.clone());
            }
        }
        if let Some(value) = proxy.fast_open {
            extra.insert(super::v2ray::HY2_FAST_OPEN.into(), value.to_string());
        }
    }
    let mut transport = build_transport(proxy)?;
    if let Some(transport) = transport.as_mut() {
        apply_tls_requirements(proxy, transport)?;
    }
    if matches!(protocol, ProxyProtocol::Hysteria2 { .. }) {
        super::v2ray::validate_hysteria2_profile(transport.as_ref().and_then(|t| t.tls.as_ref()))?;
    }

    Ok(Node {
        name: super::model::decode_display_name(&proxy.name),
        server: proxy.server.clone(),
        port,
        protocol,
        transport,
        latency_ms: None,
        tags: vec![],
        extra,
    })
}

fn apply_tls_requirements(proxy: &ClashProxy, transport: &mut TransportConfig) -> Result<()> {
    if transport.tls.is_none() && transport.reality.is_none() {
        return Ok(());
    }
    anyhow::ensure!(
        !proxy.ech_opts.as_ref().is_some_and(|o| o.enable),
        "Encrypted ClientHello is unsupported"
    );
    anyhow::ensure!(
        proxy.certificate.as_deref().unwrap_or("").is_empty()
            && proxy.private_key.as_deref().unwrap_or("").is_empty(),
        "Client certificate authentication is unsupported"
    );
    if let Some(name) = proxy.name_cert_verify.as_deref().filter(|s| !s.is_empty()) {
        let sni = transport
            .tls
            .as_ref()
            .and_then(|t| t.sni.as_deref())
            .or_else(|| transport.reality.as_ref().and_then(|r| r.sni.as_deref()))
            .filter(|s| !s.is_empty())
            .unwrap_or(&proxy.server);
        anyhow::ensure!(
            name.eq_ignore_ascii_case(sni),
            "Independent certificate verification name is unsupported"
        );
        // Mihomo explicitly verifies this name even with skip-cert-verify set.
        if let Some(tls) = &mut transport.tls {
            tls.skip_cert_verify = false;
        }
        if let Some(reality) = &mut transport.reality {
            reality.skip_cert_verify = false;
        }
    }
    Ok(())
}

fn build_transport(proxy: &ClashProxy) -> Result<Option<TransportConfig>> {
    let network = proxy.network.as_deref().unwrap_or("tcp");
    let proxy_type = proxy.proxy_type.as_str();

    // TCP, WebSocket and VLESS XHTTP are supported. Anything else
    // (grpc/h2/http/httpupgrade/...) must be rejected loudly — silently
    // downgrading to bare TCP/TLS produces a node that imports fine but can
    // never connect.
    if !matches!(network, "tcp" | "ws" | "grpc" | "httpupgrade" | "xhttp") {
        anyhow::bail!("Unsupported Clash transport; expected TCP, WebSocket or VLESS XHTTP");
    }

    if network == "xhttp" {
        anyhow::ensure!(proxy_type == "vless", "XHTTP requires VLESS");
        anyhow::ensure!(
            proxy.flow.as_deref().unwrap_or("").is_empty(),
            "XHTTP does not support Vision flow"
        );
        let xhttp = proxy.xhttp_opts.clone().unwrap_or_default();
        if let Some(reality) = &proxy.reality_opts {
            anyhow::ensure!(
                reality.public_key.as_ref().is_some_and(|k| !k.is_empty()),
                "REALITY public key is required"
            );
        }
        xhttp.validate()?;
        anyhow::ensure!(
            proxy.alpn.as_ref().is_none_or(|a| a.is_empty()
                || a.iter()
                    .all(|s| matches!(s.as_str(), "h2" | "http/1.1" | "h3"))),
            "Unsupported XHTTP ALPN"
        );
        return Ok(Some(TransportConfig {
            grpc: None,
            transport_type: TransportType::Xhttp,
            tls: proxy.tls.then(|| TlsConfig {
                sni: proxy.servername.clone().or_else(|| proxy.sni.clone()),
                skip_cert_verify: proxy.skip_cert_verify,
                alpn: proxy.alpn.clone(),
                fingerprint: proxy.client_fingerprint.clone(),
            }),
            ws: None,
            reality: proxy.reality_opts.as_ref().map(|r| RealityConfig {
                public_key: r.public_key.clone().unwrap_or_default(),
                short_id: r.short_id.clone().unwrap_or_default(),
                sni: proxy.servername.clone().or_else(|| proxy.sni.clone()),
                client_fingerprint: proxy.client_fingerprint.clone(),
                skip_cert_verify: proxy.skip_cert_verify,
            }),
            xhttp: Some(xhttp),
        }));
    }

    // These protocols use TLS even when the Clash entry omits the tls flag.
    let force_tls = matches!(
        proxy_type,
        "trojan" | "tuic" | "hysteria2" | "hy2" | "anytls"
    );

    // Reality transport
    if let Some(ref reality) = proxy.reality_opts {
        anyhow::ensure!(
            matches!(proxy_type, "vmess" | "vless" | "trojan") && network == "tcp",
            "REALITY requires VMess, VLESS or Trojan over raw TCP"
        );
        let pk = reality
            .public_key
            .as_ref()
            .filter(|s| !s.is_empty())
            .context("REALITY public key is required")?;
        return Ok(Some(TransportConfig {
            grpc: None,
            xhttp: None,
            transport_type: TransportType::Reality,
            tls: None,
            ws: None,
            reality: Some(RealityConfig {
                public_key: pk.clone(),
                short_id: reality.short_id.clone().unwrap_or_default(),
                sni: proxy.servername.clone().or_else(|| proxy.sni.clone()),
                client_fingerprint: proxy.client_fingerprint.clone(),
                skip_cert_verify: proxy.skip_cert_verify,
            }),
        }));
    }

    let has_tls = proxy.tls || force_tls;
    let has_ws = matches!(network, "ws" | "httpupgrade");

    if !has_tls && !has_ws && network != "grpc" {
        return Ok(None);
    }

    let ws = if has_ws {
        proxy.ws_opts.as_ref().map(|opts| {
            let host = opts.headers.as_ref().and_then(|headers| {
                headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("host"))
                    .map(|(_, value)| value.clone())
            });
            WsConfig {
                path: opts.path.clone(),
                host,
                headers: opts.headers.clone(),
            }
        })
    } else {
        None
    };

    let tls = has_tls.then(|| {
        // Mihomo uses the WS Host for VMess/VLESS SNI unless servername overrides it.
        let sni = proxy
            .servername
            .clone()
            .or_else(|| proxy.sni.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                if !matches!(proxy_type, "vmess" | "vless") {
                    return None;
                }
                let host = ws
                    .as_ref()?
                    .host
                    .as_deref()?
                    .parse::<http::uri::Authority>()
                    .ok()?;
                Some(host.host().trim_matches(['[', ']']).to_owned())
            });
        TlsConfig {
            sni,
            skip_cert_verify: proxy.skip_cert_verify,
            alpn: proxy.alpn.clone(),
            fingerprint: proxy.client_fingerprint.clone(),
        }
    });

    let transport_type = match (has_ws, has_tls) {
        _ if network == "grpc" => TransportType::Grpc,
        (true, _)
            if network == "httpupgrade"
                || proxy.ws_opts.as_ref().is_some_and(|o| o.http_upgrade) =>
        {
            TransportType::HttpUpgrade
        }
        (true, _) => TransportType::WebSocket,
        (false, true) => TransportType::Tls,
        _ => TransportType::Tcp,
    };

    Ok(Some(TransportConfig {
        grpc: (network == "grpc").then(|| proxy.grpc_opts.clone().unwrap_or_default()),
        xhttp: None,
        transport_type,
        tls,
        ws,
        reality: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_providers_keep_supported_wire_formats_and_skip_unsupported_entries() {
        let nodes = parse_clash_config(r#"
proxies:
  - {name: legacy, type: vmess, server: example.invalid, port: 443, uuid: '00000000-0000-4000-8000-000000000001', alterId: 64}
  - {name: encrypted, type: vless, server: example.invalid, port: 443, uuid: '00000000-0000-4000-8000-000000000002', encryption: mlkem768x25519plus.native.1rtt.BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc}
  - {name: unknown, type: vless, server: example.invalid, port: 443, uuid: '00000000-0000-4000-8000-000000000002', encryption: unknown}
  - {name: wrapped, type: trojan, server: example.invalid, port: 443, password: fixture, ss-opts: {enabled: true}}
  - {name: standard, type: trojan, server: example.invalid, port: 443, password: fixture, ss-opts: {enabled: false}}
  - {name: simple-obfs, type: ss, server: example.invalid, port: 443, password: fixture, cipher: aes-256-gcm, plugin: obfs, plugin-opts: {mode: tls}}
  - {name: websocket-mux, type: ss, server: example.invalid, port: 443, password: fixture, cipher: aes-256-gcm, plugin: v2ray-plugin, plugin-opts: {mode: websocket, mux: true}}
"#).unwrap();
        assert_eq!(
            nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            [
                "legacy",
                "encrypted",
                "standard",
                "simple-obfs",
                "websocket-mux"
            ]
        );
        assert!(matches!(
            &nodes[0].protocol,
            ProxyProtocol::VMess { alter_id: 64, .. }
        ));
        assert!(
            nodes[1]
                .extra
                .contains_key(super::super::v2ray::VLESS_ENCRYPTION)
        );
        let plugin = |i: usize| {
            super::super::ss_plugin::Plugin::load(&nodes[i].extra)
                .unwrap()
                .unwrap()
        };
        assert_eq!(plugin(3).mode, "tls");
        assert_eq!(plugin(4).mux, Some(true));
        for node in nodes {
            crate::create_outbound_unwarmed(&node).unwrap();
        }
    }

    #[test]
    fn ss2022_clash_import_preserves_the_psk_and_does_not_downgrade_uot() {
        let yaml = r#"
proxies:
  - &base {name: SS2022, type: ss, server: ss.example.invalid, port: 8388, cipher: 2022-blake3-aes-128-gcm, password: 'AAECAwQFBgcICQoLDA0ODw==', udp: true}
  - {<<: *base, name: Native, udp-over-tcp: false, udp-over-tcp-version: 2}
  - {<<: *base, name: UoT, udp-over-tcp: true, udp-over-tcp-version: 2}
  - {<<: *base, name: Wrapped, plugin: shadow-tls, plugin-opts: {version: 3, host: tls.example.invalid, password: synthetic-outer}}
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        let names: Vec<_> = nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["SS2022", "Native", "Wrapped"]);
        for node in &nodes {
            let ProxyProtocol::Shadowsocks {
                cipher,
                password,
                shadow_tls,
                ..
            } = &node.protocol
            else {
                panic!("expected Shadowsocks")
            };
            assert_eq!(cipher, "2022-blake3-aes-128-gcm");
            assert_eq!(password, "AAECAwQFBgcICQoLDA0ODw==");
            assert_eq!(shadow_tls.is_some(), node.name == "Wrapped");
            crate::create_outbound_unwarmed(node).unwrap();
        }
    }

    #[test]
    fn test_parse_clash_ss() {
        let yaml = r#"
proxies:
  - name: "SS-HK"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "test123"
    udp: true
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "SS-HK");
        assert_eq!(nodes[0].server, "1.2.3.4");
        assert_eq!(nodes[0].port, 8388);
        match &nodes[0].protocol {
            ProxyProtocol::Shadowsocks {
                cipher, password, ..
            } => {
                assert_eq!(cipher, "aes-256-gcm");
                assert_eq!(password, "test123");
            }
            _ => panic!("Expected Shadowsocks"),
        }
    }

    #[test]
    fn test_parse_clash_vmess_ws_tls() {
        let yaml = r#"
proxies:
  - name: "VMess-JP"
    type: vmess
    server: 5.6.7.8
    port: 443
    uuid: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
    alterId: 0
    cipher: auto
    tls: true
    servername: example.com
    network: ws
    ws-opts:
      path: /v2ray
      headers:
        Host: example.com
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.name, "VMess-JP");
        let transport = node.transport.as_ref().unwrap();
        assert_eq!(transport.transport_type, TransportType::WebSocket);
        assert!(transport.tls.is_some());
        assert!(transport.ws.is_some());
        assert_eq!(
            transport.ws.as_ref().unwrap().path.as_deref(),
            Some("/v2ray")
        );
    }

    #[test]
    fn test_parse_clash_vless_reality() {
        let yaml = r#"
proxies:
  - name: "VLESS-US"
    type: vless
    server: 9.10.11.12
    port: 443
    uuid: "b85798ef-e9dc-46a4-9a87-8da4499d36d0"
    flow: xtls-rprx-vision
    tls: true
    reality-opts:
      public-key: "abc123"
      short-id: "0123456789abcdef"
    servername: www.example.com
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        let transport = node.transport.as_ref().unwrap();
        assert_eq!(transport.transport_type, TransportType::Reality);
        let reality = transport.reality.as_ref().unwrap();
        assert_eq!(reality.public_key, "abc123");
    }

    #[test]
    fn mihomo_stream_transport_fields_reach_outbound_construction() {
        let yaml = r#"proxies:
  - {name: vmess-ws, type: vmess, server: 192.0.2.7, port: 443, uuid: 00000000-0000-0000-0000-000000000001, alterId: 0, cipher: auto, tls: true, network: ws, ws-opts: {path: /demo, headers: {host: front.example.invalid}}, global-padding: true, authenticated-length: true}
  - {name: vless-ws, type: vless, server: 192.0.2.7, port: 443, uuid: 00000000-0000-0000-0000-000000000001, tls: true, servername: cert.example.invalid, network: ws, ws-opts: {path: /demo, headers: {Host: front.example.invalid}}}
  - {name: trojan-grpc, type: trojan, server: 192.0.2.7, port: 443, password: fixture, sni: cert.example.invalid, alpn: [h2], skip-cert-verify: true, client-fingerprint: chrome, network: grpc, grpc-opts: {grpc-service-name: fixture.Service}}
  - {name: vmess-reality, type: vmess, server: 192.0.2.7, port: 443, uuid: 00000000-0000-0000-0000-000000000001, alterId: 0, cipher: auto, tls: true, servername: cert.example.invalid, client-fingerprint: chrome, reality-opts: {public-key: E27YYTzCqcRhtjR1KPPolrL0MWMOXBFMBBaU5Bak7j0, short-id: "abcd"}}
"#;
        let nodes = super::super::subscription::parse_subscription_content(yaml, "clash").unwrap();
        assert_eq!(nodes.len(), 4);
        for node in &nodes {
            crate::create_outbound_unwarmed(node).unwrap();
        }
        for (node, sni) in [
            (&nodes[0], "front.example.invalid"),
            (&nodes[1], "cert.example.invalid"),
        ] {
            let t = node.transport.as_ref().unwrap();
            assert_eq!(t.tls.as_ref().unwrap().sni.as_deref(), Some(sni));
            assert_eq!(
                t.ws.as_ref().unwrap().host.as_deref(),
                Some("front.example.invalid")
            );
        }
        assert_eq!(nodes[0].extra[super::super::v2ray::VMESS_PADDING], "true");
        assert_eq!(nodes[0].extra[super::super::v2ray::VMESS_AUTH_LEN], "true");
        let grpc = nodes[2].transport.as_ref().unwrap();
        assert_eq!(grpc.grpc.as_ref().unwrap().service_name, "fixture.Service");
        let tls = grpc.tls.as_ref().unwrap();
        assert_eq!(tls.sni.as_deref(), Some("cert.example.invalid"));
        assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(tls.alpn.as_ref().unwrap(), &["h2"]);
        assert!(tls.skip_cert_verify);
        let reality = nodes[3].transport.as_ref().unwrap();
        assert_eq!(reality.transport_type, TransportType::Reality);
        assert_eq!(reality.reality.as_ref().unwrap().short_id, "abcd");
    }

    #[test]
    fn test_parse_clash_tuic() {
        let yaml = r#"
proxies:
  - name: "TUIC-SG"
    type: tuic
    server: 13.14.15.16
    port: 443
    uuid: "d685aef3-b3c4-4932-9a9d-d0c2f6727dfa"
    password: "supersecret"
    congestion-controller: bbr
    udp: true
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        match &nodes[0].protocol {
            ProxyProtocol::Tuic {
                uuid,
                password,
                congestion_control,
                ..
            } => {
                assert_eq!(uuid, "d685aef3-b3c4-4932-9a9d-d0c2f6727dfa");
                assert_eq!(password, "supersecret");
                assert_eq!(congestion_control, "bbr");
            }
            _ => panic!("Expected TUIC"),
        }
    }

    #[test]
    fn mihomo_tuic_dials_ip_override_with_original_tls_identity() {
        let entry = r#"name: TUIC
type: tuic
server: target.example.invalid
ip: 192.0.2.17
port: 443
uuid: 00000000-0000-4000-8000-000000000001
password: fixture
alpn: [h3]
reduce-rtt: true
udp-relay-mode: quic"#;
        let import = |extra: &str| {
            let row = format!("{entry}\n{extra}");
            let yaml = format!("proxies:\n- {}", row.replace('\n', "\n  "));
            parse_clash_config(&yaml).unwrap()
        };
        for (extra, sni) in [
            ("", "target.example.invalid"),
            ("sni: tls.example.invalid", "tls.example.invalid"),
        ] {
            let node = import(extra).pop().unwrap();
            assert_eq!(node.server, "192.0.2.17");
            let tls = node.transport.as_ref().unwrap().tls.as_ref().unwrap();
            assert_eq!(tls.sni.as_deref(), Some(sni));
            assert!(!tls.skip_cert_verify);
            assert!(matches!(
                node.protocol,
                ProxyProtocol::Tuic {
                    udp: true,
                    relay: TuicRelay::Quic,
                    ..
                }
            ));
            assert_eq!(node.extra[super::super::v2ray::TUIC_ZERO_RTT], "true");
            assert!(crate::create_outbound_unwarmed(&node).is_ok());
        }
        assert!(!import("udp: false")[0].protocol.supports_udp());
        for extra in [
            "disable-sni: true",
            "token: tuic-v4",
            "name-cert-verify: other.invalid",
        ] {
            assert!(import(extra).is_empty());
        }
    }

    #[test]
    fn test_parse_mixed_proxies() {
        let yaml = r#"
proxies:
  - name: "SS"
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-256-gcm
    password: "pass1"
  - name: "VMess"
    type: vmess
    server: 2.2.2.2
    port: 443
    uuid: "uuid1"
  - name: "Trojan"
    type: trojan
    server: 3.3.3.3
    port: 443
    password: "pass2"
  - name: "Unknown"
    type: snell
    server: 4.4.4.4
    port: 1234
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        // snell is unsupported, should be skipped
        assert_eq!(nodes.len(), 3);
    }

    #[test]
    fn test_parse_malformed_entries_are_skipped() {
        // Real-world converter output quirks:
        // - Hysteria2 port hopping uses `ports: "a-b"` instead of `port`
        // - Entries missing both port and ports must not fail the import
        // - Entries with a wrong scalar type must not fail the import
        let yaml = r#"
proxies:
  - { name: "Hy2-Hop", type: hysteria2, server: hk1.example.com, ports: 40001-50000, password: pw, sni: example.net }
  - { name: "NoPort", type: ss, server: 1.2.3.4, cipher: aes-256-gcm, password: pw }
  - { name: "BadPort", type: ss, server: 1.2.3.4, port: { oops: 1 }, cipher: aes-256-gcm, password: pw }
  - { name: "SS-OK", type: ss, server: 5.6.7.8, port: 8388, cipher: aes-256-gcm, password: pw }
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 2, "malformed entries must be skipped");
        // Port-hopping range resolves to its first port.
        assert_eq!(nodes[0].name, "Hy2-Hop");
        assert_eq!(nodes[0].port, 40001);
        assert_eq!(nodes[1].name, "SS-OK");
        assert_eq!(nodes[1].port, 8388);
    }

    #[test]
    fn mihomo_hysteria2_batch_preserves_shared_settings_and_hopping_ports() {
        let yaml = r#"
defaults: &hy {type: hysteria2, server: proxy.example.invalid, port: "443", password: 123456, sni: tls.example.invalid, alpn: [h3]}
"proxies":
  - {<<: *hy, name: hopping, ports: "35000-35002/36000,37000-37002", hop-interval: "15-30", obfs: gecko, obfs-password: 567891, obfs-min-packet-size: 512, obfs-max-packet-size: 1100}
  - {<<: *hy, name: bad-range, ports: "9000-8000"}
  - {<<: *hy, name: original, obfs: "", obfs-password: "", udp: false}
  - {<<: *hy, name: obfuscated, ports: 40000, obfs: salamander, obfs-password: another-secret}
  - {<<: true, name: bad-merge}
  - {<<: *hy, name: invalid-port, port: 0}
"#;
        assert!(is_clash_config(yaml));
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].port, 35000);
        assert_eq!(
            nodes[0].extra[super::super::v2ray::HY2_MPORT],
            "35000-35002,36000,37000-37002"
        );
        assert_eq!(
            nodes[0].extra[super::super::v2ray::HY2_HOP_INTERVAL],
            "15000"
        );
        assert_eq!(nodes[0].extra[super::super::v2ray::HY2_HOP_MAX], "30000");
        let tls = nodes[0].transport.as_ref().unwrap().tls.as_ref().unwrap();
        assert_eq!(tls.sni.as_deref(), Some("tls.example.invalid"));
        assert_eq!(tls.alpn.as_ref().unwrap(), &["h3"]);
        let ProxyProtocol::Hysteria2 {
            password,
            udp,
            obfs: Some(obfs),
        } = &nodes[0].protocol
        else {
            panic!("expected obfuscated HY2");
        };
        assert_eq!(password, "123456");
        assert!(*udp);
        assert_eq!(obfs.kind, "gecko");
        assert_eq!(obfs.password, "567891");
        assert_eq!(obfs.gecko_sizes(), (512, 1100));
        assert_eq!(nodes[1].port, 443);
        assert!(matches!(
            nodes[1].protocol,
            ProxyProtocol::Hysteria2 {
                udp: false,
                obfs: None,
                ..
            }
        ));
        assert_eq!(nodes[2].port, 40000);
        assert!(
            matches!(&nodes[2].protocol, ProxyProtocol::Hysteria2 { obfs: Some(obfs), .. } if obfs.kind == "salamander")
        );
        for node in nodes {
            crate::create_outbound_unwarmed(&node).unwrap();
        }
    }

    #[test]
    fn clash_tls_constraints_apply_to_each_node_without_weakening_verification() {
        let yaml = r#"
base: &base {server: host.example.invalid, port: 443, password: fixture}
proxies:
  - {<<: *base, type: hysteria2, name: realm, realm-opts: {enable: true}}
  - {<<: *base, type: hysteria2, name: ech, ech-opts: {enable: true}}
  - {<<: *base, type: trojan, name: mtls, certificate: cert.pem, private-key: fixture.key}
  - {<<: *base, type: anytls, name: different-name, name-cert-verify: different.example.invalid}
  - {<<: *base, type: hysteria2, name: checked, sni: tls.example.invalid, name-cert-verify: TLS.EXAMPLE.INVALID, skip-cert-verify: true}
  - {<<: *base, type: anytls, name: defaults, ech-opts: {enable: false, config: example}, certificate: "", private-key: "", name-cert-verify: ""}
  - {<<: *base, type: hy2, name: basic, realm-opts: {enable: false}}
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(
            nodes.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            ["checked", "defaults", "basic"]
        );
        assert!(
            !nodes[0]
                .transport
                .as_ref()
                .unwrap()
                .tls
                .as_ref()
                .unwrap()
                .skip_cert_verify
        );
    }

    #[test]
    fn clash_detection_recognizes_top_level_keys_only() {
        assert!(is_clash_config(r#"{"proxies": [], "proxy-groups": []}"#));
        assert!(is_clash_config("'proxies': []"));
        assert!(!is_clash_config(
            "hy2://auth@example.invalid:443#proxies:demo"
        ));
        assert!(!is_clash_config(
            r#"{"outbounds": [], "ignored": {"proxies": []}}"#
        ));
    }

    #[test]
    fn numeric_and_unit_bandwidths_preserve_hysteria_nodes() {
        let yaml = r#"proxies:
  - {name: integer, type: hysteria2, server: example.invalid, port: 443, password: fixture, up: 10, down: 20}
  - {name: decimal, type: hysteria2, server: example.invalid, port: 443, password: fixture, up: 0.5, down: "100 Kbps"}
  - {name: units, type: hysteria2, server: example.invalid, port: 443, password: fixture, up: "1 Gbps", down: "1 bps"}
  - {name: invalid, type: hysteria2, server: example.invalid, port: 443, password: fixture, up: true}
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 3);
        for (node, up, down) in [
            (&nodes[0], "10", "20"),
            (&nodes[1], "0.5", "0.1"),
            (&nodes[2], "1000", "0.000008"),
        ] {
            assert_eq!(node.extra[super::super::v2ray::HY2_UP], up);
            assert_eq!(node.extra[super::super::v2ray::HY2_DOWN], down);
        }
    }
    #[test]
    fn test_parse_clash_meta_subscription() {
        // Real-world Clash Meta subscription format with:
        // - VLESS + Reality (no short-id) → should use Reality transport
        // - SS + shadow-tls plugin → should parse with ShadowTlsConfig
        // - Hysteria2 with sni field → SNI should be picked up
        let yaml = r#"
port: 7890
socks-port: 7891
proxies:
  - { name: "US-Xr1",type: vless,server: vless.example.com,port: 443,uuid: 00000000-0000-0000-0000-000000000001,network: tcp,tls: true,udp: false,servername: www.example.com,reality-opts: {public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA},client-fingerprint: safari}
  - { name: "US-SS-TLS",type: ss,server: ss.example.com,port: 443,password: "testpass",udp: false,cipher: 2022-blake3-aes-256-gcm,plugin: shadow-tls,plugin-opts: {host: www.example.com,password: "st-password",version: 3}}
  - { name: "HK-Hy2-1",type: hysteria2,server: hy2.example.com,port: 443,password: 00000000-0000-0000-0000-000000000001,up: "50 Mbps",down: "100 Mbps",skip-cert-verify: true,sni: www.example.com}
proxy-groups: []
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 3, "all three nodes should parse");

        // VLESS Reality: transport should be Reality, not plain TLS
        let vless = &nodes[0];
        assert_eq!(vless.name, "US-Xr1");
        let transport = vless.transport.as_ref().unwrap();
        assert!(
            matches!(transport.transport_type, TransportType::Reality),
            "VLESS Reality should have Reality transport, got {:?}",
            transport.transport_type
        );
        let reality = transport.reality.as_ref().unwrap();
        assert_eq!(
            reality.public_key,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(reality.short_id, ""); // default empty when not specified
        assert_eq!(reality.sni.as_deref(), Some("www.example.com"));

        // SS + shadow-tls: plugin opts should land in ShadowTlsConfig
        let ss = &nodes[1];
        assert_eq!(ss.name, "US-SS-TLS");
        let ProxyProtocol::Shadowsocks {
            cipher,
            password,
            shadow_tls,
            ..
        } = &ss.protocol
        else {
            panic!("expected Shadowsocks, got {:?}", ss.protocol);
        };
        assert_eq!(cipher, "2022-blake3-aes-256-gcm");
        assert_eq!(password, "testpass");
        let st = shadow_tls.as_ref().expect("shadow-tls config parsed");
        assert_eq!(st.host, "www.example.com");
        assert_eq!(st.password, "st-password");
        assert!(!st.skip_cert_verify);

        // Hysteria2: SNI should be picked up from `sni` field
        let hy2 = &nodes[2];
        assert_eq!(hy2.name, "HK-Hy2-1");
        let transport = hy2.transport.as_ref().unwrap();
        let tls = transport.tls.as_ref().unwrap();
        assert_eq!(tls.sni.as_deref(), Some("www.example.com"));
        assert!(tls.skip_cert_verify);
    }

    #[test]
    fn test_parse_clash_ss_shadow_tls_skip_cert_verify() {
        let yaml = r#"
proxies:
  - { name: "SS-ST",type: ss,server: s.example.com,port: 443,password: "p",udp: false,cipher: aes-256-gcm,plugin: shadow-tls,plugin-opts: {host: real.com,password: "pw",version: 3,skip-cert-verify: true}}
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        let ProxyProtocol::Shadowsocks { shadow_tls, .. } = &nodes[0].protocol else {
            panic!("expected Shadowsocks");
        };
        let st = shadow_tls.as_ref().expect("shadow-tls config parsed");
        assert!(st.skip_cert_verify);
    }

    #[test]
    fn test_parse_clash_ss_unsupported_plugin_rejected() {
        let yaml = r#"
proxies:
  - { name: "SS-OBFS",type: ss,server: s.example.com,port: 8388,password: "p",udp: false,cipher: aes-256-gcm,plugin: unknown-plugin,plugin-opts: {mode: tls}}
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert!(nodes.is_empty(), "unsupported plugin must skip the node");
    }

    #[test]
    fn test_unknown_network_is_rejected_not_downgraded() {
        // grpc/h2/httpupgrade/... used to be silently downgraded to bare
        // TLS/TCP, producing a node that imports but can never connect.
        for network in ["kcp", "h2", "http", "xhttp"] {
            let yaml = format!(
                r#"
proxies:
  - {{ name: "OK", type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw }}
  - {{ name: "Bad-Net", type: vmess, server: 5.6.7.8, port: 443, uuid: u, network: {network} }}
"#
            );
            let nodes = parse_clash_config(&yaml).unwrap();
            assert_eq!(
                nodes.len(),
                1,
                "network '{network}' node must be skipped, not downgraded"
            );
            assert_eq!(nodes[0].name, "OK");
        }
    }

    #[test]
    fn test_hysteria2_obfs_is_imported() {
        let yaml = r#"
proxies:
  - { name: "Hy2-Plain", type: hysteria2, server: a.example.com, port: 443, password: pw }
  - { name: "Hy2-Obfs", type: hysteria2, server: b.example.com, port: 443, password: pw, obfs: salamander, obfs-password: secret }
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "Hy2-Plain");
    }

    #[test]
    fn test_reality_keeps_client_fingerprint_and_skip_cert_verify() {
        let yaml = r#"
proxies:
  - { name: "VLESS-R", type: vless, server: 1.2.3.4, port: 443, uuid: u, tls: true, reality-opts: {public-key: pk}, servername: example.com, client-fingerprint: chrome, skip-cert-verify: true }
"#;
        let nodes = parse_clash_config(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        let reality = nodes[0]
            .transport
            .as_ref()
            .and_then(|t| t.reality.as_ref())
            .expect("reality transport");
        assert_eq!(reality.client_fingerprint.as_deref(), Some("chrome"));
        assert!(reality.skip_cert_verify);
    }
}

#[cfg(test)]
mod xhttp_tests {
    use super::*;
    const YAML: &str = r#"proxies:
  - name: synthetic-xhttp
    type: vless
    server: example.invalid
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    network: xhttp
    tls: true
    alpn: [h2]
    servername: tls.example.invalid
    xhttp-opts: {path: /synthetic?key=value, host: front.example.invalid, mode: stream-one}
"#;
    #[test]
    fn xhttp_clash_native_export_and_uri_preserve_connection_settings() {
        let nodes = parse_clash_config(YAML).unwrap();
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        let t = node.transport.as_ref().unwrap();
        assert_eq!(t.transport_type, TransportType::Xhttp);
        assert_eq!(
            t.tls.as_ref().unwrap().sni.as_deref(),
            Some("tls.example.invalid")
        );
        assert_eq!(
            t.xhttp.as_ref().unwrap().host.as_deref(),
            Some("front.example.invalid")
        );
        let native = serde_yaml::to_string(node).unwrap();
        let restored: Node = serde_yaml::from_str(&native).unwrap();
        assert_eq!(
            super::super::dedup::node_fingerprint(node),
            super::super::dedup::node_fingerprint(&restored)
        );
        let export = super::super::export::export_clash_config(&nodes);
        let restored = parse_clash_config(&export).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].transport.as_ref().unwrap().xhttp, t.xhttp);
        let uri = super::super::v2ray::node_to_share_uri(node);
        let restored = super::super::v2ray::parse_vless_uri(&uri).unwrap();
        assert_eq!(restored.transport.as_ref().unwrap().xhttp, t.xhttp);
        let mut different = node.clone();
        different
            .transport
            .as_mut()
            .unwrap()
            .xhttp
            .as_mut()
            .unwrap()
            .path = Some("/other".into());
        assert_ne!(
            super::super::dedup::node_fingerprint(node),
            super::super::dedup::node_fingerprint(&different)
        );
    }
    #[test]
    fn xhttp_unsupported_options_are_not_silently_discarded() {
        for yaml in [
            YAML.replace("stream-one", "invalid-mode"),
            YAML.replace("stream-one", "invalid-mode-2"),
            YAML.replace("alpn: [h2]", "alpn: [invalid-alpn]"),
            YAML.replace(
                "mode: stream-one",
                "mode: stream-one, extra: {unknownOption: true}",
            ),
            YAML.replace(
                "network: xhttp",
                "network: xhttp\n    flow: xtls-rprx-vision",
            ),
        ] {
            assert!(parse_clash_config(&yaml).unwrap().is_empty());
        }
        let node = parse_clash_config(&YAML.replace("mode: stream-one", "mode: auto")).unwrap();
        assert_eq!(node.len(), 1);
    }
    #[test]
    fn xhttp_missing_options_select_auto_and_invalid_reality_is_rejected() {
        let yaml = YAML
            .lines()
            .filter(|l| !l.trim_start().starts_with("xhttp-opts:"))
            .collect::<Vec<_>>()
            .join("\n");
        let nodes = parse_clash_config(&yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0]
                .transport
                .as_ref()
                .unwrap()
                .xhttp
                .as_ref()
                .unwrap()
                .mode,
            "auto"
        );
        let invalid = YAML.replace("network: xhttp", "network: xhttp\n    reality-opts: {}");
        assert!(parse_clash_config(&invalid).unwrap().is_empty());
    }
    #[test]
    fn xhttp_json_import_and_malformed_targets() {
        let config = serde_json::json!({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"example.invalid","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000001"}]}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"tls.example.invalid","alpn":["h2"]},"xhttpSettings":{"path":"/synthetic","host":"front.example.invalid","mode":"stream-one"}}}]});
        let nodes = super::super::v2ray::parse_v2ray_config(&config.to_string()).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].transport.as_ref().unwrap().transport_type,
            TransportType::Xhttp
        );
        for host in [
            "evil.invalid/path",
            "user@example.invalid",
            "example.invalid\r\nx: y",
        ] {
            let config = XhttpConfig {
                options: Default::default(),
                host: Some(host.into()),
                ..Default::default()
            };
            assert!(config.validate().is_err());
        }
    }
}
