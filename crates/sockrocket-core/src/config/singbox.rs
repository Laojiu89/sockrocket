//! Sing-box configuration parser.
//!
//! Parses sing-box JSON outbound format into sockrocket Node structs.
//! Supports: TUIC, Hysteria2, VMess, VLESS, Trojan, Shadowsocks.

use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use super::model::*;

// --- Sing-box config structures ---

#[derive(Deserialize)]
struct SingBoxConfig {
    #[serde(default)]
    outbounds: Vec<serde_json::Value>,
    #[serde(default)]
    endpoints: Vec<serde_json::Value>,
    #[serde(default)]
    dns: ProfileDns,
    #[serde(default)]
    route: ProfileRoute,
}

#[derive(Default, Deserialize)]
struct ProfileDns {
    #[serde(default)]
    servers: Vec<serde_json::Value>,
}

#[derive(Default, Deserialize)]
struct ProfileRoute {
    default_domain_resolver: Option<serde_json::Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SingBoxOutbound {
    #[serde(rename = "type")]
    outbound_type: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    server: String,
    #[serde(default)]
    server_port: u16,

    // Auth fields
    uuid: Option<String>,
    password: Option<String>,
    method: Option<String>, // SS cipher
    plugin: Option<String>,
    plugin_opts: Option<String>,
    detour: Option<String>,
    encryption: Option<String>,
    flow: Option<String>, // VLESS

    #[serde(default)]
    global_padding: bool,
    #[serde(default)]
    authenticated_length: bool,
    security: Option<String>,
    alter_id: Option<u32>,
    obfs: Option<serde_json::Value>,
    server_ports: Option<serde_json::Value>,
    hop_interval: Option<String>,
    hop_interval_max: Option<String>,
    up_mbps: Option<u64>,
    down_mbps: Option<u64>,

    // TUIC
    congestion_control: Option<String>,
    udp_relay_mode: Option<String>,
    #[serde(default)]
    udp_over_stream: bool,
    #[serde(default)]
    zero_rtt_handshake: bool,
    heartbeat: Option<String>,
    idle_session_check_interval: Option<String>,
    idle_session_timeout: Option<String>,
    #[serde(default)]
    min_idle_session: usize,

    // TLS
    tls: Option<SingBoxTls>,

    // Transport
    transport: Option<SingBoxTransport>,

    #[serde(default, deserialize_with = "string_list")]
    network: Vec<String>,

    // UDP
    #[serde(default)]
    udp: Option<bool>,

    // Multiplex
    multiplex: Option<serde_json::Value>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SingBoxTls {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    insecure: bool,
    server_name: Option<String>,
    #[serde(default, deserialize_with = "string_list")]
    alpn: Vec<String>,
    #[serde(default)]
    disable_sni: bool,
    utls: Option<SingBoxUtls>,
    reality: Option<SingBoxReality>,
    #[serde(default, flatten)]
    extensions: HashMap<String, serde_json::Value>,
    ech: Option<super::ech::Options>,
}

#[derive(Debug, Deserialize)]
struct SingBoxReality {
    #[serde(default)]
    enabled: bool,
    public_key: Option<String>,
    short_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SingBoxUtls {
    enabled: Option<bool>,
    fingerprint: Option<String>,
}

// sing-box Listable fields accept either a single item or an array.
fn string_list<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum List {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<List>::deserialize(d)? {
        None => vec![],
        Some(List::One(value)) => vec![value],
        Some(List::Many(values)) => values,
    })
}

#[derive(Debug, Deserialize)]
struct SingBoxTransport {
    #[serde(flatten)]
    grpc: GrpcConfig,
    host: Option<String>,
    #[serde(rename = "type")]
    transport_type: Option<String>,
    path: Option<String>,
    headers: Option<HashMap<String, String>>,
}

/// Check if JSON content looks like a sing-box config.
pub fn is_singbox_config(content: &str) -> bool {
    (content.contains("\"outbounds\"")
        && (content.contains("\"server_port\"") || content.contains("\"server_ports\"")))
        || content.contains("\"endpoints\"")
}

/// Parse sing-box JSON config into Node list.
pub fn parse_singbox_config(json_str: &str) -> Result<Vec<Node>> {
    let config: SingBoxConfig =
        serde_json::from_slice(json_str.as_bytes()).context("Failed to parse sing-box JSON")?;

    let outbounds = config.outbounds.iter().chain(&config.endpoints);
    let mut tagged = HashMap::new();
    if config
        .outbounds
        .iter()
        .any(|out| out.get("detour").is_some())
    {
        tagged = index_tags(outbounds.clone());
    }
    let resolvers = index_tags(config.dns.servers.iter());
    let mut nodes = Vec::new();
    for value in outbounds {
        match parse_entry(
            value,
            &tagged,
            &resolvers,
            config.route.default_domain_resolver.as_ref(),
        ) {
            Ok(Some(node)) => nodes.push(node),
            Ok(None) => {}
            Err(_) => tracing::warn!("Skipping unsupported or invalid sing-box outbound"),
        }
    }
    Ok(nodes)
}

type Tags<'a> = HashMap<&'a str, Option<&'a serde_json::Value>>;

fn index_tags<'a>(values: impl Iterator<Item = &'a serde_json::Value>) -> Tags<'a> {
    let mut tagged = Tags::new();
    for value in values {
        if let Some(tag) = value["tag"].as_str().filter(|t| !t.is_empty()) {
            tagged
                .entry(tag)
                .and_modify(|slot| *slot = None)
                .or_insert(Some(value));
        }
    }
    tagged
}

/// Parse a single sing-box outbound JSON object.
pub fn parse_singbox_outbound(json_str: &str) -> Result<Option<Node>> {
    let value: serde_json::Value =
        serde_json::from_str(json_str).context("Failed to parse sing-box outbound")?;
    parse_entry(&value, &Tags::new(), &Tags::new(), None)
}

fn parse_entry(
    value: &serde_json::Value,
    tagged: &Tags<'_>,
    resolvers: &Tags<'_>,
    default_resolver: Option<&serde_json::Value>,
) -> Result<Option<Node>> {
    let mut node = if value["type"] == "wireguard" {
        super::wireguard::from_singbox(value)?
    } else {
        let outbound =
            SingBoxOutbound::deserialize(value).context("Malformed sing-box outbound")?;
        let Some(node) = convert_singbox_outbound(&outbound, tagged)? else {
            return Ok(None);
        };
        node
    };
    if node
        .server
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_err()
    {
        // A detoured node dials the detour server, whose DNS settings govern that lookup.
        let dialer = value["detour"]
            .as_str()
            .and_then(|tag| tagged.get(tag).copied().flatten())
            .unwrap_or(value);
        if let Some(reference) = dialer.get("domain_resolver").or(default_resolver) {
            let policy = endpoint_resolver(reference, resolvers)?;
            node.extra.insert(
                super::server_dns::KEY.into(),
                serde_json::to_string(&policy)?,
            );
        }
    }
    Ok(Some(node))
}

// A subscription's dialer DNS resolves the proxy server only. Its client-facing
// DNS rules and final resolver are independent of the imported node.
fn endpoint_resolver(
    reference: &serde_json::Value,
    servers: &Tags<'_>,
) -> Result<super::server_dns::ServerDns> {
    use anyhow::ensure;
    use std::net::{IpAddr, SocketAddr};
    let (tag, strategy) = if let Some(tag) = reference.as_str() {
        (tag, "")
    } else {
        let options = reference
            .as_object()
            .context("Invalid sing-box domain resolver")?;
        ensure!(
            options
                .keys()
                .all(|k| matches!(k.as_str(), "server" | "strategy")),
            "Unsupported sing-box domain resolver options"
        );
        (
            reference["server"]
                .as_str()
                .context("Missing sing-box resolver tag")?,
            match options.get("strategy") {
                None => "",
                Some(value) => value.as_str().context("Invalid resolver strategy")?,
            },
        )
    };
    let ipv6 = match strategy {
        "" | "prefer_ipv4" => true,
        "ipv4_only" => false,
        _ => anyhow::bail!("Unsupported proxy resolver strategy"),
    };
    let server = servers
        .get(tag)
        .copied()
        .flatten()
        .context("Missing or ambiguous sing-box DNS server")?;
    let fields = server.as_object().context("Invalid sing-box DNS server")?;
    ensure!(
        fields.keys().all(|k| matches!(
            k.as_str(),
            "type" | "tag" | "server" | "server_port" | "path" | "tls"
        )),
        "Unsupported sing-box DNS server options"
    );
    let host: IpAddr = server["server"]
        .as_str()
        .context("Missing DNS server")?
        .parse()
        .context("Proxy DNS requires a bootstrap IP address")?;
    let kind = server["type"].as_str().context("Missing DNS server type")?;
    let port = match fields.get("server_port") {
        None => {
            if kind == "https" {
                443
            } else {
                53
            }
        }
        Some(value) => u16::try_from(value.as_u64().context("Invalid DNS port")?)
            .context("Invalid DNS port")?,
    };
    let address = SocketAddr::new(host, port);
    let mut insecure_servers = Vec::new();
    let endpoint = match kind {
        "https" => {
            let path = match fields.get("path") {
                None => "/dns-query",
                Some(v) => v.as_str().context("Malformed HTTPS DNS path")?,
            };
            ensure!(
                path.starts_with('/') && !path.contains(['#', '\r', '\n']),
                "Invalid HTTPS DNS path"
            );
            if let Some(tls) = fields.get("tls") {
                let opts = tls.as_object().context("Invalid DNS TLS options")?;
                ensure!(
                    opts.keys()
                        .all(|k| matches!(k.as_str(), "enabled" | "insecure")),
                    "Unsupported DNS TLS options"
                );
                ensure!(
                    opts.get("enabled")
                        .is_none_or(|v| v.as_bool() == Some(true)),
                    "HTTPS DNS requires TLS"
                );
                if let Some(flag) = opts.get("insecure")
                    && flag
                        .as_bool()
                        .context("Invalid DNS TLS verification mode")?
                {
                    insecure_servers.push(0);
                }
            }
            format!("https://{address}{path}")
        }
        "udp" | "tcp" => {
            ensure!(
                !fields.contains_key("tls") && !fields.contains_key("path"),
                "Invalid plain DNS server options"
            );
            format!("{kind}://{address}")
        }
        _ => anyhow::bail!("Unsupported sing-box DNS transport"),
    };
    let policy = super::server_dns::ServerDns {
        servers: vec![endpoint],
        bootstrap: Vec::new(),
        insecure_servers,
        ipv6,
    };
    policy.config()?;
    Ok(policy)
}

// sing-box accepts Go duration strings, including compound and fractional units.
// The timer and Mihomo's corresponding field have millisecond resolution.
fn duration_millis(value: &str) -> Result<u64> {
    let mut rest = value.strip_prefix('+').unwrap_or(value);
    if rest == "0" {
        return Ok(0);
    }
    anyhow::ensure!(!rest.is_empty(), "Empty duration");
    let mut nanos = 0.0_f64;
    while !rest.is_empty() {
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .context("Missing heartbeat time unit")?;
        let number: f64 = rest[..end].parse().context("Invalid duration")?;
        rest = &rest[end..];
        let (unit, scale) = [
            ("ns", 1.),
            ("us", 1e3),
            ("µs", 1e3),
            ("μs", 1e3),
            ("ms", 1e6),
            ("s", 1e9),
            ("m", 60e9),
            ("h", 3600e9),
        ]
        .into_iter()
        .find(|(u, _)| rest.starts_with(u))
        .context("Invalid heartbeat time unit")?;
        nanos += number * scale;
        rest = &rest[unit.len()..];
    }
    anyhow::ensure!(nanos <= i64::MAX as f64, "duration exceeds duration range");
    Ok((nanos / 1e6).ceil() as u64)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowTlsDetour {
    #[serde(rename = "type")]
    kind: String,
    tag: String,
    version: u8,
    server: String,
    server_port: u16,
    password: String,
    tls: ShadowTlsDetourTls,
    // Parsed from the dialer value together with the parent profile.
    #[serde(rename = "domain_resolver")]
    _resolver: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowTlsDetourTls {
    enabled: bool,
    server_name: Option<String>,
    #[serde(default)]
    insecure: bool,
}

fn convert_singbox_outbound(
    ob: &SingBoxOutbound,
    tagged: &HashMap<&str, Option<&serde_json::Value>>,
) -> Result<Option<Node>> {
    let mut server = ob.server.clone();
    let mut port = ob.server_port;
    let mut shadow_tls = None;
    if let Some(tag) = ob.detour.as_deref().filter(|tag| !tag.is_empty()) {
        anyhow::ensure!(
            matches!(ob.outbound_type.as_str(), "ss" | "shadowsocks"),
            "Unsupported outbound detour"
        );
        let value = tagged
            .get(tag)
            .copied()
            .flatten()
            .context("Missing or ambiguous ShadowTLS detour")?;
        let target =
            ShadowTlsDetour::deserialize(value).context("Unsupported ShadowTLS detour options")?;
        anyhow::ensure!(
            target.kind == "shadowtls"
                && target.tag == tag
                && target.version == 3
                && target.tls.enabled
                && !target.password.is_empty()
                && !target.server.is_empty()
                && target.server_port != 0,
            "Invalid ShadowTLS v3 detour"
        );
        server = target.server;
        port = target.server_port;
        shadow_tls = Some(ShadowTlsConfig {
            host: target
                .tls
                .server_name
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| server.clone()),
            password: target.password,
            skip_cert_verify: target.tls.insecure,
        });
    }

    anyhow::ensure!(
        ob.network
            .iter()
            .all(|network| matches!(network.as_str(), "" | "tcp" | "udp")),
        "Unsupported outbound network restriction"
    );
    let allow_tcp = ob.network.iter().any(|network| network == "tcp");
    let allow_udp = ob.network.iter().any(|network| network == "udp");
    let udp_only = allow_udp && !allow_tcp;
    anyhow::ensure!(
        !udp_only
            || (matches!(ob.outbound_type.as_str(), "trojan" | "hysteria2" | "hy2")
                && ob.udp != Some(false)),
        "Unsupported UDP-only outbound"
    );
    let udp = (!allow_tcp || allow_udp) && ob.udp.unwrap_or(true);

    let protocol = match ob.outbound_type.as_str() {
        "anytls" => ProxyProtocol::AnyTls {
            password: ob.password.clone().context("AnyTLS missing password")?,
            pool: AnyTlsPool {
                check_interval_ms: ob
                    .idle_session_check_interval
                    .as_deref()
                    .map(duration_millis)
                    .transpose()?,
                idle_timeout_ms: ob
                    .idle_session_timeout
                    .as_deref()
                    .map(duration_millis)
                    .transpose()?,
                min_idle: ob.min_idle_session,
                disable_reuse: false,
            }
            .checked()?,
            udp,
        },
        "tuic" => {
            let uuid = ob.uuid.as_ref().context("TUIC missing uuid")?.clone();
            let password = ob
                .password
                .as_ref()
                .context("TUIC missing password")?
                .clone();
            let congestion_control = ob
                .congestion_control
                .clone()
                .unwrap_or_else(|| "cubic".to_string());
            ProxyProtocol::Tuic {
                uuid,
                password,
                congestion_control,
                heartbeat_ms: ob.heartbeat.as_deref().map(duration_millis).transpose()?,
                relay: TuicRelay::parse(
                    ob.udp_relay_mode.as_deref(),
                    ob.udp_over_stream.then_some(2),
                )?,
                udp,
            }
        }
        "hysteria2" | "hy2" => {
            let password = ob
                .password
                .as_ref()
                .filter(|password| !password.is_empty())
                .context("Hysteria2 missing password")?
                .clone();
            let obfs: Option<Hy2Obfs> = ob
                .obfs
                .as_ref()
                .filter(|v| !v.as_object().is_some_and(|fields| fields.is_empty()))
                .map(Hy2Obfs::deserialize)
                .transpose()?;
            if let Some(o) = &obfs {
                o.validate()?;
            }
            ProxyProtocol::Hysteria2 {
                password,
                udp,
                obfs,
            }
        }
        "vless" => {
            let uuid = ob.uuid.as_ref().context("VLESS missing uuid")?.clone();
            ProxyProtocol::VLess {
                uuid,
                flow: ob.flow.clone(),
                udp,
            }
        }
        "vmess" => {
            let uuid = ob.uuid.as_ref().context("VMess missing uuid")?.clone();
            ProxyProtocol::VMess {
                uuid,
                alter_id: ob.alter_id.unwrap_or(0),
                cipher: ob.security.clone().unwrap_or_else(|| "auto".into()),
                udp,
            }
        }
        "trojan" => {
            let password = ob
                .password
                .as_ref()
                .context("Trojan missing password")?
                .clone();
            ProxyProtocol::Trojan { password, udp }
        }
        "shadowsocks" | "ss" => {
            let cipher = ob
                .method
                .as_ref()
                .context("Shadowsocks missing method")?
                .clone();
            let password = ob
                .password
                .as_ref()
                .context("Shadowsocks missing password")?
                .clone();
            ProxyProtocol::Shadowsocks {
                cipher,
                password,
                udp,
                shadow_tls,
            }
        }
        // Non-proxy types: skip
        "direct" | "block" | "dns" | "selector" | "urltest" => return Ok(None),
        other => anyhow::bail!("Unsupported sing-box outbound type: {}", other),
    };

    if let Some(tls) = &ob.tls {
        // Unknown TLS controls can strengthen authentication (pinning, custom
        // trust, mTLS, ECH, version bounds). Never turn them into weaker TLS.
        anyhow::ensure!(
            tls.extensions.is_empty(),
            "Unsupported sing-box TLS option; security constraints were not discarded"
        );
    }
    let transport = build_singbox_transport(ob)?;
    let mut extra = HashMap::new();
    if matches!(protocol, ProxyProtocol::Shadowsocks { .. })
        && let Some(name) = ob.plugin.as_deref().filter(|v| !v.is_empty())
    {
        anyhow::ensure!(
            ob.detour.as_deref().unwrap_or("").is_empty(),
            "Conflicting Shadowsocks plugin and detour"
        );
        super::ss_plugin::Plugin::parse(
            name,
            super::ss_uri::parse_options(ob.plugin_opts.as_deref().unwrap_or(""))?,
            &server,
        )?
        .save(&mut extra)?;
    }
    if matches!(protocol, ProxyProtocol::VLess { .. }) {
        super::v2ray::set_vless_encryption(&mut extra, ob.encryption.as_deref())?;
    }
    if ob.outbound_type == "tuic" && ob.zero_rtt_handshake {
        extra.insert(super::v2ray::TUIC_ZERO_RTT.into(), "true".into());
    }
    if udp_only {
        extra.insert(super::v2ray::UDP_ONLY.into(), "true".into());
    }
    if ob.outbound_type == "vmess" {
        super::v2ray::vmess_framing_options(&mut extra, ob.global_padding, ob.authenticated_length);
    }
    if matches!(protocol, ProxyProtocol::Hysteria2 { .. }) {
        if let Some(list) = &ob.server_ports
            && !list.as_array().is_some_and(Vec::is_empty)
        {
            let items = match list {
                serde_json::Value::Array(a) => a.as_slice(),
                v => std::slice::from_ref(v),
            };
            let ports = items
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|p| p.replace(':', "-"))
                        .context("Invalid Hysteria2 server port range")
                })
                .collect::<Result<Vec<_>>>()?
                .join(",");
            port = super::v2ray::hysteria2_initial_port(&ports, 0)?;
            extra.insert(super::v2ray::HY2_MPORT.into(), ports);
        }
        anyhow::ensure!(
            !server.trim().is_empty() && port != 0,
            "Missing Hysteria2 server or port"
        );
        anyhow::ensure!(
            ob.transport.is_none(),
            "Unsupported external Hysteria2 transport"
        );
        for (value, field) in [
            (&ob.hop_interval, super::v2ray::HY2_HOP_INTERVAL),
            (&ob.hop_interval_max, super::v2ray::HY2_HOP_MAX),
        ] {
            if let Some(v) = value.as_deref().filter(|v| !v.is_empty()) {
                let ms = duration_millis(v)?;
                if ms != 0 {
                    extra.insert(field.into(), ms.to_string());
                }
            }
        }
        for (rate, key) in [
            (ob.up_mbps, super::v2ray::HY2_UP),
            (ob.down_mbps, super::v2ray::HY2_DOWN),
        ] {
            if let Some(rate) = rate {
                extra.insert(
                    key.into(),
                    super::bandwidth::canonical_mbps(&rate.to_string())?,
                );
            }
        }
        super::v2ray::validate_hysteria2_profile(transport.as_ref().and_then(|t| t.tls.as_ref()))?;
    }

    let name = if ob.tag.is_empty() {
        format!("{}-{}:{}", ob.outbound_type, server, port)
    } else {
        decode_display_name(&ob.tag)
    };

    let mut node = Node {
        name,
        server,
        port,
        protocol,
        transport,
        latency_ms: None,
        tags: vec![],
        extra,
    };
    if let Some(ech) = ob.tls.as_ref().and_then(|tls| tls.ech.as_ref()) {
        ech.attach(&mut node)?;
    }
    if matches!(node.protocol, ProxyProtocol::Hysteria2 { .. }) {
        crate::create_outbound_unwarmed(&node)?;
    }
    Ok(Some(node))
}

fn build_singbox_transport(ob: &SingBoxOutbound) -> Result<Option<TransportConfig>> {
    if let Some(transport) = &ob.transport {
        anyhow::ensure!(
            matches!(
                transport.transport_type.as_deref(),
                Some("ws" | "httpupgrade" | "grpc")
            ),
            "Unsupported sing-box transport; configuration was not downgraded"
        );
    }
    anyhow::ensure!(
        !ob.tls.as_ref().is_some_and(|tls| tls.disable_sni),
        "Disabling TLS SNI is not supported"
    );
    anyhow::ensure!(
        !ob.multiplex
            .as_ref()
            .and_then(|mux| mux.get("enabled"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "Multiplex is not supported"
    );
    if let Some(tls) = &ob.tls
        && let Some(reality) = tls.reality.as_ref().filter(|r| r.enabled)
    {
        anyhow::ensure!(
            tls.enabled
                && ob.transport.is_none()
                && matches!(ob.outbound_type.as_str(), "vless" | "trojan"),
            "REALITY requires VLESS or Trojan over raw TCP with TLS enabled"
        );
        let public_key = reality
            .public_key
            .clone()
            .filter(|s| !s.is_empty())
            .context("REALITY public key is required")?;
        return Ok(Some(TransportConfig {
            grpc: None,
            xhttp: None,
            transport_type: TransportType::Reality,
            tls: None,
            ws: None,
            reality: Some(RealityConfig {
                public_key,
                short_id: reality.short_id.clone().unwrap_or_default(),
                sni: tls.server_name.clone(),
                client_fingerprint: tls
                    .utls
                    .as_ref()
                    .filter(|u| u.enabled != Some(false))
                    .and_then(|u| u.fingerprint.clone()),
                skip_cert_verify: tls.insecure,
            }),
        }));
    }
    let tls_cfg = ob.tls.as_ref();
    let proxy_type = ob.outbound_type.as_str();

    // TUIC and Hysteria2 always need TLS even if not explicitly enabled
    let force_tls = matches!(proxy_type, "tuic" | "hysteria2" | "hy2" | "anytls");
    let has_tls = tls_cfg.map(|t| t.enabled).unwrap_or(false) || force_tls;

    let has_ws = ob
        .transport
        .as_ref()
        .and_then(|t| t.transport_type.as_deref())
        .map(|t| matches!(t, "ws" | "httpupgrade"))
        .unwrap_or(false);

    let grpc = ob
        .transport
        .as_ref()
        .filter(|t| t.transport_type.as_deref() == Some("grpc"))
        .map(|t| t.grpc.clone());
    if !has_tls && !has_ws && grpc.is_none() {
        return Ok(None);
    }

    let tls = if has_tls {
        Some(TlsConfig {
            sni: tls_cfg
                .and_then(|t| t.server_name.clone())
                .filter(|s| !s.is_empty()),
            skip_cert_verify: tls_cfg.map(|t| t.insecure).unwrap_or(false),
            alpn: tls_cfg
                .filter(|t| !t.alpn.is_empty())
                .map(|t| t.alpn.clone()),
            fingerprint: tls_cfg.and_then(|t| {
                t.utls
                    .as_ref()
                    .filter(|u| u.enabled != Some(false))
                    .and_then(|u| u.fingerprint.clone())
            }),
        })
    } else {
        None
    };

    let ws = if has_ws {
        ob.transport.as_ref().map(|t| WsConfig {
            path: t.path.clone(),
            host: t
                .host
                .clone()
                .or_else(|| t.headers.as_ref().and_then(|h| h.get("Host").cloned())),
            headers: t.headers.clone(),
        })
    } else {
        None
    };

    let transport_type = match (has_ws, has_tls) {
        _ if grpc.is_some() => TransportType::Grpc,
        (true, _)
            if ob
                .transport
                .as_ref()
                .and_then(|t| t.transport_type.as_deref())
                == Some("httpupgrade") =>
        {
            TransportType::HttpUpgrade
        }
        (true, _) => TransportType::WebSocket,
        (false, true) => TransportType::Tls,
        _ => TransportType::Tcp,
    };

    Ok(Some(TransportConfig {
        grpc,
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
    fn imports_only_the_resolver_for_dialing_each_node() {
        use super::super::server_dns::{KEY, ServerDns};
        use crate::dns::DnsServer;
        use serde_json::json;

        let base =
            json!({"type":"anytls","server":"node.example","server_port":443,"password":"fixture"});
        let mut plain = base.clone();
        plain["domain_resolver"] = json!({"server":"override","strategy":"ipv4_only"});
        let mut literal = base.clone();
        literal["server"] = json!("192.0.2.33");
        let profile = json!({
            "dns":{"servers":[
                {"tag":"subscriber","type":"https","server":"192.0.2.53","server_port":8448,
                 "path":"/dns-query/private-fixture?format=wire","tls":{"enabled":true,"insecure":true}},
                {"tag":"override","type":"https","server":"2001:db8::53"},
                {"tag":"local","type":"local"}],
                "final":"local","rules":[{"clash_mode":"Direct","server":"local"}]},
            "route":{"default_domain_resolver":{"server":"subscriber","strategy":"prefer_ipv4"}},
            "outbounds":[base,plain,literal]});
        let nodes = parse_singbox_config(&profile.to_string()).unwrap();
        assert_eq!(nodes.len(), 3);
        let restored: Node =
            serde_yaml::from_str(&serde_yaml::to_string(&nodes[0]).unwrap()).unwrap();
        let private = ServerDns::from_node(&restored).unwrap().unwrap();
        assert_eq!(
            private.servers,
            ["https://192.0.2.53:8448/dns-query/private-fixture?format=wire"]
        );
        assert!(private.ipv6);
        assert!(matches!(
            private.config().unwrap().servers.as_slice(),
            [DnsServer::UnverifiedDoh { .. }]
        ));
        assert!(!restored.transport.unwrap().tls.unwrap().skip_cert_verify);
        let verified = ServerDns::from_node(&nodes[1]).unwrap().unwrap();
        assert_eq!(verified.servers, ["https://[2001:db8::53]:443/dns-query"]);
        assert!(!verified.ipv6);
        assert!(matches!(
            verified.config().unwrap().servers.as_slice(),
            [DnsServer::Endpoint { .. }]
        ));
        assert!(!nodes[2].extra.contains_key(KEY));
    }

    #[test]
    fn unusable_dialer_dns_skips_only_the_dependent_node() {
        use serde_json::json;
        let upstream = json!({"tag":"resolver","type":"https","server":"192.0.2.53",
            "path":"/private-fixture","tls":{"enabled":true}});
        let node = json!({"type":"anytls","server":"node.example","server_port":443,
            "password":"fixture","domain_resolver":"resolver"});
        let mut plain = node.clone();
        plain.as_object_mut().unwrap().remove("domain_resolver");
        let mut pinned = upstream.clone();
        pinned["tls"]["certificate_public_key_sha256"] = json!(["fixture"]);
        let mut bad = upstream.clone();
        bad["type"] = json!("fakeip");
        for resolvers in [
            vec![],
            vec![upstream.clone(), upstream],
            vec![pinned],
            vec![bad],
        ] {
            let profile = json!({"dns":{"servers":resolvers},"outbounds":[node,plain]});
            let nodes = parse_singbox_config(&profile.to_string()).unwrap();
            assert_eq!(nodes.len(), 1);
            assert!(!nodes[0].extra.contains_key(super::super::server_dns::KEY));
        }
        assert!(parse_singbox_outbound(&node.to_string()).is_err());
    }

    #[test]
    fn unresolved_detours_and_unsupported_plugins_do_not_dial_plain_ss() {
        use serde_json::json;
        let ss = json!({"type":"shadowsocks","tag":"wrapped","server":"example.invalid",
            "server_port":8388,"method":"aes-128-gcm","password":"test","detour":"outer"});
        let target = json!({"type":"shadowtls","version":3,"tag":"outer","server":"example.invalid",
            "server_port":443,"password":"test","tls":{"enabled":true}});
        assert!(parse_singbox_outbound(&ss.to_string()).is_err());
        for bad_targets in [
            vec![],
            vec![target.clone(), target.clone()],
            vec![{
                let mut v = target.clone();
                v["tls"]["certificate_public_key_sha256"] = json!(["fixture"]);
                v
            }],
            vec![{
                let mut v = target;
                v["version"] = json!(2);
                v
            }],
        ] {
            let mut values = vec![ss.clone()];
            values.extend(bad_targets);
            assert!(
                parse_singbox_config(&json!({"outbounds":values}).to_string())
                    .unwrap()
                    .is_empty()
            );
        }
        let mut plugin = ss;
        plugin.as_object_mut().unwrap().remove("detour");
        plugin["plugin"] = json!("unsupported");
        assert!(parse_singbox_outbound(&plugin.to_string()).is_err());
    }

    #[test]
    fn disabled_utls_does_not_activate_a_quic_profile() {
        for enabled in [false, true] {
            let content = serde_json::json!({"outbounds":[{"type":"hysteria2","tag":"synthetic","server":"example.invalid","server_port":443,"password":"synthetic","tls":{"enabled":true,"utls":{"enabled":enabled,"fingerprint":"chrome"}}}]}).to_string();
            let nodes = parse_singbox_config(&content).unwrap();
            assert_eq!(
                nodes[0]
                    .transport
                    .as_ref()
                    .unwrap()
                    .tls
                    .as_ref()
                    .unwrap()
                    .fingerprint
                    .as_deref(),
                enabled.then_some("chrome")
            );
        }
    }

    #[test]
    fn incompatible_quic_profile_is_skipped_before_saving() {
        let content = serde_json::json!({"outbounds":[{"type":"hysteria2","tag":"synthetic","server":"example.invalid","server_port":443,"password":"synthetic","tls":{"enabled":true,"alpn":["hysteria"],"utls":{"enabled":true,"fingerprint":"chrome"}}}]}).to_string();
        assert!(parse_singbox_config(&content).unwrap().is_empty());
    }

    #[test]
    fn unsupported_tls_security_constraints_fail_closed_even_when_insecure() {
        for key in [
            "certificate_public_key_sha256",
            "certificate_sha256",
            "certificate",
            "certificate_path",
            "client_certificate",
            "client_key",
            "min_version",
            "max_version",
            "ech",
        ] {
            let mut tls = serde_json::json!({"enabled":true,"insecure":true});
            tls[key] = serde_json::json!(["synthetic-value"]);
            let value = serde_json::json!({"type":"anytls","server":"vpn.example.invalid","server_port":443,"password":"synthetic-only","tls":tls});
            let result = parse_singbox_outbound(&value.to_string());
            assert!(
                result.is_err(),
                "security constraint {key} must not be dropped"
            );
        }
    }

    #[test]
    fn anytls_idle_options_survive_import_save_and_export() {
        let json = serde_json::json!({"type":"anytls","server":"example.invalid","server_port":443,"password":"local","idle_session_check_interval":"1m2s","idle_session_timeout":"8s","min_idle_session":6});
        let node = parse_singbox_outbound(&json.to_string()).unwrap().unwrap();
        let ProxyProtocol::AnyTls { pool, .. } = &node.protocol else {
            panic!("expected AnyTLS")
        };
        assert_eq!(pool.check_interval_ms, Some(62000));
        assert_eq!(pool.idle_timeout_ms, Some(8000));
        assert_eq!(pool.min_idle, 6);
        let yaml = crate::config::export::nodes_to_clash_yaml(std::slice::from_ref(&node)).unwrap();
        let restored = crate::parse_clash_config(&yaml).unwrap().pop().unwrap();
        let uri = crate::node_to_share_uri(&restored);
        let from_uri = super::super::v2ray::parse_anytls_uri(&uri).unwrap();
        assert_eq!(
            serde_json::to_value(node.protocol).unwrap(),
            serde_json::to_value(from_uri.protocol).unwrap()
        );
    }
    #[test]
    fn tuic_relay_modes_and_heartbeat_validate_on_import() {
        assert_eq!(duration_millis("1m0.125s").unwrap(), 60125);
        assert_eq!(duration_millis("250us").unwrap(), 1);
        for invalid in ["", "30", "1hour", "-2s", "1.2.3s"] {
            assert!(duration_millis(invalid).is_err());
        }
        let mut value = serde_json::json!({"type":"tuic","server":"example.invalid","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","password":"local","udp_relay_mode":"quic","udp_over_stream":true});
        assert!(parse_singbox_outbound(&value.to_string()).is_err());
        value["udp_over_stream"] = false.into();
        value["udp_relay_mode"] = "invalid".into();
        assert!(parse_singbox_outbound(&value.to_string()).is_err());
    }

    #[test]
    fn test_parse_singbox_tuic() {
        let json = r#"{
            "outbounds": [{
                "type": "tuic",
                "tag": "MY-TUIC",
                "server": "tuic.example.com",
                "server_port": 60000,
                "congestion_control": "bbr",
                "udp_relay_mode": "native",
                "zero_rtt_handshake": true,
                "heartbeat": "10s",
                "tls": {
                    "enabled": true,
                    "insecure": true,
                    "alpn": ["h3"],
                    "server_name": "www.example.com"
                },
                "uuid": "00000000-0000-0000-0000-000000000001",
                "password": "00000000-0000-0000-0000-000000000001"
            }]
        }"#;

        let nodes = parse_singbox_config(json).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "MY-TUIC");
        let key = super::super::v2ray::TUIC_ZERO_RTT;
        assert_eq!(nodes[0].extra.get(key).map(String::as_str), Some("true"));
        let shared = crate::parse_tuic_uri(&crate::node_to_share_uri(&nodes[0])).unwrap();
        let yaml = crate::export_clash_config(std::slice::from_ref(&shared));
        let reparsed = crate::parse_clash_config(&yaml).unwrap();
        assert_eq!(reparsed[0].extra.get(key), nodes[0].extra.get(key));
        assert_eq!(nodes[0].server, "tuic.example.com");
        assert_eq!(nodes[0].port, 60000);

        // Check TLS config preserved
        let transport = nodes[0].transport.as_ref().unwrap();
        let tls = transport.tls.as_ref().unwrap();
        assert_eq!(tls.sni.as_deref(), Some("www.example.com"));
        assert!(tls.skip_cert_verify);
        assert_eq!(tls.alpn.as_ref().unwrap(), &vec!["h3".to_string()]);

        match &nodes[0].protocol {
            ProxyProtocol::Tuic {
                uuid,
                password,
                congestion_control,
                ..
            } => {
                assert_eq!(uuid, "00000000-0000-0000-0000-000000000001");
                assert_eq!(password, "00000000-0000-0000-0000-000000000001");
                assert_eq!(congestion_control, "bbr");
            }
            _ => panic!("Expected TUIC"),
        }
    }

    #[test]
    fn test_parse_singbox_hysteria2() {
        let json = r#"{
            "outbounds": [{
                "type": "hysteria2",
                "tag": "HY2-SG",
                "up_mbps": 17,
                "down_mbps": 83,
                "server": "1.2.3.4",
                "server_port": 443,
                "password": "secret",
                "tls": {
                    "enabled": true,
                    "insecure": false,
                    "server_name": "example.com",
                    "alpn": ["h3"]
                }
            }]
        }"#;

        let nodes = parse_singbox_config(json).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "HY2-SG");
        assert_eq!(nodes[0].extra[super::super::v2ray::HY2_UP], "17");
        assert_eq!(nodes[0].extra[super::super::v2ray::HY2_DOWN], "83");
        let tls = nodes[0].transport.as_ref().unwrap().tls.as_ref().unwrap();
        assert_eq!(tls.sni.as_deref(), Some("example.com"));
        assert!(!tls.skip_cert_verify);
    }

    #[test]
    fn test_skip_non_proxy_outbounds() {
        let json = r#"{
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {"type": "dns", "tag": "dns"},
                {"type": "selector", "tag": "select"}
            ]
        }"#;
        let nodes = parse_singbox_config(json).unwrap();
        assert_eq!(nodes.len(), 0);
    }

    #[test]
    fn singbox_hy2_bulk_preserves_wire_options_and_skips_unusable_entries() {
        use super::super::v2ray::{HY2_HOP_INTERVAL, HY2_HOP_MAX, HY2_MPORT, UDP_ONLY};
        use serde_json::json;
        let valid = json!({
            "type":"hysteria2","tag":"hopping","server":"vpn.example.invalid","server_port":443,
            "server_ports":["41000:41003","42001:42003"],"hop_interval":"4.5s","hop_interval_max":"9s",
            "password":"user:p@ss:","network":"udp","tls":{"enabled":true,"alpn":"h3","server_name":"tls.example.invalid"},
            "obfs":{"type":"gecko","password":"fixture","min_packet_size":512,"max_packet_size":1100}
        });
        let mut defaults = valid.clone();
        defaults["network"] = json!(["tcp", "udp"]);
        defaults["server_ports"] = json!([]);
        defaults["hop_interval"] = json!("0s");
        defaults["hop_interval_max"] = json!("");
        defaults["tls"] = json!({"enabled":true,"alpn":[],"server_name":""});
        defaults["obfs"] = json!({});
        let mut broken = valid.clone();
        broken["hop_interval_max"] = json!("1s");
        let mut unauthenticated = valid.clone();
        unauthenticated["password"] = json!("");
        let batch = json!({"outbounds":[valid,broken,defaults,unauthenticated]});
        let nodes = crate::parse_singbox_config(&batch.to_string()).unwrap();
        assert_eq!(nodes.len(), 2);
        let stored: Node =
            serde_yaml::from_str(&serde_yaml::to_string(&nodes[0]).unwrap()).unwrap();
        let ProxyProtocol::Hysteria2 {
            password,
            obfs: Some(obfs),
            udp: true,
        } = &stored.protocol
        else {
            panic!("expected UDP with Gecko")
        };
        assert_eq!(password, "user:p@ss:");
        assert_eq!(
            (
                obfs.kind.as_str(),
                obfs.password.as_str(),
                obfs.max_packet_size
            ),
            ("gecko", "fixture", Some(1100))
        );
        assert_eq!(stored.port, 41000);
        assert_eq!(stored.extra[HY2_MPORT], "41000-41003,42001-42003");
        assert_eq!(stored.extra[HY2_HOP_INTERVAL], "4500");
        assert_eq!(stored.extra[HY2_HOP_MAX], "9000");
        assert_eq!(stored.extra[UDP_ONLY], "true");
        let tls = stored.transport.as_ref().unwrap().tls.as_ref().unwrap();
        assert_eq!(tls.sni.as_deref(), Some("tls.example.invalid"));
        assert_eq!(tls.alpn.as_ref().unwrap(), &["h3"]);
        assert!(crate::create_outbound_unwarmed(&stored).is_ok());
        assert_eq!(nodes[1].port, 443);
        assert!(nodes[1].protocol.supports_udp());
        assert!(!nodes[1].extra.contains_key(UDP_ONLY));
        assert!(
            nodes[1]
                .transport
                .as_ref()
                .unwrap()
                .tls
                .as_ref()
                .unwrap()
                .sni
                .is_none()
        );
    }

    #[test]
    fn test_is_singbox_config() {
        assert!(is_singbox_config(r#"{"outbounds":[{"server_port":443}]}"#));
        assert!(!is_singbox_config(r#"{"inbounds":[]}"#));
        assert!(!is_singbox_config("proxies:"));
    }

    #[test]
    fn test_parse_single_outbound() {
        let json = r#"{
            "type": "tuic",
            "tag": "MY-1",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "550e8400-e29b-41d4-a716-446655440000",
            "password": "pass",
            "tls": {"enabled": true, "insecure": true, "server_name": "sni.test.com"}
        }"#;
        let node = parse_singbox_outbound(json).unwrap().unwrap();
        assert_eq!(node.name, "MY-1");
        assert!(
            matches!(&node.protocol, ProxyProtocol::Tuic { congestion_control, .. } if congestion_control == "cubic")
        );
        let tls = node.transport.as_ref().unwrap().tls.as_ref().unwrap();
        assert_eq!(tls.sni.as_deref(), Some("sni.test.com"));
    }
}

#[cfg(test)]
mod capability_regressions {
    use super::*;
    #[test]
    fn reality_is_preserved_and_unsupported_transports_are_rejected() {
        let raw = serde_json::json!({"type":"vless","server":"vpn.example.invalid","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001","tls":{"enabled":true,"server_name":"tls.example.invalid","reality":{"enabled":true,"public_key":"synthetic-public-key","short_id":"aabb"}}});
        let node = parse_singbox_outbound(&raw.to_string()).unwrap().unwrap();
        let transport = node.transport.unwrap();
        assert!(matches!(transport.transport_type, TransportType::Reality));
        assert_eq!(transport.reality.unwrap().short_id, "aabb");
        let mut raw = raw;
        raw["transport"] = serde_json::json!({"type":"grpc"});
        assert!(parse_singbox_outbound(&raw.to_string()).is_err());
    }
}
