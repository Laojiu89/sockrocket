use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::hmac;
use shadowsocks::{
    config::{ReplayAttackPolicy, ServerConfig, ServerType},
    context::{Context, SharedContext},
    relay::{socks5::Address, tcprelay::ProxyServerStream},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

use super::{
    PROXY_HANDSHAKE_TIMEOUT, ProxyStats,
    connector::{SharedOutbound, SwappableOutbound, connect_upstream},
    http::handle_http,
    relay::relay_bidirectional,
    socks5::handle_socks5,
};
use crate::{
    config::listeners::{ListenerConfig, ListenerExit, ListenerType},
    dns::fakeip::FakeIpPool,
};

pub(super) struct ListenerAuth {
    tag: hmac::Tag,
}

impl ListenerAuth {
    fn new(username: &str, password: &str) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, password.as_bytes());
        let tag = hmac::sign(&key, username.as_bytes());
        Self { tag }
    }

    pub(super) fn verify_socks(&self, username: &[u8], password: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, password);
        hmac::verify(&key, username, self.tag.as_ref()).is_ok()
    }

    pub(super) fn verify_http(&self, header: &[u8]) -> bool {
        std::str::from_utf8(header).is_ok_and(|header| {
            header.lines().skip(1).any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("proxy-authorization") && self.verify_basic(value)
                })
            })
        })
    }

    pub(super) fn verify_basic(&self, value: &str) -> bool {
        let Some((scheme, value)) = value.trim().split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(value) = STANDARD.decode(value.trim()) else {
            return false;
        };
        let mut fields = value.splitn(2, |&byte| byte == b':');
        self.verify_socks(
            fields.next().unwrap_or_default(),
            fields.next().unwrap_or_default(),
        )
    }
}

enum Protocol {
    Http(Option<ListenerAuth>),
    Socks(Option<ListenerAuth>),
    Mixed(Option<ListenerAuth>),
    Shadowsocks(SharedContext, ServerConfig),
}

impl Protocol {
    fn from_config(config: &ListenerConfig) -> Result<Self> {
        let auth = || {
            (!config.username.is_empty())
                .then(|| ListenerAuth::new(&config.username, &config.password))
        };
        Ok(match config.protocol {
            ListenerType::Http => Self::Http(auth()),
            ListenerType::Socks => Self::Socks(auth()),
            ListenerType::Mixed => Self::Mixed(auth()),
            ListenerType::Shadowsocks => {
                let mut context = Context::new(ServerType::Server);
                context.set_replay_attack_policy(ReplayAttackPolicy::Reject);
                let cipher = config
                    .cipher
                    .parse()
                    .map_err(|_| anyhow::anyhow!("无效的 Shadowsocks 加密方式"))?;
                let server = ServerConfig::new(config.address(), &config.password, cipher)?;
                Self::Shadowsocks(Arc::new(context), server)
            }
        })
    }

    async fn serve(
        &self,
        stream: TcpStream,
        outbound: SharedOutbound,
        stats: ProxyStats,
        pool: Option<Arc<FakeIpPool>>,
    ) -> Result<()> {
        match self {
            Self::Http(auth) => handle_http(stream, outbound, stats, auth.as_ref()).await,
            Self::Socks(auth) => handle_socks5(stream, outbound, stats, pool, auth.as_ref()).await,
            Self::Mixed(auth) => {
                let mut first = [0];
                let read = tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, stream.peek(&mut first))
                    .await??;
                if read == 0 {
                    return Ok(());
                }
                if first[0] == 5 {
                    handle_socks5(stream, outbound, stats, pool, auth.as_ref()).await
                } else {
                    handle_http(stream, outbound, stats, auth.as_ref()).await
                }
            }
            Self::Shadowsocks(context, config) => {
                let mut client = ProxyServerStream::from_stream(
                    context.clone(),
                    stream,
                    config.method(),
                    config.key(),
                );
                let (host, port) =
                    match tokio::time::timeout(PROXY_HANDSHAKE_TIMEOUT, client.handshake())
                        .await??
                    {
                        Address::SocketAddress(address) => {
                            (address.ip().to_string(), address.port())
                        }
                        Address::DomainNameAddress(host, port) => (host, port),
                    };
                let (host, original_ip) =
                    super::socks5::restore_destination(&host, pool.as_deref())?;
                let connection = stats.track(format!("{host}:{port}"), "Shadowsocks");
                let mut remote = super::routing::with_tun_family(
                    original_ip,
                    connect_upstream(&outbound, &host, port),
                )
                .await?;
                let (up, down) =
                    relay_bidirectional(&mut connection.observe(&mut client), &mut remote).await?;
                connection.finish(up, down);
                Ok(())
            }
        }
    }
}

#[derive(Clone)]
struct ListenerPolicy {
    protocol: Arc<Protocol>,
    outbound: Option<SharedOutbound>,
}

struct RunningListener {
    config: ListenerConfig,
    settings: watch::Sender<ListenerPolicy>,
    task: JoinHandle<()>,
}

impl Drop for RunningListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Manages extra listeners separately from the daemon's built-in proxy ports.
pub struct ListenerService {
    active: HashMap<SocketAddr, RunningListener>,
    dns_source: Arc<SwappableOutbound>,
    stats: ProxyStats,
    pool: Option<Arc<FakeIpPool>>,
}

impl ListenerService {
    pub fn new(
        dns_source: Arc<SwappableOutbound>,
        stats: ProxyStats,
        pool: Option<Arc<FakeIpPool>>,
    ) -> Self {
        Self {
            active: HashMap::new(),
            dns_source,
            stats,
            pool,
        }
    }

    pub async fn apply(
        &mut self,
        configs: &[ListenerConfig],
        proxy: Option<SharedOutbound>,
    ) -> Result<()> {
        let mut pending = Vec::new();
        for config in configs.iter().filter(|config| config.enabled) {
            let address = config.address();
            let existing = self
                .active
                .get(&address)
                .filter(|entry| !entry.task.is_finished());
            let protocol = match existing {
                Some(entry)
                    if entry.config.protocol == config.protocol
                        && entry.config.username == config.username
                        && entry.config.password == config.password
                        && entry.config.cipher == config.cipher =>
                {
                    entry.settings.borrow().protocol.clone()
                }
                _ => Arc::new(Protocol::from_config(config)?),
            };
            let outbound = match config.exit {
                ListenerExit::Direct => Some(SharedOutbound::direct()),
                ListenerExit::Proxy => proxy.clone(),
            };
            let socket = match existing {
                Some(_) => None,
                None => Some(
                    TcpListener::bind(address)
                        .await
                        .with_context(|| format!("无法监听入站 {address}"))?,
                ),
            };
            pending.push((
                config.clone(),
                ListenerPolicy { protocol, outbound },
                socket,
            ));
        }

        // Bind every new address before changing any running listener.
        self.active
            .retain(|address, _| configs.iter().any(|c| c.enabled && c.address() == *address));
        for (config, policy, socket) in pending {
            if let Some(socket) = socket {
                let (settings, receiver) = watch::channel(policy);
                let task = tokio::spawn(run(
                    socket,
                    receiver,
                    self.dns_source.clone(),
                    self.stats.clone(),
                    self.pool.clone(),
                ));
                tracing::info!(name = %config.name, address = %config.address(), "Inbound listener ready");
                self.active.insert(
                    config.address(),
                    RunningListener {
                        config,
                        settings,
                        task,
                    },
                );
            } else if let Some(entry) = self.active.get_mut(&config.address()) {
                entry.config = config;
                entry.settings.send_replace(policy);
            }
        }
        Ok(())
    }
}

async fn run(
    socket: TcpListener,
    settings: watch::Receiver<ListenerPolicy>,
    dns_source: Arc<SwappableOutbound>,
    stats: ProxyStats,
    pool: Option<Arc<FakeIpPool>>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            Some(_) = connections.join_next(), if !connections.is_empty() => {},
            accepted = socket.accept() => {
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::error!(%error, "Inbound listener stopped accepting connections");
                        break;
                    }
                };
                let policy = settings.borrow().clone();
                let Some(outbound) = policy.outbound else { continue };
                let Some(slot) = stats.try_slot() else { continue };
                let outbound = dns_source.with_dns_policy(outbound);
                stream.set_nodelay(true).ok();
                let stats = stats.clone();
                let pool = pool.clone();
                connections.spawn(async move {
                    let _slot = slot;
                    let connection = policy.protocol.serve(stream, outbound, stats, pool);
                    let result = super::routing::with_client_source(Some(peer.ip()), crate::traffic::with_traffic_scope(connection)).await;
                    if let Err(error) = result { tracing::debug!(%peer, %error, "Inbound connection closed"); }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, pin::Pin};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn echo(marker: u8) -> SocketAddr {
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = server.accept().await {
                let byte = stream.read_u8().await.unwrap();
                stream.write_all(&[marker, byte]).await.unwrap();
            }
        });
        address
    }

    async fn config(protocol: ListenerType) -> ListenerConfig {
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        ListenerConfig {
            name: "test".into(),
            listen: "127.0.0.1".parse().unwrap(),
            port,
            protocol,
            exit: ListenerExit::Direct,
            enabled: true,
            username: "user".into(),
            password: "test-secret".into(),
            cipher: String::new(),
        }
    }

    fn service() -> ListenerService {
        ListenerService::new(
            Arc::new(SwappableOutbound::new(SharedOutbound::direct())),
            ProxyStats::default(),
            None,
        )
    }

    struct ProxyTo(SocketAddr);
    impl super::super::connector::Outbound for ProxyTo {
        fn connect(
            &self,
            _: &str,
            _: u16,
        ) -> Pin<
            Box<dyn Future<Output = Result<super::super::connector::BoxProxyStream>> + Send + '_>,
        > {
            Box::pin(async move { Ok(Box::new(TcpStream::connect(self.0).await?) as _) })
        }
        fn name(&self) -> &str {
            "test proxy"
        }
    }

    async fn http_exchange(listener: SocketAddr, destination: SocketAddr, auth: bool, marker: u8) {
        let mut client = TcpStream::connect(listener).await.unwrap();
        let credentials = if auth {
            "Proxy-Authorization: Basic dXNlcjp0ZXN0LXNlY3JldA==\r\n"
        } else {
            ""
        };
        client
            .write_all(
                format!(
                    "CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n{credentials}\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = [0; 12];
        client.read_exact(&mut response).await.unwrap();
        if !auth {
            assert_eq!(&response, b"HTTP/1.1 407");
            return;
        }
        assert_eq!(&response, b"HTTP/1.1 200");
        let mut tail = [0; b" Connection Established\r\n\r\n".len()];
        client.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b" Connection Established\r\n\r\n");
        client.write_u8(b'x').await.unwrap();
        let mut payload = [0; 2];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, [marker, b'x']);
    }

    #[tokio::test]
    async fn listener_mixed_auth_routes_and_hot_reloads() {
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            let direct = echo(b'D').await;
            let proxy = echo(b'P').await;
            let mut config = config(ListenerType::Mixed).await;
            let address = config.address();
            let mut service = service();
            let selected = Some(SharedOutbound(Arc::new(ProxyTo(proxy))));
            service
                .apply(std::slice::from_ref(&config), selected.clone())
                .await
                .unwrap();
            http_exchange(address, direct, false, b'D').await;
            http_exchange(address, direct, true, b'D').await;

            config.exit = ListenerExit::Proxy;
            service
                .apply(std::slice::from_ref(&config), selected.clone())
                .await
                .unwrap();
            http_exchange(address, direct, true, b'P').await;

            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(&[5, 2, 0, 2]).await.unwrap();
            assert_eq!(client.read_u16().await.unwrap(), 0x0502);
            client
                .write_all(b"\x01\x04user\x0btest-secret")
                .await
                .unwrap();
            assert_eq!(client.read_u16().await.unwrap(), 0x0100);
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend(direct.port().to_be_bytes());
            client.write_all(&request).await.unwrap();
            let mut response = [0; 10];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..2], &[5, 0]);
            client.write_u8(b'y').await.unwrap();
            assert_eq!(client.read_u16().await.unwrap().to_be_bytes(), [b'P', b'y']);

            let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
            config.port = occupied.local_addr().unwrap().port();
            assert!(service.apply(&[config], selected).await.is_err());
            http_exchange(address, direct, true, b'P').await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn listener_shadowsocks_transfers_encrypted_tcp() {
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            let direct = echo(b'D').await;
            let mut config = config(ListenerType::Shadowsocks).await;
            config.username.clear();
            config.cipher = "chacha20-ietf-poly1305".into();
            let address = config.address();
            let mut service = service();
            service
                .apply(std::slice::from_ref(&config), None)
                .await
                .unwrap();
            let server =
                ServerConfig::new(address, &config.password, config.cipher.parse().unwrap())
                    .unwrap();
            let stream = TcpStream::connect(address).await.unwrap();
            let mut client = shadowsocks::relay::tcprelay::ProxyClientStream::from_stream(
                Context::new_shared(ServerType::Local),
                stream,
                &server,
                direct,
            );
            client.write_u8(b'z').await.unwrap();
            assert_eq!(client.read_u16().await.unwrap().to_be_bytes(), [b'D', b'z']);
        })
        .await
        .unwrap();
    }
}
