//! Hysteria2 protocol client implementation.
//!
//! Hysteria2 is a QUIC-based proxy protocol that uses HTTP/3 for authentication
//! and raw QUIC streams for TCP proxying. It tunnels TCP connections over QUIC
//! with HTTP/3-style masquerading.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Result, bail};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::config::model::TlsConfig;

use super::connector::{BoxProxyStream, Outbound};
use super::quic_conn::{
    QuicConnectionState, build_quic_client_config_pinned, ensure_quic_crypto_provider,
    resolve_server_addrs,
};

const HY2_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(7);
const HY2_CONNECT_ATTEMPTS_PER_ADDR: usize = 2;
const HY2_CONNECT_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(250);
/// Stagger between concurrent per-address QUIC connect attempts
/// (happy-eyeballs). CDN-fronted nodes resolve to a mix of live and dead IPs;
/// a sequential scan pays the full QUIC handshake timeout per dead entry, which
/// blows the caller's overall deadline when several ALPN candidates are tried.
const HY2_ADDR_STAGGER: std::time::Duration = std::time::Duration::from_millis(500);
/// Stagger between ALPN candidates for the same address.
const HY2_ALPN_STAGGER: std::time::Duration = std::time::Duration::from_millis(500);

struct AuthenticatedSession {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    alpn: String,
    control: tokio::task::JoinSet<()>,
}

impl Hysteria2Outbound {
    fn endpoint_for(&self, addr: std::net::SocketAddr) -> Result<quinn::Endpoint> {
        let bind_addr: std::net::SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse()?
        } else {
            "[::]:0".parse()?
        };
        let config = if self.chrome_fingerprint {
            super::quic_fingerprint::endpoint_config()
        } else {
            quinn::EndpointConfig::default()
        };
        match &self.socket_options {
            Some(options) => options.endpoint(bind_addr, addr, config),
            None => super::quic_conn::client_endpoint_with_config(bind_addr, config),
        }
    }

    async fn try_addr(
        &self,
        addr: std::net::SocketAddr,
        mut endpoint: quinn::Endpoint,
        alpn: &str,
    ) -> Result<AuthenticatedSession> {
        endpoint.set_default_client_config(self.build_client_config(alpn).await?);
        let connecting = endpoint
            .connect(addr, &self.sni)
            .map_err(|e| anyhow::anyhow!("QUIC connect setup to {} failed: {}", addr, e))?;
        let connection = tokio::time::timeout(HY2_CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "Hysteria2 QUIC to {}:{} via {} alpn='{}' timed out after {}s",
                    self.server,
                    self.port,
                    addr,
                    alpn,
                    HY2_CONNECT_TIMEOUT.as_secs()
                )
            })?
            .map_err(|e| {
                anyhow::anyhow!(
                    "Hysteria2 QUIC to {}:{} via {} alpn='{}' failed: {}",
                    self.server,
                    self.port,
                    addr,
                    alpn,
                    e
                )
            })?;
        tracing::info!("Hysteria2 QUIC connection established, ALPN={}", alpn);
        let control = tokio::time::timeout(HY2_CONNECT_TIMEOUT, self.authenticate_h3(&connection))
            .await
            .map_err(|_| anyhow::anyhow!("Hysteria2 HTTP/3 authentication timed out"))??;
        Ok(AuthenticatedSession {
            endpoint,
            connection,
            alpn: alpn.into(),
            control,
        })
    }
}

/// Hysteria2 outbound connector.
///
/// Uses QUIC (quinn) for transport with HTTP/3 authentication and
/// raw bidirectional streams for TCP proxy requests.
pub struct Hysteria2Outbound {
    server: String,
    port: u16,
    password: String,
    sni: String,
    skip_cert_verify: bool,
    certificate_pin: Option<[u8; 32]>,
    pub(super) ech: Option<crate::config::ech::EchSource>,
    chrome_fingerprint: bool,
    socket_options: Option<Arc<super::hysteria2_socket::Options>>,
    down_bps: u64,
    upload: Option<Arc<super::hysteria2_bandwidth::Budget>>,
    fast_open: bool,
    /// A previously authenticated ALPN goes to the front on reconnect.
    alpn_candidates: Vec<String>,
    working_alpn: std::sync::Mutex<Option<String>>,
    h3_control: std::sync::Mutex<tokio::task::JoinSet<()>>,
    conn_state: QuicConnectionState,
    udp_hub: tokio::sync::Mutex<Option<Arc<super::quic_datagram::Hub>>>,
}

impl Hysteria2Outbound {
    pub fn new(
        server: &str,
        port: u16,
        password: &str,
        tls_config: Option<&TlsConfig>,
    ) -> Result<Self> {
        Self::new_options(server, port, password, tls_config, &Default::default())
    }
    pub(crate) fn new_options(
        server: &str,
        port: u16,
        password: &str,
        tls_config: Option<&TlsConfig>,
        extra: &std::collections::HashMap<String, String>,
    ) -> Result<Self> {
        use crate::config::v2ray::*;
        let bandwidth = |key| -> Result<u64> {
            extra
                .get(key)
                .map(|v| crate::config::bandwidth::parse_mbps(v))
                .transpose()
                .map(|value| value.unwrap_or(0))
        };
        let sni = tls_config
            .and_then(|t| t.sni.as_deref())
            .unwrap_or(server)
            .to_string();
        let skip_cert_verify = tls_config.map(|t| t.skip_cert_verify).unwrap_or(false);
        let chrome_fingerprint = tls_config
            .and_then(|t| t.fingerprint.as_deref())
            .or_else(|| extra.get(HY2_CLIENT_FP_HINT).map(String::as_str))
            .is_some_and(super::quic_fingerprint::is_chrome);
        let alpn_candidates = tls_config
            .and_then(|t| t.alpn.as_ref())
            .cloned()
            .unwrap_or_else(|| {
                if chrome_fingerprint {
                    vec!["h3".to_string()]
                } else {
                    vec!["hysteria".to_string(), "h3".to_string()]
                }
            });
        anyhow::ensure!(
            !chrome_fingerprint || alpn_candidates.iter().all(|p| p == "h3"),
            "Chrome QUIC fingerprint requires ALPN h3"
        );

        anyhow::ensure!(
            !alpn_candidates.is_empty()
                && alpn_candidates
                    .iter()
                    .all(|value| !value.is_empty() && value.len() <= 255),
            "Invalid Hysteria2 ALPN"
        );
        anyhow::ensure!(
            extra
                .get(HY2_FAST_OPEN)
                .is_none_or(|value| matches!(value.as_str(), "true" | "false")),
            "Invalid Hysteria2 fast-open option"
        );
        ensure_quic_crypto_provider();

        Ok(Self {
            server: server.to_string(),
            port,
            password: password.to_string(),
            sni,
            skip_cert_verify,
            ech: None,
            chrome_fingerprint,
            socket_options: None,
            certificate_pin: extra
                .get(TLS_CERT_PIN)
                .map(|p| parse_tuic_certificate_pin(p))
                .transpose()?,
            down_bps: bandwidth(HY2_DOWN)?,
            upload: super::hysteria2_bandwidth::Budget::new(bandwidth(HY2_UP)?),
            fast_open: extra.get(HY2_FAST_OPEN).is_some_and(|v| v == "true"),
            alpn_candidates,
            working_alpn: std::sync::Mutex::new(None),
            h3_control: Default::default(),
            conn_state: QuicConnectionState::new(),
            udp_hub: tokio::sync::Mutex::new(None),
        })
    }

    pub(super) fn configure_socket(
        &mut self,
        obfs: Option<&crate::config::model::Hy2Obfs>,
        extra: &std::collections::HashMap<String, String>,
    ) -> Result<()> {
        use crate::config::v2ray::{HY2_HOP_INTERVAL, HY2_HOP_MAX, HY2_MPORT};
        let interval = extra
            .get(HY2_HOP_INTERVAL)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(30_000);
        let max = extra
            .get(HY2_HOP_MAX)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(interval);
        self.socket_options = super::hysteria2_socket::Options::new(
            obfs,
            extra.get(HY2_MPORT).map(String::as_str),
            interval,
            max,
        )?;
        Ok(())
    }
    /// Build a QUIC client config (TLS + transport) for a given ALPN.
    async fn build_client_config(&self, alpn: &str) -> Result<quinn::ClientConfig> {
        let config_builder = if self.chrome_fingerprint {
            super::quic_fingerprint::client_config
        } else {
            build_quic_client_config_pinned
        };
        let mut client_config = if let Some(ech) = &self.ech {
            let tls = ech
                .tls_config(
                    self.skip_cert_verify,
                    self.certificate_pin,
                    &[alpn.to_string()],
                )
                .await?;
            quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(
                tls,
            )?))
        } else {
            config_builder(
                self.skip_cert_verify,
                &[alpn.to_string()],
                self.certificate_pin,
            )?
        };

        // Transport config: BBR congestion control for Hysteria2
        let mut transport = quinn::TransportConfig::default();
        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
        ));
        super::quic_conn::proxy_receive_windows(&mut transport);
        transport.send_window(16 * 1024 * 1024);
        if self.chrome_fingerprint {
            super::quic_fingerprint::transport_config(&mut transport);
        }
        client_config.transport_config(Arc::new(transport));
        Ok(client_config)
    }

    /// Get or create QUIC connection with authentication.
    ///
    /// Concurrent callers share a single QUIC session: the expensive
    /// connect+authenticate path is serialized inside `QuicConnectionState`.
    async fn get_connection(&self) -> Result<quinn::Connection> {
        self.get_connection_with(&|addr| self.endpoint_for(addr))
            .await
    }

    async fn get_connection_with(
        &self,
        endpoint: &(impl Fn(std::net::SocketAddr) -> Result<quinn::Endpoint> + Sync),
    ) -> Result<quinn::Connection> {
        self.conn_state
            .get_or_connect(|| async {
                let session = self.create_connection(endpoint).await?;
                *self.working_alpn.lock().unwrap() = Some(session.alpn);
                *self.h3_control.lock().unwrap() = session.control;
                Ok((session.endpoint, session.connection))
            })
            .await
    }

    async fn create_connection(
        &self,
        endpoint: &(impl Fn(std::net::SocketAddr) -> Result<quinn::Endpoint> + Sync),
    ) -> Result<AuthenticatedSession> {
        let addrs = resolve_server_addrs(&self.server, self.port).await?;
        let remembered = self.working_alpn.lock().unwrap().clone();
        let mut alpns: Vec<String> = remembered.iter().cloned().collect();
        for candidate in &self.alpn_candidates {
            if !alpns.contains(candidate) {
                alpns.push(candidate.clone());
            }
        }

        let retry_single = remembered.is_some() && addrs.len() == 1 && alpns.len() == 1;
        let attempts = if retry_single {
            HY2_CONNECT_ATTEMPTS_PER_ADDR
        } else {
            1
        };
        let mut last_error = anyhow::anyhow!("no Hysteria2 addresses to connect");
        for attempt in 0..attempts {
            if attempt > 0 {
                tokio::time::sleep(HY2_CONNECT_RETRY_BACKOFF).await;
            }
            match self.connect_staggered(&addrs, &alpns, endpoint).await {
                Ok(session) => return Ok(session),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    /// An address and ALPN win only after the peer has accepted our credentials.
    /// Dropping the other attempt futures cancels their connections and drivers.
    async fn connect_staggered(
        &self,
        addrs: &[std::net::SocketAddr],
        alpns: &[String],
        endpoint: &(impl Fn(std::net::SocketAddr) -> Result<quinn::Endpoint> + Sync),
    ) -> Result<AuthenticatedSession> {
        let mut attempts = FuturesUnordered::new();
        let mut last_error = anyhow::anyhow!("no Hysteria2 addresses to connect");
        for addr in addrs {
            for (index, alpn) in alpns.iter().enumerate() {
                if !attempts.is_empty() {
                    let stagger = if index == 0 {
                        HY2_ADDR_STAGGER
                    } else {
                        HY2_ALPN_STAGGER
                    };
                    tokio::select! {
                        Some(result) = attempts.next() => match result {
                            Ok(session) => return Ok(session),
                            Err(error) => last_error = error,
                        },
                        _ = tokio::time::sleep(stagger) => {}
                    }
                }
                attempts.push(async move { self.try_addr(*addr, endpoint(*addr)?, alpn).await });
            }
        }
        while let Some(result) = attempts.next().await {
            match result {
                Ok(session) => return Ok(session),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    /// Authenticate via HTTP/3 POST /auth request.
    ///
    /// Per the Hysteria2 spec, the client sends an HTTP/3 request:
    ///   POST /auth with Hysteria-Auth header containing the password.
    /// The server responds with status 233 if authentication succeeds.
    async fn authenticate_h3(&self, conn: &quinn::Connection) -> Result<tokio::task::JoinSet<()>> {
        let h3_conn = h3_quinn::Connection::new(conn.clone());
        let (mut driver, mut sender) = h3::client::new(h3_conn).await?;
        // RFC 9114 forbids closing the HTTP/3 control stream during the QUIC
        // session. Keep the driver and a sender alive while using raw HY2 streams.
        let mut control = tokio::task::JoinSet::new();
        let keep_sender = sender.clone();
        control.spawn(async move {
            driver.wait_idle().await;
            drop(keep_sender);
        });

        // Build the auth request
        let req = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", &self.password)
            .header("Hysteria-CC-RX", self.down_bps.to_string())
            .body(())
            .map_err(|e| anyhow::anyhow!("Failed to build auth request: {}", e))?;

        let mut stream = sender.send_request(req).await?;
        stream.finish().await?;

        let resp = stream.recv_response().await?;

        if resp.status() != 233 {
            bail!(
                "Hysteria2 auth failed: server returned status {} (expected 233)",
                resp.status()
            );
        }

        tracing::info!("Hysteria2 authentication successful (HTTP/3 status 233)");

        Ok(control)
    }
}

impl Outbound for Hysteria2Outbound {
    fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxProxyStream>> + Send + '_>> {
        let host = host.to_string();
        Box::pin(async move {
            let addr_str = super::transport::format_host_port(&host, port);

            // Two attempts: handles the race where the cached QUIC connection
            // dies between get_connection() and open_bi() (stale connection).
            let mut last_err = anyhow::anyhow!("Hysteria2: no connection attempt made");
            for attempt in 1u8..=2 {
                let conn = self.get_connection().await?;
                let (mut send, recv) = match conn.open_bi().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        last_err = anyhow::anyhow!(
                            "Hysteria2 open_bi failed (attempt {}): {}",
                            attempt,
                            e
                        );
                        tracing::debug!("{last_err} — will retry with fresh connection");
                        // open_bi can fail while close_reason() is still empty.
                        // Leaving that connection cached makes the retry, and
                        // every later flow, reuse the same stuck session.
                        conn.close(quinn::VarInt::from_u32(0), b"open_bi failed");
                        continue;
                    }
                };

                // Hysteria2 TCP request (per protocol spec):
                //   varint 0x401 (TCPRequest ID)
                //   varint address_length
                //   bytes  address string ("host:port")
                //   varint padding_length (0)
                //   bytes  padding (empty)
                let addr_bytes = addr_str.as_bytes();
                write_varint(&mut send, 0x0401).await?;
                write_varint(&mut send, addr_bytes.len() as u64).await?;
                send.write_all(addr_bytes).await?;
                write_varint(&mut send, 0).await?; // no padding
                send.flush().await?;

                // Fast-open writes may proceed while the response is pending.
                // Reads always consume/validate the complete response first.
                let response = Box::pin(await_tcp_response(recv));
                let reader = if self.fast_open {
                    Hy2Reader::Waiting(response)
                } else {
                    Hy2Reader::Ready(response.await?)
                };
                let stream = Hy2BidiStream { send, recv: reader };
                return Ok(super::hysteria2_bandwidth::stream(
                    Box::new(stream),
                    &self.upload,
                ));
            }
            Err(last_err)
        })
    }

    fn connect_datagram(
        &self,
        host: &str,
        port: u16,
    ) -> super::datagram::DatagramFuture<'_, super::datagram::BoxDatagram> {
        let host = host.to_owned();
        Box::pin(async move {
            let connection = self.get_connection().await?;
            let mut hub = self.udp_hub.lock().await;
            if hub.as_ref().is_none_or(|hub| !hub.matches(&connection)) {
                *hub = Some(super::quic_datagram::Hub::new(
                    connection,
                    super::quic_datagram::Protocol::Hysteria2,
                ));
            }
            let datagram = hub.as_ref().unwrap().associate(&host, port)?;
            Ok(super::hysteria2_bandwidth::datagram(datagram, &self.upload))
        })
    }

    fn name(&self) -> &str {
        "hysteria2"
    }
}

/// Combined bidirectional QUIC stream for Hysteria2.
struct Hy2BidiStream {
    send: quinn::SendStream,
    recv: Hy2Reader,
}
enum Hy2Reader {
    Ready(quinn::RecvStream),
    Waiting(Pin<Box<dyn Future<Output = io::Result<quinn::RecvStream>> + Send>>),
    Failed,
}

impl AsyncRead for Hy2BidiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Hy2Reader::Waiting(response) = &mut this.recv {
            match response.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(recv)) => this.recv = Hy2Reader::Ready(recv),
                Poll::Ready(Err(error)) => {
                    this.recv = Hy2Reader::Failed;
                    return Poll::Ready(Err(error));
                }
            }
        }
        let Hy2Reader::Ready(recv) = &mut this.recv else {
            return Poll::Ready(Err(io::Error::other("Hysteria2 handshake failed")));
        };
        match Pin::new(recv).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Hy2BidiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.get_mut().send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Unpin for Hy2BidiStream {}

// --- Protocol helpers ---

async fn await_tcp_response<R: AsyncRead + Unpin>(mut recv: R) -> io::Result<R> {
    let (status, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_tcp_response(&mut recv),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Hysteria2 TCPResponse timeout"))?
    .map_err(io::Error::other)?;
    if status != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "Hysteria2 destination rejected",
        ));
    }
    Ok(recv)
}

/// Upper bound for the TCPResponse message string; anything larger is a
/// protocol violation, not a message to buffer.
const HY2_MAX_TCP_RESPONSE_MSG_LEN: u64 = 64 * 1024;

/// Read a Hysteria2 TCPResponse:
///   uint8  status (0x00 = OK, 0x01 = Error)
///   varint message_length + bytes message string ("Connected" on success)
///   varint padding_length + bytes padding
///
/// The message is read in full (up to [`HY2_MAX_TCP_RESPONSE_MSG_LEN`]);
/// truncating it would leave bytes in the stream and permanently corrupt
/// subsequent reads.
async fn read_tcp_response<R: AsyncRead + Unpin>(recv: &mut R) -> Result<(u8, String)> {
    let status = recv.read_u8().await?;

    let msg_len = read_varint(recv).await?;
    anyhow::ensure!(
        msg_len <= HY2_MAX_TCP_RESPONSE_MSG_LEN,
        "Hysteria2 TCPResponse message too large: {msg_len}"
    );
    let mut msg = vec![0u8; msg_len as usize];
    recv.read_exact(&mut msg).await?;
    let msg = String::from_utf8_lossy(&msg).to_string();

    let pad_len = read_varint(recv).await?;
    anyhow::ensure!(
        pad_len <= 1 << 20,
        "Hysteria2 TCPResponse padding too large: {pad_len}"
    );
    skip_exact(recv, pad_len as usize).await?;

    Ok((status, msg))
}

/// Write a QUIC variable-length integer.
async fn write_varint<W: AsyncWrite + Unpin>(writer: &mut W, value: u64) -> Result<()> {
    if value < 64 {
        writer.write_all(&[value as u8]).await?;
    } else if value < 16384 {
        let bytes = ((value as u16) | 0x4000).to_be_bytes();
        writer.write_all(&bytes).await?;
    } else if value < 1_073_741_824 {
        let bytes = ((value as u32) | 0x80000000).to_be_bytes();
        writer.write_all(&bytes).await?;
    } else {
        let bytes = (value | 0xC000000000000000).to_be_bytes();
        writer.write_all(&bytes).await?;
    }
    Ok(())
}

/// Read a QUIC variable-length integer (2-bit length prefix: 1/2/4/8 bytes).
async fn read_varint<R: AsyncRead + Unpin>(recv: &mut R) -> Result<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first).await?;
    let total_len = 1usize << (first[0] >> 6);
    let mut value = (first[0] & 0x3f) as u64;
    for _ in 1..total_len {
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte).await?;
        value = (value << 8) | byte[0] as u64;
    }
    Ok(value)
}

/// Read and discard exactly `len` bytes.
async fn skip_exact<R: AsyncRead + Unpin>(recv: &mut R, len: usize) -> Result<()> {
    let mut remaining = len;
    let mut chunk = [0u8; 8192];
    while remaining > 0 {
        let n = remaining.min(chunk.len());
        recv.read_exact(&mut chunk[..n]).await?;
        remaining -= n;
    }
    Ok(())
}

#[cfg(test)]
mod session_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hysteria2_outbound_new() {
        let outbound = Hysteria2Outbound::new("server.com", 443, "my_password", None).unwrap();
        assert_eq!(outbound.name(), "hysteria2");
        assert_eq!(outbound.server, "server.com");
        assert_eq!(outbound.port, 443);
        assert_eq!(outbound.sni, "server.com");
    }

    #[test]
    fn chrome_profile_accepts_new_and_legacy_saved_settings_and_preserves_native_default() {
        use crate::config::v2ray::HY2_CLIENT_FP_HINT;
        let legacy =
            std::collections::HashMap::from([(HY2_CLIENT_FP_HINT.into(), "chrome".into())]);
        let outbound =
            Hysteria2Outbound::new_options("example.invalid", 443, "synthetic", None, &legacy)
                .unwrap();
        assert!(outbound.chrome_fingerprint);
        assert_eq!(outbound.alpn_candidates, ["h3"]);
        let tls = TlsConfig {
            sni: None,
            skip_cert_verify: false,
            alpn: Some(vec!["hysteria".into()]),
            fingerprint: Some("chrome".into()),
        };
        assert!(Hysteria2Outbound::new("example.invalid", 443, "synthetic", Some(&tls)).is_err());

        let tls = TlsConfig {
            sni: None,
            skip_cert_verify: false,
            alpn: None,
            fingerprint: Some("chrome115".into()),
        };
        let outbound =
            Hysteria2Outbound::new("example.invalid", 443, "synthetic", Some(&tls)).unwrap();
        assert!(outbound.chrome_fingerprint);
        let tls = TlsConfig {
            fingerprint: Some("none".into()),
            ..tls
        };
        let outbound = Hysteria2Outbound::new_options(
            "example.invalid",
            443,
            "synthetic",
            Some(&tls),
            &legacy,
        )
        .unwrap();
        assert!(
            !outbound.chrome_fingerprint,
            "an explicit selection overrides legacy metadata"
        );
    }

    #[test]
    fn test_hysteria2_with_tls_config() {
        let tls = TlsConfig {
            sni: Some("custom.sni.com".to_string()),
            skip_cert_verify: true,
            alpn: Some(vec!["h3".to_string()]),
            fingerprint: None,
        };
        let outbound = Hysteria2Outbound::new("server.com", 443, "pass", Some(&tls)).unwrap();
        assert_eq!(outbound.sni, "custom.sni.com");
    }

    #[tokio::test]
    async fn fast_open_reader_strips_response_and_preserves_payload() {
        let (client, mut server) = tokio::io::duplex(1024);
        let response = await_tcp_response(client);
        server.write_all(&[0, 0, 0, b'o', b'k']).await.unwrap();
        let mut client = response.await.unwrap();
        let mut bytes = [0; 2];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ok");
    }

    #[tokio::test(start_paused = true)]
    async fn fast_open_reader_times_out_and_rejects_denied_destinations() {
        let (client, _server) = tokio::io::duplex(1024);
        assert_eq!(
            await_tcp_response(client).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        let (client, mut server) = tokio::io::duplex(1024);
        server.write_all(&[1, 0, 0]).await.unwrap();
        assert_eq!(
            await_tcp_response(client).await.unwrap_err().kind(),
            io::ErrorKind::ConnectionRefused
        );
    }

    /// Regression: a TCPResponse message longer than 4096 bytes must be read
    /// in full; truncating it left bytes in the stream and corrupted the
    /// connection permanently.
    #[tokio::test]
    async fn test_read_tcp_response_reads_full_message() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let payload = vec![b'x'; 6000]; // larger than the old 4096 cap

        let server_task = tokio::spawn({
            let payload = payload.clone();
            async move {
                server.write_u8(0x00).await.unwrap(); // status OK
                write_varint(&mut server, payload.len() as u64)
                    .await
                    .unwrap();
                server.write_all(&payload).await.unwrap();
                write_varint(&mut server, 7).await.unwrap(); // padding length
                server.write_all(&[0u8; 7]).await.unwrap(); // padding
            }
        });

        let (status, msg) = read_tcp_response(&mut client).await.unwrap();
        server_task.await.unwrap();

        assert_eq!(status, 0x00);
        assert_eq!(msg.len(), 6000);
        assert!(msg.as_bytes().iter().all(|&b| b == b'x'));
    }

    #[tokio::test]
    async fn test_read_tcp_response_rejects_oversized_message() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            server.write_u8(0x00).await.unwrap();
            // Claim a message larger than the 64 KiB cap.
            write_varint(&mut server, HY2_MAX_TCP_RESPONSE_MSG_LEN + 1)
                .await
                .unwrap();
        });

        let err = read_tcp_response(&mut client).await.unwrap_err();
        server_task.await.unwrap();
        assert!(
            format!("{err:#}").contains("message too large"),
            "unexpected error: {err:#}"
        );
    }

    #[tokio::test]
    async fn test_read_tcp_response_error_status_with_message() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            server.write_u8(0x01).await.unwrap(); // status Error
            write_varint(&mut server, 8).await.unwrap();
            server.write_all(b"rejected").await.unwrap();
            write_varint(&mut server, 0).await.unwrap(); // no padding
        });

        let (status, msg) = read_tcp_response(&mut client).await.unwrap();
        server_task.await.unwrap();
        assert_eq!(status, 0x01);
        assert_eq!(msg, "rejected");
    }
}
