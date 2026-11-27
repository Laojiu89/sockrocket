// An in-memory UDP pair lets the real QUIC and HTTP/3 implementations exchange
// packets without external endpoints or router networking.
use super::*;
use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use std::{io::IoSliceMut, net::SocketAddr, sync::Mutex};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

#[derive(Debug)]
struct MemoryUdp {
    local: SocketAddr,
    peer: SocketAddr,
    send: UnboundedSender<Vec<u8>>,
    recv: Mutex<UnboundedReceiver<Vec<u8>>>,
}

#[derive(Debug)]
struct Writable;
impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for MemoryUdp {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable)
    }
    fn try_send(&self, tx: &Transmit<'_>) -> io::Result<()> {
        assert_eq!(tx.destination, self.peer);
        let _ = self.send.send(tx.contents.to_vec());
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut recv = self.recv.lock().unwrap();
        let Some(bytes) = std::task::ready!(recv.poll_recv(cx)) else {
            return Poll::Pending;
        };
        bufs[0][..bytes.len()].copy_from_slice(&bytes);
        meta[0] = RecvMeta {
            addr: self.peer,
            len: bytes.len(),
            stride: bytes.len(),
            ecn: None,
            dst_ip: Some(self.local.ip()),
        };
        Poll::Ready(Ok(1))
    }
}

fn endpoints() -> (quinn::Endpoint, quinn::Endpoint) {
    ensure_quic_crypto_provider();
    let cert = rustls::pki_types::CertificateDer::from(
        include_bytes!("../testdata/localhost-cert.der").to_vec(),
    );
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("../testdata/localhost-key.der").to_vec(),
    );
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
    tls.alpn_protocols = vec![b"hysteria".to_vec(), b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let (to_server, from_client) = mpsc::unbounded_channel();
    let (to_client, from_server) = mpsc::unbounded_channel();
    let server = "127.0.0.1:9443".parse().unwrap();
    let client = "127.0.0.1:9444".parse().unwrap();
    let endpoint = |config, local, peer, send, recv| {
        quinn::Endpoint::new_with_abstract_socket(
            Default::default(),
            config,
            Arc::new(MemoryUdp {
                local,
                peer,
                send,
                recv: Mutex::new(recv),
            }),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap()
    };
    (
        endpoint(
            Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
            server,
            client,
            to_client,
            from_client,
        ),
        endpoint(None, client, server, to_server, from_server),
    )
}

async fn handle_auth(server: quinn::Endpoint) {
    let conn = server.accept().await.unwrap().await.unwrap();
    let negotiated = conn
        .handshake_data()
        .unwrap()
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .unwrap();
    let accepted = negotiated.protocol.as_deref() == Some(b"h3");
    let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .unwrap();
    let (req, mut stream) = h3
        .accept()
        .await
        .unwrap()
        .unwrap()
        .resolve_request()
        .await
        .unwrap();
    assert_eq!(req.uri().path(), "/auth");
    assert_eq!(req.headers()["Hysteria-Auth"], "fixture");
    let status = if accepted { 233 } else { 404 };
    stream
        .send_response(http::Response::builder().status(status).body(()).unwrap())
        .await
        .unwrap();
    stream.finish().await.unwrap();
    drop(stream);
    if accepted {
        // A strict H3 peer notices FIN on any critical stream here.
        let packet = tokio::select! {
            biased;
            result = h3.accept() => panic!("HTTP/3 ended during the HY2 session: {:?}", result.err()),
            packet = conn.read_datagram() => packet.unwrap(),
        };
        assert!(packet.ends_with(b"udp-echo"));
        conn.send_datagram(packet).unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        assert_eq!(read_varint(&mut recv).await.unwrap(), 0x401);
        let len = read_varint(&mut recv).await.unwrap() as usize;
        let mut address = vec![0; len];
        recv.read_exact(&mut address).await.unwrap();
        assert_eq!(address, b"echo.invalid:443");
        let padding = read_varint(&mut recv).await.unwrap();
        skip_exact(&mut recv, padding as usize).await.unwrap();
        send.write_all(b"\x00\x00\x00tcp-echo").await.unwrap();
        send.finish().unwrap();
    }
    conn.closed().await;
}

#[tokio::test]
async fn authenticated_alpn_keeps_http3_control_alive_for_tcp_and_udp() {
    let exercise = async {
        let address: SocketAddr = "127.0.0.1:9443".parse().unwrap();
        let servers = Mutex::new(tokio::task::JoinSet::new());
        let endpoint = |_| {
            let (server, client) = endpoints();
            servers.lock().unwrap().spawn(handle_auth(server));
            Ok(client)
        };
        let mut outbound =
            Hysteria2Outbound::new("127.0.0.1", address.port(), "fixture", None).unwrap();
        outbound.skip_cert_verify = true;
        *outbound.working_alpn.lock().unwrap() = Some("hysteria".into());
        outbound.get_connection_with(&endpoint).await.unwrap();
        assert_eq!(
            outbound.working_alpn.lock().unwrap().as_deref(),
            Some("h3"),
            "a stale ALPN must not prevent authenticated fallback"
        );
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let udp = outbound.connect_datagram("echo.invalid", 53).await.unwrap();
        udp.send(b"udp-echo").await.unwrap();
        let mut packet = [0; 32];
        let size = udp.recv(&mut packet).await.unwrap();
        assert_eq!(&packet[..size], b"udp-echo");
        let mut tcp = outbound.connect("echo.invalid", 443).await.unwrap();
        let mut reply = [0; 8];
        tcp.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"tcp-echo");
        drop(tcp);
        drop(udp);
        drop(outbound);
        let mut servers = servers.into_inner().unwrap();
        assert_eq!(servers.len(), 2);
        while let Some(result) = servers.join_next().await {
            result.unwrap();
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), exercise)
        .await
        .unwrap();
}

#[tokio::test]
async fn one_bulk_stream_can_use_two_mib_of_connection_credit() {
    let (server, mut client) = endpoints();
    let mut outbound = Hysteria2Outbound::new("127.0.0.1", 9443, "fixture", None).unwrap();
    outbound.skip_cert_verify = true;
    client.set_default_client_config(outbound.build_client_config("h3").await.unwrap());
    let connecting = client
        .connect(server.local_addr().unwrap(), "localhost")
        .unwrap();
    let (peer, connected) = tokio::join!(
        async { server.accept().await.unwrap().await.unwrap() },
        connecting
    );
    let connected = connected.unwrap();
    let payload = Bytes::from(
        (0..2 * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let expected = payload.clone();
    let sender = tokio::spawn(async move {
        let mut stream = peer.open_uni().await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.finish().unwrap();
        assert_eq!(stream.stopped().await.unwrap(), None);
        peer
    });
    let mut recv = connected.accept_uni().await.unwrap();
    // Until the application reads, only the negotiated initial credit can
    // advance the sender. Wait for acknowledgement of all bytes on the wire.
    let peer = tokio::time::timeout(std::time::Duration::from_secs(5), sender)
        .await
        .expect("2 MiB stream stalled waiting for application reads")
        .unwrap();
    assert_eq!(recv.read_to_end(expected.len()).await.unwrap(), expected);
    peer.close(0u32.into(), b"done");
}
