use super::{connector::BoxProxyStream, quic_conn::verified_client, transport};
use crate::config::ech::EchSource;
use anyhow::{Context, Result};
use rustls::{ClientConfig, client::EchMode, pki_types::ServerName};
use std::{sync::Arc, time::Duration};

impl EchSource {
    pub(super) async fn tls_config(
        &self,
        insecure: bool,
        pin: Option<[u8; 32]>,
        alpn: &[String],
    ) -> Result<ClientConfig> {
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_ech(EchMode::Enable(self.resolve().await?))?;
        let mut tls = verified_client(builder, insecure, pin);
        tls.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();
        Ok(tls)
    }
    pub(super) async fn connect(
        &self,
        server: &str,
        port: u16,
        sni: &str,
        insecure: bool,
        pin: Option<[u8; 32]>,
        alpn: &[String],
    ) -> Result<BoxProxyStream> {
        let timeout = Duration::from_secs(15);
        tokio::time::timeout(timeout, async {
            let config = self.tls_config(insecure, pin, alpn).await?;
            let socket =
                transport::connect_server_tcp(&transport::format_host_port(server, port), timeout)
                    .await?;
            let stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from(sni.to_owned())?, socket)
                .await?;
            anyhow::ensure!(
                stream.get_ref().1.ech_status() == rustls::client::EchStatus::Accepted,
                "Server did not accept ECH"
            );
            Ok(Box::new(stream) as BoxProxyStream)
        })
        .await
        .context("ECH TLS connection timed out")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    #[tokio::test]
    async fn hides_inner_name_and_aborts_when_server_ignores_ech() {
        let source = EchSource::Inline(crate::config::ech::TEST_CONFIG.into());
        let config = Arc::new(source.tls_config(true, None, &[]).await.unwrap());
        let mut client =
            rustls::ClientConnection::new(config, ServerName::try_from("private.example").unwrap())
                .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        assert!(
            hello
                .windows(b"public.example".len())
                .any(|s| s == b"public.example")
        );
        assert!(
            !hello
                .windows(b"private.example".len())
                .any(|s| s == b"private.example")
        );

        let cert = CertificateDer::from(include_bytes!("testdata/localhost-cert.der").to_vec());
        let key = PrivatePkcs8KeyDer::from(include_bytes!("testdata/localhost-key.der").to_vec());
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        server.read_tls(&mut hello.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut reply = Vec::new();
        server.write_tls(&mut reply).unwrap();
        client.read_tls(&mut reply.as_slice()).unwrap();
        assert!(matches!(
            client.process_new_packets(),
            Err(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_)
            ))
        ));
    }
}
