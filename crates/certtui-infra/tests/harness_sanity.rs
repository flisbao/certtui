//! Sanity checks of the in-process TLS test server harness.

// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// the shared client helpers below are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

mod support;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use certtui_infra::tls::CapturingVerifier;
use rustls::{
    AlertDescription, ClientConfig, ProtocolVersion, RootCertStore, SupportedProtocolVersion,
};
use rustls_pki_types::{CertificateDer, ServerName};
use support::tls_server::{
    ALERT_HANDSHAKE_FAILURE, ALERT_PROTOCOL_VERSION, Behavior, Observation, PLAIN_HTTP_REPLY,
    TestServer,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// A `ClientHello`-looking record: enough for the raw stubs to read.
const FAKE_HELLO: [u8; 9] = [0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00];

fn ring() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn roots_client(ca_der: &[u8]) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(ca_der.to_vec())).unwrap();
    ClientConfig::builder_with_provider(ring())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn capturing_client(
    verifier: &Arc<CapturingVerifier>,
    versions: &[&'static SupportedProtocolVersion],
) -> ClientConfig {
    ClientConfig::builder_with_provider(ring())
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth()
}

async fn handshake(
    config: ClientConfig,
    addr: SocketAddr,
    name: &'static str,
) -> io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(name).unwrap(), tcp)
        .await
}

/// Handshakes with an accept-everything client and returns what it captured.
async fn capture(server: &TestServer) -> certtui_infra::tls::CapturedHandshake {
    let verifier = CapturingVerifier::new();
    let config = capturing_client(&verifier, rustls::ALL_VERSIONS);
    handshake(config, server.addr(), "localhost").await.unwrap();
    verifier.captured().unwrap()
}

async fn read_all(addr: SocketAddr, send: &[u8]) -> Vec<u8> {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(send).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), tcp.read_to_end(&mut out)).await;
    out
}

#[tokio::test]
async fn quando_server_ok_deve_aceitar_handshake_de_cliente_rustls_com_roots_proprios() {
    let server = TestServer::start(Behavior::Ok).await.unwrap();
    let tls = handshake(roots_client(server.ca_der()), server.addr(), "localhost")
        .await
        .unwrap();
    let certs = tls.get_ref().1.peer_certificates().unwrap();
    let got: Vec<&[u8]> = certs.iter().map(AsRef::as_ref).collect();
    // Leaf, intermediate, CA: the order a real server sends.
    assert_eq!(got.len(), 3);
    assert_eq!(
        got.first().copied(),
        server.presented_chain().first().map(Vec::as_slice)
    );
    assert_eq!(
        got.get(1).copied(),
        server.presented_chain().get(1).map(Vec::as_slice)
    );
    assert_eq!(got.get(2).copied(), Some(server.ca_der()));
}

#[tokio::test]
async fn quando_cliente_confia_so_no_ca_deve_validar_cadeia_de_tres_niveis() {
    // The CA only signs the intermediate, so a successful verification with
    // the CA as sole root proves leaf <- intermediate <- CA were chained.
    let server = TestServer::start(Behavior::Ok).await.unwrap();
    let result = handshake(roots_client(server.ca_der()), server.addr(), "127.0.0.1").await;
    // `ServerName::try_from("127.0.0.1")` is an IP name: SAN covers it too.
    assert!(result.is_ok(), "{result:?}");
}

#[tokio::test]
async fn quando_server_ok_deve_registrar_sni_alpn_e_conexoes() {
    let server = TestServer::start(Behavior::Ok).await.unwrap();
    assert_eq!(server.last_sni(), Observation::NotYet);
    assert_eq!(server.last_alpn(), Observation::NotYet);
    let mut config = roots_client(server.ca_der());
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    handshake(config, server.addr(), "localhost").await.unwrap();
    assert_eq!(
        server.last_sni(),
        Observation::Present("localhost".to_owned())
    );
    assert_eq!(
        server.negotiated_alpn(Duration::from_secs(1)).await,
        Observation::Present(b"http/1.1".to_vec())
    );
    assert_eq!(server.accepted_connections(), 1);
}

#[tokio::test]
async fn quando_alvo_e_ip_cliente_nao_envia_sni_e_server_registra_ausencia() {
    let server = TestServer::start(Behavior::Ok).await.unwrap();
    handshake(roots_client(server.ca_der()), server.addr(), "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(server.last_sni(), Observation::Absent);
}

#[tokio::test]
async fn quando_cadeia_incompleta_deve_apresentar_so_o_leaf() {
    let server = TestServer::start(Behavior::IncompleteChain).await.unwrap();
    let got = capture(&server).await;
    assert_eq!(server.presented_chain().len(), 1);
    assert_eq!(Some(&got.end_entity), server.presented_chain().first());
    assert_eq!(got.intermediates.len(), 0);
}

#[tokio::test]
async fn quando_ordem_trocada_deve_apresentar_leaf_ca_intermediario() {
    let server = TestServer::start(Behavior::WrongOrder).await.unwrap();
    let got = capture(&server).await;
    let presented = server.presented_chain();
    assert_eq!(presented.len(), 3);
    assert_eq!(Some(&got.end_entity), presented.first());
    assert_eq!(got.intermediates.first(), presented.get(1));
    assert_eq!(got.intermediates.get(1), presented.get(2));
    // The second certificate is the CA itself, i.e. swapped with the intermediate.
    assert_eq!(
        got.intermediates.first().map(Vec::as_slice),
        Some(server.ca_der())
    );
}

#[tokio::test]
async fn quando_cert_expirado_deve_falhar_com_roots_e_passar_com_captura() {
    let server = TestServer::start(Behavior::Expired).await.unwrap();
    let strict = handshake(roots_client(server.ca_der()), server.addr(), "localhost").await;
    assert!(strict.is_err());
    let got = capture(&server).await;
    assert_eq!(Some(&got.end_entity), server.presented_chain().first());
}

#[tokio::test]
async fn quando_autoassinado_deve_apresentar_um_unico_cert_igual_a_ancora() {
    let server = TestServer::start(Behavior::SelfSigned).await.unwrap();
    let got = capture(&server).await;
    assert_eq!(got.intermediates.len(), 0);
    assert_eq!(got.end_entity.as_slice(), server.ca_der());
}

#[tokio::test]
async fn quando_server_tem_staple_deve_entregar_bytes_a_cliente_que_pede_status() {
    let staple = vec![0x30, 0x03, 0x0A, 0x01, 0x00];
    let server = TestServer::start(Behavior::WithStaple(staple.clone()))
        .await
        .unwrap();
    let got = capture(&server).await;
    assert_eq!(got.ocsp_response, staple);
}

#[tokio::test]
async fn quando_server_tls12_only_deve_negociar_tls12() {
    let server = TestServer::start(Behavior::Tls12Only).await.unwrap();
    let verifier = CapturingVerifier::new();
    let config = capturing_client(&verifier, rustls::ALL_VERSIONS);
    let tls = handshake(config, server.addr(), "localhost").await.unwrap();
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_2)
    );
}

#[tokio::test]
async fn quando_server_tls13_only_recusa_cliente_so_tls12() {
    let server = TestServer::start(Behavior::Tls13Only).await.unwrap();
    let verifier = CapturingVerifier::new();
    let all = handshake(
        capturing_client(&verifier, rustls::ALL_VERSIONS),
        server.addr(),
        "localhost",
    )
    .await
    .unwrap();
    assert_eq!(
        all.get_ref().1.protocol_version(),
        Some(ProtocolVersion::TLSv1_3)
    );
    let only12 = handshake(
        capturing_client(&verifier, &[&rustls::version::TLS12]),
        server.addr(),
        "localhost",
    )
    .await;
    assert!(only12.is_err());
}

#[tokio::test]
async fn quando_server_e_http_puro_deve_responder_400_em_texto() {
    let server = TestServer::start(Behavior::PlainHttp).await.unwrap();
    assert_eq!(read_all(server.addr(), &FAKE_HELLO).await, PLAIN_HTTP_REPLY);
}

#[tokio::test]
async fn quando_server_fecha_na_hora_deve_dar_eof() {
    let server = TestServer::start(Behavior::CloseImmediately).await.unwrap();
    assert_eq!(read_all(server.addr(), &[]).await, Vec::<u8>::new());
    assert_eq!(server.accepted_connections(), 1);
}

#[tokio::test]
async fn quando_server_tls10_deve_responder_alert_protocol_version() {
    let server = TestServer::start(Behavior::Tls10Only).await.unwrap();
    assert_eq!(
        read_all(server.addr(), &FAKE_HELLO).await,
        ALERT_PROTOCOL_VERSION
    );
}

#[tokio::test]
async fn quando_cliente_rustls_fala_com_server_tls10_deve_receber_alert_protocol_version() {
    let server = TestServer::start(Behavior::Tls10Only).await.unwrap();
    let verifier = CapturingVerifier::new();
    let config = capturing_client(&verifier, rustls::ALL_VERSIONS);
    let err = handshake(config, server.addr(), "localhost")
        .await
        .unwrap_err();
    let inner = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>());
    assert_eq!(
        inner,
        Some(&rustls::Error::AlertReceived(
            AlertDescription::ProtocolVersion
        ))
    );
}

#[tokio::test]
async fn quando_server_manda_alert_deve_responder_handshake_failure() {
    let server = TestServer::start(Behavior::TlsAlert).await.unwrap();
    assert_eq!(
        read_all(server.addr(), &FAKE_HELLO).await,
        ALERT_HANDSHAKE_FAILURE
    );
}

#[tokio::test]
async fn quando_server_inunda_bytes_deve_enviar_mais_de_64_kib_e_tolerar_desconexao() {
    let server = TestServer::start(Behavior::FloodBytes).await.unwrap();
    let mut tcp = TcpStream::connect(server.addr()).await.unwrap();
    let mut buf = vec![0_u8; 8192];
    let mut total = 0_usize;
    while total <= 64 * 1024 {
        let n = tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert!(n > 0, "flood ended early after {total} bytes");
        total += n;
    }
    drop(tcp);
    // Still serving after the peer vanished mid-flood.
    let again = TcpStream::connect(server.addr()).await;
    assert!(again.is_ok());
}

#[tokio::test]
async fn quando_server_nunca_responde_deve_manter_socket_aberto_sem_escrever() {
    let server = TestServer::start(Behavior::NeverResponds).await.unwrap();
    let mut tcp = TcpStream::connect(server.addr()).await.unwrap();
    tcp.write_all(&FAKE_HELLO).await.unwrap();
    let mut buf = [0_u8; 16];
    let read = tokio::time::timeout(Duration::from_millis(300), tcp.read(&mut buf)).await;
    assert!(read.is_err(), "server must not answer or close: {read:?}");
}

#[tokio::test]
async fn quando_server_e_lento_deve_atrasar_o_handshake_pelo_menos_o_tempo_configurado() {
    let delay = Duration::from_millis(300);
    let server = TestServer::start(Behavior::Slow(delay)).await.unwrap();
    let started = Instant::now();
    handshake(roots_client(server.ca_der()), server.addr(), "localhost")
        .await
        .unwrap();
    assert!(started.elapsed() >= delay);
}

#[tokio::test]
async fn quando_server_e_encerrado_deve_parar_de_aceitar_conexoes() {
    let server = TestServer::start(Behavior::Ok).await.unwrap();
    let addr = server.addr();
    server.shutdown();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(TcpStream::connect(addr).await.is_err());
}
