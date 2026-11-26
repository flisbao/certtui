//! `RustlsChainFetcher` against well-behaved and merely odd TLS servers.

// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// the helpers below are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use certtui_app::ports::ChainFetcher;
use certtui_domain::model::LoadNote;
use certtui_infra::tls::RustlsChainFetcher;
use support::fetch::{fetch_ok, request_to};
use support::tls_server::{Behavior, Observation, TestServer};
use tokio_util::sync::CancellationToken;

async fn start(behavior: Behavior) -> TestServer {
    TestServer::start(behavior).await.unwrap()
}

#[tokio::test]
async fn quando_server_tls13_deve_capturar_cadeia_e_info() {
    let server = start(Behavior::Tls13Only).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.ders, server.presented_chain());
    let session = got.session.as_ref().unwrap();
    assert_eq!(session.version, "TLSv1.3");
    assert_ne!(session.cipher_suite, "");
    assert!(session.cipher_suite.starts_with("TLS13_"), "{got:?}");
    assert!(session.key_exchange_group.is_some(), "{got:?}");
    assert_eq!(session.peer_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let alpn = session.alpn.clone().unwrap();
    assert!(alpn == "h2" || alpn == "http/1.1", "{alpn}");
    let seen = server.negotiated_alpn(Duration::from_secs(2)).await;
    assert_eq!(seen, Observation::Present(alpn.into_bytes()));
    assert_eq!(got.ocsp_staple, None);
}

#[tokio::test]
async fn quando_server_tls12_only_deve_negociar_tls12() {
    let server = start(Behavior::Tls12Only).await;
    let got = fetch_ok(&server).await;

    let session = got.session.as_ref().unwrap();
    assert_eq!(session.version, "TLSv1.2");
    assert_ne!(session.cipher_suite, "");
    assert!(session.cipher_suite.contains("ECDHE"), "{got:?}");
    assert_eq!(got.ders, server.presented_chain());
    assert!(session.alpn.is_some(), "{got:?}");
}

#[tokio::test]
async fn quando_cadeia_e_incompleta_deve_capturar_so_o_que_veio() {
    let server = start(Behavior::IncompleteChain).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.ders.len(), 1);
    assert_eq!(got.ders, server.presented_chain());
}

#[tokio::test]
async fn quando_cadeia_fora_de_ordem_deve_preservar_ordem_apresentada() {
    let server = start(Behavior::WrongOrder).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.ders.len(), 3);
    assert_eq!(got.ders, server.presented_chain());
    assert_eq!(got.ders.get(1).map(Vec::as_slice), Some(server.ca_der()));
}

#[tokio::test]
async fn quando_cert_expirado_deve_capturar_mesmo_assim() {
    let server = start(Behavior::Expired).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.ders, server.presented_chain());
}

#[tokio::test]
async fn quando_cert_e_autoassinado_deve_capturar_mesmo_assim() {
    let server = start(Behavior::SelfSigned).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.ders.len(), 1);
    assert_eq!(got.ders, server.presented_chain());
}

#[tokio::test]
async fn quando_server_tem_staple_deve_capturar_bytes_identicos() {
    let staple = vec![0x30, 0x03, 0x0a, 0x01, 0x00, 0xde, 0xad, 0xbe, 0xef];
    let server = start(Behavior::WithStaple(staple.clone())).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.ocsp_staple, Some(staple));
}

#[tokio::test]
async fn quando_fetch_roda_em_task_spawnada_deve_compilar_e_funcionar() {
    let server = start(Behavior::Ok).await;
    let req = request_to(&server);
    let fetcher = Arc::new(RustlsChainFetcher::new());

    let task = tokio::spawn(async move { fetcher.fetch(&req, CancellationToken::new()).await });

    let got = task.await.unwrap().unwrap();
    assert_eq!(got.ders, server.presented_chain());
}

#[tokio::test]
async fn quando_fetch_tem_sucesso_deve_medir_fases_sem_dns() {
    let server = start(Behavior::Ok).await;
    let got = fetch_ok(&server).await;
    let t = got.timings;

    assert_eq!(t.dns, None, "connect_to skips DNS");
    let (connect, handshake, total) = (t.connect.unwrap(), t.handshake.unwrap(), t.total.unwrap());
    assert!(total >= connect + handshake, "{t:?}");
    assert!(total < Duration::from_secs(3), "{t:?}");
}

#[tokio::test]
async fn quando_server_nao_prova_posse_da_chave_tls13_deve_manter_cadeia_e_anotar() {
    let server = start(Behavior::ImpostorTls13).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.ders, server.presented_chain());
    assert_eq!(got.note, Some(LoadNote::HandshakeSignatureInvalid));
    assert!(got.session.is_none(), "{got:?}");
}

#[tokio::test]
async fn quando_server_nao_prova_posse_da_chave_tls12_deve_manter_cadeia_e_anotar() {
    let server = start(Behavior::ImpostorTls12).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.ders, server.presented_chain());
    assert_eq!(got.note, Some(LoadNote::HandshakeSignatureInvalid));
}

#[tokio::test]
async fn quando_server_e_legitimo_deve_nao_anotar_assinatura() {
    let server = start(Behavior::Ok).await;
    let got = fetch_ok(&server).await;

    assert_eq!(got.note, None);
}
