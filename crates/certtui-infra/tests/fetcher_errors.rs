//! Broken peers must produce short, clear errors, quickly (RF2, RF3).

// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// the helpers below are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

mod support;

use std::time::{Duration, Instant};

use certtui_app::fetch::FetchError;
use certtui_app::ports::ChainFetcher;
use certtui_infra::tls::RustlsChainFetcher;
use support::fetch::request_to;
use support::tls_server::{Behavior, TestServer};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Fetches from a server with `behavior`; returns the outcome and its duration.
async fn fetch_from(behavior: Behavior) -> (Result<(), FetchError>, Duration) {
    let server = TestServer::start(behavior).await.unwrap();
    let started = Instant::now();
    let got = RustlsChainFetcher::new()
        .fetch(&request_to(&server), CancellationToken::new())
        .await;
    (got.map(|_| ()), started.elapsed())
}

fn assert_clean_handshake_error(got: &Result<(), FetchError>) {
    assert!(matches!(got, Err(FetchError::Handshake(_))), "{got:?}");
    if let Err(FetchError::Handshake(msg)) = got {
        assert!(!msg.is_empty() && msg.chars().count() <= 200, "{msg:?}");
        assert!(msg.chars().all(|c| !c.is_control()), "{msg:?}");
    }
}

#[tokio::test]
async fn quando_server_fala_http_puro_deve_dar_handshake_error_rapido() {
    let (got, elapsed) = fetch_from(Behavior::PlainHttp).await;

    assert_clean_handshake_error(&got);
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[tokio::test]
async fn quando_server_fecha_na_hora_deve_dar_erro_rapido() {
    let (got, elapsed) = fetch_from(Behavior::CloseImmediately).await;

    assert_clean_handshake_error(&got);
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[tokio::test]
async fn quando_server_manda_alert_deve_dar_handshake_error_rapido() {
    let (got, elapsed) = fetch_from(Behavior::TlsAlert).await;

    assert_eq!(
        got,
        Err(FetchError::Handshake(
            "the peer sent alert HandshakeFailure".to_owned()
        ))
    );
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[tokio::test]
async fn quando_server_so_tls10_deve_dar_unsupported_protocol() {
    let (got, elapsed) = fetch_from(Behavior::Tls10Only).await;

    assert_eq!(got, Err(FetchError::UnsupportedProtocol));
    assert!(elapsed < Duration::from_secs(1), "{elapsed:?}");
}

#[tokio::test]
async fn quando_porta_esta_fechada_deve_dar_connect_error() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let server = TestServer::start(Behavior::Ok).await.unwrap();
    let mut req = request_to(&server);
    req.target.connect_to = Some(addr);

    let got = RustlsChainFetcher::new()
        .fetch(&req, CancellationToken::new())
        .await;

    let Err(FetchError::Connect(msg)) = got else {
        panic!("expected a connect error, got {got:?}");
    };
    assert!(msg.chars().all(|c| !c.is_control()), "{msg:?}");
}
