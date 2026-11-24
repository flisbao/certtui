//! Timeouts, byte budget and cancellation: the fetcher must always come back.

// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// the helpers below are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

mod support;

use std::time::{Duration, Instant};

use certtui_app::fetch::{FetchError, Stage};
use certtui_app::ports::ChainFetcher;
use certtui_infra::tls::RustlsChainFetcher;
use support::fetch::request_to;
use support::tls_server::{Behavior, TestServer};
use tokio_util::sync::CancellationToken;

async fn start(behavior: Behavior) -> TestServer {
    TestServer::start(behavior).await.unwrap()
}

#[tokio::test]
async fn quando_server_nunca_responde_deve_falhar_em_no_maximo_total_timeout_mais_1s() {
    let server = start(Behavior::NeverResponds).await;
    let mut req = request_to(&server);
    req.limits.target_total_timeout = Duration::from_secs(2);
    req.limits.handshake_timeout = Duration::from_secs(10);

    let started = Instant::now();
    let got = RustlsChainFetcher::new()
        .fetch(&req, CancellationToken::new())
        .await;

    assert_eq!(got, Err(FetchError::Timeout(Stage::Total)));
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(3), "{elapsed:?}");
}

#[tokio::test]
async fn quando_server_e_lento_no_handshake_deve_dar_timeout_handshake() {
    let server = start(Behavior::Slow(Duration::from_secs(5))).await;
    let mut req = request_to(&server);
    req.limits.handshake_timeout = Duration::from_millis(400);

    let started = Instant::now();
    let got = RustlsChainFetcher::new()
        .fetch(&req, CancellationToken::new())
        .await;

    assert_eq!(got, Err(FetchError::Timeout(Stage::Handshake)));
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
}

#[tokio::test]
async fn quando_server_inunda_bytes_deve_dar_byte_budget_exceeded_ou_handshake_error() {
    let server = start(Behavior::FloodBytes).await;
    let mut req = request_to(&server);
    req.limits.max_handshake_bytes = 32 * 1024;

    let started = Instant::now();
    let got = RustlsChainFetcher::new()
        .fetch(&req, CancellationToken::new())
        .await;

    match got {
        Err(FetchError::ByteBudgetExceeded { limit }) => assert_eq!(limit, 32 * 1024),
        Err(FetchError::Handshake(_)) => {}
        other => panic!("unexpected outcome: {other:?}"),
    }
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
}

#[tokio::test]
async fn quando_cancelado_no_meio_deve_dar_cancelled_em_menos_de_200ms() {
    let server = start(Behavior::NeverResponds).await;
    let req = request_to(&server);
    let token = CancellationToken::new();
    let fetcher = RustlsChainFetcher::new();

    let canceller = async {
        while server.accepted_connections() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let at = Instant::now();
        token.cancel();
        at
    };
    let (got, cancelled_at) = tokio::join!(fetcher.fetch(&req, token.clone()), canceller);

    assert_eq!(got, Err(FetchError::Cancelled));
    let lag = cancelled_at.elapsed();
    assert!(lag < Duration::from_millis(200), "{lag:?}");
}

#[tokio::test]
async fn quando_ja_cancelado_na_entrada_deve_dar_cancelled_sem_conectar() {
    let server = start(Behavior::Ok).await;
    let token = CancellationToken::new();
    token.cancel();

    let got = RustlsChainFetcher::new()
        .fetch(&request_to(&server), token)
        .await;

    assert_eq!(got, Err(FetchError::Cancelled));
    assert_eq!(server.accepted_connections(), 0);
}

#[tokio::test]
async fn quando_tls_valido_excede_orcamento_deve_retornar_limite_exato() {
    let server = start(Behavior::Ok).await;
    let mut req = request_to(&server);
    req.limits.max_handshake_bytes = 16;
    let result = RustlsChainFetcher::new()
        .fetch(&req, CancellationToken::new())
        .await;
    assert_eq!(result, Err(FetchError::ByteBudgetExceeded { limit: 16 }));
}
