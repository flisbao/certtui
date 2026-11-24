//! Helpers shared by the `fetcher_*` integration tests.

// Justificativa: each integration test file compiles this module separately and
// uses a different subset of it.
#![allow(dead_code)]
// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// these helpers are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

use std::time::Duration;

use certtui_app::fetch::{FetchRequest, FetchedChain};
use certtui_app::ports::ChainFetcher;
use certtui_domain::limits::Limits;
use certtui_domain::target::NetworkTarget;
use certtui_infra::tls::RustlsChainFetcher;
use tokio_util::sync::CancellationToken;

use super::tls_server::TestServer;

/// Limits small enough to keep the timing tests fast, large enough to be calm.
#[must_use]
pub fn quick_limits() -> Limits {
    Limits {
        dns_timeout: Duration::from_secs(1),
        connect_timeout: Duration::from_secs(2),
        handshake_timeout: Duration::from_secs(3),
        target_total_timeout: Duration::from_secs(5),
        max_handshake_bytes: 256 * 1024,
        ..Limits::default()
    }
}

/// A request for host `localhost` that connects straight to `server`.
#[must_use]
pub fn request_to(server: &TestServer) -> FetchRequest {
    FetchRequest {
        target: NetworkTarget {
            host: "localhost".to_owned(),
            port: server.addr().port(),
            sni: None,
            connect_to: Some(server.addr()),
        },
        limits: quick_limits(),
    }
}

/// Fetches from `server` with the quick limits and a fresh token.
pub async fn fetch_ok(server: &TestServer) -> FetchedChain {
    RustlsChainFetcher::new()
        .fetch(&request_to(server), CancellationToken::new())
        .await
        .unwrap()
}
