//! The HTTP CONNECT tunnel against a fake proxy: what the fetcher captures
//! through it and how it fails when the proxy misbehaves.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use certtui_app::fetch::{FetchError, FetchRequest, Stage};
use certtui_app::ports::ChainFetcher;
use certtui_app::proxy::{ProxyEndpoint, ProxySettings};
use certtui_domain::target::NetworkTarget;
use certtui_infra::proxy::{ProxyError, connect_via_proxy};
use certtui_infra::tls::RustlsChainFetcher;
use support::fake_proxy::{FakeProxy, ProxyBehavior};
use support::fetch::quick_limits;
use support::tls_server::{Behavior, TestServer};
use tokio_util::sync::CancellationToken;

fn endpoint(proxy: &FakeProxy) -> ProxyEndpoint {
    ProxyEndpoint {
        host: "127.0.0.1".to_owned(),
        port: proxy.addr().port(),
    }
}

fn settings(proxy: &FakeProxy, no_proxy: Option<&str>) -> ProxySettings {
    ProxySettings {
        endpoint: endpoint(proxy),
        no_proxy: no_proxy.map(ToOwned::to_owned),
    }
}

/// A request for `localhost:<port of server>` with no `connect_to`: only the
/// proxy knows where it really goes.
fn request(server: &TestServer) -> FetchRequest {
    FetchRequest {
        target: NetworkTarget {
            host: "localhost".to_owned(),
            port: server.addr().port(),
            sni: None,
            connect_to: None,
        },
        limits: quick_limits(),
    }
}

fn fetcher_through(settings: ProxySettings) -> RustlsChainFetcher {
    let fetcher = RustlsChainFetcher::new();
    fetcher.use_proxy(Some(settings));
    fetcher
}

async fn start(behavior: Behavior) -> TestServer {
    TestServer::start(behavior).await.unwrap()
}

#[tokio::test]
async fn quando_proxy_ok_deve_tunelar_e_capturar_cadeia() {
    let server = start(Behavior::Ok).await;
    let proxy = FakeProxy::start(ProxyBehavior::Ok, Some(server.addr())).await;
    let fetcher = fetcher_through(settings(&proxy, None));

    let chain = fetcher
        .fetch(&request(&server), CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(chain.ders.len(), server.presented_chain().len());
    assert_eq!(proxy.connections(), 1);
    let expected = format!("CONNECT localhost:{} HTTP/1.1", server.addr().port());
    assert_eq!(proxy.request_lines(), [expected]);
}

#[tokio::test]
async fn quando_host_esta_no_no_proxy_deve_conectar_direto() {
    let server = start(Behavior::Ok).await;
    let proxy = FakeProxy::start(ProxyBehavior::Status502, None).await;
    let fetcher = fetcher_through(settings(&proxy, Some("localhost")));
    let mut req = request(&server);
    // Direct connection: the host must resolve to the server.
    req.target.connect_to = Some(server.addr());

    fetcher.fetch(&req, CancellationToken::new()).await.unwrap();

    assert_eq!(proxy.connections(), 0);
}

#[tokio::test]
async fn quando_proxy_explicito_e_host_casa_nada_deve_usar_o_proxy_mesmo_em_localhost() {
    let server = start(Behavior::Ok).await;
    let proxy = FakeProxy::start(ProxyBehavior::Ok, Some(server.addr())).await;
    // `no_proxy: None` is a proxy given with --proxy: it applies to all hosts.
    let fetcher = fetcher_through(settings(&proxy, None));
    fetcher
        .fetch(&request(&server), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(proxy.connections(), 1);
}

#[tokio::test]
async fn quando_proxy_407_deve_dar_auth_required() {
    let proxy = FakeProxy::start(ProxyBehavior::Status407, None).await;
    let result = connect_via_proxy(
        &endpoint(&proxy),
        "example.com",
        443,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(result.unwrap_err(), ProxyError::AuthRequired);
}

#[tokio::test]
async fn quando_proxy_407_no_fetcher_deve_explicar_a_autenticacao() {
    let server = start(Behavior::Ok).await;
    let proxy = FakeProxy::start(ProxyBehavior::Status407, None).await;
    let error = fetcher_through(settings(&proxy, None))
        .fetch(&request(&server), CancellationToken::new())
        .await
        .unwrap_err();
    match error {
        FetchError::Connect(message) => {
            assert!(message.contains("authentication"), "{message}");
            assert!(message.contains("proxy"), "{message}");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn quando_proxy_502_deve_dar_status_502() {
    let proxy = FakeProxy::start(ProxyBehavior::Status502, None).await;
    let result = connect_via_proxy(
        &endpoint(&proxy),
        "example.com",
        443,
        Duration::from_secs(2),
    )
    .await;
    assert_eq!(result.unwrap_err(), ProxyError::Status(502));
}

#[tokio::test]
async fn quando_proxy_fecha_sem_resposta_deve_dar_erro_rapido() {
    let proxy = FakeProxy::start(ProxyBehavior::CloseImmediately, None).await;
    let started = Instant::now();
    let result = connect_via_proxy(
        &endpoint(&proxy),
        "example.com",
        443,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(result.unwrap_err(), ProxyError::Closed);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn quando_resposta_passa_de_8kib_deve_dar_erro_e_nao_ler_mais() {
    let proxy = FakeProxy::start(ProxyBehavior::HugeHeader, None).await;
    let started = Instant::now();
    let result = connect_via_proxy(
        &endpoint(&proxy),
        "example.com",
        443,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(result.unwrap_err(), ProxyError::ResponseTooLarge);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn quando_resposta_nunca_termina_deve_parar_em_8kib() {
    let proxy = FakeProxy::start(ProxyBehavior::NeverEndingResponse, None).await;
    let started = Instant::now();
    let result = connect_via_proxy(
        &endpoint(&proxy),
        "example.com",
        443,
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(result.unwrap_err(), ProxyError::ResponseTooLarge);
    assert!(started.elapsed() < Duration::from_secs(2));
    // Give the proxy a moment to notice the closed socket, then check that it
    // was not able to push megabytes: the client stopped reading.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        proxy.flooded_bytes() < 8 * 1024 * 1024,
        "{} bytes",
        proxy.flooded_bytes()
    );
}

#[tokio::test]
async fn quando_proxy_e_lento_deve_estourar_connect_timeout() {
    let server = start(Behavior::Ok).await;
    let proxy = FakeProxy::start(ProxyBehavior::Slow, None).await;
    let started = Instant::now();
    let error = fetcher_through(settings(&proxy, None))
        .fetch(&request(&server), CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(error, FetchError::Timeout(Stage::Connect));
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(1), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
}

#[tokio::test]
async fn quando_proxy_esta_fora_do_ar_deve_dar_connect_error_citando_o_proxy() {
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let server = start(Behavior::Ok).await;
    let settings = ProxySettings {
        endpoint: ProxyEndpoint {
            host: "127.0.0.1".to_owned(),
            port: closed,
        },
        no_proxy: None,
    };
    let error = fetcher_through(settings)
        .fetch(&request(&server), CancellationToken::new())
        .await
        .unwrap_err();
    match error {
        FetchError::Connect(message) => assert!(message.contains("proxy"), "{message}"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn arc_de_fetcher_deve_aceitar_use_proxy() {
    // `use_proxy` is part of the port, so a shared `dyn ChainFetcher` can be
    // configured after it was built.
    let fetcher: Arc<dyn ChainFetcher> = Arc::new(RustlsChainFetcher::new());
    fetcher.use_proxy(None);
}
