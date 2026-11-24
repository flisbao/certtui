//! How the fetcher picks the address and the SNI it connects with.

// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// the helpers below are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

mod support;

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use certtui_app::fetch::{FetchError, FetchRequest, FetchedChain, Stage};
use certtui_app::ports::ChainFetcher;
use certtui_domain::target::NetworkTarget;
use certtui_infra::tls::{Resolver, RustlsChainFetcher};
use support::fetch::{quick_limits, request_to};
use support::tls_server::{Behavior, Observation, TestServer};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Resolver double: replies with a fixed outcome and counts the calls.
struct FakeResolver {
    calls: AtomicUsize,
    reply: fn() -> io::Result<Vec<SocketAddr>>,
}

#[async_trait]
impl Resolver for FakeResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        (self.reply)()
    }
}

/// Resolver double that never answers.
struct HangingResolver;

#[async_trait]
impl Resolver for HangingResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        std::future::pending().await
    }
}

/// Resolver double returning exactly two addresses, in order.
struct PairResolver(SocketAddr, SocketAddr);

#[async_trait]
impl Resolver for PairResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![self.0, self.1])
    }
}

fn fake(reply: fn() -> io::Result<Vec<SocketAddr>>) -> Arc<FakeResolver> {
    Arc::new(FakeResolver {
        calls: AtomicUsize::new(0),
        reply,
    })
}

async fn start(behavior: Behavior) -> TestServer {
    TestServer::start(behavior).await.unwrap()
}

/// An address on which nothing listens (bound, then released).
async fn dead_addr() -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    listener.local_addr().unwrap()
}

fn target(host: &str, port: u16) -> NetworkTarget {
    NetworkTarget {
        host: host.to_owned(),
        port,
        sni: None,
        connect_to: None,
    }
}

async fn fetch(
    fetcher: &RustlsChainFetcher,
    target: NetworkTarget,
) -> Result<FetchedChain, FetchError> {
    let req = FetchRequest {
        target,
        limits: quick_limits(),
    };
    fetcher.fetch(&req, CancellationToken::new()).await
}

#[tokio::test]
async fn quando_sni_customizado_deve_ser_o_visto_pelo_server() {
    let server = start(Behavior::Ok).await;
    let mut req = request_to(&server);
    req.target.sni = Some("custom.example".to_owned());

    RustlsChainFetcher::new()
        .fetch(&req, CancellationToken::new())
        .await
        .unwrap();

    let expected = Observation::Present("custom.example".to_owned());
    assert_eq!(server.last_sni(), expected);
}

#[tokio::test]
async fn quando_alvo_e_nome_sem_sni_deve_enviar_o_host() {
    let server = start(Behavior::Ok).await;

    RustlsChainFetcher::new()
        .fetch(&request_to(&server), CancellationToken::new())
        .await
        .unwrap();

    let expected = Observation::Present("localhost".to_owned());
    assert_eq!(server.last_sni(), expected);
}

#[tokio::test]
async fn quando_alvo_e_ip_sem_sni_deve_nao_enviar_sni() {
    let server = start(Behavior::Ok).await;
    let t = target("127.0.0.1", server.addr().port());

    let got = fetch(&RustlsChainFetcher::new(), t).await.unwrap();

    assert_eq!(server.last_sni(), Observation::Absent);
    assert_eq!(got.ders, server.presented_chain());
    assert_eq!(got.timings.dns, None, "an IP literal needs no DNS");
}

#[tokio::test]
async fn quando_alvo_e_ip_com_sni_deve_enviar_o_sni_dado() {
    let server = start(Behavior::Ok).await;
    let mut t = target("127.0.0.1", server.addr().port());
    t.sni = Some("virtual.example".to_owned());

    fetch(&RustlsChainFetcher::new(), t).await.unwrap();

    let expected = Observation::Present("virtual.example".to_owned());
    assert_eq!(server.last_sni(), expected);
}

#[tokio::test]
async fn quando_connect_to_deve_pular_dns_e_manter_sni_do_alvo() {
    let server = start(Behavior::Ok).await;
    let resolver = fake(|| Err(io::Error::other("DNS must not run")));
    let fetcher = RustlsChainFetcher::with_resolver(resolver.clone());
    let mut t = target("unresolvable.invalid", 443);
    t.connect_to = Some(server.addr());

    let got = fetch(&fetcher, t).await.unwrap();

    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(got.timings.dns, None);
    let expected = Observation::Present("unresolvable.invalid".to_owned());
    assert_eq!(server.last_sni(), expected);
}

#[tokio::test]
async fn quando_primeiro_ip_recusa_deve_usar_o_segundo() {
    let server = start(Behavior::Ok).await;
    let fetcher =
        RustlsChainFetcher::with_resolver(Arc::new(PairResolver(dead_addr().await, server.addr())));

    let got = fetch(&fetcher, target("two-ips.example", 443))
        .await
        .unwrap();

    assert_eq!(got.ders, server.presented_chain());
    assert_eq!(
        got.session.unwrap().peer_ip,
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    assert_eq!(server.accepted_connections(), 1);
    assert!(got.timings.dns.is_some());
}

#[tokio::test]
async fn quando_todos_os_ips_recusam_deve_dar_connect_error() {
    let dead = dead_addr().await;
    let fetcher = RustlsChainFetcher::with_resolver(Arc::new(PairResolver(dead, dead)));

    let got = fetch(&fetcher, target("dead.example", dead.port())).await;

    assert!(matches!(got, Err(FetchError::Connect(_))), "{got:?}");
}

#[tokio::test]
async fn quando_dns_falha_deve_dar_dns_error_sem_controles() {
    let fetcher = RustlsChainFetcher::with_resolver(fake(|| {
        Err(io::Error::other("no such host\r\n\u{1b}[31mred"))
    }));

    let got = fetch(&fetcher, target("nope.example", 443)).await;

    let Err(FetchError::Dns(msg)) = got else {
        panic!("expected a DNS error, got {got:?}");
    };
    assert!(msg.chars().all(|c| !c.is_control()), "{msg:?}");
}

#[tokio::test]
async fn quando_dns_devolve_lista_vazia_deve_dar_dns_error() {
    let fetcher = RustlsChainFetcher::with_resolver(fake(|| Ok(Vec::new())));

    let got = fetch(&fetcher, target("empty.example", 443)).await;

    assert!(matches!(got, Err(FetchError::Dns(_))), "{got:?}");
}

#[tokio::test]
async fn quando_dns_trava_deve_dar_timeout_dns() {
    let fetcher = RustlsChainFetcher::with_resolver(Arc::new(HangingResolver));
    let mut req = FetchRequest {
        target: target("hang.example", 443),
        limits: quick_limits(),
    };
    req.limits.dns_timeout = Duration::from_millis(200);

    let started = std::time::Instant::now();
    let got = fetcher.fetch(&req, CancellationToken::new()).await;

    assert_eq!(got, Err(FetchError::Timeout(Stage::Dns)));
    assert!(started.elapsed() < Duration::from_secs(2));
}
