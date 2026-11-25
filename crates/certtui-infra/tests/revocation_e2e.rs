//! The real adapters together: `ReqwestHttpFetcher` over HTTP, the
//! `X509RevocationProtocol` wire formats, the `RevocationService` strategy,
//! against a local server answering with the fixtures of
//! `tests/fixtures/revocation`.
//!
//! The fixture certificates point at `*.example.test`; `Rewrite` redirects
//! those hosts to the local server so everything else is the production path.

// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// the helpers below are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use certtui_app::http::HttpError;
use certtui_app::ports::HttpFetcher;
use certtui_app::revocation::{
    RevocationOutcome, RevocationScope, RevocationService, StapleState, check_revocation,
};
use certtui_app::testing::FixedClock;
use certtui_domain::limits::Limits;
use certtui_domain::model::{CertOrigin, CertificateRecord, Chain, RevocationStatus};
use certtui_domain::time::Timestamp;
use certtui_infra::http::ReqwestHttpFetcher;
use certtui_infra::revocation::X509RevocationProtocol;
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

macro_rules! fixture {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/revocation/",
            $name
        ))
    };
}

/// 2026-11-02T00:00:00Z, inside the validity of every "good" fixture.
const NOW: i64 = 1_793_577_600;

/// Sends the fixtures' `*.example.test` URLs to the local test server.
struct Rewrite {
    inner: ReqwestHttpFetcher,
    base: String,
}

impl Rewrite {
    fn map(&self, url: &str) -> String {
        [
            "http://ocsp.example.test",
            "http://crl.example.test",
            "http://ca.example.test",
        ]
        .iter()
        .find_map(|host| {
            url.strip_prefix(host)
                .map(|rest| format!("{}{rest}", self.base))
        })
        .unwrap_or_else(|| url.to_owned())
    }
}

#[async_trait::async_trait]
impl HttpFetcher for Rewrite {
    async fn get(&self, url: &str, max: usize, timeout: Duration) -> Result<Vec<u8>, HttpError> {
        self.inner.get(&self.map(url), max, timeout).await
    }

    async fn post(
        &self,
        url: &str,
        content_type: &str,
        body: Vec<u8>,
        max: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, HttpError> {
        self.inner
            .post(&self.map(url), content_type, body, max, timeout)
            .await
    }
}

fn chain(leaf: &[u8]) -> Chain {
    let limits = Limits::default();
    let records = [leaf, fixture!("ca.der")]
        .iter()
        .enumerate()
        .map(|(position, der)| {
            CertificateRecord::from_der(der, CertOrigin::Presented { position }, &limits).unwrap()
        })
        .collect();
    Chain::new(records, &limits).unwrap()
}

async fn check(server: &MockServer, leaf: &[u8], staple: Option<&[u8]>) -> RevocationOutcome {
    let http = Rewrite {
        inner: ReqwestHttpFetcher::new(3),
        base: server.uri(),
    };
    let service = RevocationService::new(
        Arc::new(http),
        Arc::new(X509RevocationProtocol),
        Arc::new(FixedClock(Timestamp::from_unix_saturating(NOW))),
        Limits::default(),
    );
    check_revocation(
        &service,
        &chain(leaf),
        staple,
        RevocationScope::Leaf,
        CancellationToken::new(),
    )
    .await
}

async fn ocsp_answers(server: &MockServer, status: u16, body: &[u8]) {
    Mock::given(method("POST"))
        .and(path("/ocsp"))
        .respond_with(ResponseTemplate::new(status).set_body_bytes(body.to_vec()))
        .mount(server)
        .await;
    // The GET fallback (`/ocsp/<request>`) gets the same answer.
    Mock::given(method("GET"))
        .and(path_regex("^/ocsp/.+"))
        .respond_with(ResponseTemplate::new(status).set_body_bytes(body.to_vec()))
        .mount(server)
        .await;
}

async fn crl_answers(server: &MockServer, body: &[u8]) {
    Mock::given(method("GET"))
        .and(path("/ca.crl"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(server)
        .await;
}

fn status(outcome: &RevocationOutcome) -> RevocationStatus {
    assert_eq!(outcome.statuses.len(), 1, "{outcome:?}");
    outcome.statuses.first().unwrap().1.clone()
}

fn assert_unknown(outcome: &RevocationOutcome) -> String {
    let got = status(outcome);
    assert!(matches!(got, RevocationStatus::Unknown { .. }), "{got:?}");
    let RevocationStatus::Unknown { why } = got else {
        return String::new();
    };
    why
}

#[tokio::test]
async fn quando_ocsp_diz_good_deve_dar_good() {
    let server = MockServer::start().await;
    ocsp_answers(&server, 200, fixture!("ocsp-good.der")).await;

    let got = check(&server, fixture!("leaf-good.der"), None).await;

    assert_eq!(status(&got), RevocationStatus::Good);
    assert_eq!(got.staple, StapleState::Missing);
}

#[tokio::test]
async fn quando_ocsp_diz_revoked_deve_dar_revoked_com_motivo() {
    let server = MockServer::start().await;
    ocsp_answers(&server, 200, fixture!("ocsp-revoked.der")).await;

    let got = check(&server, fixture!("leaf-revoked.der"), None).await;

    match status(&got) {
        RevocationStatus::Revoked { reason, at } => {
            assert_eq!(reason.as_deref(), Some("keyCompromise"));
            assert!(at.is_some());
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[tokio::test]
async fn quando_responder_devolve_html_404_ou_500_deve_dar_unknown_nunca_good() {
    for (code, body) in [
        (200_u16, &b"<html>captive portal</html>"[..]),
        (404, b"not found"),
        (500, b"oops"),
        (503, b""),
    ] {
        let server = MockServer::start().await;
        ocsp_answers(&server, code, body).await;
        // No CRL route: the CRL attempt also fails with 404.

        let got = check(&server, fixture!("leaf-good.der"), None).await;

        let why = assert_unknown(&got);
        assert!(!why.is_empty(), "{code}");
    }
}

#[tokio::test]
async fn quando_ocsp_e_try_later_ou_unauthorized_deve_dar_unknown_com_o_motivo() {
    for (body, word) in [
        (&fixture!("ocsp-try-later.der")[..], "tryLater"),
        (&fixture!("ocsp-unauthorized.der")[..], "unauthorized"),
    ] {
        let server = MockServer::start().await;
        ocsp_answers(&server, 200, body).await;

        let got = check(&server, fixture!("leaf-good.der"), None).await;

        let why = assert_unknown(&got);
        assert!(why.contains(word), "{why}");
    }
}

#[tokio::test]
async fn quando_resposta_e_de_outro_cert_ou_tem_assinatura_ruim_deve_dar_unknown() {
    for body in [
        &fixture!("ocsp-other-cert.der")[..],
        fixture!("ocsp-bad-signature.der"),
        fixture!("ocsp-expired.der"),
        fixture!("ocsp-delegated-no-eku.der"),
    ] {
        let server = MockServer::start().await;
        ocsp_answers(&server, 200, body).await;

        let got = check(&server, fixture!("leaf-good.der"), None).await;

        assert_unknown(&got);
    }
}

#[tokio::test]
async fn quando_ocsp_cai_e_a_crl_lista_o_serial_deve_dar_revoked_pela_crl() {
    let server = MockServer::start().await;
    ocsp_answers(&server, 500, b"down").await;
    crl_answers(&server, fixture!("crl-with-revoked.der")).await;

    let got = check(&server, fixture!("leaf-revoked.der"), None).await;

    assert!(
        matches!(status(&got), RevocationStatus::Revoked { .. }),
        "{got:?}"
    );
}

#[tokio::test]
async fn quando_crl_nao_lista_o_serial_deve_dar_good_pela_crl() {
    let server = MockServer::start().await;
    ocsp_answers(&server, 500, b"down").await;
    crl_answers(&server, fixture!("crl-with-revoked.der")).await;

    let got = check(&server, fixture!("leaf-good.der"), None).await;

    assert_eq!(status(&got), RevocationStatus::Good);
}

#[tokio::test]
async fn quando_crl_e_parcial_delta_ou_sem_next_update_deve_dar_unknown_nunca_good() {
    for body in [
        &fixture!("crl-no-next-update.der")[..],
        fixture!("crl-delta.der"),
        fixture!("crl-idp-other-dp.der"),
        fixture!("crl-idp-ca-only.der"),
        fixture!("crl-stale.der"),
        fixture!("crl-bad-signature.der"),
    ] {
        let server = MockServer::start().await;
        ocsp_answers(&server, 500, b"down").await;
        crl_answers(&server, body).await;

        let got = check(&server, fixture!("leaf-revoked.der"), None).await;

        assert_unknown(&got);
    }
}

#[tokio::test]
async fn quando_staple_e_valido_deve_nao_fazer_nenhuma_requisicao() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let got = check(
        &server,
        fixture!("leaf-good.der"),
        Some(fixture!("ocsp-good.der")),
    )
    .await;

    assert_eq!(status(&got), RevocationStatus::Good);
    assert_eq!(got.staple, StapleState::Valid);
}

#[tokio::test]
async fn quando_staple_e_invalido_deve_marcar_invalid_e_consultar_o_responder() {
    let server = MockServer::start().await;
    ocsp_answers(&server, 200, fixture!("ocsp-good.der")).await;

    let got = check(
        &server,
        fixture!("leaf-good.der"),
        Some(fixture!("ocsp-bad-signature.der")),
    )
    .await;

    assert_eq!(status(&got), RevocationStatus::Good);
    assert!(
        matches!(got.staple, StapleState::Invalid(_)),
        "{:?}",
        got.staple
    );
}

#[tokio::test]
async fn quando_servidor_nao_responde_a_tempo_deve_dar_unknown_dentro_do_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
        .mount(&server)
        .await;
    let http = Rewrite {
        inner: ReqwestHttpFetcher::new(3),
        base: server.uri(),
    };
    let limits = Limits {
        http_timeout: Duration::from_millis(200),
        ..Limits::default()
    };
    let service = RevocationService::new(
        Arc::new(http),
        Arc::new(X509RevocationProtocol),
        Arc::new(FixedClock(Timestamp::from_unix_saturating(NOW))),
        limits,
    );

    let started = std::time::Instant::now();
    let got = check_revocation(
        &service,
        &chain(fixture!("leaf-good.der")),
        None,
        RevocationScope::Leaf,
        CancellationToken::new(),
    )
    .await;

    assert_unknown(&got);
    // POST + GET fallback + CRL, each cut at 200 ms.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}
