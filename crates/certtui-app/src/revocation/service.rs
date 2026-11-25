//! Revocation strategy (spec section 6.3): staple, then OCSP, then CRL.
//!
//! A network failure is never fatal: every path that cannot reach a verdict
//! ends in `Unknown { why }` with a short reason. `Good` and `Revoked` come
//! only from a response the [`RevocationProtocol`] fully verified.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;

use certtui_domain::chain_analysis::analyze_chain;
use certtui_domain::limits::Limits;
use certtui_domain::model::{CertificateRecord, Chain, RevocationStatus};
use tokio_util::sync::CancellationToken;

use crate::http::HttpError;
use crate::ports::{Clock, HttpFetcher};
use crate::revocation::cache::{CacheKey, CachedItem, CachedPayload, RevocationCache};
use crate::revocation::protocol::{OcspRequest, RevocationProtocol};

/// How many certificates are checked at the same time.
pub const REVOCATION_PARALLELISM: usize = 4;

/// Longest `why` kept for an `Unknown` built from several failed attempts.
const MAX_WHY_CHARS: usize = 300;

const OCSP_CONTENT_TYPE: &str = "application/ocsp-request";

/// Which certificates of the path are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationScope {
    /// Only the leaf (the default).
    Leaf,
    /// The leaf and every intermediate; roots are not checked.
    Full,
    /// Nothing (`--no-revocation`).
    Off,
}

/// What became of the stapled OCSP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StapleState {
    /// The server sent none.
    Missing,
    /// Verified (signature, `CertID`, freshness).
    Valid,
    /// Present but rejected, with the reason.
    Invalid(String),
    /// Not a network target, or revocation is off.
    NotApplicable,
}

/// The result of one revocation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationOutcome {
    /// `(index into the chain, status)`, in path order.
    pub statuses: Vec<(usize, RevocationStatus)>,
    /// State of the stapled response.
    pub staple: StapleState,
}

/// The collaborators of a revocation run, plus the per-execution cache.
pub struct RevocationService {
    http: Arc<dyn HttpFetcher>,
    protocol: Arc<dyn RevocationProtocol>,
    clock: Arc<dyn Clock>,
    limits: Limits,
    cache: Mutex<RevocationCache>,
}

impl RevocationService {
    /// A service whose cache holds at most `limits.max_revocation_cache_bytes`.
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpFetcher>,
        protocol: Arc<dyn RevocationProtocol>,
        clock: Arc<dyn Clock>,
        limits: Limits,
    ) -> Self {
        let cache = Mutex::new(RevocationCache::new(limits.max_revocation_cache_bytes));
        Self {
            http,
            protocol,
            clock,
            limits,
            cache,
        }
    }

    fn cache_get(&self, key: &CacheKey) -> Option<Arc<CachedItem>> {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
    }

    fn cache_put(&self, key: CacheKey, item: CachedItem) {
        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, item);
    }
}

impl std::fmt::Debug for RevocationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationService")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Checks revocation for the certificates of `chain` selected by `scope`.
///
/// `staple` is the OCSP response the server stapled, if any (network targets
/// only; pass `None` otherwise and read `StapleState::Missing` accordingly).
/// Stops promptly when `cancel` fires: the unfinished certificates become
/// `Unknown { "cancelled" }`.
pub async fn check_revocation(
    svc: &RevocationService,
    chain: &Chain,
    staple: Option<&[u8]>,
    scope: RevocationScope,
    cancel: CancellationToken,
) -> RevocationOutcome {
    if scope == RevocationScope::Off {
        return RevocationOutcome {
            statuses: Vec::new(),
            staple: StapleState::NotApplicable,
        };
    }
    let path = analyze_chain(chain, &[], &svc.limits).path;
    let records = chain.records();
    let targets = select_targets(records, &path, scope);

    let (staple_state, staple_status) = leaf_staple(svc, records, &path, staple);
    let mut checks: Vec<BoxFuture<'_, (usize, RevocationStatus)>> = Vec::new();
    for (position, &cert_index) in targets.iter().enumerate() {
        let issuer_index = path.get(path_position(&path, cert_index).saturating_add(1));
        let cert = records.get(cert_index);
        let issuer = issuer_index.and_then(|i| records.get(*i));
        let known = (position == 0 && cert_index == 0)
            .then(|| staple_status.clone())
            .flatten();
        let cancel = &cancel;
        checks.push(Box::pin(async move {
            let status = match (cert, known) {
                (None, _) => unknown("certificate not available"),
                (Some(_), Some(status)) => status,
                (Some(cert), None) => svc.check_one(cert, issuer, cancel).await,
            };
            (cert_index, status)
        }));
    }
    let mut statuses = Vec::with_capacity(checks.len());
    while !checks.is_empty() {
        let rest = checks.split_off(REVOCATION_PARALLELISM.min(checks.len()));
        statuses.extend(join_all(std::mem::replace(&mut checks, rest)).await);
    }
    RevocationOutcome {
        statuses,
        staple: staple_state,
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

fn path_position(path: &[usize], cert_index: usize) -> usize {
    path.iter()
        .position(|i| *i == cert_index)
        .unwrap_or(usize::MAX - 1)
}

fn unknown(why: &str) -> RevocationStatus {
    RevocationStatus::Unknown {
        why: why.to_owned(),
    }
}

fn is_self_signed(record: &CertificateRecord) -> bool {
    record.summary.subject.rfc4514 == record.summary.issuer.rfc4514
}

/// Which chain indices to check: the leaf, or every non-root certificate.
fn select_targets(
    records: &[CertificateRecord],
    path: &[usize],
    scope: RevocationScope,
) -> Vec<usize> {
    match scope {
        RevocationScope::Off => Vec::new(),
        RevocationScope::Leaf => path.first().copied().into_iter().collect(),
        RevocationScope::Full => path
            .iter()
            .enumerate()
            .filter(|(position, index)| {
                *position == 0 || records.get(**index).is_some_and(|r| !is_self_signed(r))
            })
            .map(|(_, index)| *index)
            .collect(),
    }
}

/// Judges the stapled response against the leaf. A staple that verifies as
/// `Good` or `Revoked` settles the leaf; one that verifies as `Unknown` is
/// valid but inconclusive, so the run goes on.
fn leaf_staple(
    svc: &RevocationService,
    records: &[CertificateRecord],
    path: &[usize],
    staple: Option<&[u8]>,
) -> (StapleState, Option<RevocationStatus>) {
    let Some(staple) = staple else {
        return (StapleState::Missing, None);
    };
    let leaf = path.first().and_then(|i| records.get(*i));
    let issuer = path.get(1).and_then(|i| records.get(*i));
    let (Some(leaf), Some(issuer)) = (leaf, issuer) else {
        return (
            StapleState::Invalid("issuer not available".to_owned()),
            None,
        );
    };
    match svc
        .protocol
        .evaluate_ocsp(staple, &leaf.der, &issuer.der, svc.clock.now())
    {
        Ok(status @ (RevocationStatus::Good | RevocationStatus::Revoked { .. })) => {
            (StapleState::Valid, Some(status))
        }
        Ok(RevocationStatus::Unknown { .. }) => (StapleState::Valid, None),
        Err(err) => (StapleState::Invalid(err.to_string()), None),
    }
}

/// An attempt that ended because the caller cancelled.
struct Cancelled;

/// How one source (OCSP or CRL) ended.
enum Step {
    /// A verified `Good` or `Revoked`.
    Answer(RevocationStatus),
    /// No verdict; why, one entry per failed attempt.
    Failed(Vec<String>),
}

impl RevocationService {
    async fn check_one(
        &self,
        cert: &CertificateRecord,
        issuer: Option<&CertificateRecord>,
        cancel: &CancellationToken,
    ) -> RevocationStatus {
        if is_self_signed(cert) {
            return unknown("self-signed certificate has no issuer to ask");
        }
        let Some(issuer) = issuer else {
            return unknown("issuer not available");
        };
        let ocsp_urls = &cert.summary.aia.ocsp;
        let crl_urls = &cert.summary.crl_distribution_points;
        if ocsp_urls.is_empty() && crl_urls.is_empty() {
            return unknown("no revocation endpoints");
        }
        let mut reasons = Vec::new();
        let ocsp = self.try_ocsp(cert, issuer, cancel).await;
        if let Some(done) = settle(ocsp, &mut reasons) {
            return done;
        }
        let crl = self.try_crl(cert, issuer, cancel).await;
        if let Some(done) = settle(crl, &mut reasons) {
            return done;
        }
        unknown(&truncate(&reasons.join("; ")))
    }

    async fn try_ocsp(
        &self,
        cert: &CertificateRecord,
        issuer: &CertificateRecord,
        cancel: &CancellationToken,
    ) -> Result<Step, Cancelled> {
        if cert.summary.aia.ocsp.is_empty() {
            return Ok(Step::Failed(Vec::new()));
        }
        let request = match self.protocol.build_ocsp_request(&cert.der, &issuer.der) {
            Ok(request) => request,
            Err(err) => return Ok(Step::Failed(vec![format!("ocsp request: {err}")])),
        };
        let key = CacheKey::Ocsp {
            issuer_key_hash: request.cache_key.0.clone(),
            serial: request.cache_key.1.clone(),
        };
        if let Some(item) = self.cache_get(&key)
            && let CachedPayload::Status(status) = &item.payload
        {
            return Ok(Step::Answer(status.clone()));
        }
        let mut reasons = Vec::new();
        for url in &cert.summary.aia.ocsp {
            let body = match self.ocsp_exchange(url, &request, cancel).await? {
                Ok(body) => body,
                Err(err) => {
                    reasons.push(format!("ocsp: {err}"));
                    continue;
                }
            };
            match self
                .protocol
                .evaluate_ocsp(&body, &cert.der, &issuer.der, self.clock.now())
            {
                Ok(status @ (RevocationStatus::Good | RevocationStatus::Revoked { .. })) => {
                    self.cache_put(key, CachedItem::status(status.clone()));
                    return Ok(Step::Answer(status));
                }
                Ok(RevocationStatus::Unknown { why }) => reasons.push(format!("ocsp: {why}")),
                Err(err) => reasons.push(format!("ocsp: {err}")),
            }
        }
        Ok(Step::Failed(reasons))
    }

    /// POST first; when it fails, GET with the request in the URL.
    async fn ocsp_exchange(
        &self,
        url: &str,
        request: &OcspRequest,
        cancel: &CancellationToken,
    ) -> Result<Result<Vec<u8>, HttpError>, Cancelled> {
        let max = self.limits.max_ocsp_response_bytes;
        let timeout = self.limits.http_timeout;
        let posted = cancellable(
            cancel,
            self.http
                .post(url, OCSP_CONTENT_TYPE, request.body.clone(), max, timeout),
        )
        .await?;
        if posted.is_ok() {
            return Ok(posted);
        }
        let get_url = format!("{}/{}", url.trim_end_matches('/'), request.get_url_suffix);
        cancellable(cancel, self.http.get(&get_url, max, timeout)).await
    }

    async fn try_crl(
        &self,
        cert: &CertificateRecord,
        issuer: &CertificateRecord,
        cancel: &CancellationToken,
    ) -> Result<Step, Cancelled> {
        let mut reasons = Vec::new();
        for url in &cert.summary.crl_distribution_points {
            let bytes = match self.crl_bytes(url, cancel).await? {
                Ok(bytes) => bytes,
                Err(why) => {
                    reasons.push(why);
                    continue;
                }
            };
            match self
                .protocol
                .evaluate_crl(&bytes, &cert.der, &issuer.der, self.clock.now())
            {
                Ok(status @ (RevocationStatus::Good | RevocationStatus::Revoked { .. })) => {
                    return Ok(Step::Answer(status));
                }
                Ok(RevocationStatus::Unknown { why }) => reasons.push(format!("crl: {why}")),
                Err(err) => reasons.push(format!("crl: {err}")),
            }
        }
        Ok(Step::Failed(reasons))
    }

    /// The CRL body for `url`, from the cache or the network.
    async fn crl_bytes(
        &self,
        url: &str,
        cancel: &CancellationToken,
    ) -> Result<Result<Vec<u8>, String>, Cancelled> {
        let key = CacheKey::Crl {
            url: url.to_owned(),
        };
        if let Some(item) = self.cache_get(&key)
            && let CachedPayload::Bytes(bytes) = &item.payload
        {
            return Ok(Ok(bytes.clone()));
        }
        let max = self.limits.max_crl_bytes;
        let fetched =
            cancellable(cancel, self.http.get(url, max, self.limits.http_timeout)).await?;
        Ok(match fetched {
            Ok(bytes) if bytes.len() > max => Err("crl too large".to_owned()),
            Ok(bytes) => {
                self.cache_put(key, CachedItem::bytes(bytes.clone()));
                Ok(bytes)
            }
            Err(HttpError::BodyTooLarge { .. }) => Err("crl too large".to_owned()),
            Err(err) => Err(format!("crl: {err}")),
        })
    }
}

/// A verdict if the step settled the question (answer or cancellation),
/// otherwise records why it failed and lets the next source try.
fn settle(step: Result<Step, Cancelled>, reasons: &mut Vec<String>) -> Option<RevocationStatus> {
    match step {
        Err(Cancelled) => Some(unknown("cancelled")),
        Ok(Step::Answer(status)) => Some(status),
        Ok(Step::Failed(why)) => {
            reasons.extend(why);
            None
        }
    }
}

fn truncate(text: &str) -> String {
    if text.chars().count() <= MAX_WHY_CHARS {
        return text.to_owned();
    }
    text.chars().take(MAX_WHY_CHARS).collect::<String>() + "..."
}

/// Runs `fut` until it finishes or `cancel` fires, whichever comes first.
async fn cancellable<T>(
    cancel: &CancellationToken,
    fut: impl Future<Output = T>,
) -> Result<T, Cancelled> {
    crate::cancel::cancellable(cancel, fut)
        .await
        .ok_or(Cancelled)
}

/// Polls every future to completion together, returning results in order.
async fn join_all<T>(mut futures: Vec<BoxFuture<'_, T>>) -> Vec<T> {
    let mut done: Vec<Option<T>> = futures.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (future, slot) in futures.iter_mut().zip(done.iter_mut()) {
            if slot.is_some() {
                continue;
            }
            match future.as_mut().poll(cx) {
                Poll::Ready(value) => *slot = Some(value),
                Poll::Pending => pending = true,
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    done.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::protocol::RevocationError;
    use crate::testing::{FakeHttpFetcher, FakeRevocationProtocol, FixedClock};
    use certtui_domain::model::CertOrigin;
    use certtui_domain::time::Timestamp;
    use std::time::Duration;

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/revocation/",
                $name
            ))
        };
    }

    const OCSP_URL: &str = "http://ocsp.example.test/ocsp";
    const CRL_URL: &str = "http://crl.example.test/ca.crl";
    const REQ_BODY: &[u8] = b"request";
    const GET_URL: &str = "http://ocsp.example.test/ocsp/c3VmZml4";

    fn chain(ders: &[&[u8]]) -> Chain {
        let limits = Limits::default();
        let records = ders
            .iter()
            .enumerate()
            .map(|(position, der)| {
                CertificateRecord::from_der(der, CertOrigin::Presented { position }, &limits)
                    .unwrap()
            })
            .collect();
        Chain::new(records, &limits).unwrap()
    }

    fn leaf_and_ca() -> Chain {
        chain(&[fixture!("leaf-good.der"), fixture!("ca.der")])
    }

    fn three() -> Chain {
        chain(&[
            fixture!("leaf-int.der"),
            fixture!("intermediate.der"),
            fixture!("ca.der"),
        ])
    }

    fn protocol(
        ocsp: Result<RevocationStatus, RevocationError>,
        crl: Result<RevocationStatus, RevocationError>,
    ) -> FakeRevocationProtocol {
        FakeRevocationProtocol::new(
            Ok(OcspRequest {
                body: REQ_BODY.to_vec(),
                get_url_suffix: "c3VmZml4".to_owned(),
                cache_key: (vec![1], vec![2]),
            }),
            ocsp,
            crl,
        )
    }

    fn service(http: &Arc<FakeHttpFetcher>, protocol: FakeRevocationProtocol) -> RevocationService {
        RevocationService::new(
            Arc::clone(http) as Arc<dyn HttpFetcher>,
            Arc::new(protocol),
            Arc::new(FixedClock(Timestamp::from_unix_saturating(1_793_577_600))),
            Limits::default(),
        )
    }

    async fn run(
        svc: &RevocationService,
        chain: &Chain,
        staple: Option<&[u8]>,
        scope: RevocationScope,
    ) -> RevocationOutcome {
        check_revocation(svc, chain, staple, scope, CancellationToken::new()).await
    }

    fn why_of(outcome: &RevocationOutcome, index: usize) -> String {
        match outcome.statuses.iter().find(|(i, _)| *i == index) {
            Some((_, RevocationStatus::Unknown { why })) => why.clone(),
            other => panic!("expected Unknown at {index}, got {other:?}"),
        }
    }

    fn calls(http: &FakeHttpFetcher) -> Vec<(&'static str, String)> {
        http.calls()
            .into_iter()
            .map(|c| (c.method, c.url))
            .collect()
    }

    #[tokio::test]
    async fn quando_staple_e_valido_deve_nao_chamar_http() {
        let http = Arc::new(FakeHttpFetcher::new());
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Err(RevocationError::Stale)),
        );

        let got = run(&svc, &leaf_and_ca(), Some(b"staple"), RevocationScope::Leaf).await;

        assert_eq!(got.statuses, vec![(0, RevocationStatus::Good)]);
        assert_eq!(got.staple, StapleState::Valid);
        assert_eq!(http.calls(), Vec::new());
    }

    #[tokio::test]
    async fn quando_staple_e_invalido_deve_marcar_invalid_e_seguir_para_ocsp() {
        let http = Arc::new(FakeHttpFetcher::new().on("POST", OCSP_URL, Ok(b"fresh".to_vec())));
        let proto = protocol(Ok(RevocationStatus::Good), Err(RevocationError::Stale))
            .ocsp_for(b"staple", Err(RevocationError::BadSignature));
        let svc = service(&http, proto);

        let got = run(&svc, &leaf_and_ca(), Some(b"staple"), RevocationScope::Leaf).await;

        assert_eq!(got.statuses, vec![(0, RevocationStatus::Good)]);
        assert_eq!(
            got.staple,
            StapleState::Invalid("signature does not verify".to_owned())
        );
        assert_eq!(calls(&http), vec![("POST", OCSP_URL.to_owned())]);
    }

    #[tokio::test]
    async fn quando_sem_staple_deve_marcar_missing() {
        let http = Arc::new(FakeHttpFetcher::new().on("POST", OCSP_URL, Ok(b"r".to_vec())));
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Err(RevocationError::Stale)),
        );

        let got = run(&svc, &leaf_and_ca(), None, RevocationScope::Leaf).await;

        assert_eq!(got.staple, StapleState::Missing);
    }

    #[tokio::test]
    async fn quando_post_falha_deve_tentar_get() {
        let http = Arc::new(
            FakeHttpFetcher::new()
                .on("POST", OCSP_URL, Err(HttpError::Status(405)))
                .on("GET", GET_URL, Ok(b"resp".to_vec())),
        );
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Err(RevocationError::Stale)),
        );

        let got = run(&svc, &leaf_and_ca(), None, RevocationScope::Leaf).await;

        assert_eq!(got.statuses, vec![(0, RevocationStatus::Good)]);
        assert_eq!(
            calls(&http),
            vec![("POST", OCSP_URL.to_owned()), ("GET", GET_URL.to_owned())]
        );
        let post = http.calls().into_iter().next().unwrap();
        assert_eq!(post.body, REQ_BODY);
        assert_eq!(post.max_bytes, Limits::default().max_ocsp_response_bytes);
    }

    #[tokio::test]
    async fn quando_ocsp_falha_deve_tentar_crl() {
        let revoked = RevocationStatus::Revoked {
            reason: Some("keyCompromise".to_owned()),
            at: None,
        };
        let http = Arc::new(FakeHttpFetcher::new().on("GET", CRL_URL, Ok(b"crl".to_vec())));
        let svc = service(
            &http,
            protocol(Err(RevocationError::Stale), Ok(revoked.clone())),
        );

        let got = run(&svc, &leaf_and_ca(), None, RevocationScope::Leaf).await;

        assert_eq!(got.statuses, vec![(0, revoked)]);
        assert!(calls(&http).contains(&("GET", CRL_URL.to_owned())));
    }

    #[tokio::test]
    async fn quando_tudo_falha_deve_dar_unknown_e_nao_erro() {
        // 404 everywhere, an unsuccessful OCSP answer and a stale CRL.
        let http = Arc::new(
            FakeHttpFetcher::new()
                .on("POST", OCSP_URL, Ok(b"tryLater".to_vec()))
                .on("GET", CRL_URL, Ok(b"old".to_vec())),
        );
        let proto = protocol(
            Err(RevocationError::Unsuccessful("tryLater".to_owned())),
            Err(RevocationError::Stale),
        );
        let svc = service(&http, proto);

        let got = run(&svc, &leaf_and_ca(), None, RevocationScope::Leaf).await;

        let why = why_of(&got, 0);
        assert!(why.contains("tryLater"), "{why}");
        assert!(why.contains("stale"), "{why}");
    }

    #[tokio::test]
    async fn quando_http_devolve_html_ou_500_deve_dar_unknown() {
        let http = Arc::new(
            FakeHttpFetcher::new()
                .on("POST", OCSP_URL, Err(HttpError::Status(500)))
                .on("GET", GET_URL, Err(HttpError::Status(500)))
                .on("GET", CRL_URL, Err(HttpError::Timeout)),
        );
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Ok(RevocationStatus::Good)),
        );

        let got = run(&svc, &leaf_and_ca(), None, RevocationScope::Leaf).await;

        let why = why_of(&got, 0);
        assert!(why.contains("500"), "{why}");
        assert!(why.contains("timed out"), "{why}");
    }

    #[tokio::test]
    async fn quando_scope_leaf_deve_checar_so_o_leaf() {
        let http = Arc::new(FakeHttpFetcher::new().on("POST", OCSP_URL, Ok(b"r".to_vec())));
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Err(RevocationError::Stale)),
        );

        let got = run(&svc, &three(), None, RevocationScope::Leaf).await;

        let indices: Vec<_> = got.statuses.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, vec![0]);
    }

    #[tokio::test]
    async fn quando_scope_full_deve_checar_intermediarios_e_pular_a_raiz() {
        let http = Arc::new(FakeHttpFetcher::new().on("POST", OCSP_URL, Ok(b"r".to_vec())));
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Err(RevocationError::Stale)),
        );

        let got = run(&svc, &three(), None, RevocationScope::Full).await;

        let indices: Vec<_> = got.statuses.iter().map(|(i, _)| *i).collect();
        assert_eq!(indices, vec![0, 1]);
    }

    #[tokio::test]
    async fn quando_scope_off_deve_nao_fazer_nada() {
        let http = Arc::new(FakeHttpFetcher::new());
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Ok(RevocationStatus::Good)),
        );

        let got = run(&svc, &three(), Some(b"staple"), RevocationScope::Off).await;

        assert_eq!(got.statuses, Vec::new());
        assert_eq!(got.staple, StapleState::NotApplicable);
        assert_eq!(http.calls(), Vec::new());
    }

    #[tokio::test]
    async fn quando_mesmo_serial_repetido_deve_usar_cache_e_chamar_http_uma_vez() {
        let http = Arc::new(FakeHttpFetcher::new().on("POST", OCSP_URL, Ok(b"r".to_vec())));
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Err(RevocationError::Stale)),
        );
        let chain = leaf_and_ca();

        let first = run(&svc, &chain, None, RevocationScope::Leaf).await;
        let second = run(&svc, &chain, None, RevocationScope::Leaf).await;

        assert_eq!(first.statuses, second.statuses);
        assert_eq!(http.calls().len(), 1);
    }

    #[tokio::test]
    async fn quando_crl_repetida_deve_baixar_uma_vez() {
        let http = Arc::new(FakeHttpFetcher::new().on("GET", CRL_URL, Ok(b"crl".to_vec())));
        let svc = service(
            &http,
            protocol(Err(RevocationError::Stale), Ok(RevocationStatus::Good)),
        );
        let chain = leaf_and_ca();

        run(&svc, &chain, None, RevocationScope::Leaf).await;
        run(&svc, &chain, None, RevocationScope::Leaf).await;

        let crl_gets = calls(&http)
            .into_iter()
            .filter(|(_, u)| u == CRL_URL)
            .count();
        assert_eq!(crl_gets, 1);
    }

    #[tokio::test]
    async fn quando_crl_passa_do_limite_deve_dar_unknown_crl_too_large() {
        let http = Arc::new(
            FakeHttpFetcher::new()
                .on("POST", OCSP_URL, Err(HttpError::Status(500)))
                .on("GET", GET_URL, Err(HttpError::Status(500)))
                .on("GET", CRL_URL, Err(HttpError::BodyTooLarge { limit: 8 })),
        );
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Ok(RevocationStatus::Good)),
        );

        let got = run(&svc, &leaf_and_ca(), None, RevocationScope::Leaf).await;

        assert!(why_of(&got, 0).contains("crl too large"));
        let crl_call = http.calls().into_iter().find(|c| c.url == CRL_URL).unwrap();
        assert_eq!(crl_call.max_bytes, Limits::default().max_crl_bytes);
    }

    #[tokio::test]
    async fn quando_cancelado_deve_parar_rapido() {
        let http = Arc::new(FakeHttpFetcher::hanging());
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Ok(RevocationStatus::Good)),
        );
        let chain = leaf_and_ca();
        let cancel = CancellationToken::new();

        let work = check_revocation(&svc, &chain, None, RevocationScope::Leaf, cancel.clone());
        let stopper = async {
            tokio::task::yield_now().await;
            cancel.cancel();
        };
        let (got, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(work, stopper)
        })
        .await
        .unwrap();

        assert_eq!(why_of(&got, 0), "cancelled");
        assert_eq!(http.calls().len(), 1, "stopped at the first request");
    }

    #[tokio::test]
    async fn quando_sem_urls_deve_dar_unknown_sem_endpoints() {
        let http = Arc::new(FakeHttpFetcher::new());
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Ok(RevocationStatus::Good)),
        );
        let chain = chain(&[fixture!("responder.der"), fixture!("ca.der")]);

        let got = run(&svc, &chain, None, RevocationScope::Leaf).await;

        assert_eq!(why_of(&got, 0), "no revocation endpoints");
        assert_eq!(http.calls(), Vec::new());
    }

    #[tokio::test]
    async fn quando_nao_ha_emissor_na_cadeia_deve_dar_unknown_issuer_not_available() {
        let http = Arc::new(FakeHttpFetcher::new());
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Ok(RevocationStatus::Good)),
        );
        let chain = chain(&[fixture!("leaf-good.der")]);

        let got = run(&svc, &chain, Some(b"staple"), RevocationScope::Leaf).await;

        assert_eq!(why_of(&got, 0), "issuer not available");
        assert_eq!(
            got.staple,
            StapleState::Invalid("issuer not available".to_owned())
        );
        assert_eq!(http.calls(), Vec::new());
    }

    #[tokio::test]
    async fn quando_leaf_e_autoassinado_deve_dar_unknown_sem_rede() {
        let http = Arc::new(FakeHttpFetcher::new());
        let svc = service(
            &http,
            protocol(Ok(RevocationStatus::Good), Ok(RevocationStatus::Good)),
        );
        let chain = chain(&[fixture!("ca.der")]);

        let got = run(&svc, &chain, None, RevocationScope::Leaf).await;

        assert!(why_of(&got, 0).contains("self-signed"));
        assert_eq!(http.calls(), Vec::new());
    }
}
