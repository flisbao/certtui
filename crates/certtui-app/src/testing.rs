//! Test doubles for the application ports.

use certtui_domain::limits::Limits;
use certtui_domain::time::Timestamp;

use tokio_util::sync::CancellationToken;

use crate::error::LoadError;
use crate::fetch::{FetchError, FetchRequest, FetchedChain};
use std::sync::{Mutex, PoisonError};

use certtui_domain::model::{Chain, RevocationStatus};

use crate::http::HttpError;
use crate::ports::{
    ChainFetcher, ChainVerification, ChainVerifier, Clock, HttpFetcher, LoadedCerts, LocalSource,
    SourceLoader, TrustStoreProvider,
};
use crate::revocation::{OcspRequest, RevocationError, RevocationProtocol};
use crate::trust::{TrustAnchors, TrustError, TrustSource};

/// A [`Clock`] that always returns the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock(pub Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// A [`SourceLoader`] that returns a canned result whatever the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeSourceLoader(pub Result<LoadedCerts, LoadError>);

impl SourceLoader for FakeSourceLoader {
    fn load(&self, _src: &LocalSource, _limits: &Limits) -> Result<LoadedCerts, LoadError> {
        self.0.clone()
    }
}

/// A [`ChainFetcher`] that returns a canned result whatever the request,
/// except that an already cancelled token yields [`FetchError::Cancelled`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeChainFetcher(pub Result<FetchedChain, FetchError>);

#[async_trait::async_trait]
impl ChainFetcher for FakeChainFetcher {
    async fn fetch(
        &self,
        _req: &FetchRequest,
        cancel: CancellationToken,
    ) -> Result<FetchedChain, FetchError> {
        if cancel.is_cancelled() {
            return Err(FetchError::Cancelled);
        }
        self.0.clone()
    }
}

/// A [`ChainVerifier`] that returns a canned verification and records the
/// hostname of every call.
#[derive(Debug)]
pub struct FakeChainVerifier {
    verification: ChainVerification,
    hostnames: Mutex<Vec<Option<String>>>,
}

impl FakeChainVerifier {
    /// A verifier that always answers `verification`.
    #[must_use]
    pub fn new(verification: ChainVerification) -> Self {
        Self {
            verification,
            hostnames: Mutex::new(Vec::new()),
        }
    }

    /// The hostname argument of every `verify` call so far.
    #[must_use]
    pub fn hostnames(&self) -> Vec<Option<String>> {
        self.hostnames
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ChainVerifier for FakeChainVerifier {
    fn verify(
        &self,
        _chain: &Chain,
        _anchors: &TrustAnchors,
        hostname: Option<&str>,
        _now: Timestamp,
    ) -> ChainVerification {
        self.hostnames
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(hostname.map(str::to_owned));
        self.verification.clone()
    }
}

/// A [`TrustStoreProvider`] that returns a canned result whatever the sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeTrustProvider(pub Result<TrustAnchors, TrustError>);

impl TrustStoreProvider for FakeTrustProvider {
    fn anchors(&self, _sources: &[TrustSource]) -> Result<TrustAnchors, TrustError> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_fixed_clock_deve_devolver_o_mesmo_instante() {
        let t = Timestamp::from_unix(1_763_892_000).unwrap();
        let clock = FixedClock(t);
        assert_eq!(clock.now(), t);
        assert_eq!(clock.now(), t);
        let boxed: Box<dyn Clock> = Box::new(clock);
        assert_eq!(boxed.now(), t);
    }
}

/// A [`RevocationProtocol`] that returns canned results: one default per
/// operation, overridable per exact response/CRL bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRevocationProtocol {
    /// Result of `build_ocsp_request`.
    pub request: Result<OcspRequest, RevocationError>,
    /// Default result of `evaluate_ocsp`.
    pub ocsp: Result<RevocationStatus, RevocationError>,
    /// Default result of `evaluate_crl`.
    pub crl: Result<RevocationStatus, RevocationError>,
    ocsp_overrides: Vec<(Vec<u8>, Result<RevocationStatus, RevocationError>)>,
    crl_overrides: Vec<(Vec<u8>, Result<RevocationStatus, RevocationError>)>,
}

impl FakeRevocationProtocol {
    /// A fake with the given defaults and no overrides.
    #[must_use]
    pub fn new(
        request: Result<OcspRequest, RevocationError>,
        ocsp: Result<RevocationStatus, RevocationError>,
        crl: Result<RevocationStatus, RevocationError>,
    ) -> Self {
        Self {
            request,
            ocsp,
            crl,
            ocsp_overrides: Vec::new(),
            crl_overrides: Vec::new(),
        }
    }

    /// Answers `result` when `evaluate_ocsp` receives exactly `response`.
    #[must_use]
    pub fn ocsp_for(
        mut self,
        response: &[u8],
        result: Result<RevocationStatus, RevocationError>,
    ) -> Self {
        self.ocsp_overrides.push((response.to_vec(), result));
        self
    }

    /// Answers `result` when `evaluate_crl` receives exactly `crl`.
    #[must_use]
    pub fn crl_for(
        mut self,
        crl: &[u8],
        result: Result<RevocationStatus, RevocationError>,
    ) -> Self {
        self.crl_overrides.push((crl.to_vec(), result));
        self
    }
}

fn pick(
    overrides: &[(Vec<u8>, Result<RevocationStatus, RevocationError>)],
    data: &[u8],
    default: &Result<RevocationStatus, RevocationError>,
) -> Result<RevocationStatus, RevocationError> {
    overrides
        .iter()
        .find(|(bytes, _)| bytes == data)
        .map_or_else(|| default.clone(), |(_, result)| result.clone())
}

impl RevocationProtocol for FakeRevocationProtocol {
    fn build_ocsp_request(
        &self,
        _cert_der: &[u8],
        _issuer_der: &[u8],
    ) -> Result<OcspRequest, RevocationError> {
        self.request.clone()
    }

    fn evaluate_ocsp(
        &self,
        response: &[u8],
        _cert_der: &[u8],
        _issuer_der: &[u8],
        _now: Timestamp,
    ) -> Result<RevocationStatus, RevocationError> {
        pick(&self.ocsp_overrides, response, &self.ocsp)
    }

    fn evaluate_crl(
        &self,
        crl: &[u8],
        _cert_der: &[u8],
        _issuer_der: &[u8],
        _now: Timestamp,
    ) -> Result<RevocationStatus, RevocationError> {
        pick(&self.crl_overrides, crl, &self.crl)
    }
}

/// One request seen by a [`FakeHttpFetcher`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCall {
    /// `"GET"` or `"POST"`.
    pub method: &'static str,
    /// The URL asked for.
    pub url: String,
    /// The POST body (empty for GET).
    pub body: Vec<u8>,
    /// The byte ceiling the caller asked for.
    pub max_bytes: usize,
}

/// An [`HttpFetcher`] with scripted answers per `(method, url)`, a call log,
/// and an optional mode where every request hangs forever.
///
/// An unscripted request answers `Status(404)`.
#[derive(Debug, Default)]
pub struct FakeHttpFetcher {
    routes: Vec<(String, String, Result<Vec<u8>, HttpError>)>,
    calls: Mutex<Vec<HttpCall>>,
    hang: bool,
}

impl FakeHttpFetcher {
    /// A fetcher that answers `Status(404)` to everything.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fetcher whose requests never complete.
    #[must_use]
    pub fn hanging() -> Self {
        Self {
            hang: true,
            ..Self::default()
        }
    }

    /// Scripts the answer to `method` (`"GET"`/`"POST"`) on `url`.
    #[must_use]
    pub fn on(mut self, method: &str, url: &str, result: Result<Vec<u8>, HttpError>) -> Self {
        self.routes
            .push((method.to_owned(), url.to_owned(), result));
        self
    }

    /// Every request seen so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<HttpCall> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn serve(
        &self,
        method: &'static str,
        url: &str,
        body: Vec<u8>,
        max_bytes: usize,
    ) -> Result<Vec<u8>, HttpError> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(HttpCall {
                method,
                url: url.to_owned(),
                body,
                max_bytes,
            });
        if self.hang {
            std::future::pending::<()>().await;
        }
        self.routes
            .iter()
            .find(|(m, u, _)| m == method && u == url)
            .map_or(Err(HttpError::Status(404)), |(_, _, result)| result.clone())
    }
}

#[async_trait::async_trait]
impl HttpFetcher for FakeHttpFetcher {
    async fn get(
        &self,
        url: &str,
        max_bytes: usize,
        _timeout: std::time::Duration,
    ) -> Result<Vec<u8>, HttpError> {
        self.serve("GET", url, Vec::new(), max_bytes).await
    }

    async fn post(
        &self,
        url: &str,
        _content_type: &str,
        body: Vec<u8>,
        max_bytes: usize,
        _timeout: std::time::Duration,
    ) -> Result<Vec<u8>, HttpError> {
        self.serve("POST", url, body, max_bytes).await
    }
}
