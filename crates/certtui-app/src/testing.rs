//! Test doubles for the application ports.

use certtui_domain::limits::Limits;
use certtui_domain::time::Timestamp;

use tokio_util::sync::CancellationToken;

use crate::error::LoadError;
use crate::fetch::{FetchError, FetchRequest, FetchedChain};
use std::sync::{Mutex, PoisonError};

use certtui_domain::model::Chain;

use crate::ports::{
    ChainFetcher, ChainVerification, ChainVerifier, Clock, LoadedCerts, LocalSource, SourceLoader,
    TrustStoreProvider,
};
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
