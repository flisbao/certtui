//! Observes a peer's client certificate request on a single handshake.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::sign::CertifiedKey;

#[derive(Debug, Default)]
pub(super) struct ClientCertRequest {
    observed: AtomicBool,
}

impl ClientCertRequest {
    pub(super) fn observed(&self) -> bool {
        self.observed.load(Ordering::Relaxed)
    }
}

impl ResolvesClientCert for ClientCertRequest {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.observed.store(true, Ordering::Relaxed);
        None
    }

    fn has_certs(&self) -> bool {
        false
    }
}
