//! The `RevocationProtocol` port: encoding and judging OCSP and CRL data.
//!
//! The application layer decides *where* to ask (staple, OCSP, CRL, cache);
//! this port knows the wire formats. Implementations must treat every byte as
//! hostile, never panic, and never report `Good` for anything they could not
//! fully verify.

use certtui_domain::model::RevocationStatus;
use certtui_domain::time::Timestamp;
use thiserror::Error;

/// An encoded OCSP request plus what the caller needs to send and cache it.
#[derive(Clone, PartialEq, Eq)]
pub struct OcspRequest {
    /// DER of the `OCSPRequest`, for a POST body.
    pub body: Vec<u8>,
    /// Base64url (padding kept, as RFC 6960 appendix A allows) of the request,
    /// to be appended to the responder URL for a GET.
    pub get_url_suffix: String,
    /// `(issuer_key_hash, serial)`: the identity of the question, used as the
    /// cache key.
    pub cache_key: (Vec<u8>, Vec<u8>),
}

impl std::fmt::Debug for OcspRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcspRequest")
            .field("body_len", &self.body.len())
            .field("get_url_suffix_len", &self.get_url_suffix.len())
            .finish_non_exhaustive()
    }
}

/// Why OCSP or CRL data could not be turned into a verdict.
///
/// Messages are short English sentences with no secrets and no raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RevocationError {
    /// The data could not be parsed.
    #[error("malformed data: {0}")]
    Malformed(String),
    /// The signature does not verify.
    #[error("signature does not verify")]
    BadSignature,
    /// `thisUpdate` is in the future (beyond the allowed clock skew).
    #[error("data is not valid yet")]
    NotYetValid,
    /// `nextUpdate` has passed (beyond the allowed clock skew).
    #[error("data is stale")]
    Stale,
    /// The response answers a different certificate than the one asked about.
    #[error("response is for a different certificate")]
    CertIdMismatch,
    /// The signer is neither the issuer nor an authorized delegated responder.
    #[error("responder is not authorized to sign for this issuer")]
    ResponderNotAuthorized,
    /// The responder refused to answer (`tryLater`, `unauthorized`, ...).
    #[error("responder did not answer successfully: {0}")]
    Unsuccessful(String),
    /// The data is larger than the allowed size.
    #[error("data is too large")]
    TooLarge,
}

/// Builds OCSP requests and judges OCSP responses and CRLs.
///
/// Object safe. Pure and synchronous: no I/O, time comes in as `now`.
pub trait RevocationProtocol: Send + Sync {
    /// Builds the OCSP request for `cert_der`, issued by `issuer_der`.
    ///
    /// # Errors
    ///
    /// [`RevocationError::Malformed`] when either certificate cannot be parsed.
    fn build_ocsp_request(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<OcspRequest, RevocationError>;

    /// Judges a DER `OCSPResponse` about `cert_der` as of `now`: status
    /// successful, `CertID` matching, signature valid (issuer or authorized
    /// delegated responder) and fresh.
    ///
    /// # Errors
    ///
    /// A [`RevocationError`] for anything that stops the response from being
    /// trusted; never `Ok(Good)` for an unverified response.
    fn evaluate_ocsp(
        &self,
        response: &[u8],
        cert_der: &[u8],
        issuer_der: &[u8],
        now: Timestamp,
    ) -> Result<RevocationStatus, RevocationError>;

    /// Judges a DER CRL about `cert_der` as of `now`: signature by the issuer,
    /// freshness, scope, then the serial lookup. A CRL that is unusable for
    /// this certificate (no `nextUpdate`, delta, other scope) is
    /// `Ok(Unknown { why })`, never `Good`.
    ///
    /// # Errors
    ///
    /// A [`RevocationError`] when the CRL cannot be trusted at all.
    fn evaluate_crl(
        &self,
        crl: &[u8],
        cert_der: &[u8],
        issuer_der: &[u8],
        now: Timestamp,
    ) -> Result<RevocationStatus, RevocationError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeRevocationProtocol;

    fn now() -> Timestamp {
        Timestamp::from_unix_saturating(1_793_577_600)
    }

    #[test]
    fn quando_fake_e_usado_como_dyn_deve_devolver_os_resultados_prontos() {
        let fake = FakeRevocationProtocol {
            request: Ok(OcspRequest {
                body: vec![1],
                get_url_suffix: "AQ==".to_owned(),
                cache_key: (vec![2], vec![3]),
            }),
            ocsp: Ok(RevocationStatus::Good),
            crl: Err(RevocationError::Stale),
        };
        let proto: &dyn RevocationProtocol = &fake;

        let req = proto.build_ocsp_request(b"c", b"i").unwrap();
        assert_eq!(req.cache_key, (vec![2], vec![3]));
        assert_eq!(
            proto.evaluate_ocsp(b"r", b"c", b"i", now()),
            Ok(RevocationStatus::Good)
        );
        assert_eq!(
            proto.evaluate_crl(b"r", b"c", b"i", now()),
            Err(RevocationError::Stale)
        );
    }

    #[test]
    fn quando_debug_do_pedido_deve_nao_vazar_o_corpo() {
        let req = OcspRequest {
            body: vec![0xDE, 0xAD],
            get_url_suffix: "3q0=".to_owned(),
            cache_key: (vec![], vec![]),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("body_len: 2"), "{dbg}");
        assert!(!dbg.contains("222"), "{dbg}");
    }
}
