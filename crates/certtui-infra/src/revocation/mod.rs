//! OCSP and CRL wire formats: the [`RevocationProtocol`] adapter.
//!
//! Pure and synchronous: bytes in, verdicts out. Every input is hostile, so
//! each failure is a typed [`RevocationError`], never a panic and never `Good`.

mod ocsp;

use certtui_app::revocation::{OcspRequest, RevocationError, RevocationProtocol};
use certtui_domain::model::RevocationStatus;
use certtui_domain::time::Timestamp;
use x509_parser::certificate::X509Certificate;

/// `RevocationProtocol` backed by `x509-ocsp` (formats), `x509-parser`
/// (certificates, signature verification) and `sha1`/`sha2` (`CertID`).
#[derive(Debug, Clone, Copy, Default)]
pub struct X509RevocationProtocol;

impl RevocationProtocol for X509RevocationProtocol {
    fn build_ocsp_request(
        &self,
        cert_der: &[u8],
        issuer_der: &[u8],
    ) -> Result<OcspRequest, RevocationError> {
        ocsp::build_request(cert_der, issuer_der)
    }

    fn evaluate_ocsp(
        &self,
        response: &[u8],
        cert_der: &[u8],
        issuer_der: &[u8],
        now: Timestamp,
    ) -> Result<RevocationStatus, RevocationError> {
        ocsp::evaluate(response, cert_der, issuer_der, now)
    }

    fn evaluate_crl(
        &self,
        _crl: &[u8],
        _cert_der: &[u8],
        _issuer_der: &[u8],
        _now: Timestamp,
    ) -> Result<RevocationStatus, RevocationError> {
        Err(RevocationError::Malformed(
            "CRL evaluation is not available yet".to_owned(),
        ))
    }
}

/// Parses one DER certificate; trailing bytes are ignored.
fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, RevocationError> {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, cert)| cert)
        .map_err(|_| RevocationError::Malformed("certificate does not parse".to_owned()))
}
