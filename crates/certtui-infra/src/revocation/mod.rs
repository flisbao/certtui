//! OCSP and CRL wire formats: the [`RevocationProtocol`] adapter.
//!
//! Pure and synchronous: bytes in, verdicts out. Every input is hostile, so
//! each failure is a typed [`RevocationError`], never a panic and never `Good`.

mod crl;
mod ocsp;

/// How far a response's or CRL's clock may differ from ours (5 minutes), in seconds.
const CLOCK_SKEW_SECS: i64 = 5 * 60;

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
        crl: &[u8],
        cert_der: &[u8],
        issuer_der: &[u8],
        now: Timestamp,
    ) -> Result<RevocationStatus, RevocationError> {
        crl::evaluate(crl, cert_der, issuer_der, now)
    }
}

/// Checks that `cert` names `issuer` and is signed by its key, so a verdict
/// about the issuer's serial space is never applied to a stranger's certificate.
fn ensure_issued_by(
    cert: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> Result<(), RevocationError> {
    if cert.issuer().as_raw() != issuer.subject().as_raw()
        || cert.verify_signature(Some(issuer.public_key())).is_err()
    {
        return Err(RevocationError::IssuerMismatch);
    }
    Ok(())
}

/// Parses one DER certificate; trailing bytes are ignored.
fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, RevocationError> {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, cert)| cert)
        .map_err(|_| RevocationError::Malformed("certificate does not parse".to_owned()))
}

/// The minimal two's-complement form of a DER INTEGER body.
///
/// Serials reach us from two parsers that may differ in padding, so they are
/// reduced to one form before comparing. Only *redundant* sign bytes go: a
/// `00` before a byte below `0x80`, an `FF` before a byte at or above it. A
/// needed `00` stays, so the positive `00 80` (128) never equals the negative
/// `80` (-128).
fn canonical_integer(bytes: &[u8]) -> &[u8] {
    let mut rest = bytes;
    while let [first, second, ..] = rest {
        let redundant =
            (*first == 0x00 && second & 0x80 == 0) || (*first == 0xFF && second & 0x80 != 0);
        if !redundant {
            break;
        }
        rest = rest.get(1..).unwrap_or_default();
    }
    rest
}

#[cfg(test)]
mod tests {
    use super::canonical_integer;

    #[test]
    fn quando_serial_tem_padding_redundante_deve_reduzir_a_forma_minima() {
        assert_eq!(canonical_integer(&[0x00, 0x00, 0x01]), &[0x01]);
        assert_eq!(canonical_integer(&[0xFF, 0xFF, 0x80]), &[0x80]);
        assert_eq!(canonical_integer(&[0xFF, 0x7F]), &[0xFF, 0x7F]);
        assert_eq!(canonical_integer(&[0xFF, 0x80]), &[0x80]);
        assert_eq!(canonical_integer(&[0x00]), &[0x00]);
        assert_eq!(canonical_integer(&[]), &[] as &[u8]);
    }

    #[test]
    fn quando_serial_positivo_e_negativo_tem_os_mesmos_bytes_de_magnitude_deve_diferir() {
        // +128 is `00 80`; -128 is `80`.
        assert_ne!(canonical_integer(&[0x00, 0x80]), canonical_integer(&[0x80]));
        assert_eq!(canonical_integer(&[0x00, 0x80]), &[0x00, 0x80]);
        assert_eq!(canonical_integer(&[0x00, 0x00, 0x80]), &[0x00, 0x80]);
    }
}
