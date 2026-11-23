//! A parsed certificate together with its raw DER, fingerprints and origin.

use std::path::PathBuf;
use std::sync::Arc;

use crate::error::ParseError;
use crate::limits::Limits;
use crate::model::{CertificateSummary, Fingerprints, parse_der_cert};

/// Where a certificate came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertOrigin {
    /// Sent by the server during the handshake.
    Presented {
        /// Position in the order the server sent it (0 = first).
        position: usize,
    },
    /// Fetched through an Authority Information Access URL.
    AiaFetched {
        /// The URL the certificate was fetched from.
        url: String,
    },
    /// Read from a file.
    File {
        /// Path of the file.
        path: PathBuf,
        /// Index of the certificate inside the file.
        index: usize,
    },
    /// Read from standard input.
    Stdin {
        /// Index of the certificate inside the input.
        index: usize,
    },
    /// Read from a keystore.
    Keystore {
        /// Path of the keystore file.
        path: PathBuf,
        /// Alias of the entry inside the keystore.
        alias: String,
    },
}

/// A certificate: raw DER, parsed summary, fingerprints and origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRecord {
    /// The full DER encoding (at most `Limits::max_cert_der_bytes`).
    pub der: Arc<[u8]>,
    /// Parsed, display-oriented view of the certificate.
    pub summary: CertificateSummary,
    /// Fingerprints computed once, over the complete DER.
    pub fingerprints: Fingerprints,
    /// Where the certificate came from.
    pub origin: CertOrigin,
}

impl CertificateRecord {
    /// Parses `der`, computes its fingerprints and copies it into a shared
    /// buffer.
    ///
    /// # Errors
    ///
    /// Any [`ParseError`] returned by [`parse_der_cert`] (too large,
    /// malformed, trailing data).
    pub fn from_der(
        der: &[u8],
        origin: CertOrigin,
        limits: &Limits,
    ) -> Result<CertificateRecord, ParseError> {
        let summary = parse_der_cert(der, limits)?;
        Ok(CertificateRecord {
            der: Arc::from(der),
            summary,
            fingerprints: Fingerprints::compute(der),
            origin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::model::{FingerprintAlgorithm, FingerprintFormat};

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    #[test]
    fn quando_record_from_der_deve_calcular_fingerprints_do_der_completo() {
        let der = std::fs::read(format!("{FIXTURES}/rsa2048-leaf.der")).unwrap();
        let record = CertificateRecord::from_der(
            &der,
            CertOrigin::Presented { position: 0 },
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(&*record.der, der.as_slice());
        assert_eq!(record.fingerprints, Fingerprints::compute(&der));
        assert_eq!(
            record.fingerprints.format(
                FingerprintAlgorithm::Sha256,
                FingerprintFormat::ColonHexUpper
            ),
            "DD:DB:9B:86:33:47:FC:84:96:10:30:C3:F4:C5:7C:66:CA:BF:92:1E:D4:B4:3A:15:CE:41:B7:9F:39:A6:63:BB"
        );
    }

    #[test]
    fn quando_der_invalido_deve_propagar_parse_error() {
        let r = CertificateRecord::from_der(
            &[0x30, 0x00],
            CertOrigin::Stdin { index: 0 },
            &Limits::default(),
        );
        assert!(matches!(r, Err(ParseError::Malformed(_))));
    }
}
