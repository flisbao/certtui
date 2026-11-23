//! Typed errors of the domain layer.

use thiserror::Error;

/// Error parsing a DER-encoded certificate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// The DER input exceeds `Limits::max_cert_der_bytes`; nothing was parsed.
    #[error("certificate DER is {len} bytes, above the limit of {max} bytes")]
    TooLarge {
        /// Size of the rejected input in bytes.
        len: usize,
        /// The configured maximum in bytes.
        max: usize,
    },
    /// The input is not a well-formed X.509 certificate (truncated, bad
    /// ASN.1, bad structure).
    #[error("malformed certificate: {0}")]
    Malformed(String),
    /// A valid certificate was followed by extra bytes.
    #[error("{extra} trailing byte(s) after the certificate")]
    TrailingData {
        /// Number of bytes after the end of the certificate.
        extra: usize,
    },
}
