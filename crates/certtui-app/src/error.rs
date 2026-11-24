//! Typed errors of the application layer.

use certtui_domain::model::LoadNote;
use thiserror::Error;

/// Error loading certificates from a local source (file, stdin, directory).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LoadError {
    /// The input is larger than the allowed byte limit.
    #[error("input is larger than the limit of {limit} bytes")]
    TooLarge {
        /// The configured maximum in bytes.
        limit: usize,
    },
    /// An I/O failure while reading the source.
    #[error("I/O error: {0}")]
    Io(String),
    /// No certificate could be extracted. `notes` holds every diagnostic
    /// collected on the way (never any content).
    #[error("no certificates found")]
    NoCertificatesFound {
        /// Diagnostics from the loader and from parsing.
        notes: Vec<LoadNote>,
    },
    /// The source kind or format is not supported.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// The source is structurally invalid.
    #[error("malformed input: {0}")]
    Malformed(String),
    /// More certificates than the applicable cap were parsed: for local
    /// sources `Limits::max_certs_per_source`. This is the application-level
    /// mapping of `ChainError::TooLong`.
    #[error("found {len} certificates, above the limit of {max}")]
    TooManyCerts {
        /// Number of certificates found.
        len: usize,
        /// The configured maximum.
        max: usize,
    },
}
