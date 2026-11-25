//! Typed errors of the application layer.

use certtui_domain::model::LoadNote;
use thiserror::Error;

use crate::fetch::FetchError;
use crate::keystore::KeystoreError;

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
    /// The keystore is encrypted and no password was given.
    #[error("keystore requires a password")]
    PasswordRequired,
    /// A keystore could not be read (wrong password, corrupt, unsupported).
    #[error("{0}")]
    Keystore(KeystoreError),
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

/// Error inspecting a network target.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InspectError {
    /// The chain could not be fetched (or the peer presented none).
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// The peer presented certificates, but none of them parses. `notes`
    /// holds one diagnostic per failure (never any content).
    #[error("none of the presented certificates could be parsed")]
    NoUsableCertificates {
        /// Diagnostics collected while parsing.
        notes: Vec<LoadNote>,
    },
    /// The peer presented more certificates than `Limits::max_chain_len`.
    #[error("the peer presented {len} certificates, above the limit of {max}")]
    ChainTooLong {
        /// Number of certificates presented.
        len: usize,
        /// The configured maximum.
        max: usize,
    },
}
