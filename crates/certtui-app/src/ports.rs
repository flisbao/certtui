//! Ports: traits the application layer needs from the outside world.

use std::fmt;
use std::path::PathBuf;

use certtui_domain::limits::Limits;
use certtui_domain::model::{CertOrigin, LoadNote};
use certtui_domain::time::Timestamp;
use tokio_util::sync::CancellationToken;

use crate::error::LoadError;
use crate::fetch::{FetchError, FetchRequest, FetchedChain};

/// Source of the current time.
///
/// Injected everywhere "now" is needed (spec section 2, principle 5) so
/// that expiry logic stays deterministic under test.
pub trait Clock: Send + Sync {
    /// The current instant in UTC.
    fn now(&self) -> Timestamp;
}

/// Where local certificates are read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalSource {
    /// A single file.
    File(PathBuf),
    /// Standard input.
    Stdin,
    /// A directory of files.
    Directory {
        /// Directory to scan.
        path: PathBuf,
        /// Whether to descend into subdirectories.
        recursive: bool,
    },
}

/// A DER blob extracted from a source, not yet parsed as X.509.
///
/// `Debug` prints the length and origin, but not the bytes: the bytes may
/// belong to anything a loader mistook for a certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct RawCert {
    /// The DER bytes.
    pub der: Vec<u8>,
    /// Where it came from.
    pub origin: CertOrigin,
}

impl fmt::Debug for RawCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawCert")
            .field("der_len", &self.der.len())
            .field("origin", &self.origin)
            .finish()
    }
}

/// What a [`SourceLoader`] found in a source.
#[derive(Clone, PartialEq, Eq)]
pub struct LoadedCerts {
    /// Candidate certificates, in source order.
    pub certs: Vec<RawCert>,
    /// Diagnostics from reading and extraction.
    pub notes: Vec<LoadNote>,
}

impl fmt::Debug for LoadedCerts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedCerts")
            .field("certs", &self.certs)
            .field("notes", &self.notes)
            .finish()
    }
}

/// Reads certificates from files, stdin or directories.
pub trait SourceLoader: Send + Sync {
    /// Loads the candidate certificates of `src`, reading at most the bytes
    /// allowed by `limits`.
    ///
    /// # Errors
    ///
    /// [`LoadError`] when the source cannot be read or is unsupported.
    fn load(&self, src: &LocalSource, limits: &Limits) -> Result<LoadedCerts, LoadError>;
}

/// Fetches the certificate chain a network target presents.
///
/// Object safe: the application layer holds it as `dyn ChainFetcher`.
#[async_trait::async_trait]
pub trait ChainFetcher: Send + Sync {
    /// Connects to `req.target` within `req.limits` and returns what the
    /// peer presented. A rejection alert following a client certificate
    /// request may return the already presented chain with a diagnostic and
    /// absent session parameters. Implementations stop promptly once `cancel` fires.
    ///
    /// # Errors
    ///
    /// [`FetchError`] when resolution, connection or the handshake fails,
    /// a budget is exceeded, or the fetch is cancelled.
    async fn fetch(
        &self,
        req: &FetchRequest,
        cancel: CancellationToken,
    ) -> Result<FetchedChain, FetchError>;
}
