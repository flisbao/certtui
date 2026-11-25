//! Revocation checking: the protocol port and, in later modules, the service.

pub mod cache;
pub mod protocol;
pub mod service;

pub use cache::{CacheKey, CachedItem, CachedPayload, RevocationCache};
pub use certtui_domain::model::StapleState;
pub use protocol::{OcspRequest, RevocationError, RevocationProtocol};
pub use service::{
    REVOCATION_PARALLELISM, RevocationOutcome, RevocationScope, RevocationService, check_revocation,
};
