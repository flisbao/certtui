//! Revocation checking: the protocol port and, in later modules, the service.

pub mod cache;
pub mod protocol;

pub use cache::{CacheKey, CachedItem, CachedPayload, RevocationCache};
pub use protocol::{OcspRequest, RevocationError, RevocationProtocol};
