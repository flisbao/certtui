//! Revocation checking: the protocol port and, in later modules, the service.

pub mod protocol;

pub use protocol::{OcspRequest, RevocationError, RevocationProtocol};
