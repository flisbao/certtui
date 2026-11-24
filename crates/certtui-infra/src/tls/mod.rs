//! TLS fetch building blocks.

pub mod capturing_verifier;
pub mod limited_stream;

pub use capturing_verifier::{CapturedHandshake, CapturingVerifier};
pub use limited_stream::{ByteBudgetExceeded, LimitedStream};
