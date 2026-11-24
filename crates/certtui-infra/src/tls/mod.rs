//! TLS fetch: the `ChainFetcher` adapter and its building blocks.

// `CapturingVerifier` and `Resolver` are public only because the integration
// tests (a separate crate) drive them; they are not part of the supported API.
#[doc(hidden)]
pub mod capturing_verifier;
mod connect;
pub mod fetcher;
pub mod limited_stream;
mod session;

#[doc(hidden)]
pub use capturing_verifier::{CapturedHandshake, CapturingVerifier};
#[doc(hidden)]
pub use connect::{Resolver, SystemResolver};
pub use fetcher::RustlsChainFetcher;
pub use limited_stream::{ByteBudgetExceeded, LimitedStream};
