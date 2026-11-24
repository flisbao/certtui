//! Infrastructure layer: adapters implementing the application ports.

pub mod clock;

/// Local filesystem and standard-input source adapters.
pub mod source;

/// TLS chain fetching: the `ChainFetcher` adapter and its building blocks.
pub mod tls;
