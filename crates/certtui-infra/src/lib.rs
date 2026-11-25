//! Infrastructure layer: adapters implementing the application ports.

pub mod clock;

/// Capped HTTP(S) fetching for OCSP, CRL and AIA: the `HttpFetcher` adapter.
pub mod http;

/// Local filesystem and standard-input source adapters.
pub mod source;

/// TLS chain fetching: the `ChainFetcher` adapter and its building blocks.
pub mod tls;

/// Trust anchor loading: system, Mozilla and custom CA files.
pub mod trust;

/// Chain verification against trust anchors (`rustls-webpki`).
pub mod chain_verifier;
