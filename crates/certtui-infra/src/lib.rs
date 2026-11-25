//! Infrastructure layer: adapters implementing the application ports.

pub mod clock;

/// Which destinations a certificate-supplied URL may reach (SSRF guard).
pub mod destination;

/// Capped HTTP(S) fetching for OCSP, CRL and AIA: the `HttpFetcher` adapter.
pub mod http;

/// OCSP and CRL wire formats: the `RevocationProtocol` adapter.
pub mod revocation;

/// PKCS#12 and JKS keystore readers (certificates only).
pub mod keystore;

/// Local filesystem and standard-input source adapters.
pub mod source;

/// TLS chain fetching: the `ChainFetcher` adapter and its building blocks.
pub mod tls;

/// Trust anchor loading: system, Mozilla and custom CA files.
pub mod trust;

/// Chain verification against trust anchors (`rustls-webpki`).
pub mod chain_verifier;
