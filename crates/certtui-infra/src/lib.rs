//! Infrastructure layer: adapters implementing the application ports.

pub mod clock;

/// Local filesystem and standard-input source adapters.
pub mod source;

/// TLS fetch building blocks: byte-budgeted stream wrapper.
pub mod tls;
