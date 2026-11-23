//! Application layer: use cases and ports built on the domain.

pub mod ports;

#[cfg(any(test, feature = "testing"))]
pub mod testing;
