//! Ports: traits the application layer needs from the outside world.

use certtui_domain::time::Timestamp;

/// Source of the current time.
///
/// Injected everywhere "now" is needed (spec section 2, principle 5) so
/// that expiry logic stays deterministic under test.
pub trait Clock: Send + Sync {
    /// The current instant in UTC.
    fn now(&self) -> Timestamp;
}
