//! Test doubles for the application ports.

use certtui_domain::time::Timestamp;

use crate::ports::Clock;

/// A [`Clock`] that always returns the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock(pub Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_fixed_clock_deve_devolver_o_mesmo_instante() {
        let t = Timestamp::from_unix(1_763_892_000).unwrap();
        let clock = FixedClock(t);
        assert_eq!(clock.now(), t);
        assert_eq!(clock.now(), t);
        let boxed: Box<dyn Clock> = Box::new(clock);
        assert_eq!(boxed.now(), t);
    }
}
