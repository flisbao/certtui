//! Test doubles for the application ports.

use certtui_domain::limits::Limits;
use certtui_domain::time::Timestamp;

use crate::error::LoadError;
use crate::ports::{Clock, LoadedCerts, LocalSource, SourceLoader};

/// A [`Clock`] that always returns the same instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedClock(pub Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

/// A [`SourceLoader`] that returns a canned result whatever the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeSourceLoader(pub Result<LoadedCerts, LoadError>);

impl SourceLoader for FakeSourceLoader {
    fn load(&self, _src: &LocalSource, _limits: &Limits) -> Result<LoadedCerts, LoadError> {
        self.0.clone()
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
