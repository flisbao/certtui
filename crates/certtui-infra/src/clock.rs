//! Wall-clock implementation of the [`Clock`] port.

use std::time::{SystemTime, UNIX_EPOCH};

use certtui_app::ports::Clock;
use certtui_domain::time::Timestamp;

/// [`Clock`] backed by the operating system's wall clock.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
            // The system clock is set before 1970.
            Err(before) => {
                i64::try_from(before.duration().as_secs()).map_or(i64::MIN, i64::wrapping_neg)
            }
        };
        Timestamp::from_unix_saturating(secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_system_clock_deve_ser_posterior_a_2025() {
        // 2025-01-01T00:00:00Z
        let inicio_2025 = Timestamp::from_unix(1_735_689_600).unwrap();
        assert!(SystemClock.now() > inicio_2025);
    }
}
