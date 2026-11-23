//! The single time type of the application (spec D12): [`Timestamp`].
//!
//! [`Timestamp`] wraps the `time` crate's UTC date-time without exposing it,
//! so the rest of the codebase depends on one small, panic-free API.

use std::fmt;

use serde::{Serialize, Serializer};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Seconds in one day.
const SECONDS_PER_DAY: i64 = 86_400;
/// Unix seconds of `0000-01-01T00:00:00Z`, the earliest RFC 3339 instant.
const MIN_UNIX: i64 = -62_167_219_200;
/// Unix seconds of `9999-12-31T23:59:59Z`, the latest RFC 3339 instant.
const MAX_UNIX: i64 = 253_402_300_799;

/// Error building a [`Timestamp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TimestampError {
    /// The Unix timestamp lies outside years 0000 to 9999 (the RFC 3339
    /// range).
    #[error("unix timestamp {0} is outside the supported range (years 0000-9999)")]
    OutOfRange(i64),
}

/// An instant in UTC with one-second precision.
///
/// The supported range is `0000-01-01T00:00:00Z` to
/// `9999-12-31T23:59:59Z`, so every value formats as a valid RFC 3339
/// string. Ordering is chronological.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

/// Converts Unix seconds known to be within `MIN_UNIX..=MAX_UNIX`; the
/// epoch is an unreachable fallback so no panic path exists.
const fn convert(secs: i64) -> OffsetDateTime {
    match OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => dt,
        Err(_) => OffsetDateTime::UNIX_EPOCH,
    }
}

impl Timestamp {
    /// The earliest representable instant, `0000-01-01T00:00:00Z`.
    pub const MIN: Self = Self(convert(MIN_UNIX));

    /// The latest representable instant, `9999-12-31T23:59:59Z`.
    pub const MAX: Self = Self(convert(MAX_UNIX));

    /// Builds a timestamp from seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::OutOfRange`] when `secs` is outside years
    /// 0000 to 9999.
    pub fn from_unix(secs: i64) -> Result<Self, TimestampError> {
        if !(MIN_UNIX..=MAX_UNIX).contains(&secs) {
            return Err(TimestampError::OutOfRange(secs));
        }
        OffsetDateTime::from_unix_timestamp(secs)
            .map(Self)
            .map_err(|_| TimestampError::OutOfRange(secs))
    }

    /// Like [`Timestamp::from_unix`] but clamps out-of-range values to
    /// [`Timestamp::MIN`] or [`Timestamp::MAX`] instead of failing.
    #[must_use]
    pub fn from_unix_saturating(secs: i64) -> Self {
        Self::from_unix(secs.clamp(MIN_UNIX, MAX_UNIX)).unwrap_or(Self::MAX)
    }

    /// Seconds since the Unix epoch (negative before 1970).
    #[must_use]
    pub fn unix(self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Whole days from `self` until `later`, rounded toward negative
    /// infinity (floor division).
    ///
    /// A `later` less than a day ahead yields `0`; a `later` already in the
    /// past yields a negative number (at least `-1`).
    #[must_use]
    pub fn days_until(self, later: Self) -> i64 {
        // Both values lie within +/-2.6e11 seconds, so the difference
        // cannot overflow `i64`.
        later
            .unix()
            .saturating_sub(self.unix())
            .div_euclid(SECONDS_PER_DAY)
    }
}

impl fmt::Display for Timestamp {
    /// Formats as RFC 3339 in UTC, e.g. `2026-11-23T10:00:00Z`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.0.format(&Rfc3339).map_err(|_| fmt::Error)?;
        f.write_str(&text)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_unix_zero_deve_formatar_epoch() {
        let ts = Timestamp::from_unix(0).unwrap();
        assert_eq!(ts.to_string(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn quando_data_futura_deve_contar_dias_com_piso() {
        let base = Timestamp::from_unix(1_000_000).unwrap();
        let quase_um_dia = Timestamp::from_unix(1_000_000 + 24 * 3600 - 60).unwrap();
        let um_dia = Timestamp::from_unix(1_000_000 + 24 * 3600).unwrap();
        assert_eq!(base.days_until(quase_um_dia), 0);
        assert_eq!(base.days_until(um_dia), 1);
    }

    #[test]
    fn quando_data_passada_deve_dar_dias_negativos() {
        let base = Timestamp::from_unix(1_000_000).unwrap();
        let um_segundo_antes = Timestamp::from_unix(1_000_000 - 1).unwrap();
        let um_dia_antes = Timestamp::from_unix(1_000_000 - 24 * 3600).unwrap();
        // Floor division: any elapsed time yields at least -1.
        assert_eq!(base.days_until(um_segundo_antes), -1);
        assert_eq!(base.days_until(um_dia_antes), -1);
    }

    #[test]
    fn quando_unix_fora_do_intervalo_deve_dar_erro() {
        assert_eq!(
            Timestamp::from_unix(i64::MAX),
            Err(TimestampError::OutOfRange(i64::MAX))
        );
        assert!(Timestamp::from_unix(i64::MIN).is_err());
    }

    #[test]
    fn quando_ano_9999_deve_formatar_sem_panic() {
        let ts = Timestamp::from_unix(253_402_300_799).unwrap();
        assert_eq!(ts.to_string(), "9999-12-31T23:59:59Z");
        assert_eq!(ts.unix(), 253_402_300_799);
        assert!(Timestamp::from_unix(253_402_300_800).is_err());
    }

    #[test]
    fn quando_data_anterior_a_1970_deve_formatar_e_ida_e_volta() {
        let ts = Timestamp::from_unix(-86_400).unwrap();
        assert_eq!(ts.to_string(), "1969-12-31T00:00:00Z");
        assert_eq!(ts.unix(), -86_400);
    }

    #[test]
    fn quando_extremos_deve_calcular_dias_sem_overflow() {
        assert_eq!(Timestamp::MIN.days_until(Timestamp::MAX), 3_652_424);
        assert_eq!(Timestamp::MAX.days_until(Timestamp::MIN), -3_652_425);
    }

    #[test]
    fn quando_saturar_deve_prender_nos_limites() {
        assert_eq!(Timestamp::from_unix_saturating(i64::MAX), Timestamp::MAX);
        assert_eq!(Timestamp::from_unix_saturating(i64::MIN), Timestamp::MIN);
        assert_eq!(Timestamp::from_unix_saturating(5).unix(), 5);
        assert_eq!(Timestamp::MIN.to_string(), "0000-01-01T00:00:00Z");
    }

    #[test]
    fn quando_ordenar_deve_seguir_a_ordem_cronologica() {
        let a = Timestamp::from_unix(1).unwrap();
        let b = Timestamp::from_unix(2).unwrap();
        assert!(a < b);
        assert_eq!(a.max(b), b);
    }

    #[test]
    fn quando_serializar_deve_virar_string_rfc3339() {
        let ts = Timestamp::from_unix(0).unwrap();
        assert_eq!(
            serde_json::to_string(&ts).unwrap(),
            "\"1970-01-01T00:00:00Z\""
        );
    }
}
