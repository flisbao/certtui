//! Resource budget (spec section 9): default limits, hard caps and
//! config-driven overrides.
//!
//! Every limit lives in [`Limits`]. A configuration may lower or raise a
//! limit up to its hard cap; anything above the cap is truncated and reported
//! through a [`LimitWarning`]. A zero override is always rejected.

use std::time::Duration;

use serde::Deserialize;

/// One kibibyte (1024 bytes).
const KIB: usize = 1024;
/// One mebibyte (1024 KiB).
const MIB: usize = 1024 * KIB;

/// Resource limits enforced across the whole application.
///
/// Sizes and counts are `usize`; timeouts are [`Duration`]. [`Default`]
/// yields the "default" column of spec section 9 and [`Limits::HARD_CAPS`]
/// the "hard cap" column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size in bytes of a single DER certificate.
    pub max_cert_der_bytes: usize,
    /// Maximum chain length (presented certificates plus AIA-fetched ones).
    pub max_chain_len: usize,
    /// Maximum size in bytes of an input file (cert, PEM or P7B).
    pub max_input_file_bytes: usize,
    /// Maximum size in bytes of a keystore file.
    pub max_keystore_bytes: usize,
    /// Maximum number of certificates read from a single source.
    pub max_certs_per_source: usize,
    /// Maximum number of bytes read from standard input.
    pub max_stdin_bytes: usize,
    /// Maximum number of entries visited in a directory scan.
    pub max_dir_entries: usize,
    /// Maximum directory depth in a directory scan.
    pub max_dir_depth: usize,
    /// Maximum number of certificates in a CA bundle file.
    pub max_ca_file_certs: usize,
    /// Maximum number of diagnostics kept from a scan.
    pub max_scan_diagnostics: usize,
    /// Timeout for DNS resolution.
    pub dns_timeout: Duration,
    /// Timeout for establishing the TCP connection.
    pub connect_timeout: Duration,
    /// Timeout for the TLS handshake.
    pub handshake_timeout: Duration,
    /// Overall timeout for a single target.
    pub target_total_timeout: Duration,
    /// Maximum number of bytes accepted during a TLS handshake.
    pub max_handshake_bytes: usize,
    /// Timeout for HTTP requests (OCSP, CRL, AIA).
    pub http_timeout: Duration,
    /// Maximum size in bytes of an OCSP response.
    pub max_ocsp_response_bytes: usize,
    /// Maximum size in bytes of a CRL.
    pub max_crl_bytes: usize,
    /// Maximum size in bytes of a certificate fetched through AIA.
    pub max_aia_cert_bytes: usize,
    /// Maximum number of HTTP redirects followed.
    pub max_http_redirects: usize,
    /// Maximum size in bytes of the revocation cache.
    pub max_revocation_cache_bytes: usize,
    /// Maximum number of targets processed concurrently in a batch.
    pub batch_concurrency: usize,
    /// Maximum number of targets in a batch.
    pub max_batch_targets: usize,
    /// Capacity of bounded `mpsc` channels.
    pub channel_capacity: usize,
    /// Maximum number of history entries kept.
    pub history_entries: usize,
    /// Maximum clipboard text size in bytes (before Base64).
    pub max_clipboard_bytes: usize,
    /// Timeout for the native clipboard.
    pub clipboard_timeout: Duration,
}

impl Limits {
    /// Default values (spec section 9, "default" column).
    const DEFAULTS: Limits = Limits {
        max_cert_der_bytes: 64 * KIB,
        max_chain_len: 10,
        max_input_file_bytes: 4 * MIB,
        max_keystore_bytes: 4 * MIB,
        max_certs_per_source: 500,
        max_stdin_bytes: 4 * MIB,
        max_dir_entries: 1_000,
        max_dir_depth: 3,
        max_ca_file_certs: 1_000,
        max_scan_diagnostics: 100,
        dns_timeout: Duration::from_secs(3),
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(10),
        target_total_timeout: Duration::from_secs(20),
        max_handshake_bytes: 256 * KIB,
        http_timeout: Duration::from_secs(5),
        max_ocsp_response_bytes: 64 * KIB,
        max_crl_bytes: 8 * MIB,
        max_aia_cert_bytes: 64 * KIB,
        max_http_redirects: 3,
        max_revocation_cache_bytes: 32 * MIB,
        batch_concurrency: 32,
        max_batch_targets: 10_000,
        channel_capacity: 256,
        history_entries: 200,
        max_clipboard_bytes: 256 * KIB,
        clipboard_timeout: Duration::from_secs(2),
    };

    /// Hard caps (spec section 9, "hard cap" column); overrides above these
    /// are truncated. `channel_capacity` has no cap in the spec, so its cap
    /// equals its default (256).
    pub const HARD_CAPS: Limits = Limits {
        max_cert_der_bytes: 256 * KIB,
        max_chain_len: 16,
        max_input_file_bytes: 16 * MIB,
        max_keystore_bytes: 16 * MIB,
        max_certs_per_source: 2_000,
        max_stdin_bytes: 16 * MIB,
        max_dir_entries: 10_000,
        max_dir_depth: 3,
        max_ca_file_certs: 5_000,
        max_scan_diagnostics: 1_000,
        dns_timeout: Duration::from_secs(30),
        connect_timeout: Duration::from_secs(30),
        handshake_timeout: Duration::from_secs(60),
        target_total_timeout: Duration::from_secs(120),
        max_handshake_bytes: MIB,
        http_timeout: Duration::from_secs(30),
        max_ocsp_response_bytes: 256 * KIB,
        max_crl_bytes: 32 * MIB,
        max_aia_cert_bytes: 256 * KIB,
        max_http_redirects: 5,
        max_revocation_cache_bytes: 128 * MIB,
        batch_concurrency: 256,
        max_batch_targets: 100_000,
        channel_capacity: 256,
        history_entries: 1_000,
        max_clipboard_bytes: MIB,
        clipboard_timeout: Duration::from_secs(10),
    };

    /// Applies configuration overrides on top of `self`.
    ///
    /// Each present override is checked against [`Limits::HARD_CAPS`]: values
    /// above the cap are truncated to it and reported as a [`LimitWarning`].
    ///
    /// # Errors
    ///
    /// Returns [`LimitsError::ZeroNotAllowed`] if any override is `0`.
    pub fn with_overrides(
        self,
        o: &LimitsOverrides,
    ) -> Result<(Limits, Vec<LimitWarning>), LimitsError> {
        let caps = Self::HARD_CAPS;
        let mut out = self;
        let mut w = Vec::new();
        // Exhaustive destructuring (no `..`): adding a field to
        // `LimitsOverrides` without wiring it here fails to compile.
        let LimitsOverrides {
            max_cert_der_bytes,
            max_chain_len,
            max_input_file_bytes,
            max_keystore_bytes,
            max_certs_per_source,
            max_stdin_bytes,
            max_dir_entries,
            max_dir_depth,
            max_ca_file_certs,
            max_scan_diagnostics,
            dns_timeout_secs,
            connect_timeout_secs,
            handshake_timeout_secs,
            target_total_timeout_secs,
            max_handshake_bytes,
            http_timeout_secs,
            max_ocsp_response_bytes,
            max_crl_bytes,
            max_aia_cert_bytes,
            max_http_redirects,
            max_revocation_cache_bytes,
            batch_concurrency,
            max_batch_targets,
            channel_capacity,
            history_entries,
            max_clipboard_bytes,
            clipboard_timeout_secs,
        } = *o;

        // Counts/sizes: the override field has the same name as the limit.
        macro_rules! counts {
            ($($f:ident),* $(,)?) => {$(
                apply_count(
                    stringify!($f),
                    $f,
                    caps.$f,
                    &mut out.$f,
                    &mut w,
                )?;
            )*};
        }
        // Timeouts: the override field carries a `_secs` suffix.
        macro_rules! secs {
            ($($f:ident => $o:ident),* $(,)?) => {$(
                apply_secs(
                    stringify!($o),
                    $o,
                    caps.$f,
                    &mut out.$f,
                    &mut w,
                )?;
            )*};
        }

        counts!(
            max_cert_der_bytes,
            max_chain_len,
            max_input_file_bytes,
            max_keystore_bytes,
            max_certs_per_source,
            max_stdin_bytes,
            max_dir_entries,
            max_dir_depth,
            max_ca_file_certs,
            max_scan_diagnostics,
            max_handshake_bytes,
            max_ocsp_response_bytes,
            max_crl_bytes,
            max_aia_cert_bytes,
            max_http_redirects,
            max_revocation_cache_bytes,
            batch_concurrency,
            max_batch_targets,
            channel_capacity,
            history_entries,
            max_clipboard_bytes,
        );
        secs!(
            dns_timeout => dns_timeout_secs,
            connect_timeout => connect_timeout_secs,
            handshake_timeout => handshake_timeout_secs,
            target_total_timeout => target_total_timeout_secs,
            http_timeout => http_timeout_secs,
            clipboard_timeout => clipboard_timeout_secs,
        );

        Ok((out, w))
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULTS
    }
}

/// Optional overrides for [`Limits`], typically deserialized from the
/// configuration file.
///
/// Field names match [`Limits`]; timeouts carry a `_secs` suffix and are
/// expressed in whole seconds. Unknown fields are rejected on deserialization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsOverrides {
    /// Override for [`Limits::max_cert_der_bytes`].
    pub max_cert_der_bytes: Option<u64>,
    /// Override for [`Limits::max_chain_len`].
    pub max_chain_len: Option<u64>,
    /// Override for [`Limits::max_input_file_bytes`].
    pub max_input_file_bytes: Option<u64>,
    /// Override for [`Limits::max_keystore_bytes`].
    pub max_keystore_bytes: Option<u64>,
    /// Override for [`Limits::max_certs_per_source`].
    pub max_certs_per_source: Option<u64>,
    /// Override for [`Limits::max_stdin_bytes`].
    pub max_stdin_bytes: Option<u64>,
    /// Override for [`Limits::max_dir_entries`].
    pub max_dir_entries: Option<u64>,
    /// Override for [`Limits::max_dir_depth`].
    pub max_dir_depth: Option<u64>,
    /// Override for [`Limits::max_ca_file_certs`].
    pub max_ca_file_certs: Option<u64>,
    /// Override for [`Limits::max_scan_diagnostics`].
    pub max_scan_diagnostics: Option<u64>,
    /// Override for [`Limits::dns_timeout`], in seconds.
    pub dns_timeout_secs: Option<u64>,
    /// Override for [`Limits::connect_timeout`], in seconds.
    pub connect_timeout_secs: Option<u64>,
    /// Override for [`Limits::handshake_timeout`], in seconds.
    pub handshake_timeout_secs: Option<u64>,
    /// Override for [`Limits::target_total_timeout`], in seconds.
    pub target_total_timeout_secs: Option<u64>,
    /// Override for [`Limits::max_handshake_bytes`].
    pub max_handshake_bytes: Option<u64>,
    /// Override for [`Limits::http_timeout`], in seconds.
    pub http_timeout_secs: Option<u64>,
    /// Override for [`Limits::max_ocsp_response_bytes`].
    pub max_ocsp_response_bytes: Option<u64>,
    /// Override for [`Limits::max_crl_bytes`].
    pub max_crl_bytes: Option<u64>,
    /// Override for [`Limits::max_aia_cert_bytes`].
    pub max_aia_cert_bytes: Option<u64>,
    /// Override for [`Limits::max_http_redirects`].
    pub max_http_redirects: Option<u64>,
    /// Override for [`Limits::max_revocation_cache_bytes`].
    pub max_revocation_cache_bytes: Option<u64>,
    /// Override for [`Limits::batch_concurrency`].
    pub batch_concurrency: Option<u64>,
    /// Override for [`Limits::max_batch_targets`].
    pub max_batch_targets: Option<u64>,
    /// Override for [`Limits::channel_capacity`].
    pub channel_capacity: Option<u64>,
    /// Override for [`Limits::history_entries`].
    pub history_entries: Option<u64>,
    /// Override for [`Limits::max_clipboard_bytes`].
    pub max_clipboard_bytes: Option<u64>,
    /// Override for [`Limits::clipboard_timeout`], in seconds.
    pub clipboard_timeout_secs: Option<u64>,
}

/// Warning emitted when an override exceeded its hard cap and was truncated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitWarning {
    /// Name of the override field (e.g. `max_chain_len`, `dns_timeout_secs`).
    pub field: &'static str,
    /// Value requested by the configuration.
    pub requested: u64,
    /// Value actually applied (the hard cap).
    pub applied: u64,
}

/// Errors produced while applying [`LimitsOverrides`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    /// An override of zero was supplied; zero is never a valid limit.
    #[error("limit override `{field}` must not be zero")]
    ZeroNotAllowed {
        /// Name of the offending override field.
        field: &'static str,
    },
}

/// Validates `requested` against `cap`: rejects zero and truncates above the
/// cap, returning the value to apply and an optional warning.
fn clamp(
    field: &'static str,
    requested: u64,
    cap: u64,
) -> Result<(u64, Option<LimitWarning>), LimitsError> {
    if requested == 0 {
        return Err(LimitsError::ZeroNotAllowed { field });
    }
    if requested > cap {
        let warning = LimitWarning {
            field,
            requested,
            applied: cap,
        };
        return Ok((cap, Some(warning)));
    }
    Ok((requested, None))
}

/// Applies a count/size override to `slot`, recording a warning if truncated.
fn apply_count(
    field: &'static str,
    requested: Option<u64>,
    cap: usize,
    slot: &mut usize,
    warnings: &mut Vec<LimitWarning>,
) -> Result<(), LimitsError> {
    let Some(requested) = requested else {
        return Ok(());
    };
    let cap = u64::try_from(cap).unwrap_or(u64::MAX);
    let (value, warning) = clamp(field, requested, cap)?;
    // `value <= cap`, and `cap` came from a `usize`, so this never saturates.
    *slot = usize::try_from(value).unwrap_or(usize::MAX);
    warnings.extend(warning);
    Ok(())
}

/// Applies a timeout override (whole seconds) to `slot`, recording a warning
/// if truncated.
fn apply_secs(
    field: &'static str,
    requested: Option<u64>,
    cap: Duration,
    slot: &mut Duration,
    warnings: &mut Vec<LimitWarning>,
) -> Result<(), LimitsError> {
    let Some(requested) = requested else {
        return Ok(());
    };
    let (value, warning) = clamp(field, requested, cap.as_secs())?;
    *slot = Duration::from_secs(value);
    warnings.extend(warning);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Independent oracle: deliberately not shared with the implementation's
    // own `KIB`/`MIB` (`use super::*` would otherwise shadow-import them).
    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;

    #[test]
    fn quando_default_deve_bater_com_a_tabela_9() {
        let esperado = Limits {
            max_cert_der_bytes: 64 * KIB,
            max_chain_len: 10,
            max_input_file_bytes: 4 * MIB,
            max_keystore_bytes: 4 * MIB,
            max_certs_per_source: 500,
            max_stdin_bytes: 4 * MIB,
            max_dir_entries: 1_000,
            max_dir_depth: 3,
            max_ca_file_certs: 1_000,
            max_scan_diagnostics: 100,
            dns_timeout: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(5),
            handshake_timeout: Duration::from_secs(10),
            target_total_timeout: Duration::from_secs(20),
            max_handshake_bytes: 256 * KIB,
            http_timeout: Duration::from_secs(5),
            max_ocsp_response_bytes: 64 * KIB,
            max_crl_bytes: 8 * MIB,
            max_aia_cert_bytes: 64 * KIB,
            max_http_redirects: 3,
            max_revocation_cache_bytes: 32 * MIB,
            batch_concurrency: 32,
            max_batch_targets: 10_000,
            channel_capacity: 256,
            history_entries: 200,
            max_clipboard_bytes: 256 * KIB,
            clipboard_timeout: Duration::from_secs(2),
        };
        assert_eq!(Limits::default(), esperado);
    }

    #[test]
    fn quando_hard_caps_deve_bater_com_a_tabela_9() {
        let esperado = Limits {
            max_cert_der_bytes: 256 * KIB,
            max_chain_len: 16,
            max_input_file_bytes: 16 * MIB,
            max_keystore_bytes: 16 * MIB,
            max_certs_per_source: 2_000,
            max_stdin_bytes: 16 * MIB,
            max_dir_entries: 10_000,
            max_dir_depth: 3,
            max_ca_file_certs: 5_000,
            max_scan_diagnostics: 1_000,
            dns_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(60),
            target_total_timeout: Duration::from_secs(120),
            max_handshake_bytes: MIB,
            http_timeout: Duration::from_secs(30),
            max_ocsp_response_bytes: 256 * KIB,
            max_crl_bytes: 32 * MIB,
            max_aia_cert_bytes: 256 * KIB,
            max_http_redirects: 5,
            max_revocation_cache_bytes: 128 * MIB,
            batch_concurrency: 256,
            max_batch_targets: 100_000,
            channel_capacity: 256,
            history_entries: 1_000,
            max_clipboard_bytes: MIB,
            clipboard_timeout: Duration::from_secs(10),
        };
        assert_eq!(Limits::HARD_CAPS, esperado);
    }

    #[test]
    fn quando_override_excede_teto_deve_truncar_e_avisar() {
        let o = LimitsOverrides {
            max_chain_len: Some(99),
            ..LimitsOverrides::default()
        };
        let (l, warnings) = Limits::default().with_overrides(&o).unwrap();
        assert_eq!(l.max_chain_len, 16);
        assert_eq!(
            warnings,
            vec![LimitWarning {
                field: "max_chain_len",
                requested: 99,
                applied: 16
            }]
        );
    }

    #[test]
    fn quando_override_de_timeout_excede_teto_deve_truncar_e_avisar() {
        let o = LimitsOverrides {
            dns_timeout_secs: Some(999),
            ..LimitsOverrides::default()
        };
        let (l, warnings) = Limits::default().with_overrides(&o).unwrap();
        assert_eq!(l.dns_timeout, Duration::from_secs(30));
        assert_eq!(
            warnings,
            vec![LimitWarning {
                field: "dns_timeout_secs",
                requested: 999,
                applied: 30
            }]
        );
    }

    #[test]
    fn quando_override_dentro_do_teto_deve_aplicar_sem_aviso() {
        let o = LimitsOverrides {
            max_chain_len: Some(12),
            connect_timeout_secs: Some(7),
            ..LimitsOverrides::default()
        };
        let (l, warnings) = Limits::default().with_overrides(&o).unwrap();
        assert_eq!(l.max_chain_len, 12);
        assert_eq!(l.connect_timeout, Duration::from_secs(7));
        assert_eq!(warnings, Vec::new());
    }

    #[test]
    fn quando_sem_overrides_deve_manter_limites() {
        let (l, warnings) = Limits::default()
            .with_overrides(&LimitsOverrides::default())
            .unwrap();
        assert_eq!(l, Limits::default());
        assert_eq!(warnings, Vec::new());
    }

    #[test]
    fn quando_override_zero_deve_falhar() {
        let o = LimitsOverrides {
            max_cert_der_bytes: Some(0),
            ..LimitsOverrides::default()
        };
        let err = Limits::default().with_overrides(&o).unwrap_err();
        assert_eq!(
            err,
            LimitsError::ZeroNotAllowed {
                field: "max_cert_der_bytes"
            }
        );
    }

    #[test]
    fn quando_override_de_timeout_zero_deve_falhar() {
        let o = LimitsOverrides {
            http_timeout_secs: Some(0),
            ..LimitsOverrides::default()
        };
        let err = Limits::default().with_overrides(&o).unwrap_err();
        assert_eq!(
            err,
            LimitsError::ZeroNotAllowed {
                field: "http_timeout_secs"
            }
        );
    }

    #[test]
    fn quando_defaults_deve_ser_menor_ou_igual_ao_teto() {
        let d = Limits::default();
        let c = Limits::HARD_CAPS;
        let checks = [
            (
                d.max_cert_der_bytes <= c.max_cert_der_bytes,
                "max_cert_der_bytes",
            ),
            (d.max_chain_len <= c.max_chain_len, "max_chain_len"),
            (
                d.max_input_file_bytes <= c.max_input_file_bytes,
                "max_input_file_bytes",
            ),
            (
                d.max_keystore_bytes <= c.max_keystore_bytes,
                "max_keystore_bytes",
            ),
            (
                d.max_certs_per_source <= c.max_certs_per_source,
                "max_certs_per_source",
            ),
            (d.max_stdin_bytes <= c.max_stdin_bytes, "max_stdin_bytes"),
            (d.max_dir_entries <= c.max_dir_entries, "max_dir_entries"),
            (d.max_dir_depth <= c.max_dir_depth, "max_dir_depth"),
            (
                d.max_ca_file_certs <= c.max_ca_file_certs,
                "max_ca_file_certs",
            ),
            (
                d.max_scan_diagnostics <= c.max_scan_diagnostics,
                "max_scan_diagnostics",
            ),
            (d.dns_timeout <= c.dns_timeout, "dns_timeout"),
            (d.connect_timeout <= c.connect_timeout, "connect_timeout"),
            (
                d.handshake_timeout <= c.handshake_timeout,
                "handshake_timeout",
            ),
            (
                d.target_total_timeout <= c.target_total_timeout,
                "target_total_timeout",
            ),
            (
                d.max_handshake_bytes <= c.max_handshake_bytes,
                "max_handshake_bytes",
            ),
            (d.http_timeout <= c.http_timeout, "http_timeout"),
            (
                d.max_ocsp_response_bytes <= c.max_ocsp_response_bytes,
                "max_ocsp_response_bytes",
            ),
            (d.max_crl_bytes <= c.max_crl_bytes, "max_crl_bytes"),
            (
                d.max_aia_cert_bytes <= c.max_aia_cert_bytes,
                "max_aia_cert_bytes",
            ),
            (
                d.max_http_redirects <= c.max_http_redirects,
                "max_http_redirects",
            ),
            (
                d.max_revocation_cache_bytes <= c.max_revocation_cache_bytes,
                "max_revocation_cache_bytes",
            ),
            (
                d.batch_concurrency <= c.batch_concurrency,
                "batch_concurrency",
            ),
            (
                d.max_batch_targets <= c.max_batch_targets,
                "max_batch_targets",
            ),
            (d.channel_capacity <= c.channel_capacity, "channel_capacity"),
            (d.history_entries <= c.history_entries, "history_entries"),
            (
                d.max_clipboard_bytes <= c.max_clipboard_bytes,
                "max_clipboard_bytes",
            ),
            (
                d.clipboard_timeout <= c.clipboard_timeout,
                "clipboard_timeout",
            ),
        ];
        let violados: Vec<&str> = checks
            .iter()
            .filter(|(ok, _)| !ok)
            .map(|(_, nome)| *nome)
            .collect();
        assert_eq!(violados, Vec::<&str>::new());
    }

    #[test]
    fn quando_json_tem_campo_desconhecido_deve_falhar() {
        let r: Result<LimitsOverrides, _> = serde_json::from_str(r#"{"campo_inexistente": 1}"#);
        assert!(r.is_err());
    }

    #[test]
    fn quando_json_tem_campos_validos_deve_desserializar() {
        let o: LimitsOverrides =
            serde_json::from_str(r#"{"max_chain_len": 12, "dns_timeout_secs": 4}"#).unwrap();
        assert_eq!(o.max_chain_len, Some(12));
        assert_eq!(o.dns_timeout_secs, Some(4));
        assert_eq!(o.max_cert_der_bytes, None);
    }

    /// Independent oracle (not shared with the implementation): every
    /// override set to a distinct value strictly below its hard cap.
    fn overrides_distintos_abaixo_do_teto() -> LimitsOverrides {
        LimitsOverrides {
            max_cert_der_bytes: Some(1_001),
            max_chain_len: Some(2),
            max_input_file_bytes: Some(1_003),
            max_keystore_bytes: Some(1_004),
            max_certs_per_source: Some(1_005),
            max_stdin_bytes: Some(1_006),
            max_dir_entries: Some(1_007),
            max_dir_depth: Some(1),
            max_ca_file_certs: Some(1_009),
            max_scan_diagnostics: Some(990),
            dns_timeout_secs: Some(11),
            connect_timeout_secs: Some(12),
            handshake_timeout_secs: Some(13),
            target_total_timeout_secs: Some(14),
            max_handshake_bytes: Some(1_015),
            http_timeout_secs: Some(16),
            max_ocsp_response_bytes: Some(1_017),
            max_crl_bytes: Some(1_018),
            max_aia_cert_bytes: Some(1_019),
            max_http_redirects: Some(4),
            max_revocation_cache_bytes: Some(1_021),
            batch_concurrency: Some(22),
            max_batch_targets: Some(1_023),
            channel_capacity: Some(24),
            history_entries: Some(25),
            max_clipboard_bytes: Some(1_026),
            clipboard_timeout_secs: Some(9),
        }
    }

    #[test]
    fn quando_todos_os_overrides_tem_valor_distinto_dentro_do_teto_deve_aplicar_em_todos_os_campos()
    {
        let (l, warnings) = Limits::default()
            .with_overrides(&overrides_distintos_abaixo_do_teto())
            .unwrap();
        let esperado = Limits {
            max_cert_der_bytes: 1_001,
            max_chain_len: 2,
            max_input_file_bytes: 1_003,
            max_keystore_bytes: 1_004,
            max_certs_per_source: 1_005,
            max_stdin_bytes: 1_006,
            max_dir_entries: 1_007,
            max_dir_depth: 1,
            max_ca_file_certs: 1_009,
            max_scan_diagnostics: 990,
            dns_timeout: Duration::from_secs(11),
            connect_timeout: Duration::from_secs(12),
            handshake_timeout: Duration::from_secs(13),
            target_total_timeout: Duration::from_secs(14),
            max_handshake_bytes: 1_015,
            http_timeout: Duration::from_secs(16),
            max_ocsp_response_bytes: 1_017,
            max_crl_bytes: 1_018,
            max_aia_cert_bytes: 1_019,
            max_http_redirects: 4,
            max_revocation_cache_bytes: 1_021,
            batch_concurrency: 22,
            max_batch_targets: 1_023,
            channel_capacity: 24,
            history_entries: 25,
            max_clipboard_bytes: 1_026,
            clipboard_timeout: Duration::from_secs(9),
        };
        assert_eq!(l, esperado);
        assert_eq!(warnings, Vec::new());
    }

    #[test]
    fn quando_todos_os_overrides_passam_do_teto_deve_dar_hard_caps_e_27_avisos() {
        let far = Some(u64::MAX);
        let o = LimitsOverrides {
            max_cert_der_bytes: far,
            max_chain_len: far,
            max_input_file_bytes: far,
            max_keystore_bytes: far,
            max_certs_per_source: far,
            max_stdin_bytes: far,
            max_dir_entries: far,
            max_dir_depth: far,
            max_ca_file_certs: far,
            max_scan_diagnostics: far,
            dns_timeout_secs: far,
            connect_timeout_secs: far,
            handshake_timeout_secs: far,
            target_total_timeout_secs: far,
            max_handshake_bytes: far,
            http_timeout_secs: far,
            max_ocsp_response_bytes: far,
            max_crl_bytes: far,
            max_aia_cert_bytes: far,
            max_http_redirects: far,
            max_revocation_cache_bytes: far,
            batch_concurrency: far,
            max_batch_targets: far,
            channel_capacity: far,
            history_entries: far,
            max_clipboard_bytes: far,
            clipboard_timeout_secs: far,
        };
        let (l, warnings) = Limits::default().with_overrides(&o).unwrap();
        assert_eq!(l, Limits::HARD_CAPS);
        let campos: Vec<&str> = warnings.iter().map(|w| w.field).collect();
        assert_eq!(
            campos,
            [
                "max_cert_der_bytes",
                "max_chain_len",
                "max_input_file_bytes",
                "max_keystore_bytes",
                "max_certs_per_source",
                "max_stdin_bytes",
                "max_dir_entries",
                "max_dir_depth",
                "max_ca_file_certs",
                "max_scan_diagnostics",
                "max_handshake_bytes",
                "max_ocsp_response_bytes",
                "max_crl_bytes",
                "max_aia_cert_bytes",
                "max_http_redirects",
                "max_revocation_cache_bytes",
                "batch_concurrency",
                "max_batch_targets",
                "channel_capacity",
                "history_entries",
                "max_clipboard_bytes",
                "dns_timeout_secs",
                "connect_timeout_secs",
                "handshake_timeout_secs",
                "target_total_timeout_secs",
                "http_timeout_secs",
                "clipboard_timeout_secs",
            ]
        );
        assert!(warnings.iter().all(|w| w.requested == u64::MAX));
    }

    #[test]
    fn quando_override_igual_ao_teto_deve_aplicar_sem_aviso() {
        let o = LimitsOverrides {
            max_chain_len: Some(16),
            dns_timeout_secs: Some(30),
            ..LimitsOverrides::default()
        };
        let (l, warnings) = Limits::default().with_overrides(&o).unwrap();
        assert_eq!(l.max_chain_len, 16);
        assert_eq!(l.dns_timeout, Duration::from_secs(30));
        assert_eq!(warnings, Vec::new());
    }
}
