//! Lints that report revocation, the OCSP staple and AIA-fetched certificates.

use std::fmt::Write as _;

use crate::finding::{Finding, FindingCategory, FindingCode, Severity};
use crate::lint::{Lint, LintContext};
use crate::model::{CertOrigin, CertificateRecord, RevocationStatus, StapleState};
use crate::sanitize::sanitize_display;

/// OCSP or a CRL reports a certificate revoked.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevokedLint;

/// Revocation status could not be determined.
#[derive(Debug, Clone, Copy, Default)]
pub struct RevocationUnknownLint;

/// The stapled OCSP response was rejected.
#[derive(Debug, Clone, Copy, Default)]
pub struct OcspStapleInvalidLint;

/// A network server stapled no OCSP response.
#[derive(Debug, Clone, Copy, Default)]
pub struct OcspStapleMissingLint;

/// A certificate was fetched through AIA instead of being presented.
#[derive(Debug, Clone, Copy, Default)]
pub struct AiaFetchedLint;

fn is_self_signed(record: &CertificateRecord) -> bool {
    record.summary.subject.rfc4514 == record.summary.issuer.rfc4514
}

impl Lint for RevokedLint {
    fn code(&self) -> FindingCode {
        FindingCode::Revoked
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        ctx.revocation
            .iter()
            .filter_map(|entry| {
                let RevocationStatus::Revoked { reason, at } = &entry.status else {
                    return None;
                };
                let mut message = "certificate has been revoked".to_owned();
                if let Some(reason) = reason {
                    // Writing to a `String` cannot fail.
                    let _ = write!(message, " (reason: {})", sanitize_display(reason));
                }
                if let Some(at) = at {
                    // Writing to a `String` cannot fail.
                    let _ = write!(message, " on {at}");
                }
                Some(Finding {
                    code: FindingCode::Revoked,
                    severity: Severity::Error,
                    category: FindingCategory::Revocation,
                    cert_index: Some(entry.cert_index),
                    message,
                })
            })
            .collect()
    }
}

impl Lint for RevocationUnknownLint {
    fn code(&self) -> FindingCode {
        FindingCode::RevocationUnknown
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        ctx.revocation
            .iter()
            .filter_map(|entry| {
                let RevocationStatus::Unknown { why } = &entry.status else {
                    return None;
                };
                // A self-signed certificate has no issuer to ask: not a finding.
                let record = ctx.chain.get(entry.cert_index)?;
                if is_self_signed(record) {
                    return None;
                }
                Some(Finding {
                    code: FindingCode::RevocationUnknown,
                    severity: Severity::Warning,
                    category: FindingCategory::Revocation,
                    cert_index: Some(entry.cert_index),
                    message: format!(
                        "revocation status could not be determined: {}",
                        sanitize_display(why)
                    ),
                })
            })
            .collect()
    }
}

impl Lint for OcspStapleInvalidLint {
    fn code(&self) -> FindingCode {
        FindingCode::OcspStapleInvalid
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        let StapleState::Invalid(why) = ctx.staple else {
            return Vec::new();
        };
        vec![Finding {
            code: FindingCode::OcspStapleInvalid,
            severity: Severity::Warning,
            category: FindingCategory::Revocation,
            cert_index: Some(0),
            message: format!(
                "stapled OCSP response is invalid: {}",
                sanitize_display(why)
            ),
        }]
    }
}

impl Lint for OcspStapleMissingLint {
    fn code(&self) -> FindingCode {
        FindingCode::OcspStapleMissing
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.is_network_target || *ctx.staple != StapleState::Missing {
            return Vec::new();
        }
        vec![Finding {
            code: FindingCode::OcspStapleMissing,
            severity: Severity::Info,
            category: FindingCategory::Revocation,
            cert_index: Some(0),
            message: "the server did not staple an OCSP response".to_owned(),
        }]
    }
}

impl Lint for AiaFetchedLint {
    fn code(&self) -> FindingCode {
        FindingCode::AiaFetched
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        ctx.chain
            .records()
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                let CertOrigin::AiaFetched { url } = &record.origin else {
                    return None;
                };
                Some(Finding {
                    code: FindingCode::AiaFetched,
                    severity: Severity::Info,
                    category: FindingCategory::Presentation,
                    cert_index: Some(index),
                    message: format!(
                        "certificate was fetched through AIA from {}",
                        sanitize_display(url)
                    ),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::test_support::{Fixture, fixture_record, network_fixture_of};
    use crate::lint::{ChainIncompleteLint, run_lints};
    use crate::model::CertRevocation;
    use crate::time::Timestamp;

    fn revoked() -> RevocationStatus {
        RevocationStatus::Revoked {
            reason: Some("keyCompromise".to_owned()),
            at: Some(Timestamp::from_unix_saturating(1_792_022_400)),
        }
    }

    fn entry(cert_index: usize, status: RevocationStatus) -> CertRevocation {
        CertRevocation { cert_index, status }
    }

    /// A network target whose leaf is issued by someone else (not self-signed).
    fn net() -> Fixture {
        network_fixture_of(vec![fixture_record("chain-3.der")])
    }

    #[test]
    fn quando_cert_revogado_deve_dar_revoked_com_motivo_e_data() {
        let mut f = net();
        f.revocation = vec![entry(0, revoked())];

        let findings = RevokedLint.check(&f.ctx(0, false));

        assert_eq!(findings.len(), 1);
        let finding = findings.first().unwrap();
        assert_eq!(finding.code, FindingCode::Revoked);
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(finding.category, FindingCategory::Revocation);
        assert_eq!(finding.cert_index, Some(0));
        assert!(
            finding.message.contains("keyCompromise"),
            "{}",
            finding.message
        );
        assert!(
            finding.message.contains("2026-10-15"),
            "{}",
            finding.message
        );
    }

    #[test]
    fn quando_status_good_deve_nao_dar_revoked() {
        let mut f = net();
        f.revocation = vec![entry(0, RevocationStatus::Good)];
        assert_eq!(RevokedLint.check(&f.ctx(0, false)), Vec::new());
    }

    #[test]
    fn quando_status_unknown_deve_dar_revocation_unknown_com_motivo() {
        let mut f = net();
        f.revocation = vec![entry(
            0,
            RevocationStatus::Unknown {
                why: "ocsp: request timed out".to_owned(),
            },
        )];

        let findings = RevocationUnknownLint.check(&f.ctx(0, false));

        assert_eq!(findings.len(), 1);
        let finding = findings.first().unwrap();
        assert_eq!(finding.code, FindingCode::RevocationUnknown);
        assert_eq!(finding.severity, Severity::Warning);
        assert!(
            finding.message.contains("request timed out"),
            "{}",
            finding.message
        );
    }

    #[test]
    fn quando_status_good_deve_nao_dar_revocation_unknown() {
        let mut f = net();
        f.revocation = vec![entry(0, RevocationStatus::Good)];
        assert_eq!(RevocationUnknownLint.check(&f.ctx(0, false)), Vec::new());
    }

    #[test]
    fn quando_motivo_tem_escape_ansi_deve_sanitizar_a_mensagem() {
        let mut f = net();
        f.revocation = vec![entry(
            0,
            RevocationStatus::Unknown {
                why: "bad\u{1b}[31m\nline".to_owned(),
            },
        )];
        let message = RevocationUnknownLint
            .check(&f.ctx(0, false))
            .remove(0)
            .message;
        assert!(!message.contains('\u{1b}'), "{message:?}");
    }

    #[test]
    fn quando_cert_e_autoassinado_deve_nao_dar_revocation_unknown() {
        let f = &mut Fixture::of(vec![crate::lint::test_support::record(
            "solo",
            0,
            10_000_000_000,
        )]);
        f.revocation = vec![entry(
            0,
            RevocationStatus::Unknown {
                why: "self-signed certificate has no issuer to ask".to_owned(),
            },
        )];
        assert_eq!(RevocationUnknownLint.check(&f.ctx(0, false)), Vec::new());
    }

    #[test]
    fn quando_staple_invalido_deve_dar_ocsp_staple_invalid() {
        let mut f = net();
        f.staple = StapleState::Invalid("signature does not verify".to_owned());

        let findings = OcspStapleInvalidLint.check(&f.ctx(0, false));

        assert_eq!(findings.len(), 1);
        let finding = findings.first().unwrap();
        assert_eq!(finding.code, FindingCode::OcspStapleInvalid);
        assert_eq!(finding.severity, Severity::Warning);
        assert!(finding.message.contains("signature does not verify"));
    }

    #[test]
    fn quando_staple_valido_deve_nao_dar_ocsp_staple_invalid() {
        let mut f = net();
        f.staple = StapleState::Valid;
        assert_eq!(OcspStapleInvalidLint.check(&f.ctx(0, false)), Vec::new());
    }

    #[test]
    fn quando_staple_ausente_em_rede_deve_dar_info() {
        let mut f = net();
        f.staple = StapleState::Missing;

        let findings = OcspStapleMissingLint.check(&f.ctx(0, false));

        assert_eq!(findings.len(), 1);
        let finding = findings.first().unwrap();
        assert_eq!(finding.code, FindingCode::OcspStapleMissing);
        assert_eq!(finding.severity, Severity::Info);
    }

    #[test]
    fn quando_alvo_e_arquivo_deve_nao_dar_staple_missing() {
        let mut f = Fixture::of(vec![fixture_record("chain-3.der")]);
        f.staple = StapleState::Missing;
        assert_eq!(OcspStapleMissingLint.check(&f.ctx(0, false)), Vec::new());
    }

    #[test]
    fn quando_staple_esta_not_applicable_deve_nao_dar_staple_missing() {
        let f = net();
        assert_eq!(OcspStapleMissingLint.check(&f.ctx(0, false)), Vec::new());
    }

    fn aia_chain() -> Fixture {
        // Same certificates, the second one re-tagged as fetched through AIA.
        let mut records = vec![
            fixture_record("chain-3.der"),
            fixture_record("rsa2048-leaf.der"),
        ];
        if let Some(second) = records.get_mut(1) {
            second.origin = CertOrigin::AiaFetched {
                url: "http://ca.example/ca.der".to_owned(),
            };
        }
        network_fixture_of(records)
    }

    #[test]
    fn quando_cert_veio_por_aia_deve_dar_aia_fetched() {
        let f = aia_chain();

        let findings = AiaFetchedLint.check(&f.ctx(0, false));

        assert_eq!(findings.len(), 1);
        let finding = findings.first().unwrap();
        assert_eq!(finding.code, FindingCode::AiaFetched);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.category, FindingCategory::Presentation);
        assert_eq!(finding.cert_index, Some(1));
        assert!(finding.message.contains("http://ca.example/ca.der"));
    }

    #[test]
    fn quando_nenhum_cert_veio_por_aia_deve_nao_dar_aia_fetched() {
        let f = net();
        assert_eq!(AiaFetchedLint.check(&f.ctx(0, false)), Vec::new());
    }

    #[test]
    fn quando_aia_completa_a_cadeia_deve_manter_chain_incomplete() {
        // The leaf's issuer is not among the anchors: AIA_FETCHED is added,
        // CHAIN_INCOMPLETE stays.
        let f = aia_chain();
        assert!(
            f.analysis.incomplete,
            "the leaf's issuer is not in the chain"
        );

        let findings = run_lints(&f.ctx(0, false));

        let codes: Vec<_> = findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&FindingCode::AiaFetched), "{codes:?}");
        assert!(
            ChainIncompleteLint
                .check(&f.ctx(0, false))
                .iter()
                .any(|x| x.code == FindingCode::ChainIncomplete)
        );
        assert!(codes.contains(&FindingCode::ChainIncomplete), "{codes:?}");
    }
}
