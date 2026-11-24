//! Lints about the validity period of certificates.

use crate::finding::{Finding, FindingCategory, FindingCode, Severity};
use crate::lint::{Lint, LintContext};

/// Reports every certificate whose `not_after` is already in the past.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExpiredLint;

impl Lint for ExpiredLint {
    fn code(&self) -> FindingCode {
        FindingCode::Expired
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        ctx.unique_records()
            .filter(|(_, record)| ctx.now > record.summary.not_after)
            .map(|(i, record)| Finding {
                code: FindingCode::Expired,
                severity: Severity::Error,
                category: FindingCategory::Trust,
                cert_index: Some(i),
                message: format!("certificate expired on {}", record.summary.not_after),
            })
            .collect()
    }
}

/// Reports every certificate whose `not_before` is still in the future.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotYetValidLint;

impl Lint for NotYetValidLint {
    fn code(&self) -> FindingCode {
        FindingCode::NotYetValid
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        ctx.unique_records()
            .filter(|(_, record)| ctx.now < record.summary.not_before)
            .map(|(i, record)| Finding {
                code: FindingCode::NotYetValid,
                severity: Severity::Error,
                category: FindingCategory::Trust,
                cert_index: Some(i),
                message: format!(
                    "certificate is not valid before {}",
                    record.summary.not_before
                ),
            })
            .collect()
    }
}

/// Reports unexpired certificates with `critical_days` or fewer left.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExpiresSoonCriticalLint;

impl Lint for ExpiresSoonCriticalLint {
    fn code(&self) -> FindingCode {
        FindingCode::ExpiresSoonCritical
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        let critical = i64::from(ctx.thresholds.critical_days);
        ctx.unique_records()
            .filter(|(_, record)| ctx.now <= record.summary.not_after)
            .filter_map(|(i, record)| {
                let days = ctx.now.days_until(record.summary.not_after);
                (days <= critical).then(|| Finding {
                    code: FindingCode::ExpiresSoonCritical,
                    severity: Severity::Error,
                    category: FindingCategory::Quality,
                    cert_index: Some(i),
                    message: format!(
                        "certificate expires in {days} days, on {}",
                        record.summary.not_after
                    ),
                })
            })
            .collect()
    }
}

/// Reports unexpired certificates with more than `critical_days` but at most
/// `warn_days` left.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExpiresSoonLint;

impl Lint for ExpiresSoonLint {
    fn code(&self) -> FindingCode {
        FindingCode::ExpiresSoon
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        let critical = i64::from(ctx.thresholds.critical_days);
        let warn = i64::from(ctx.thresholds.warn_days);
        ctx.unique_records()
            .filter(|(_, record)| ctx.now <= record.summary.not_after)
            .filter_map(|(i, record)| {
                let days = ctx.now.days_until(record.summary.not_after);
                (days > critical && days <= warn).then(|| Finding {
                    code: FindingCode::ExpiresSoon,
                    severity: Severity::Warning,
                    category: FindingCategory::Quality,
                    cert_index: Some(i),
                    message: format!(
                        "certificate expires in {days} days, on {}",
                        record.summary.not_after
                    ),
                })
            })
            .collect()
    }
}

/// Reports a publicly trusted leaf valid for longer than
/// `max_leaf_validity_days`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ValidityTooLongLint;

impl Lint for ValidityTooLongLint {
    fn code(&self) -> FindingCode {
        FindingCode::ValidityTooLong
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.publicly_trusted {
            return Vec::new();
        }
        let Some(leaf) = ctx.chain.get(0) else {
            return Vec::new();
        };
        let max = i64::from(ctx.thresholds.max_leaf_validity_days);
        // Whole days, rounded down: a leaf is flagged only once it exceeds the
        // limit by a full day, so a few seconds of slack never trigger it.
        let days = leaf.summary.not_before.days_until(leaf.summary.not_after);
        if days <= max {
            return Vec::new();
        }
        vec![Finding {
            code: FindingCode::ValidityTooLong,
            severity: Severity::Warning,
            category: FindingCategory::Quality,
            cert_index: Some(0),
            message: format!("leaf certificate is valid for {days} days, more than {max}"),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::Thresholds;
    use crate::lint::test_support::{Fixture, pki, record, records_of, ts};

    const DAY: i64 = 86_400;
    /// A validity window of one year, ending at `END`.
    const END: i64 = 400 * DAY;

    fn year_fixture() -> Fixture {
        Fixture::new(END - 365 * DAY, END)
    }

    fn codes(findings: &[Finding]) -> Vec<FindingCode> {
        findings.iter().map(|f| f.code).collect()
    }

    /// Compares against an empty list so a failure prints the findings.
    fn assert_no_findings(findings: &[Finding]) {
        assert_eq!(codes(findings), Vec::<FindingCode>::new());
    }

    #[test]
    fn quando_now_igual_a_not_after_deve_nao_expirar() {
        let f = year_fixture();
        assert_no_findings(&ExpiredLint.check(&f.ctx(END, false)));
    }

    #[test]
    fn quando_cert_repetido_e_expirado_deve_dar_expired_uma_vez() {
        let p = pki();
        let mut records = records_of(&[&p.leaf, &p.int, &p.int]);
        for record in &mut records {
            record.summary.not_after = ts(DAY);
        }
        let f = Fixture::of(records);
        let findings = ExpiredLint.check(&f.ctx(2 * DAY, false));
        let indices: Vec<_> = findings.iter().map(|x| x.cert_index).collect();
        assert_eq!(indices, [Some(0), Some(1)]);
    }

    #[test]
    fn quando_now_igual_a_not_before_deve_ser_valido() {
        let f = year_fixture();
        assert_no_findings(&NotYetValidLint.check(&f.ctx(END - 365 * DAY, false)));
    }

    #[test]
    fn quando_now_depois_de_not_after_deve_dar_expired() {
        let f = year_fixture();
        let findings = ExpiredLint.check(&f.ctx(END + 1, false));
        assert_eq!(codes(&findings), [FindingCode::Expired]);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Trust);
        assert_eq!(findings[0].cert_index, Some(0));
        assert_eq!(
            findings[0].message,
            "certificate expired on 1971-02-05T00:00:00Z"
        );
    }

    #[test]
    fn quando_now_antes_de_not_before_deve_dar_not_yet_valid() {
        let f = year_fixture();
        let findings = NotYetValidLint.check(&f.ctx(END - 365 * DAY - 1, false));
        assert_eq!(codes(&findings), [FindingCode::NotYetValid]);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_no_findings(&NotYetValidLint.check(&f.ctx(END - 365 * DAY, false)));
    }

    #[test]
    fn quando_faltam_7_dias_deve_dar_critical_e_nao_warning() {
        let f = year_fixture();
        let ctx = f.ctx(END - 7 * DAY, false);
        let critical = ExpiresSoonCriticalLint.check(&ctx);
        assert_eq!(codes(&critical), [FindingCode::ExpiresSoonCritical]);
        assert_eq!(critical[0].severity, Severity::Error);
        assert_eq!(critical[0].category, FindingCategory::Quality);
        assert_no_findings(&ExpiresSoonLint.check(&ctx));
    }

    #[test]
    fn quando_faltam_30_dias_deve_dar_warning() {
        let f = year_fixture();
        let ctx = f.ctx(END - 30 * DAY, false);
        let warning = ExpiresSoonLint.check(&ctx);
        assert_eq!(codes(&warning), [FindingCode::ExpiresSoon]);
        assert_eq!(warning[0].severity, Severity::Warning);
        assert_no_findings(&ExpiresSoonCriticalLint.check(&ctx));
    }

    #[test]
    fn quando_faltam_8_dias_deve_dar_warning_e_nao_critical() {
        let f = year_fixture();
        let ctx = f.ctx(END - 8 * DAY, false);
        assert_eq!(
            codes(&ExpiresSoonLint.check(&ctx)),
            [FindingCode::ExpiresSoon]
        );
        assert_no_findings(&ExpiresSoonCriticalLint.check(&ctx));
    }

    #[test]
    fn quando_faltam_31_dias_deve_nao_dar_nada() {
        let f = year_fixture();
        let ctx = f.ctx(END - 31 * DAY, false);
        assert_no_findings(&ExpiresSoonLint.check(&ctx));
        assert_no_findings(&ExpiresSoonCriticalLint.check(&ctx));
    }

    #[test]
    fn quando_cert_expirado_deve_nao_dar_expires_soon() {
        let f = year_fixture();
        let ctx = f.ctx(END + DAY, false);
        assert_no_findings(&ExpiresSoonLint.check(&ctx));
        assert_no_findings(&ExpiresSoonCriticalLint.check(&ctx));
    }

    #[test]
    fn quando_leaf_publica_tem_398_dias_deve_nao_disparar() {
        let f = Fixture::new(0, 398 * DAY);
        assert_no_findings(&ValidityTooLongLint.check(&f.ctx(DAY, true)));
    }

    #[test]
    fn quando_leaf_publica_tem_399_dias_deve_disparar() {
        let f = Fixture::new(0, 399 * DAY);
        let findings = ValidityTooLongLint.check(&f.ctx(DAY, true));
        assert_eq!(codes(&findings), [FindingCode::ValidityTooLong]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].category, FindingCategory::Quality);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_leaf_nao_e_publica_deve_nao_disparar_validity_too_long() {
        let f = Fixture::new(0, 3_650 * DAY);
        assert_no_findings(&ValidityTooLongLint.check(&f.ctx(DAY, false)));
    }

    #[test]
    fn quando_so_intermediario_e_longo_deve_nao_disparar_validity_too_long() {
        let f = Fixture::of(vec![
            record("leaf", 0, 90 * DAY),
            record("int", 0, 3_650 * DAY),
        ]);
        assert_no_findings(&ValidityTooLongLint.check(&f.ctx(DAY, true)));
    }

    #[test]
    fn quando_thresholds_customizados_deve_respeitar() {
        let mut f = year_fixture();
        f.thresholds = Thresholds {
            warn_days: 60,
            critical_days: 20,
            max_leaf_validity_days: 100,
        };
        let ctx = f.ctx(END - 20 * DAY, true);
        assert_eq!(
            codes(&ExpiresSoonCriticalLint.check(&ctx)),
            [FindingCode::ExpiresSoonCritical]
        );
        let ctx = f.ctx(END - 60 * DAY, true);
        assert_eq!(
            codes(&ExpiresSoonLint.check(&ctx)),
            [FindingCode::ExpiresSoon]
        );
        assert_no_findings(&ExpiresSoonLint.check(&f.ctx(END - 61 * DAY, true)));
        assert_eq!(
            codes(&ValidityTooLongLint.check(&ctx)),
            [FindingCode::ValidityTooLong]
        );
    }

    #[test]
    fn quando_varios_certs_expirados_deve_indicar_cada_indice() {
        let f = Fixture::of(vec![
            record("leaf", 0, 10 * DAY),
            record("int", 0, 1_000 * DAY),
            record("root", 0, 20 * DAY),
        ]);
        let findings = ExpiredLint.check(&f.ctx(30 * DAY, false));
        let indices: Vec<Option<usize>> = findings.iter().map(|x| x.cert_index).collect();
        assert_eq!(indices, [Some(0), Some(2)]);
    }
}
