//! Lint framework (spec section 5.2): each rule is a struct implementing
//! [`Lint`]; a new rule is a new struct plus one line in [`registry`]. The
//! engine, [`run_lints`], never changes.

use std::cmp::Reverse;

use crate::finding::Finding;
use crate::finding::FindingCode;

mod chain;
mod context;
mod crypto;
mod profile;
mod revocation;
mod trust;
mod validity;

#[cfg(test)]
mod test_support;

pub use chain::{
    ChainDuplicateCertLint, ChainExtraCertLint, ChainIncompleteLint, ChainOrderWrongLint,
    ChainRootSentLint, SelfSignedLeafLint,
};
pub use context::{LintContext, Thresholds};
pub use crypto::{WeakKeyLint, WeakSignatureLint};
pub use profile::{
    BasicConstraintsViolationLint, LeafMissingServerAuthLint, MissingSanLint, NoEmbeddedSctLint,
};
pub use revocation::{
    AiaFetchedLint, OcspStapleInvalidLint, OcspStapleMissingLint, RevocationUnknownLint,
    RevokedLint,
};
pub use trust::{HostnameMismatchLint, TrustUntrustedLint};
pub use validity::{
    ExpiredLint, ExpiresSoonCriticalLint, ExpiresSoonLint, NotYetValidLint, ValidityTooLongLint,
};

/// One rule over a chain.
pub trait Lint: Send + Sync {
    /// The finding this rule reports.
    fn code(&self) -> FindingCode;

    /// Runs the rule; an empty list means the chain passes.
    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding>;
}

/// Every rule, in a stable order.
#[must_use]
pub fn registry() -> Vec<Box<dyn Lint>> {
    vec![
        Box::new(ChainIncompleteLint),
        Box::new(ChainOrderWrongLint),
        Box::new(ChainDuplicateCertLint),
        Box::new(ChainRootSentLint),
        Box::new(ChainExtraCertLint),
        Box::new(SelfSignedLeafLint),
        Box::new(WeakSignatureLint),
        Box::new(WeakKeyLint),
        Box::new(MissingSanLint),
        Box::new(LeafMissingServerAuthLint),
        Box::new(BasicConstraintsViolationLint),
        Box::new(NoEmbeddedSctLint),
        Box::new(RevokedLint),
        Box::new(RevocationUnknownLint),
        Box::new(OcspStapleInvalidLint),
        Box::new(OcspStapleMissingLint),
        Box::new(AiaFetchedLint),
        Box::new(TrustUntrustedLint),
        Box::new(HostnameMismatchLint),
        Box::new(ExpiredLint),
        Box::new(NotYetValidLint),
        Box::new(ExpiresSoonCriticalLint),
        Box::new(ExpiresSoonLint),
        Box::new(ValidityTooLongLint),
    ]
}

/// Runs every registered rule and orders the findings by descending
/// severity, then certificate index, then code. The order is stable: findings
/// that tie keep the registry order.
#[must_use]
pub fn run_lints(ctx: &LintContext<'_>) -> Vec<Finding> {
    let mut findings: Vec<Finding> = registry().iter().flat_map(|lint| lint.check(ctx)).collect();
    sort_findings(&mut findings);
    findings
}

/// Sorts by severity (descending), certificate index, then code name.
fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by_key(|f| (Reverse(f.severity), f.cert_index, f.code.as_str()));
}

#[cfg(test)]
mod tests {
    use super::test_support::Fixture;
    use super::*;
    use crate::finding::{FindingCategory, Severity};

    fn finding(
        code: FindingCode,
        severity: Severity,
        cert_index: Option<usize>,
        m: &str,
    ) -> Finding {
        Finding {
            code,
            severity,
            category: FindingCategory::Quality,
            cert_index,
            message: m.to_owned(),
        }
    }

    #[test]
    fn quando_achados_misturados_deve_ordenar_por_severidade_desc_e_estavel() {
        let mut findings = vec![
            finding(FindingCode::ExpiresSoon, Severity::Warning, Some(0), "a"),
            finding(FindingCode::Expired, Severity::Error, Some(2), "b"),
            finding(FindingCode::Expired, Severity::Error, Some(1), "c"),
            finding(FindingCode::NotYetValid, Severity::Error, Some(1), "d"),
            finding(FindingCode::ChainRootSent, Severity::Info, None, "e"),
            // Ties on every key keep their input order.
            finding(FindingCode::Expired, Severity::Error, Some(1), "f"),
        ];
        sort_findings(&mut findings);
        let order: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert_eq!(order, ["c", "f", "d", "b", "a", "e"]);
    }

    #[test]
    fn quando_registry_deve_ter_um_lint_por_codigo_do_m3() {
        let codes: Vec<&str> = registry().iter().map(|l| l.code().as_str()).collect();
        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len());
    }

    #[test]
    fn quando_run_lints_deve_ordenar_achados_reais() {
        // Self-signed, expired, without SAN or SCT, and (being public) valid
        // for far more than 398 days: three errors ordered by code, then the
        // warning, then the info.
        let fixture = Fixture::new(0, 500 * 86_400);
        let ctx = fixture.ctx(600 * 86_400, true);
        let findings = run_lints(&ctx);
        let codes: Vec<FindingCode> = findings.iter().map(|f| f.code).collect();
        assert_eq!(
            codes,
            [
                FindingCode::Expired,
                FindingCode::MissingSan,
                FindingCode::SelfSignedLeaf,
                FindingCode::ValidityTooLong,
                FindingCode::NoEmbeddedSct,
            ]
        );
    }
}
