//! Lints about how the certificate chain is presented.

use crate::finding::{Finding, FindingCategory, FindingCode, Severity};
use crate::lint::{Lint, LintContext};

/// An issuer is neither in the chain nor among the trust anchors.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainIncompleteLint;

/// The chain is not sent leaf to root.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainOrderWrongLint;

/// The same certificate appears more than once.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainDuplicateCertLint;

/// The server sent the self-signed root.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainRootSentLint;

/// A certificate does not belong to the issuer path.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChainExtraCertLint;

/// The leaf is its own issuer.
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfSignedLeafLint;

/// A presentation finding. Callers gate on `is_network_target` first: files
/// and stdin have no server whose presentation could be wrong.
fn presentation(
    code: FindingCode,
    severity: Severity,
    cert_index: Option<usize>,
    message: String,
) -> Finding {
    Finding {
        code,
        severity,
        category: FindingCategory::Presentation,
        cert_index,
        message,
    }
}

impl Lint for ChainIncompleteLint {
    fn code(&self) -> FindingCode {
        FindingCode::ChainIncomplete
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.is_network_target || !ctx.analysis.incomplete {
            return Vec::new();
        }
        vec![presentation(
            FindingCode::ChainIncomplete,
            Severity::Error,
            ctx.analysis.path.last().copied(),
            "issuer is neither in the chain nor among the trust anchors".to_owned(),
        )]
    }
}

impl Lint for ChainOrderWrongLint {
    fn code(&self) -> FindingCode {
        FindingCode::ChainOrderWrong
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        // Path indices are unique, so "sorted" means the issuers follow the
        // leaf in the order they were sent; extras and repeats do not count.
        if !ctx.is_network_target || ctx.analysis.path.is_sorted() {
            return Vec::new();
        }
        vec![presentation(
            FindingCode::ChainOrderWrong,
            Severity::Warning,
            None,
            "chain is not sent in leaf-to-root order".to_owned(),
        )]
    }
}

impl Lint for ChainDuplicateCertLint {
    fn code(&self) -> FindingCode {
        FindingCode::ChainDuplicateCert
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.is_network_target {
            return Vec::new();
        }
        ctx.analysis
            .duplicates
            .iter()
            .map(|&i| {
                presentation(
                    FindingCode::ChainDuplicateCert,
                    Severity::Warning,
                    Some(i),
                    format!("certificate at position {i} repeats an earlier one"),
                )
            })
            .collect()
    }
}

impl Lint for ChainRootSentLint {
    fn code(&self) -> FindingCode {
        FindingCode::ChainRootSent
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.is_network_target || !ctx.analysis.root_sent {
            return Vec::new();
        }
        vec![presentation(
            FindingCode::ChainRootSent,
            Severity::Info,
            ctx.analysis.path.last().copied(),
            "server sent the self-signed root certificate".to_owned(),
        )]
    }
}

impl Lint for ChainExtraCertLint {
    fn code(&self) -> FindingCode {
        FindingCode::ChainExtraCert
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.is_network_target {
            return Vec::new();
        }
        ctx.analysis
            .extras
            .iter()
            .map(|&i| {
                presentation(
                    FindingCode::ChainExtraCert,
                    Severity::Warning,
                    Some(i),
                    format!("certificate at position {i} does not belong to the issuer path"),
                )
            })
            .collect()
    }
}

impl Lint for SelfSignedLeafLint {
    fn code(&self) -> FindingCode {
        FindingCode::SelfSignedLeaf
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.analysis.leaf_self_signed {
            return Vec::new();
        }
        vec![Finding {
            code: FindingCode::SelfSignedLeaf,
            severity: Severity::Error,
            category: FindingCategory::Trust,
            cert_index: Some(0),
            message: "leaf certificate is self-signed".to_owned(),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::test_support::{network_fixture, pki, self_signed_der};

    fn codes(findings: &[Finding]) -> Vec<FindingCode> {
        findings.iter().map(|f| f.code).collect()
    }

    fn no_findings(findings: &[Finding]) {
        assert_eq!(codes(findings), Vec::<FindingCode>::new());
    }

    #[test]
    fn quando_falta_intermediario_deve_dar_chain_incomplete() {
        let p = pki();
        let f = network_fixture(&[&p.leaf]);
        let findings = ChainIncompleteLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::ChainIncomplete]);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Presentation);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_cadeia_completa_deve_nao_dar_chain_incomplete() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int, &p.root]);
        no_findings(&ChainIncompleteLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_ordem_embaralhada_deve_dar_chain_order_wrong() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.root, &p.int]);
        let findings = ChainOrderWrongLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::ChainOrderWrong]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].category, FindingCategory::Presentation);
        assert_eq!(findings[0].cert_index, None);
    }

    #[test]
    fn quando_ordem_correta_deve_nao_dar_chain_order_wrong() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int, &p.root]);
        no_findings(&ChainOrderWrongLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_so_ha_duplicata_deve_nao_dar_chain_order_wrong() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int, &p.int, &p.root]);
        no_findings(&ChainOrderWrongLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_cert_repetido_deve_dar_chain_duplicate_cert() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int, &p.int, &p.int]);
        let findings = ChainDuplicateCertLint.check(&f.ctx(0, false));
        assert_eq!(
            codes(&findings),
            [
                FindingCode::ChainDuplicateCert,
                FindingCode::ChainDuplicateCert
            ]
        );
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].category, FindingCategory::Presentation);
        let indices: Vec<_> = findings.iter().map(|x| x.cert_index).collect();
        assert_eq!(indices, [Some(2), Some(3)]);
    }

    #[test]
    fn quando_cert_nao_repetido_deve_nao_dar_chain_duplicate_cert() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int, &p.root]);
        no_findings(&ChainDuplicateCertLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_raiz_enviada_deve_dar_chain_root_sent() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int, &p.root]);
        let findings = ChainRootSentLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::ChainRootSent]);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].category, FindingCategory::Presentation);
        assert_eq!(findings[0].cert_index, Some(2));
    }

    #[test]
    fn quando_sem_raiz_deve_nao_dar_chain_root_sent() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int]);
        no_findings(&ChainRootSentLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_sobra_cert_deve_dar_chain_extra_cert() {
        let p = pki();
        let other = pki();
        let f = network_fixture(&[&p.leaf, &p.int, &other.leaf]);
        let findings = ChainExtraCertLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::ChainExtraCert]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].category, FindingCategory::Presentation);
        assert_eq!(findings[0].cert_index, Some(2));
    }

    #[test]
    fn quando_nao_sobra_cert_deve_nao_dar_chain_extra_cert() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int, &p.root]);
        no_findings(&ChainExtraCertLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_leaf_autoassinada_deve_dar_self_signed_leaf() {
        let der = self_signed_der();
        let f = network_fixture(&[&der]);
        let findings = SelfSignedLeafLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::SelfSignedLeaf]);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Trust);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_leaf_assinada_por_ca_deve_nao_dar_self_signed_leaf() {
        let p = pki();
        let f = network_fixture(&[&p.leaf, &p.int]);
        no_findings(&SelfSignedLeafLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_alvo_e_arquivo_deve_nao_rodar_lints_de_apresentacao() {
        let p = pki();
        let other = pki();
        let mut f = network_fixture(&[&p.leaf, &other.int, &p.int, &p.int, &p.root]);
        f.network = false;
        let ctx = f.ctx(0, false);
        no_findings(&ChainIncompleteLint.check(&ctx));
        no_findings(&ChainOrderWrongLint.check(&ctx));
        no_findings(&ChainDuplicateCertLint.check(&ctx));
        no_findings(&ChainRootSentLint.check(&ctx));
        no_findings(&ChainExtraCertLint.check(&ctx));
    }

    #[test]
    fn quando_alvo_e_arquivo_deve_rodar_self_signed_leaf() {
        let der = self_signed_der();
        let mut f = network_fixture(&[&der]);
        f.network = false;
        assert_eq!(
            codes(&SelfSignedLeafLint.check(&f.ctx(0, false))),
            [FindingCode::SelfSignedLeaf]
        );
    }
}
