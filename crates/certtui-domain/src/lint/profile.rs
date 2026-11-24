//! Lints about the certificate profile: names, key usage, constraints and
//! transparency.

use crate::finding::{Finding, FindingCategory, FindingCode, Severity};
use crate::lint::{Lint, LintContext};
use crate::model::ExtendedKeyUsage;

/// The leaf has no Subject Alternative Name.
#[derive(Debug, Clone, Copy, Default)]
pub struct MissingSanLint;

/// The leaf's EKU does not allow server authentication.
#[derive(Debug, Clone, Copy, Default)]
pub struct LeafMissingServerAuthLint;

/// A CA on the path is not a CA, or its `pathLen` is exceeded.
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicConstraintsViolationLint;

/// A publicly trusted leaf carries no embedded SCT.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEmbeddedSctLint;

impl Lint for MissingSanLint {
    fn code(&self) -> FindingCode {
        FindingCode::MissingSan
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        match ctx.chain.get(0) {
            Some(leaf) if leaf.summary.subject_alt_names.is_empty() => vec![Finding {
                code: FindingCode::MissingSan,
                severity: Severity::Error,
                category: FindingCategory::Quality,
                cert_index: Some(0),
                message: "leaf certificate has no Subject Alternative Name".to_owned(),
            }],
            _ => Vec::new(),
        }
    }
}

impl Lint for LeafMissingServerAuthLint {
    fn code(&self) -> FindingCode {
        FindingCode::LeafMissingServerAuth
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.is_network_target {
            return Vec::new();
        }
        let Some(leaf) = ctx.chain.get(0) else {
            return Vec::new();
        };
        let eku = &leaf.summary.extended_key_usage;
        let allows_server = eku
            .iter()
            .any(|usage| matches!(usage, ExtendedKeyUsage::ServerAuth | ExtendedKeyUsage::Any));
        if eku.is_empty() || allows_server {
            return Vec::new();
        }
        vec![Finding {
            code: FindingCode::LeafMissingServerAuth,
            severity: Severity::Warning,
            category: FindingCategory::Quality,
            cert_index: Some(0),
            message: "extended key usage does not include serverAuth".to_owned(),
        }]
    }
}

impl Lint for BasicConstraintsViolationLint {
    fn code(&self) -> FindingCode {
        FindingCode::BasicConstraintsViolation
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        ctx.analysis
            .path
            .iter()
            .enumerate()
            // Position 0 is the leaf, which is not required to be a CA.
            .skip(1)
            .filter_map(|(position, &index)| {
                let record = ctx.chain.get(index)?;
                let message = match &record.summary.basic_constraints {
                    Some(constraints) if constraints.ca => {
                        // CAs strictly between the leaf and this one.
                        let below = u32::try_from(position.saturating_sub(1)).unwrap_or(u32::MAX);
                        let path_len = constraints.path_len.filter(|max| *max < below)?;
                        format!(
                            "pathLen of {path_len} is exceeded by {below} intermediate certificates below it"
                        )
                    }
                    _ => "certificate is used as a CA but is not marked CA:true".to_owned(),
                };
                Some(Finding {
                    code: FindingCode::BasicConstraintsViolation,
                    severity: Severity::Error,
                    category: FindingCategory::Trust,
                    cert_index: Some(index),
                    message,
                })
            })
            .collect()
    }
}

impl Lint for NoEmbeddedSctLint {
    fn code(&self) -> FindingCode {
        FindingCode::NoEmbeddedSct
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        match ctx.chain.get(0) {
            Some(leaf) if ctx.publicly_trusted && leaf.summary.embedded_scts.is_empty() => {
                vec![Finding {
                    code: FindingCode::NoEmbeddedSct,
                    severity: Severity::Info,
                    category: FindingCategory::Quality,
                    cert_index: Some(0),
                    message: "publicly trusted leaf has no embedded SCT".to_owned(),
                }]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::test_support::{fixture_record, network_fixture_of, pki, records_of, ts};
    use crate::model::{BasicConstraints, CertificateRecord, SctEntry, SubjectAltName};

    fn codes(findings: &[Finding]) -> Vec<FindingCode> {
        findings.iter().map(|f| f.code).collect()
    }

    fn no_findings(findings: &[Finding]) {
        assert_eq!(codes(findings), Vec::<FindingCode>::new());
    }

    fn pki_records() -> Vec<CertificateRecord> {
        let p = pki();
        records_of(&[&p.leaf, &p.int, &p.root])
    }

    fn bc(ca: bool, path_len: Option<u32>) -> BasicConstraints {
        BasicConstraints { ca, path_len }
    }

    fn with_san(mut record: CertificateRecord) -> CertificateRecord {
        record.summary.subject_alt_names = vec![SubjectAltName::Dns("a.example".to_owned())];
        record
    }

    #[test]
    fn quando_leaf_sem_san_deve_dar_missing_san() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.subject_alt_names.clear();
        let f = network_fixture_of(vec![leaf]);
        let findings = MissingSanLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::MissingSan]);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Quality);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_leaf_com_san_deve_nao_dar_missing_san() {
        let mut records = pki_records();
        records[0] = with_san(records.remove(0));
        let f = network_fixture_of(records);
        no_findings(&MissingSanLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_eku_sem_server_auth_deve_dar_leaf_missing_server_auth() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.extended_key_usage = vec![ExtendedKeyUsage::ClientAuth];
        let f = network_fixture_of(vec![leaf]);
        let findings = LeafMissingServerAuthLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::LeafMissingServerAuth]);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].category, FindingCategory::Quality);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_eku_ausente_deve_nao_dar_leaf_missing_server_auth() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.extended_key_usage.clear();
        let f = network_fixture_of(vec![leaf]);
        no_findings(&LeafMissingServerAuthLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_eku_tem_server_auth_ou_any_deve_nao_dar_leaf_missing_server_auth() {
        for eku in [
            vec![ExtendedKeyUsage::ClientAuth, ExtendedKeyUsage::ServerAuth],
            vec![ExtendedKeyUsage::Any],
        ] {
            let mut leaf = fixture_record("rsa2048-leaf.der");
            leaf.summary.extended_key_usage = eku;
            let f = network_fixture_of(vec![leaf]);
            no_findings(&LeafMissingServerAuthLint.check(&f.ctx(0, false)));
        }
    }

    #[test]
    fn quando_alvo_e_arquivo_deve_nao_dar_leaf_missing_server_auth() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.extended_key_usage = vec![ExtendedKeyUsage::CodeSigning];
        let mut f = network_fixture_of(vec![leaf]);
        f.network = false;
        no_findings(&LeafMissingServerAuthLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_intermediario_sem_ca_true_deve_dar_basic_constraints_violation() {
        for broken in [None, Some(bc(false, None))] {
            let mut records = pki_records();
            records[1].summary.basic_constraints = broken;
            let f = network_fixture_of(records);
            let findings = BasicConstraintsViolationLint.check(&f.ctx(0, false));
            assert_eq!(codes(&findings), [FindingCode::BasicConstraintsViolation]);
            assert_eq!(findings[0].severity, Severity::Error);
            assert_eq!(findings[0].category, FindingCategory::Trust);
            assert_eq!(findings[0].cert_index, Some(1));
        }
    }

    #[test]
    fn quando_path_len_violado_deve_dar_basic_constraints_violation() {
        let mut records = pki_records();
        // The root allows no intermediate below it, yet one is present.
        records[2].summary.basic_constraints = Some(bc(true, Some(0)));
        let f = network_fixture_of(records);
        let findings = BasicConstraintsViolationLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::BasicConstraintsViolation]);
        assert_eq!(findings[0].cert_index, Some(2));
    }

    #[test]
    fn quando_tudo_ok_deve_nao_dar_basic_constraints_violation() {
        let mut records = pki_records();
        records[1].summary.basic_constraints = Some(bc(true, Some(0)));
        records[2].summary.basic_constraints = Some(bc(true, Some(1)));
        // The leaf is not a CA and is never checked.
        records[0].summary.basic_constraints = None;
        let f = network_fixture_of(records);
        no_findings(&BasicConstraintsViolationLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_leaf_publica_sem_sct_deve_dar_no_embedded_sct() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.embedded_scts.clear();
        let f = network_fixture_of(vec![leaf]);
        let findings = NoEmbeddedSctLint.check(&f.ctx(0, true));
        assert_eq!(codes(&findings), [FindingCode::NoEmbeddedSct]);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].category, FindingCategory::Quality);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_tem_sct_deve_nao_dar_no_embedded_sct() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.embedded_scts = vec![SctEntry {
            version: 1,
            log_id: [0; 32],
            timestamp: ts(0),
        }];
        let f = network_fixture_of(vec![leaf]);
        no_findings(&NoEmbeddedSctLint.check(&f.ctx(0, true)));
    }

    #[test]
    fn quando_ancora_e_custom_deve_nao_dar_no_embedded_sct() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.embedded_scts.clear();
        let f = network_fixture_of(vec![leaf]);
        no_findings(&NoEmbeddedSctLint.check(&f.ctx(0, false)));
    }
}
