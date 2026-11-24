//! Lints about weak cryptography.

use crate::finding::{Finding, FindingCategory, FindingCode, Severity};
use crate::lint::{Lint, LintContext};
use crate::model::{HashAlgorithm, PublicKeyAlgorithm};

/// MD5 or SHA-1 signature on a certificate that is not an anchor.
#[derive(Debug, Clone, Copy, Default)]
pub struct WeakSignatureLint;

/// RSA below 2048 bits or EC below 256 bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct WeakKeyLint;

impl Lint for WeakSignatureLint {
    fn code(&self) -> FindingCode {
        FindingCode::WeakSignature
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        let anchor_index = ctx.analysis.path.last().copied();
        ctx.chain
            .records()
            .iter()
            .enumerate()
            .filter(|(_, record)| {
                matches!(
                    record.summary.signature_algorithm.hash,
                    HashAlgorithm::Md5 | HashAlgorithm::Sha1
                )
            })
            // A self-signed certificate ending the path is the anchor, whose
            // own signature is never verified.
            .filter(|(i, record)| {
                !(Some(*i) == anchor_index
                    && record.summary.subject.rfc4514 == record.summary.issuer.rfc4514)
            })
            .map(|(i, record)| Finding {
                code: FindingCode::WeakSignature,
                severity: Severity::Error,
                category: FindingCategory::Quality,
                cert_index: Some(i),
                message: format!(
                    "certificate is signed with a weak hash ({})",
                    record.summary.signature_algorithm.name
                ),
            })
            .collect()
    }
}

impl Lint for WeakKeyLint {
    fn code(&self) -> FindingCode {
        FindingCode::WeakKey
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        ctx.chain
            .records()
            .iter()
            .enumerate()
            .filter_map(|(i, record)| {
                let key = &record.summary.public_key;
                // `bits == 0` means the size could not be determined.
                let (family, minimum) = match key.algorithm {
                    PublicKeyAlgorithm::Rsa => ("RSA", 2048),
                    PublicKeyAlgorithm::EcP256
                    | PublicKeyAlgorithm::EcP384
                    | PublicKeyAlgorithm::EcP521 => ("EC", 256),
                    _ => return None,
                };
                (key.bits != 0 && key.bits < minimum).then(|| Finding {
                    code: FindingCode::WeakKey,
                    severity: Severity::Error,
                    category: FindingCategory::Quality,
                    cert_index: Some(i),
                    message: format!(
                        "{family} key of {} bits is below the minimum of {minimum}",
                        key.bits
                    ),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::test_support::{fixture_record, network_fixture_of, pki, records_of};
    use crate::model::{PublicKeyAlgorithm, SignatureAlgorithm};

    const SHA1_RSA: &str = "1.2.840.113549.1.1.5";
    const MD5_RSA: &str = "1.2.840.113549.1.1.4";

    fn codes(findings: &[Finding]) -> Vec<FindingCode> {
        findings.iter().map(|f| f.code).collect()
    }

    fn no_findings(findings: &[Finding]) {
        assert_eq!(codes(findings), Vec::<FindingCode>::new());
    }

    fn pki_records() -> Vec<crate::model::CertificateRecord> {
        let p = pki();
        records_of(&[&p.leaf, &p.int, &p.root])
    }

    #[test]
    fn quando_leaf_assinada_com_sha1_deve_dar_weak_signature() {
        let mut records = pki_records();
        records[0].summary.signature_algorithm = SignatureAlgorithm::from_oid(SHA1_RSA);
        let f = network_fixture_of(records);
        let findings = WeakSignatureLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::WeakSignature]);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Quality);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_intermediario_md5_deve_dar_weak_signature_no_indice_dele() {
        let mut records = pki_records();
        records[1].summary.signature_algorithm = SignatureAlgorithm::from_oid(MD5_RSA);
        let f = network_fixture_of(records);
        let findings = WeakSignatureLint.check(&f.ctx(0, false));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cert_index, Some(1));
    }

    #[test]
    fn quando_raiz_autoassinada_sha1_deve_nao_dar_weak_signature() {
        let mut records = pki_records();
        records[2].summary.signature_algorithm = SignatureAlgorithm::from_oid(SHA1_RSA);
        let f = network_fixture_of(records);
        no_findings(&WeakSignatureLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_assinatura_forte_deve_nao_dar_weak_signature() {
        let f = network_fixture_of(pki_records());
        no_findings(&WeakSignatureLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_rsa_1024_deve_dar_weak_key() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.public_key.bits = 1024;
        let f = network_fixture_of(vec![leaf]);
        let findings = WeakKeyLint.check(&f.ctx(0, false));
        assert_eq!(codes(&findings), [FindingCode::WeakKey]);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Quality);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_rsa_2048_deve_nao_dar_weak_key() {
        let f = network_fixture_of(vec![fixture_record("rsa2048-leaf.der")]);
        no_findings(&WeakKeyLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_ec_p256_deve_nao_dar_weak_key() {
        let f = network_fixture_of(vec![fixture_record("ec-p256-leaf.der")]);
        no_findings(&WeakKeyLint.check(&f.ctx(0, false)));
    }

    #[test]
    fn quando_ec_abaixo_de_256_bits_deve_dar_weak_key() {
        let mut leaf = fixture_record("ec-p256-leaf.der");
        leaf.summary.public_key.algorithm = PublicKeyAlgorithm::EcP256;
        leaf.summary.public_key.bits = 224;
        let f = network_fixture_of(vec![leaf]);
        assert_eq!(
            codes(&WeakKeyLint.check(&f.ctx(0, false))),
            [FindingCode::WeakKey]
        );
    }

    #[test]
    fn quando_tamanho_da_chave_e_desconhecido_deve_nao_dar_weak_key() {
        let mut leaf = fixture_record("rsa2048-leaf.der");
        leaf.summary.public_key.bits = 0;
        let f = network_fixture_of(vec![leaf]);
        no_findings(&WeakKeyLint.check(&f.ctx(0, false)));
    }
}
