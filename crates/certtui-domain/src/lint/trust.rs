//! Lints that report the trust verdict.

use crate::finding::{Finding, FindingCategory, FindingCode, Severity};
use crate::lint::{Lint, LintContext};
use crate::model::{LoadNote, TrustVerdict};
use crate::sanitize::sanitize_display;

/// The chain does not validate against the chosen anchors.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustUntrustedLint;

/// The target name does not match the leaf's SANs.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostnameMismatchLint;

/// The server did not prove it holds the leaf's private key.
#[derive(Debug, Clone, Copy, Default)]
pub struct HandshakeSignatureInvalidLint;

impl Lint for HandshakeSignatureInvalidLint {
    fn code(&self) -> FindingCode {
        FindingCode::HandshakeSignatureInvalid
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.notes.contains(&LoadNote::HandshakeSignatureInvalid) {
            return Vec::new();
        }
        vec![Finding {
            code: FindingCode::HandshakeSignatureInvalid,
            severity: Severity::Error,
            category: FindingCategory::Trust,
            cert_index: Some(0),
            message: "the TLS handshake signature does not verify with the leaf's public key: \
                      the server did not prove it holds the private key (possible interception)"
                .to_owned(),
        }]
    }
}

/// A keystore was read without its integrity check, so what it lists is
/// unauthenticated.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeystoreIntegrityUnverifiedLint;

impl Lint for KeystoreIntegrityUnverifiedLint {
    fn code(&self) -> FindingCode {
        FindingCode::KeystoreIntegrityUnverified
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if !ctx.notes.contains(&LoadNote::KeystoreIntegrityUnverified) {
            return Vec::new();
        }
        vec![Finding {
            code: FindingCode::KeystoreIntegrityUnverified,
            severity: Severity::Warning,
            category: FindingCategory::Trust,
            cert_index: None,
            message: "the keystore was read without verifying its integrity \
                      (no password, or no MAC): its contents are unauthenticated"
                .to_owned(),
        }]
    }
}

impl Lint for TrustUntrustedLint {
    fn code(&self) -> FindingCode {
        FindingCode::TrustUntrusted
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        let TrustVerdict::Untrusted { reason } = ctx.trust else {
            return Vec::new();
        };
        vec![Finding {
            code: FindingCode::TrustUntrusted,
            severity: Severity::Error,
            category: FindingCategory::Trust,
            cert_index: None,
            message: format!("chain is not trusted: {}", sanitize_display(reason)),
        }]
    }
}

impl Lint for HostnameMismatchLint {
    fn code(&self) -> FindingCode {
        FindingCode::HostnameMismatch
    }

    fn check(&self, ctx: &LintContext<'_>) -> Vec<Finding> {
        if ctx.hostname_ok != Some(false) {
            return Vec::new();
        }
        let message = match ctx.hostname {
            Some(host) => format!(
                "certificate does not match the name \"{}\"",
                sanitize_display(host)
            ),
            None => "certificate does not match the target name".to_owned(),
        };
        vec![Finding {
            code: FindingCode::HostnameMismatch,
            severity: Severity::Error,
            category: FindingCategory::Trust,
            cert_index: Some(0),
            message,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lint::test_support::{fixture_record, network_fixture_of};

    fn fixture() -> crate::lint::test_support::Fixture {
        network_fixture_of(vec![fixture_record("rsa2048-leaf.der")])
    }

    #[test]
    fn quando_assinatura_do_handshake_nao_confere_deve_dar_erro_no_leaf() {
        let mut f = fixture();
        f.notes = vec![LoadNote::HandshakeSignatureInvalid];
        let findings = HandshakeSignatureInvalidLint.check(&f.ctx(0, false));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::HandshakeSignatureInvalid);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Trust);
        assert_eq!(findings[0].cert_index, Some(0));
    }

    #[test]
    fn quando_handshake_sem_nota_de_assinatura_deve_nao_dar_erro() {
        let f = fixture();
        assert_eq!(
            HandshakeSignatureInvalidLint.check(&f.ctx(0, false)),
            Vec::new()
        );
    }

    #[test]
    fn quando_keystore_foi_lido_sem_integridade_deve_dar_warning() {
        let mut f = fixture();
        f.notes = vec![LoadNote::KeystoreIntegrityUnverified];
        let findings = KeystoreIntegrityUnverifiedLint.check(&f.ctx(0, false));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::KeystoreIntegrityUnverified);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert_eq!(findings[0].category, FindingCategory::Trust);
        assert_eq!(findings[0].cert_index, None);
    }

    #[test]
    fn quando_keystore_foi_verificado_ou_nao_e_keystore_deve_nao_dar_warning() {
        let mut f = fixture();
        assert_eq!(
            KeystoreIntegrityUnverifiedLint.check(&f.ctx(0, false)),
            Vec::new()
        );
        f.notes = vec![LoadNote::PrivateKeyBlocksIgnored { count: 1 }];
        assert_eq!(
            KeystoreIntegrityUnverifiedLint.check(&f.ctx(0, false)),
            Vec::new()
        );
    }

    #[test]
    fn quando_untrusted_deve_dar_trust_untrusted_com_motivo() {
        let mut f = fixture();
        f.trust = TrustVerdict::Untrusted {
            reason: "unknown issuer".to_owned(),
        };
        let findings = TrustUntrustedLint.check(&f.ctx(0, false));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::TrustUntrusted);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Trust);
        assert_eq!(findings[0].cert_index, None);
        assert!(findings[0].message.contains("unknown issuer"));
    }

    #[test]
    fn quando_motivo_tem_controle_deve_sanitizar_a_mensagem() {
        let mut f = fixture();
        f.trust = TrustVerdict::Untrusted {
            reason: "bad\u{1b}[31m name".to_owned(),
        };
        let findings = TrustUntrustedLint.check(&f.ctx(0, false));
        assert!(!findings[0].message.contains('\u{1b}'));
    }

    #[test]
    fn quando_trusted_deve_nao_dar_trust_untrusted() {
        let mut f = fixture();
        f.trust = TrustVerdict::Trusted {
            anchor: "Root".to_owned(),
        };
        assert_eq!(TrustUntrustedLint.check(&f.ctx(0, false)), Vec::new());
    }

    #[test]
    fn quando_confianca_nao_avaliada_deve_nao_dar_trust_untrusted() {
        let f = fixture();
        assert_eq!(TrustUntrustedLint.check(&f.ctx(0, false)), Vec::new());
    }

    #[test]
    fn quando_hostname_nao_bate_deve_dar_hostname_mismatch() {
        let f = fixture();
        let mut ctx = f.ctx(0, false);
        ctx.hostname = Some("other.example");
        ctx.hostname_ok = Some(false);
        let findings = HostnameMismatchLint.check(&ctx);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::HostnameMismatch);
        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[0].category, FindingCategory::Trust);
        assert_eq!(findings[0].cert_index, Some(0));
        assert!(findings[0].message.contains("other.example"));
    }

    #[test]
    fn quando_hostname_bate_deve_nao_dar_hostname_mismatch() {
        let f = fixture();
        let mut ctx = f.ctx(0, false);
        ctx.hostname_ok = Some(true);
        assert_eq!(HostnameMismatchLint.check(&ctx), Vec::new());
    }

    #[test]
    fn quando_hostname_nao_foi_checado_deve_nao_dar_hostname_mismatch() {
        let f = fixture();
        assert_eq!(HostnameMismatchLint.check(&f.ctx(0, false)), Vec::new());
    }
}
