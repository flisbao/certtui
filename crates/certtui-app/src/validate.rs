//! The `validate` use case: trust verdict and lints for an inspected chain.

use certtui_domain::chain_analysis::{KnownIssuer, analyze_chain};
use certtui_domain::limits::Limits;
use certtui_domain::lint::{LintContext, Thresholds, run_lints};
use certtui_domain::model::{InspectionReport, TrustVerdict, parse_name_der};
use certtui_domain::sanitize::sanitize_display;

use crate::ports::{ChainVerifier, Clock};
use crate::trust::{TrustAnchors, TrustSource};

/// What [`validate`] needs besides the report.
pub struct ValidationInputs<'a> {
    /// Decides trust and the hostname match.
    pub verifier: &'a dyn ChainVerifier,
    /// The anchors the chain is verified against.
    pub anchors: &'a TrustAnchors,
    /// Source of "now".
    pub clock: &'a dyn Clock,
    /// Day-based limits of the validity lints.
    pub thresholds: Thresholds,
    /// The name the leaf must match; `None` skips the hostname check.
    pub hostname: Option<String>,
    /// The report comes from a network target (enables the presentation
    /// lints).
    pub is_network_target: bool,
}

/// Fills `trust` and `findings` of `report`.
///
/// The chain is verified against `inputs.anchors` at the clock's "now", laid
/// out with `analyze_chain` (anchor subjects count as known issuers) and then
/// run through every lint. `revocation` is left untouched.
#[must_use]
pub fn validate(report: InspectionReport, inputs: ValidationInputs<'_>) -> InspectionReport {
    let ValidationInputs {
        verifier,
        anchors,
        clock,
        thresholds,
        hostname,
        is_network_target,
    } = inputs;
    let now = clock.now();
    let verification = verifier.verify(&report.chain, anchors, hostname.as_deref(), now);
    let known_issuers = known_issuers(anchors);
    let analysis = analyze_chain(&report.chain, &known_issuers, &Limits::default());
    let publicly_trusted = anchored_in_public_store(&verification.trust, anchors);
    let findings = run_lints(&LintContext {
        chain: &report.chain,
        analysis: &analysis,
        hostname: hostname.as_deref(),
        is_network_target,
        now,
        thresholds: &thresholds,
        trust: &verification.trust,
        hostname_ok: verification.hostname_ok,
        publicly_trusted,
    });
    InspectionReport {
        trust: verification.trust,
        findings,
        ..report
    }
}

/// The subject of every anchor whose name parses.
fn known_issuers(anchors: &TrustAnchors) -> Vec<KnownIssuer> {
    anchors
        .entries
        .iter()
        .filter_map(|anchor| parse_name_der(&anchor.subject_der))
        .map(|name| KnownIssuer {
            subject_rfc4514: name.rfc4514,
        })
        .collect()
}

/// Whether the verdict names an anchor that came from the system or Mozilla
/// store. The verdict carries the anchor label, sanitized for display.
fn anchored_in_public_store(trust: &TrustVerdict, anchors: &TrustAnchors) -> bool {
    let TrustVerdict::Trusted { anchor } = trust else {
        return false;
    };
    anchors.entries.iter().any(|entry| {
        matches!(entry.source, TrustSource::System | TrustSource::Mozilla)
            && sanitize_display(&entry.label) == anchor.as_str()
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use certtui_domain::finding::{FindingCode, Severity};
    use certtui_domain::limits::Limits;
    use certtui_domain::model::{CertOrigin, CertificateRecord, Chain, Timings, TrustVerdict};
    use certtui_domain::target::{NetworkTarget, Target};
    use certtui_domain::time::Timestamp;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, date_time_ymd,
    };

    use super::*;
    use crate::ports::ChainVerification;
    use crate::testing::{FakeChainVerifier, FixedClock};
    use crate::trust::{TrustAnchor, TrustSource};

    fn ca_params(cn: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, cn);
        params
    }

    /// DER of the name `CN=<cn>` (a single `UTF8String` attribute).
    fn name_der(cn: &str) -> Vec<u8> {
        let value = cn.as_bytes();
        // OID (5 bytes) + UTF8String header (2 bytes) + value.
        let attribute_len = 7 + value.len();
        let set_len = attribute_len + 2;
        let mut der = vec![0x30, u8::try_from(set_len + 2).unwrap()];
        der.extend([0x31, u8::try_from(set_len).unwrap()]);
        der.extend([0x30, u8::try_from(attribute_len).unwrap()]);
        der.extend([0x06, 0x03, 0x55, 0x04, 0x03, 0x0c]);
        der.push(u8::try_from(value.len()).unwrap());
        der.extend(value);
        der
    }

    /// leaf (valid in 2026, SAN a.example) -> intermediate -> root (not sent).
    fn chain_der(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> Vec<Vec<u8>> {
        let root_key = KeyPair::generate().expect("key");
        let root_issuer = Issuer::new(ca_params("Root"), root_key);
        let int_key = KeyPair::generate().expect("key");
        let int = ca_params("Int")
            .signed_by(&int_key, &root_issuer)
            .expect("int");
        let int_issuer = Issuer::new(ca_params("Int"), int_key);
        let leaf_key = KeyPair::generate().expect("key");
        let mut leaf_params =
            CertificateParams::new(vec!["a.example".to_owned()]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "a.example");
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        leaf_params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        let leaf = leaf_params.signed_by(&leaf_key, &int_issuer).expect("leaf");
        vec![leaf.der().to_vec(), int.der().to_vec()]
    }

    fn report(ders: &[Vec<u8>], target: Target) -> InspectionReport {
        let records = ders
            .iter()
            .enumerate()
            .map(|(position, der)| {
                CertificateRecord::from_der(
                    der,
                    CertOrigin::Presented { position },
                    &Limits::default(),
                )
                .expect("record")
            })
            .collect();
        InspectionReport {
            target,
            tls: None,
            ocsp_staple: None,
            chain: Chain::new(records, &Limits::default()).expect("chain"),
            trust: TrustVerdict::NotEvaluated,
            revocation: Vec::new(),
            findings: Vec::new(),
            timings: Timings::default(),
            notes: Vec::new(),
        }
    }

    fn network() -> Target {
        Target::Network(NetworkTarget {
            host: "a.example".to_owned(),
            port: 443,
            sni: None,
            connect_to: None,
        })
    }

    fn anchors(source: TrustSource) -> TrustAnchors {
        TrustAnchors {
            entries: vec![TrustAnchor {
                subject_der: name_der("Root"),
                spki_der: vec![1],
                name_constraints_der: None,
                source,
                label: "Root".to_owned(),
            }],
            warnings: Vec::new(),
        }
    }

    fn feb_2026() -> FixedClock {
        // 2026-02-01T00:00:00Z
        FixedClock(Timestamp::from_unix(1_769_904_000).expect("timestamp"))
    }

    fn trusted() -> ChainVerification {
        ChainVerification {
            trust: TrustVerdict::Trusted {
                anchor: "Root".to_owned(),
            },
            hostname_ok: Some(true),
        }
    }

    fn inputs<'a>(
        verifier: &'a FakeChainVerifier,
        anchors: &'a TrustAnchors,
        clock: &'a FixedClock,
        hostname: Option<&str>,
        is_network_target: bool,
    ) -> ValidationInputs<'a> {
        ValidationInputs {
            verifier,
            anchors,
            clock,
            thresholds: Thresholds::default(),
            hostname: hostname.map(str::to_owned),
            is_network_target,
        }
    }

    #[test]
    fn quando_leaf_e_confiavel_deve_preencher_trusted_e_sem_findings_de_erro() {
        let ders = chain_der((2026, 1, 1), (2026, 4, 1));
        let verifier = FakeChainVerifier::new(trusted());
        let anchors = anchors(TrustSource::Custom);
        let clock = feb_2026();
        let got = validate(
            report(&ders, network()),
            inputs(&verifier, &anchors, &clock, Some("a.example"), true),
        );
        assert_eq!(
            got.trust,
            TrustVerdict::Trusted {
                anchor: "Root".to_owned()
            }
        );
        let errors: Vec<_> = got
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(verifier.hostnames(), [Some("a.example".to_owned())]);
    }

    #[test]
    fn quando_leaf_expirada_deve_gerar_expired_e_trust_untrusted() {
        let ders = chain_der((2020, 1, 1), (2020, 2, 1));
        let verifier = FakeChainVerifier::new(ChainVerification {
            trust: TrustVerdict::Untrusted {
                reason: "certificate expired".to_owned(),
            },
            hostname_ok: Some(true),
        });
        let anchors = anchors(TrustSource::Custom);
        let clock = feb_2026();
        let got = validate(
            report(&ders, network()),
            inputs(&verifier, &anchors, &clock, Some("a.example"), true),
        );
        let codes: Vec<FindingCode> = got.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&FindingCode::Expired), "{codes:?}");
        assert!(codes.contains(&FindingCode::TrustUntrusted), "{codes:?}");
        assert!(got.findings.iter().all(|f| f.severity <= Severity::Error));
        let first = got.findings.first().expect("a finding");
        assert_eq!(first.severity, Severity::Error);
    }

    #[test]
    fn quando_alvo_e_arquivo_sem_host_check_deve_nao_checar_hostname() {
        let ders = chain_der((2026, 1, 1), (2026, 4, 1));
        let verifier = FakeChainVerifier::new(ChainVerification {
            trust: TrustVerdict::Trusted {
                anchor: "Root".to_owned(),
            },
            hostname_ok: None,
        });
        let anchors = anchors(TrustSource::Custom);
        let clock = feb_2026();
        let got = validate(
            report(&ders, Target::File(PathBuf::from("chain.pem"))),
            inputs(&verifier, &anchors, &clock, None, false),
        );
        assert_eq!(verifier.hostnames(), [None]);
        assert!(
            got.findings
                .iter()
                .all(|f| f.code != FindingCode::HostnameMismatch)
        );
    }

    #[test]
    fn quando_hostname_nao_bate_deve_gerar_hostname_mismatch() {
        let ders = chain_der((2026, 1, 1), (2026, 4, 1));
        let verifier = FakeChainVerifier::new(ChainVerification {
            trust: TrustVerdict::Trusted {
                anchor: "Root".to_owned(),
            },
            hostname_ok: Some(false),
        });
        let anchors = anchors(TrustSource::Custom);
        let clock = feb_2026();
        let got = validate(
            report(&ders, network()),
            inputs(&verifier, &anchors, &clock, Some("other.example"), true),
        );
        let codes: Vec<FindingCode> = got.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&FindingCode::HostnameMismatch), "{codes:?}");
    }

    #[test]
    fn quando_ancora_e_publica_e_leaf_longa_deve_marcar_publicly_trusted() {
        // Valid for 2 years: too long for a public leaf, fine for a private one.
        let ders = chain_der((2026, 1, 1), (2028, 1, 1));
        let anchors_public = anchors(TrustSource::Mozilla);
        let anchors_private = anchors(TrustSource::Custom);
        let clock = feb_2026();
        let verifier = FakeChainVerifier::new(trusted());
        let public = validate(
            report(&ders, network()),
            inputs(&verifier, &anchors_public, &clock, Some("a.example"), true),
        );
        let private = validate(
            report(&ders, network()),
            inputs(&verifier, &anchors_private, &clock, Some("a.example"), true),
        );
        let has = |r: &InspectionReport| {
            r.findings
                .iter()
                .any(|f| f.code == FindingCode::ValidityTooLong)
        };
        assert!(has(&public));
        assert!(!has(&private));
    }

    #[test]
    fn quando_trust_nao_e_trusted_deve_nao_marcar_publicly_trusted() {
        let ders = chain_der((2026, 1, 1), (2028, 1, 1));
        let verifier = FakeChainVerifier::new(ChainVerification {
            trust: TrustVerdict::Untrusted {
                reason: "unknown issuer".to_owned(),
            },
            hostname_ok: None,
        });
        let anchors = anchors(TrustSource::Mozilla);
        let clock = feb_2026();
        let got = validate(
            report(&ders, network()),
            inputs(&verifier, &anchors, &clock, None, true),
        );
        assert!(
            got.findings
                .iter()
                .all(|f| f.code != FindingCode::ValidityTooLong)
        );
    }

    #[test]
    fn quando_anchors_vazias_deve_dar_untrusted_sem_panic() {
        let ders = chain_der((2026, 1, 1), (2026, 4, 1));
        let verifier = FakeChainVerifier::new(ChainVerification {
            trust: TrustVerdict::Untrusted {
                reason: "no trust anchors loaded".to_owned(),
            },
            hostname_ok: None,
        });
        let none = TrustAnchors::default();
        let clock = feb_2026();
        let got = validate(
            report(&ders, network()),
            inputs(&verifier, &none, &clock, None, true),
        );
        assert!(matches!(got.trust, TrustVerdict::Untrusted { .. }));
        // With no anchors the intermediate's issuer cannot be found.
        assert!(
            got.findings
                .iter()
                .any(|f| f.code == FindingCode::ChainIncomplete)
        );
    }
}
