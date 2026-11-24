//! `WebpkiChainVerifier`: the [`ChainVerifier`] port backed by `rustls-webpki`.

use std::net::IpAddr;
use std::time::Duration;

use certtui_app::ports::{ChainVerification, ChainVerifier};
use certtui_app::trust::{TrustAnchor, TrustAnchors};
use certtui_domain::model::{Chain, TrustVerdict};
use certtui_domain::sanitize::sanitize_display;
use certtui_domain::time::Timestamp;
use rustls_pki_types::{CertificateDer, Der, ServerName, TrustAnchor as PkiAnchor, UnixTime};
use webpki::{EndEntityCert, Error as WebpkiError, KeyUsage};

/// Verifies chains for server authentication with `rustls-webpki`
/// (provider `ring`).
#[derive(Debug, Clone, Copy, Default)]
pub struct WebpkiChainVerifier;

impl WebpkiChainVerifier {
    /// Creates the verifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ChainVerifier for WebpkiChainVerifier {
    fn verify(
        &self,
        chain: &Chain,
        anchors: &TrustAnchors,
        hostname: Option<&str>,
        now: Timestamp,
    ) -> ChainVerification {
        let Some(leaf_record) = chain.get(0) else {
            return ChainVerification {
                trust: untrusted("empty chain"),
                hostname_ok: None,
            };
        };
        let leaf_der = CertificateDer::from(&*leaf_record.der);
        let leaf = match EndEntityCert::try_from(&leaf_der) {
            Ok(leaf) => leaf,
            Err(error) => {
                return ChainVerification {
                    trust: untrusted(reason(&error)),
                    hostname_ok: hostname.map(|_| false),
                };
            }
        };
        let hostname_ok = hostname.map(|name| hostname_matches(&leaf, name));
        if anchors.is_empty() {
            return ChainVerification {
                trust: untrusted("no trust anchors loaded"),
                hostname_ok,
            };
        }
        let intermediates: Vec<CertificateDer<'_>> = chain
            .records()
            .iter()
            .skip(1)
            .map(|record| CertificateDer::from(&*record.der))
            .collect();
        let pki_anchors: Vec<PkiAnchor<'_>> = anchors.entries.iter().map(to_pki_anchor).collect();
        let time =
            UnixTime::since_unix_epoch(Duration::from_secs(u64::try_from(now.unix()).unwrap_or(0)));
        let verdict = match leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &pki_anchors,
            &intermediates,
            time,
            KeyUsage::server_auth(),
            None,
            None,
        ) {
            Ok(path) => {
                let used = path.anchor();
                let label = anchors
                    .entries
                    .iter()
                    .find(|a| {
                        a.subject_der == used.subject.as_ref()
                            && a.spki_der == used.subject_public_key_info.as_ref()
                    })
                    .map_or("unknown anchor", |a| a.label.as_str());
                TrustVerdict::Trusted {
                    anchor: sanitize_display(label).into_owned(),
                }
            }
            Err(error) => untrusted(reason(&error)),
        };
        ChainVerification {
            trust: verdict,
            hostname_ok,
        }
    }
}

fn untrusted(reason: &str) -> TrustVerdict {
    TrustVerdict::Untrusted {
        reason: reason.to_owned(),
    }
}

fn to_pki_anchor(anchor: &TrustAnchor) -> PkiAnchor<'_> {
    PkiAnchor {
        subject: Der::from(anchor.subject_der.as_slice()),
        subject_public_key_info: Der::from(anchor.spki_der.as_slice()),
        name_constraints: anchor.name_constraints_der.as_deref().map(Der::from),
    }
}

/// An unparsable name or IP literal never matches.
fn hostname_matches(leaf: &EndEntityCert<'_>, name: &str) -> bool {
    let bare = name
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(name);
    let server_name = match bare.parse::<IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => match ServerName::try_from(bare) {
            Ok(server_name) => server_name,
            Err(_) => return false,
        },
    };
    leaf.verify_is_valid_for_subject_name(&server_name).is_ok()
}

/// Fixed, content-free text for a webpki error.
fn reason(error: &WebpkiError) -> &'static str {
    match error {
        WebpkiError::UnknownIssuer => "unknown issuer",
        WebpkiError::CertExpired { .. } => "certificate expired",
        WebpkiError::CertNotValidYet { .. } => "certificate not yet valid",
        WebpkiError::InvalidSignatureForPublicKey => "invalid signature",
        WebpkiError::UnsupportedSignatureAlgorithmContext(_)
        | WebpkiError::UnsupportedSignatureAlgorithmForPublicKeyContext(_)
        | WebpkiError::SignatureAlgorithmMismatch => "unsupported signature algorithm",
        WebpkiError::CaUsedAsEndEntity => "CA certificate used as end entity",
        WebpkiError::EndEntityUsedAsCa => "end-entity certificate used as CA",
        WebpkiError::PathLenConstraintViolated => "path length constraint violated",
        WebpkiError::NameConstraintViolation => "name constraint violated",
        WebpkiError::RequiredEkuNotFoundContext(_) => {
            "certificate not valid for server authentication"
        }
        WebpkiError::CertDistrusted => "certificate distrusted",
        WebpkiError::MaximumPathDepthExceeded | WebpkiError::MaximumPathBuildCallsExceeded => {
            "path building limit exceeded"
        }
        WebpkiError::BadDer | WebpkiError::BadDerTime | WebpkiError::TrailingData(_) => {
            "malformed certificate"
        }
        _ => "chain validation failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::anchor_from_der;
    use certtui_app::trust::TrustSource;
    use certtui_domain::limits::Limits;
    use certtui_domain::model::{CertOrigin, CertificateRecord};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        date_time_ymd,
    };

    /// 2026-11-24T12:00:00Z.
    const NOW: i64 = 1_795_867_200;

    struct Pki {
        root_der: Vec<u8>,
        chain: Vec<Vec<u8>>,
    }

    fn ca_params(cn: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, cn);
        params
    }

    /// root -> intermediate -> leaf(`host`); `leaf_not_after` optional.
    fn pki(host: &str, leaf_not_after: Option<(i32, u8, u8)>) -> Pki {
        pki_with_root(host, leaf_not_after, "Test Root")
    }

    fn pki_with_root(host: &str, leaf_not_after: Option<(i32, u8, u8)>, root_cn: &str) -> Pki {
        let root_key = KeyPair::generate().expect("key");
        let root = ca_params(root_cn).self_signed(&root_key).expect("root");
        let root_issuer = Issuer::new(ca_params(root_cn), root_key);
        let int_key = KeyPair::generate().expect("key");
        let int = ca_params("Test Intermediate")
            .signed_by(&int_key, &root_issuer)
            .expect("int");
        let int_issuer = Issuer::new(ca_params("Test Intermediate"), int_key);
        let leaf_key = KeyPair::generate().expect("key");
        let mut leaf_params = CertificateParams::new(vec![host.to_owned()]).expect("params");
        if let Some((y, m, d)) = leaf_not_after {
            leaf_params.not_after = date_time_ymd(y, m, d);
        }
        let leaf = leaf_params.signed_by(&leaf_key, &int_issuer).expect("leaf");
        Pki {
            root_der: root.der().to_vec(),
            chain: vec![leaf.der().to_vec(), int.der().to_vec()],
        }
    }

    fn chain_of(ders: &[Vec<u8>]) -> Chain {
        let limits = Limits::default();
        let records = ders
            .iter()
            .enumerate()
            .map(|(position, der)| {
                CertificateRecord::from_der(der, CertOrigin::Presented { position }, &limits)
                    .expect("record")
            })
            .collect();
        Chain::new(records, &limits).expect("chain")
    }

    fn anchors_of(root_der: &[u8]) -> TrustAnchors {
        TrustAnchors {
            entries: vec![anchor_from_der(root_der, TrustSource::Custom).expect("anchor")],
            warnings: Vec::new(),
        }
    }

    fn now() -> Timestamp {
        Timestamp::from_unix(NOW).expect("timestamp")
    }

    fn verify(chain: &Chain, anchors: &TrustAnchors, host: Option<&str>) -> ChainVerification {
        WebpkiChainVerifier::new().verify(chain, anchors, host, now())
    }

    #[test]
    fn quando_leaf_assinada_por_ca_nas_ancoras_deve_ser_trusted() {
        let pki = pki("example.test", None);
        let result = verify(
            &chain_of(&pki.chain),
            &anchors_of(&pki.root_der),
            Some("example.test"),
        );
        assert_eq!(
            result.trust,
            TrustVerdict::Trusted {
                anchor: "Test Root".to_owned()
            }
        );
        assert_eq!(result.hostname_ok, Some(true));
    }

    #[test]
    fn quando_ca_desconhecida_deve_ser_untrusted_unknown_issuer() {
        let pki = pki("example.test", None);
        let other = pki_with_root("other.test", None, "Other Root");
        let result = verify(&chain_of(&pki.chain), &anchors_of(&other.root_der), None);
        assert_eq!(
            result.trust,
            TrustVerdict::Untrusted {
                reason: "unknown issuer".to_owned()
            }
        );
    }

    #[test]
    fn quando_intermediario_vem_fora_de_ordem_deve_ser_trusted() {
        let pki = pki("example.test", None);
        let mut ders = pki.chain.clone();
        // leaf, root-signed extra (the root itself), then the intermediate.
        ders.insert(1, pki.root_der.clone());
        let result = verify(&chain_of(&ders), &anchors_of(&pki.root_der), None);
        assert!(
            matches!(result.trust, TrustVerdict::Trusted { .. }),
            "{result:?}"
        );
    }

    #[test]
    fn quando_leaf_expirada_deve_ser_untrusted_com_motivo_expirado() {
        let pki = pki("example.test", Some((2020, 1, 1)));
        let result = verify(&chain_of(&pki.chain), &anchors_of(&pki.root_der), None);
        assert_eq!(
            result.trust,
            TrustVerdict::Untrusted {
                reason: "certificate expired".to_owned()
            }
        );
    }

    #[test]
    fn quando_hostname_nao_bate_deve_marcar_hostname_ok_false() {
        let pki = pki("example.test", None);
        let result = verify(
            &chain_of(&pki.chain),
            &anchors_of(&pki.root_der),
            Some("other.test"),
        );
        assert_eq!(result.hostname_ok, Some(false));
        assert!(matches!(result.trust, TrustVerdict::Trusted { .. }));
    }

    #[test]
    fn quando_sem_hostname_deve_dar_hostname_ok_none() {
        let pki = pki("example.test", None);
        let result = verify(&chain_of(&pki.chain), &anchors_of(&pki.root_der), None);
        assert_eq!(result.hostname_ok, None);
    }

    #[test]
    fn quando_anchors_vazias_deve_ser_untrusted_no_trust_anchors() {
        let pki = pki("example.test", None);
        let result = verify(
            &chain_of(&pki.chain),
            &TrustAnchors::default(),
            Some("example.test"),
        );
        assert_eq!(
            result.trust,
            TrustVerdict::Untrusted {
                reason: "no trust anchors loaded".to_owned()
            }
        );
        assert_eq!(result.hostname_ok, Some(true));
    }

    #[test]
    fn quando_leaf_e_autoassinada_e_nao_esta_nas_ancoras_deve_ser_untrusted() {
        let key = KeyPair::generate().expect("key");
        let leaf = CertificateParams::new(vec!["self.test".to_owned()])
            .expect("params")
            .self_signed(&key)
            .expect("leaf");
        let pki = pki("example.test", None);
        let result = verify(
            &chain_of(&[leaf.der().to_vec()]),
            &anchors_of(&pki.root_der),
            Some("self.test"),
        );
        assert!(
            matches!(result.trust, TrustVerdict::Untrusted { .. }),
            "{result:?}"
        );
    }

    #[test]
    fn quando_hostname_e_ip_literal_sem_san_ip_nao_deve_casar() {
        let pki = pki("example.test", None);
        let result = verify(
            &chain_of(&pki.chain),
            &anchors_of(&pki.root_der),
            Some("192.0.2.1"),
        );
        assert_eq!(result.hostname_ok, Some(false));
    }
}
