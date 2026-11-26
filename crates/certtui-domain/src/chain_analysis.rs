//! Iterative analysis of a presented certificate chain: the issuer path from
//! the leaf, certificates that do not belong to it, repeats and gaps.

use crate::limits::Limits;
use crate::model::{CertificateRecord, Chain};

/// An issuer known outside the chain (a trust anchor), by subject name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownIssuer {
    /// RFC 4514 form of the anchor subject.
    pub subject_rfc4514: String,
}

/// How a presented chain is laid out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Justificativa: cada flag é um fato independente da cadeia, consumido por lints distintos.
pub struct ChainAnalysis {
    /// Indices (in presentation order) of the path from the leaf to the last
    /// certificate whose issuer could be found, leaf first.
    pub path: Vec<usize>,
    /// Indices that are not part of the path and not repeats.
    pub extras: Vec<usize>,
    /// Indices of certificates whose SHA-256 repeats an earlier index.
    pub duplicates: Vec<usize>,
    /// The path ends in a self-signed certificate other than the leaf.
    pub root_sent: bool,
    /// The path's last certificate is not self-signed and its issuer is not
    /// among the known anchors.
    pub incomplete: bool,
    /// The path is exactly `0, 1, 2, ...`.
    pub in_presented_order: bool,
    /// The leaf (index 0) is its own issuer.
    pub leaf_self_signed: bool,
}

/// Analyses `chain` without recursion: at most `limits.max_chain_len` steps,
/// each certificate visited once, so cycles end.
#[must_use]
pub fn analyze_chain(chain: &Chain, anchors: &[KnownIssuer], limits: &Limits) -> ChainAnalysis {
    let records = chain.records();
    let duplicates = find_duplicates(records);
    let is_duplicate = |i: usize| duplicates.contains(&i);

    let mut path: Vec<usize> = Vec::new();
    if !records.is_empty() {
        path.push(0);
    }
    let mut current = 0_usize;
    let mut steps = 0_usize;
    while let Some(record) = records.get(current) {
        if steps >= limits.max_chain_len || is_self_signed(record) {
            break;
        }
        let Some(next) = find_issuer(records, current, &path, &is_duplicate) else {
            break;
        };
        path.push(next);
        current = next;
        steps = steps.saturating_add(1);
    }

    let extras: Vec<usize> = (0..records.len())
        .filter(|i| !path.contains(i) && !is_duplicate(*i))
        .collect();
    let last = path.last().and_then(|i| records.get(*i));
    let last_self_signed = last.is_some_and(is_self_signed);
    // Complete when any certificate on the path is issued by a known anchor,
    // not only the last: a server may append a cross-signed root whose own
    // issuer is unknown, while the certificate before it already anchors.
    let anchored = path.iter().filter_map(|i| records.get(*i)).any(|record| {
        anchors.iter().any(|anchor| {
            anchor
                .subject_rfc4514
                .eq_ignore_ascii_case(&record.summary.issuer.rfc4514)
        })
    });
    let incomplete = last.is_some_and(|record| !is_self_signed(record) && !anchored);
    let in_presented_order = path.iter().copied().eq(0..path.len());
    ChainAnalysis {
        root_sent: last_self_signed && path.len() > 1,
        leaf_self_signed: records.first().is_some_and(is_self_signed),
        path,
        extras,
        duplicates,
        incomplete,
        in_presented_order,
    }
}

fn is_self_signed(record: &CertificateRecord) -> bool {
    record.summary.subject.rfc4514 == record.summary.issuer.rfc4514
}

/// Indices whose SHA-256 equals that of an earlier index.
fn find_duplicates(records: &[CertificateRecord]) -> Vec<usize> {
    records
        .iter()
        .enumerate()
        .filter(|(i, record)| {
            records
                .iter()
                .take(*i)
                .any(|earlier| earlier.fingerprints.sha256 == record.fingerprints.sha256)
        })
        .map(|(i, _)| i)
        .collect()
}

/// The unvisited, non-duplicate certificate that issued `records[current]`:
/// matching key identifiers first, then matching distinguished names.
fn find_issuer(
    records: &[CertificateRecord],
    current: usize,
    path: &[usize],
    is_duplicate: &dyn Fn(usize) -> bool,
) -> Option<usize> {
    let subject = records.get(current)?;
    let candidates = || {
        records
            .iter()
            .enumerate()
            .filter(|(i, _)| !path.contains(i) && !is_duplicate(*i))
    };
    if let Some(aki) = &subject.summary.authority_key_id {
        let by_key = candidates()
            .find(|(_, r)| r.summary.subject_key_id.as_ref() == Some(aki))
            .map(|(i, _)| i);
        if by_key.is_some() {
            return by_key;
        }
    }
    candidates()
        .find(|(_, r)| r.summary.subject.rfc4514 == subject.summary.issuer.rfc4514)
        .map(|(i, _)| i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CertOrigin;
    use proptest::prelude::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use std::sync::OnceLock;

    fn params(cn: &str, ca: bool) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::new()).expect("params");
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }
        params.distinguished_name.push(DnType::CommonName, cn);
        params
    }

    fn copy_key(key: &KeyPair) -> KeyPair {
        KeyPair::from_pem(&key.serialize_pem()).expect("key")
    }

    fn record(der: &[u8], position: usize) -> CertificateRecord {
        CertificateRecord::from_der(der, CertOrigin::Presented { position }, &Limits::default())
            .expect("record")
    }

    fn chain_of(ders: &[&[u8]]) -> Chain {
        let records = ders
            .iter()
            .enumerate()
            .map(|(i, der)| record(der, i))
            .collect();
        Chain::new(records, &Limits::default()).expect("chain")
    }

    /// root -> intermediate -> leaf.
    struct Pki {
        root: Vec<u8>,
        int: Vec<u8>,
        leaf: Vec<u8>,
    }

    fn pki() -> Pki {
        let root_key = KeyPair::generate().expect("key");
        let root = params("Root", true).self_signed(&root_key).expect("root");
        let root_issuer = Issuer::new(params("Root", true), root_key);
        let int_key = KeyPair::generate().expect("key");
        let int = params("Int", true)
            .signed_by(&int_key, &root_issuer)
            .expect("int");
        let int_issuer = Issuer::new(params("Int", true), int_key);
        let leaf_key = KeyPair::generate().expect("key");
        let leaf = params("leaf", false)
            .signed_by(&leaf_key, &int_issuer)
            .expect("leaf");
        Pki {
            root: root.der().to_vec(),
            int: int.der().to_vec(),
            leaf: leaf.der().to_vec(),
        }
    }

    fn analyze(chain: &Chain, anchors: &[KnownIssuer]) -> ChainAnalysis {
        analyze_chain(chain, anchors, &Limits::default())
    }

    fn anchor(subject: &str) -> KnownIssuer {
        KnownIssuer {
            subject_rfc4514: subject.to_owned(),
        }
    }

    #[test]
    fn quando_cadeia_ok_deve_ter_path_completo_e_ordem_correta() {
        let p = pki();
        let a = analyze(&chain_of(&[&p.leaf, &p.int, &p.root]), &[]);
        assert_eq!(a.path, vec![0, 1, 2]);
        assert!(a.in_presented_order);
        assert!(a.extras.is_empty() && a.duplicates.is_empty());
        assert!(!a.incomplete);
        assert!(!a.leaf_self_signed);
    }

    #[test]
    fn quando_ordem_embaralhada_deve_reordenar_e_marcar_fora_de_ordem() {
        let p = pki();
        let a = analyze(&chain_of(&[&p.leaf, &p.root, &p.int]), &[]);
        assert_eq!(a.path, vec![0, 2, 1]);
        assert!(!a.in_presented_order);
        assert!(!a.incomplete);
    }

    #[test]
    fn quando_falta_intermediario_deve_marcar_incompleta() {
        let p = pki();
        let a = analyze(&chain_of(&[&p.leaf]), &[]);
        assert_eq!(a.path, vec![0]);
        assert!(a.incomplete);
        assert!(!a.root_sent);
    }

    #[test]
    fn quando_emissor_esta_nas_ancoras_deve_nao_marcar_incompleta() {
        let p = pki();
        let a = analyze(&chain_of(&[&p.leaf, &p.int]), &[anchor("CN=Root")]);
        assert_eq!(a.path, vec![0, 1]);
        assert!(!a.incomplete);
        assert!(!a.root_sent);
    }

    #[test]
    fn quando_raiz_cross_signed_e_enviada_e_o_intermediario_ancora_deve_nao_marcar_incompleta() {
        // leaf <- Int <- Root (anchor), plus Root cross-signed by an Old Root
        // that is not an anchor (the example.com / Let's Encrypt pattern).
        let root_key = KeyPair::generate().expect("key");
        let old_root = Issuer::new(params("Old Root", true), KeyPair::generate().expect("key"));
        let cross = params("Root", true)
            .signed_by(&root_key, &old_root)
            .expect("cross");
        let root_issuer = Issuer::new(params("Root", true), root_key);
        let int_key = KeyPair::generate().expect("key");
        let int = params("Int", true)
            .signed_by(&int_key, &root_issuer)
            .expect("int");
        let int_issuer = Issuer::new(params("Int", true), int_key);
        let leaf = params("leaf", false)
            .signed_by(&KeyPair::generate().expect("key"), &int_issuer)
            .expect("leaf");

        let a = analyze(
            &chain_of(&[leaf.der(), int.der(), cross.der()]),
            &[anchor("CN=Root")],
        );

        assert!(!a.incomplete);
    }

    #[test]
    fn quando_raiz_enviada_deve_marcar_root_sent() {
        let p = pki();
        let a = analyze(&chain_of(&[&p.leaf, &p.int, &p.root]), &[]);
        assert!(a.root_sent);
    }

    #[test]
    fn quando_cert_sobrando_deve_listar_em_extras() {
        let p = pki();
        let other = pki();
        let a = analyze(&chain_of(&[&p.leaf, &p.int, &other.leaf]), &[]);
        assert_eq!(a.path, vec![0, 1]);
        assert_eq!(a.extras, vec![2]);
    }

    #[test]
    fn quando_cert_repetido_deve_listar_em_duplicates() {
        let p = pki();
        let a = analyze(&chain_of(&[&p.leaf, &p.int, &p.int, &p.root]), &[]);
        assert_eq!(a.duplicates, vec![2]);
        assert_eq!(a.path, vec![0, 1, 3]);
        assert_eq!(a.extras, Vec::<usize>::new());
    }

    #[test]
    fn quando_ha_ciclo_deve_terminar_sem_repetir_indices() {
        let key_a = KeyPair::generate().expect("key");
        let key_b = KeyPair::generate().expect("key");
        let a = params("A", true)
            .signed_by(&key_a, &Issuer::new(params("B", true), copy_key(&key_b)))
            .expect("a");
        let b = params("B", true)
            .signed_by(&key_b, &Issuer::new(params("A", true), copy_key(&key_a)))
            .expect("b");
        let analysis = analyze(&chain_of(&[a.der(), b.der()]), &[]);
        assert_eq!(analysis.path, vec![0, 1]);
        assert_eq!(analysis.extras, Vec::<usize>::new());
        assert!(analysis.incomplete);
    }

    #[test]
    fn quando_ski_e_aki_divergem_mas_dn_bate_deve_usar_dn() {
        let root_key = KeyPair::generate().expect("key");
        let root_issuer = Issuer::new(params("Root", true), root_key);
        let signing_key = KeyPair::generate().expect("key");
        let leaf_key = KeyPair::generate().expect("key");
        let int_issuer = Issuer::new(params("Int", true), signing_key);
        let leaf = params("leaf", false)
            .signed_by(&leaf_key, &int_issuer)
            .expect("leaf");
        // Same subject name as the issuer, different key (different SKI).
        let other_key = KeyPair::generate().expect("key");
        let int = params("Int", true)
            .signed_by(&other_key, &root_issuer)
            .expect("int");
        let analysis = analyze(&chain_of(&[leaf.der(), int.der()]), &[]);
        assert_eq!(analysis.path, vec![0, 1]);
    }

    #[test]
    fn quando_leaf_e_autoassinada_deve_marcar_leaf_self_signed() {
        let key = KeyPair::generate().expect("key");
        let leaf = params("solo", false).self_signed(&key).expect("leaf");
        let a = analyze(&chain_of(&[leaf.der()]), &[]);
        assert!(a.leaf_self_signed);
        assert!(!a.incomplete);
        assert!(!a.root_sent);
    }

    #[test]
    fn quando_cadeia_vazia_deve_dar_analise_vazia() {
        let chain = Chain::new(Vec::new(), &Limits::default()).expect("chain");
        let a = analyze(&chain, &[]);
        assert!(a.path.is_empty() && a.extras.is_empty() && !a.incomplete);
    }

    fn pool() -> &'static Vec<CertificateRecord> {
        static POOL: OnceLock<Vec<CertificateRecord>> = OnceLock::new();
        POOL.get_or_init(|| {
            let a = pki();
            let b = pki();
            [a.leaf, a.int, a.root, b.leaf, b.int, b.root]
                .iter()
                .enumerate()
                .map(|(i, der)| record(der, i))
                .collect()
        })
    }

    proptest! {
        #[test]
        fn quando_chain_arbitraria_deve_terminar_com_path_menor_ou_igual_ao_limite(
            picks in proptest::collection::vec(0_usize..6, 0..=10)
        ) {
            let limits = Limits::default();
            let records: Vec<CertificateRecord> = picks
                .iter()
                .filter_map(|i| pool().get(*i).cloned())
                .collect();
            let n = records.len();
            let chain = Chain::new(records, &limits).expect("chain");
            let a = analyze_chain(&chain, &[], &limits);
            prop_assert!(a.path.len() <= limits.max_chain_len);
            let mut all: Vec<usize> = a.path.iter().chain(&a.extras).chain(&a.duplicates).copied().collect();
            all.sort_unstable();
            prop_assert_eq!(all, (0..n).collect::<Vec<_>>());
        }
    }
}
