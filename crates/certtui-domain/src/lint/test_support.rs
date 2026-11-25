//! Helpers shared by the lint tests.

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use time::OffsetDateTime;

use crate::chain_analysis::{ChainAnalysis, analyze_chain};
use crate::limits::Limits;
use crate::lint::{LintContext, Thresholds};
use crate::model::{
    CertOrigin, CertRevocation, CertificateRecord, Chain, LoadNote, StapleState, TrustVerdict,
};
use crate::time::Timestamp;

/// Owns everything a [`LintContext`] borrows.
pub(crate) struct Fixture {
    pub chain: Chain,
    pub analysis: ChainAnalysis,
    pub thresholds: Thresholds,
    pub trust: TrustVerdict,
    /// Whether contexts report a network target.
    pub network: bool,
    pub revocation: Vec<CertRevocation>,
    pub staple: StapleState,
    pub notes: Vec<LoadNote>,
}

/// A self-signed record valid between two Unix instants.
pub(crate) fn record(cn: &str, not_before: i64, not_after: i64) -> CertificateRecord {
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.distinguished_name.push(DnType::CommonName, cn);
    params.not_before = OffsetDateTime::from_unix_timestamp(not_before).expect("not_before");
    params.not_after = OffsetDateTime::from_unix_timestamp(not_after).expect("not_after");
    let key = KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    CertificateRecord::from_der(
        cert.der(),
        CertOrigin::Presented { position: 0 },
        &Limits::default(),
    )
    .expect("record")
}

/// A timestamp from Unix seconds.
pub(crate) fn ts(secs: i64) -> Timestamp {
    Timestamp::from_unix(secs).expect("timestamp")
}

impl Fixture {
    /// A one-certificate chain valid from `not_before` to `not_after`.
    pub(crate) fn new(not_before: i64, not_after: i64) -> Self {
        Self::of(vec![record("leaf", not_before, not_after)])
    }

    /// A chain of the given records, with default thresholds.
    pub(crate) fn of(records: Vec<CertificateRecord>) -> Self {
        let limits = Limits::default();
        let chain = Chain::new(records, &limits).expect("chain");
        let analysis = analyze_chain(&chain, &[], &limits);
        Self {
            chain,
            analysis,
            thresholds: Thresholds::default(),
            trust: TrustVerdict::NotEvaluated,
            network: false,
            revocation: Vec::new(),
            staple: StapleState::NotApplicable,
            notes: Vec::new(),
        }
    }

    /// A context judging validity at `now` (Unix seconds).
    pub(crate) fn ctx(&self, now: i64, publicly_trusted: bool) -> LintContext<'_> {
        LintContext {
            chain: &self.chain,
            analysis: &self.analysis,
            hostname: None,
            is_network_target: self.network,
            now: ts(now),
            thresholds: &self.thresholds,
            trust: &self.trust,
            hostname_ok: None,
            publicly_trusted,
            revocation: &self.revocation,
            staple: &self.staple,
            notes: &self.notes,
        }
    }
}

/// DER certificates of a root -> intermediate -> leaf hierarchy.
pub(crate) struct Pki {
    pub root: Vec<u8>,
    pub int: Vec<u8>,
    pub leaf: Vec<u8>,
}

fn ca_params(cn: &str, ca: bool) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    if ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    params.distinguished_name.push(DnType::CommonName, cn);
    params
}

/// A fresh hierarchy; every call yields unrelated keys.
pub(crate) fn pki() -> Pki {
    let root_key = KeyPair::generate().expect("key");
    let root = ca_params("Root", true)
        .self_signed(&root_key)
        .expect("root");
    let root_issuer = Issuer::new(ca_params("Root", true), root_key);
    let int_key = KeyPair::generate().expect("key");
    let int = ca_params("Int", true)
        .signed_by(&int_key, &root_issuer)
        .expect("int");
    let int_issuer = Issuer::new(ca_params("Int", true), int_key);
    let leaf_key = KeyPair::generate().expect("key");
    let leaf = ca_params("leaf", false)
        .signed_by(&leaf_key, &int_issuer)
        .expect("leaf");
    Pki {
        root: root.der().to_vec(),
        int: int.der().to_vec(),
        leaf: leaf.der().to_vec(),
    }
}

/// A self-signed non-CA certificate.
pub(crate) fn self_signed_der() -> Vec<u8> {
    let key = KeyPair::generate().expect("key");
    ca_params("solo", false)
        .self_signed(&key)
        .expect("cert")
        .der()
        .to_vec()
}

/// Records over `ders`, in presentation order.
pub(crate) fn records_of(ders: &[&[u8]]) -> Vec<CertificateRecord> {
    ders.iter()
        .enumerate()
        .map(|(position, der)| {
            CertificateRecord::from_der(der, CertOrigin::Presented { position }, &Limits::default())
                .expect("record")
        })
        .collect()
}

/// A network-target fixture over `ders`, in presentation order.
pub(crate) fn network_fixture(ders: &[&[u8]]) -> Fixture {
    let mut fixture = Fixture::of(records_of(ders));
    fixture.network = true;
    fixture
}

/// A network-target fixture over already-built records.
pub(crate) fn network_fixture_of(records: Vec<CertificateRecord>) -> Fixture {
    let mut fixture = Fixture::of(records);
    fixture.network = true;
    fixture
}

/// A record parsed from a file in `tests/fixtures`.
pub(crate) fn fixture_record(file: &str) -> CertificateRecord {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/");
    let der = std::fs::read(format!("{path}{file}")).expect("fixture");
    records_of(&[&der]).remove(0)
}
