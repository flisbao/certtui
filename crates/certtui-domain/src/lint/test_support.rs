//! Helpers shared by the lint tests.

use rcgen::{CertificateParams, DnType, KeyPair};
use time::OffsetDateTime;

use crate::chain_analysis::{ChainAnalysis, analyze_chain};
use crate::limits::Limits;
use crate::lint::{LintContext, Thresholds};
use crate::model::{CertOrigin, CertificateRecord, Chain, TrustVerdict};
use crate::time::Timestamp;

/// Owns everything a [`LintContext`] borrows.
pub(crate) struct Fixture {
    pub chain: Chain,
    pub analysis: ChainAnalysis,
    pub thresholds: Thresholds,
    pub trust: TrustVerdict,
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
        }
    }

    /// A context judging validity at `now` (Unix seconds).
    pub(crate) fn ctx(&self, now: i64, publicly_trusted: bool) -> LintContext<'_> {
        LintContext {
            chain: &self.chain,
            analysis: &self.analysis,
            hostname: None,
            is_network_target: false,
            now: ts(now),
            thresholds: &self.thresholds,
            trust: &self.trust,
            hostname_ok: None,
            publicly_trusted,
        }
    }
}
