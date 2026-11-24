//! The read-only input every lint receives.

use crate::chain_analysis::ChainAnalysis;
use crate::model::{CertificateRecord, Chain, TrustVerdict};
use crate::time::Timestamp;

/// Day-based limits that drive the validity lints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    /// A certificate expiring within this many days gets a warning.
    pub warn_days: u32,
    /// A certificate expiring within this many days gets an error.
    pub critical_days: u32,
    /// Longest validity, in days, accepted for a publicly trusted leaf.
    pub max_leaf_validity_days: u32,
}

impl Default for Thresholds {
    /// The defaults of spec section 7: 30, 7 and 398 days.
    fn default() -> Self {
        Self {
            warn_days: 30,
            critical_days: 7,
            max_leaf_validity_days: 398,
        }
    }
}

/// Everything a lint may look at; built once per inspection.
#[derive(Debug, Clone, Copy)]
pub struct LintContext<'a> {
    /// The certificates as presented.
    pub chain: &'a Chain,
    /// How the chain is laid out.
    pub analysis: &'a ChainAnalysis,
    /// The name the target was checked against, if any.
    pub hostname: Option<&'a str>,
    /// The input came from the network (not a file or stdin).
    pub is_network_target: bool,
    /// The instant validity is judged at.
    pub now: Timestamp,
    /// Day-based limits.
    pub thresholds: &'a Thresholds,
    /// Outcome of the trust evaluation.
    pub trust: &'a TrustVerdict,
    /// Whether the hostname matched the SANs; `None` when not checked.
    pub hostname_ok: Option<bool>,
    /// The chain is anchored in a public store (system or Mozilla).
    pub publicly_trusted: bool,
}

impl<'a> LintContext<'a> {
    /// The certificates with their index, minus byte-identical repeats:
    /// `CHAIN_DUPLICATE_CERT` reports those, so per-certificate lints skip
    /// them rather than repeat (or contradict) the verdict on the original.
    pub fn unique_records(
        &self,
    ) -> impl Iterator<Item = (usize, &'a CertificateRecord)> + use<'a, '_> {
        let duplicates = &self.analysis.duplicates;
        self.chain
            .records()
            .iter()
            .enumerate()
            .filter(move |(i, _)| !duplicates.contains(i))
    }
}
