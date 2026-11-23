//! Tolerant extraction of certificates from free text.
//!
//! [`scan_text`] works on raw bytes (the input may be invalid UTF-8), runs in
//! linear time, uses no regular expressions and no recursion. It never keeps
//! file content in its diagnostics, only offsets and reasons.

mod der_len;
mod lines;
mod pem;

use std::ops::Range;

use serde::Serialize;

use crate::limits::Limits;
pub use crate::model::note::RejectReason;

/// What kind of DER object a [`Candidate`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// A DER X.509 certificate.
    Certificate,
    /// A DER PKCS#7 / CMS `SignedData` structure.
    Pkcs7,
}

/// A DER blob found in the text, not yet parsed as a certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Byte offset in the input where the candidate starts.
    pub offset: usize,
    /// What the candidate is expected to be.
    pub kind: CandidateKind,
    /// The DER bytes, cut at the length declared in their own header.
    pub der: Vec<u8>,
}

impl std::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Candidate")
            .field("offset", &self.offset)
            .field("kind", &self.kind)
            .field("der_len", &self.der.len())
            .finish()
    }
}

/// A rejected block: where it was and why. Never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScanDiagnostic {
    /// Byte offset of the rejected block in the input.
    pub offset: usize,
    /// Why it was rejected.
    pub reason: RejectReason,
}

/// Result of scanning a text for certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Candidates found, in text order.
    pub candidates: Vec<Candidate>,
    /// Rejected blocks, limited by `Limits::max_scan_diagnostics`.
    pub diagnostics: Vec<ScanDiagnostic>,
    /// Number of private key blocks skipped without being decoded. Filled by
    /// the private-key detector; zero until that detector exists.
    pub private_key_blocks_ignored: usize,
    /// `true` when extraction stopped at `Limits::max_certs_per_source`.
    pub truncated: bool,
    /// `true` when at least one diagnostic was dropped because
    /// `Limits::max_scan_diagnostics` was reached.
    pub diagnostics_truncated: bool,
}

/// Sorted, non-overlapping byte ranges already claimed by a detector, so the
/// following detectors do not look at them again.
#[derive(Debug, Default)]
pub(crate) struct ConsumedRanges {
    ranges: Vec<Range<usize>>,
}

// Justificativa: the query helpers are first used by the detectors of the
// following tasks; until then only the tests exercise them.
#[cfg_attr(not(test), allow(dead_code))]
impl ConsumedRanges {
    /// Records `range`, keeping the list sorted by start. Empty ranges are
    /// ignored. Ranges must not overlap one already recorded (detectors check
    /// [`Self::overlaps`] or only claim bytes past their own cursor); this is
    /// a `debug_assert`, not a runtime check.
    pub(crate) fn push(&mut self, range: Range<usize>) {
        if range.is_empty() {
            return;
        }
        let at = self.ranges.partition_point(|r| r.start <= range.start);
        debug_assert!(
            at.checked_sub(1)
                .and_then(|i| self.ranges.get(i))
                .is_none_or(|prev| prev.end <= range.start)
                && self
                    .ranges
                    .get(at)
                    .is_none_or(|next| range.end <= next.start),
            "consumed ranges must not overlap"
        );
        self.ranges.insert(at, range);
    }

    /// Whether `pos` lies inside a consumed range.
    pub(crate) fn contains(&self, pos: usize) -> bool {
        let at = self.ranges.partition_point(|r| r.start <= pos);
        at.checked_sub(1)
            .and_then(|i| self.ranges.get(i))
            .is_some_and(|r| pos < r.end)
    }

    /// Whether any consumed range intersects `range`.
    pub(crate) fn overlaps(&self, range: &Range<usize>) -> bool {
        if range.is_empty() {
            return false;
        }
        let at = self.ranges.partition_point(|r| r.start < range.end);
        at.checked_sub(1)
            .and_then(|i| self.ranges.get(i))
            .is_some_and(|r| r.end > range.start)
    }

    /// The consumed ranges, sorted by start.
    pub(crate) fn as_slice(&self) -> &[Range<usize>] {
        &self.ranges
    }
}

/// Accumulator shared by all detectors of one scan.
#[derive(Debug)]
pub(crate) struct Detections {
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) diagnostics: Vec<ScanDiagnostic>,
    pub(crate) private_key_blocks_ignored: usize,
    pub(crate) truncated: bool,
    pub(crate) diagnostics_truncated: bool,
    pub(crate) consumed: ConsumedRanges,
    max_candidates: usize,
    max_diagnostics: usize,
}

impl Detections {
    pub(crate) fn new(limits: &Limits) -> Self {
        Self {
            candidates: Vec::new(),
            diagnostics: Vec::new(),
            private_key_blocks_ignored: 0,
            truncated: false,
            diagnostics_truncated: false,
            consumed: ConsumedRanges::default(),
            max_candidates: limits.max_certs_per_source,
            max_diagnostics: limits.max_scan_diagnostics,
        }
    }

    /// Adds a candidate. Returns `false` (and marks the scan as truncated)
    /// when the per-source certificate limit is already reached.
    pub(crate) fn push_candidate(&mut self, candidate: Candidate) -> bool {
        if self.candidates.len() >= self.max_candidates {
            self.truncated = true;
            return false;
        }
        self.candidates.push(candidate);
        true
    }

    /// Records a rejection; past `max_scan_diagnostics` it is dropped and
    /// `diagnostics_truncated` is set.
    pub(crate) fn reject(&mut self, offset: usize, reason: RejectReason) {
        if self.diagnostics.len() < self.max_diagnostics {
            self.diagnostics.push(ScanDiagnostic { offset, reason });
        } else {
            self.diagnostics_truncated = true;
        }
    }

    fn into_outcome(self) -> ScanOutcome {
        ScanOutcome {
            candidates: self.candidates,
            diagnostics: self.diagnostics,
            private_key_blocks_ignored: self.private_key_blocks_ignored,
            truncated: self.truncated,
            diagnostics_truncated: self.diagnostics_truncated,
        }
    }
}

/// Extracts certificate candidates from arbitrary text, in text order.
///
/// `input` may be any bytes. Cost is linear in `input.len()`.
#[must_use]
pub fn scan_text(input: &[u8], limits: &Limits) -> ScanOutcome {
    let mut detections = Detections::new(limits);
    pem::detect(input, limits, &mut detections);
    detections.into_outcome()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_range_consumido_deve_ser_encontrado_por_contains_e_overlaps() {
        let mut c = ConsumedRanges::default();
        c.push(10..20);
        c.push(0..5);
        c.push(30..40);
        assert_eq!(c.as_slice(), &[0..5, 10..20, 30..40]);
        assert!(c.contains(0) && c.contains(4) && c.contains(10) && c.contains(39));
        assert!(!c.contains(5) && !c.contains(20) && !c.contains(29) && !c.contains(40));
        assert!(c.overlaps(&(4..11)));
        assert!(c.overlaps(&(19..31)));
        assert!(!c.overlaps(&(5..10)));
        assert!(!c.overlaps(&(20..30)));
        assert!(!c.overlaps(&(7..7)));
    }

    #[test]
    fn quando_diagnosticos_passam_do_limite_deve_descartar_o_excesso() {
        let limits = Limits {
            max_scan_diagnostics: 2,
            ..Limits::default()
        };
        let mut d = Detections::new(&limits);
        for i in 0..5 {
            d.reject(i, RejectReason::InvalidBase64);
        }
        assert_eq!(d.diagnostics.len(), 2);
        assert!(d.diagnostics_truncated);
    }

    #[test]
    fn quando_diagnosticos_cabem_no_limite_nao_deve_marcar_truncado() {
        let limits = Limits {
            max_scan_diagnostics: 2,
            ..Limits::default()
        };
        let mut d = Detections::new(&limits);
        d.reject(0, RejectReason::InvalidBase64);
        d.reject(1, RejectReason::InvalidBase64);
        assert!(!d.diagnostics_truncated);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "consumed ranges must not overlap")]
    fn quando_range_consumido_sobrepoe_deve_falhar_em_debug() {
        let mut c = ConsumedRanges::default();
        c.push(0..10);
        c.push(5..15);
    }

    #[test]
    fn quando_candidatos_passam_do_limite_deve_marcar_truncado() {
        let limits = Limits {
            max_certs_per_source: 1,
            ..Limits::default()
        };
        let mut d = Detections::new(&limits);
        let cand = || Candidate {
            offset: 0,
            kind: CandidateKind::Certificate,
            der: vec![0x30, 0x00],
        };
        assert!(d.push_candidate(cand()));
        assert!(!d.push_candidate(cand()));
        assert!(d.truncated);
    }
}
