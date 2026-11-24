//! Tolerant extraction of certificates from free text.
//!
//! [`scan_text`] works on raw bytes (the input may be invalid UTF-8), runs in
//! linear time, uses no regular expressions and no recursion. It never keeps
//! file content in its diagnostics, only offsets and reasons. Private key
//! blocks are skipped whole and counted, never decoded.

mod base64_run;
mod der_len;
mod finish;
mod hex_run;
mod lines;
mod nested;
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
    /// Number of private key blocks skipped without being decoded. Their
    /// content is never read, kept or reported; only this count remains. It
    /// counts `BEGIN` lines (once per line, even when repeated), and each
    /// block is claimed whole: through its `END` or, without one, through the
    /// next `BEGIN` or the end of the input. A certificate inside a broken,
    /// unterminated key block (no `BEGIN` of its own) is therefore not found.
    pub private_key_blocks_ignored: usize,
    /// `true` when extraction stopped at, or candidates were dropped because
    /// of, `Limits::max_certs_per_source`. It also means the internal bounds
    /// tripped: the detectors' collection bound (twice that limit) or the
    /// bound on structural failures (that limit again), so some later
    /// candidates may not have been looked at, and fewer than
    /// `cert_limit` candidates may have been kept.
    pub truncated: bool,
    /// `true` when at least one diagnostic was dropped because
    /// `Limits::max_scan_diagnostics` was reached.
    pub diagnostics_truncated: bool,
    /// The `Limits::max_certs_per_source` this scan ran with.
    pub cert_limit: usize,
    /// The `Limits::max_scan_diagnostics` this scan ran with.
    pub diagnostics_limit: usize,
}

/// Sorted, non-overlapping byte ranges already claimed by a detector, so the
/// following detectors do not look at them again.
#[derive(Debug, Default)]
pub(crate) struct ConsumedRanges {
    ranges: Vec<Range<usize>>,
}

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

    /// The consumed ranges, sorted by start.
    pub(crate) fn as_slice(&self) -> &[Range<usize>] {
        &self.ranges
    }
}

/// Query helpers exercised only by the tests: the detectors claim ranges and
/// never ask about them.
#[cfg(test)]
impl ConsumedRanges {
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
}

/// Accumulator shared by all detectors of one scan.
///
/// `truncated` is set when a detector hits its collection bound (twice
/// `Limits::max_certs_per_source`, leaving room for candidates `finish` will
/// drop), not only when the final cap is exceeded.
#[derive(Debug)]
pub(crate) struct Detections {
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) diagnostics: Vec<ScanDiagnostic>,
    pub(crate) private_key_blocks_ignored: usize,
    pub(crate) truncated: bool,
    pub(crate) diagnostics_truncated: bool,
    pub(crate) consumed: ConsumedRanges,
    /// How many of the first `candidates` came from armored PEM blocks (set
    /// by [`scan_flat`] right after the PEM detector, before anything else
    /// pushes). The others are subject to the structural check of `finish`.
    pub(crate) pem_candidates: usize,
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
            pem_candidates: 0,
            max_candidates: finish::detection_cap(limits),
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
}

/// The parts of `0..len` that are not inside any of the sorted, non-overlapping
/// `consumed` ranges, in order. Empty parts are not yielded.
pub(crate) fn free_regions(
    len: usize,
    consumed: &[Range<usize>],
) -> impl Iterator<Item = Range<usize>> + '_ {
    let mut pos = 0;
    let mut ranges = consumed.iter();
    let mut done = false;
    std::iter::from_fn(move || {
        while !done {
            let region = if let Some(r) = ranges.next() {
                let region = pos..r.start.min(len);
                pos = pos.max(r.end);
                region
            } else {
                done = true;
                pos..len
            };
            if region.start < region.end {
                return Some(region);
            }
        }
        None
    })
}

/// Runs the flat detectors (PEM, private keys, bare Base64, hex) on `input`,
/// each one only on what the previous ones did not claim.
fn scan_flat(input: &[u8], limits: &Limits, det: &mut Detections) {
    pem::detect(input, limits, det);
    det.pem_candidates = det.candidates.len();
    let claimed = det.consumed.as_slice().to_vec();
    base64_run::find_bare_base64(input, &claimed, limits, det);
    let claimed = det.consumed.as_slice().to_vec();
    hex_run::find_hex_der(input, &claimed, limits, det);
}

/// Extracts certificate candidates from arbitrary text, in text order.
///
/// `input` may be any bytes. Cost is linear in `input.len()`. The detectors
/// run in this order, each on what the previous ones left alone: PEM blocks,
/// private keys (skipped and counted), bare Base64, hex, and finally Base64
/// that decodes to text which is scanned again (see the `nested` module).
/// Candidates found inside decoded text carry the offset of the Base64 run
/// they came from. The detectors' results then go through `finish`:
/// candidates and diagnostics are sorted by offset (stable; among those of one
/// decoded run the order is the order in the decoded text, and a layer decoded
/// from a run sits where that run is); candidates that did not come from a
/// PEM block must parse as X.509 certificates (the others are dropped with a
/// `NotDerSequence` diagnostic); duplicates (same SHA-256) are removed, first
/// one kept; and `max_certs_per_source` / `max_scan_diagnostics` cap the
/// result (`truncated` / `diagnostics_truncated`). The detectors themselves
/// may collect up to twice `max_certs_per_source` candidates, to leave room
/// for the ones `finish` drops; when they hit that bound, the nested results
/// kept are the first found (detection order), not the first in text order,
/// and `truncated` is set.
///
/// # Known limitations
///
/// - An uppercase identifier of 16 or more characters that starts with `MI`
///   followed by `E`-`T` (for example `MINIMUMVIABLEPRODUCT`) looks like the
///   start of a Base64 DER header and can hide a bare Base64 certificate that
///   follows it.
/// - Bare (unarmored) certificates after more than `max_certs_per_source`
///   structural failures are dropped unparsed, and the scan reports
///   `truncated`; PEM certificates and PKCS#7 blocks are still kept.
/// - Hexdump columns (offset and ASCII gutters around the hex) are not
///   supported; only plain hex with the usual separators is.
/// - A bare Base64 certificate inside a Base64 layer (a Secret) is only found
///   when it is alone in the decoded text; a comment line before or after it
///   hides it (PEM blocks and hex in decoded text are not affected).
/// - JSON `\uXXXX` escapes are not decoded; only `\n` and `\r` escapes are
///   treated as line breaks.
#[must_use]
pub fn scan_text(input: &[u8], limits: &Limits) -> ScanOutcome {
    let mut detections = Detections::new(limits);
    scan_flat(input, limits, &mut detections);
    let claimed = detections.consumed.as_slice().to_vec();
    let _decoded = nested::find_nested_base64(input, &claimed, limits, &mut detections);
    finish::finish(detections, limits)
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
        // The detectors collect twice the final cap, leaving room for the
        // candidates `finish` drops.
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
        assert!(d.push_candidate(cand()));
        assert!(!d.truncated);
        assert!(!d.push_candidate(cand()));
        assert!(d.truncated);
    }
}
