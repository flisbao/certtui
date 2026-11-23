//! Detector of Base64 that hides more text (for example a Kubernetes `Secret`,
//! whose `tls.crt` is the Base64 of a PEM file).
//!
//! A Base64 run of at least [`MIN_RUN_CHARS`] characters that no earlier
//! detector claimed is decoded. When the result is text that may hide
//! certificates, it joins a work queue (a [`VecDeque`], drained by a `while
//! let` loop: no recursion) and is scanned with the same detectors as the
//! input, including the PEM detector, so private key blocks inside a decoded
//! `Secret` are skipped and counted, never returned. The decoded text may
//! contain further Base64 runs, to a depth of [`MAX_NESTED_DECODE_DEPTH`]; a
//! deeper layer is reported as `NestingTooDeep` and not decoded.
//!
//! Decoded text is worth scanning when it contains `-----BEGIN ` or when it is
//! itself Base64 text (a wrapped layer). Anything else (binary, prose) is
//! dropped without a diagnostic, because long Base64-looking strings are
//! everywhere (hashes, tokens, identifiers).
//!
//! Cost: every run is read once, a run that is not decoded costs `O(first
//! token)`, and the bytes decoded across the whole queue never exceed twice the
//! input (an explicit budget on top of the depth limit), so the scan stays
//! linear. Candidates and diagnostics found inside decoded text carry the
//! offset of the top-level run they came from; they never carry content.
//!
//! A run may continue across lines (wrapped Base64, YAML block scalars), but a
//! continuation line must hold nothing but one Base64 token, so the next
//! `key: value` line of a manifest is never glued to the previous value.

use std::collections::VecDeque;
use std::ops::Range;

use base64::Engine as _;

use super::lines::separator_len;
use super::pem::LENIENT;
use super::{Candidate, Detections, RejectReason, free_regions};
use crate::limits::Limits;

/// How many times decoded text may itself be decoded: the input is depth 0,
/// text decoded from it depth 1, and so on.
pub(crate) const MAX_NESTED_DECODE_DEPTH: u8 = 2;

/// Fewer Base64 characters than this is not worth decoding.
const MIN_RUN_CHARS: usize = 64;

/// A run is only attempted when its first token has at least this many
/// characters; shorter words and identifiers are prose.
const MIN_FIRST_TOKEN_CHARS: usize = 16;

/// Most spaces or tabs skipped in one gap between two tokens of a run.
const MAX_GAP: usize = 256;

/// Start of every PEM block.
const BEGIN_MARKER: &[u8] = b"-----BEGIN ";

/// Character of the standard or URL-safe alphabet, or padding.
const fn is_alphabet(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=')
}

/// Maps the URL-safe characters to the standard alphabet.
const fn normalize(b: u8) -> u8 {
    match b {
        b'-' => b'+',
        b'_' => b'/',
        other => other,
    }
}

/// End of the token (maximal alphabet sequence) that starts at `from`, never
/// past `limit`.
fn token_end(input: &[u8], from: usize, limit: usize) -> usize {
    let mut j = from;
    while j < limit && input.get(j).is_some_and(|&c| is_alphabet(c)) {
        j += 1;
    }
    j
}

/// Position after at most [`MAX_GAP`] spaces or tabs starting at `from`.
fn skip_blanks(input: &[u8], from: usize, limit: usize) -> usize {
    let mut j = from;
    while j < limit && j - from < MAX_GAP && input.get(j).is_some_and(|&c| c == b' ' || c == b'\t')
    {
        j += 1;
    }
    j
}

/// Whether the token that ends at `end` closes its line: a line break, the end
/// of the text, or a closing quote, bracket or comma (the end of a JSON or YAML
/// string that holds the last line of a wrapped value). A `.` or `:` does not,
/// so a `key: value` line is never taken for a continuation.
fn closes_line(input: &[u8], end: usize, limit: usize) -> bool {
    let pos = skip_blanks(input, end, limit);
    pos >= limit
        || separator_len(input, pos).is_some()
        || input
            .get(pos)
            .is_some_and(|b| matches!(b, b'"' | b'\'' | b',' | b'}' | b']' | b')'))
}

/// Start of the next token when the run continues on the next line: a line
/// break, optional indentation, and a token that is alone on its line.
fn continuation(input: &[u8], from: usize, limit: usize) -> Option<usize> {
    let brk = skip_blanks(input, from, limit);
    let after = brk.checked_add(separator_len(input, brk)?)?;
    if after > limit {
        return None;
    }
    let next = skip_blanks(input, after, limit);
    if !input
        .get(next)
        .is_some_and(|&c| next < limit && is_alphabet(c))
    {
        return None;
    }
    let end = token_end(input, next, limit);
    closes_line(input, end, limit).then_some(next)
}

/// A Base64 run: its characters (URL-safe mapped to the standard alphabet,
/// padding left out) and where the scan resumes.
struct Run {
    chars: Vec<u8>,
    end: usize,
}

/// Collects the run whose first token starts at `start` and ends at
/// `first_end`. The run stops at padding (`=`) and at the first line that is
/// not a lone token.
fn collect_run(input: &[u8], start: usize, first_end: usize, limit: usize) -> Run {
    let mut chars: Vec<u8> = Vec::new();
    let mut pos = start;
    let mut end = first_end;
    loop {
        let token = input.get(pos..end).unwrap_or_default();
        let data = token.split(|&b| b == b'=').next().unwrap_or_default();
        chars.extend(data.iter().map(|&b| normalize(b)));
        if data.len() < token.len() {
            // Padding ends the run.
            break;
        }
        let Some(next) = continuation(input, end, limit) else {
            break;
        };
        pos = next;
        end = token_end(input, next, limit);
    }
    Run { chars, end }
}

/// Whether `text` is nothing but Base64 characters and whitespace, at least
/// [`MIN_RUN_CHARS`] of them: a wrapped layer.
fn is_base64_text(text: &[u8]) -> bool {
    let mut chars = 0usize;
    for &b in text {
        if is_alphabet(b) {
            chars += 1;
        } else if !b.is_ascii_whitespace() {
            return false;
        }
    }
    chars >= MIN_RUN_CHARS
}

/// Whether decoded `text` is worth scanning again.
fn worth_scanning(text: &[u8]) -> bool {
    text.windows(BEGIN_MARKER.len()).any(|w| w == BEGIN_MARKER) || is_base64_text(text)
}

/// Decoded text waiting to be scanned.
struct Work {
    text: Vec<u8>,
    /// Offset of the top-level run it came from, inherited by everything
    /// found inside.
    offset: usize,
    /// Depth of `text`.
    depth: u8,
}

/// The work queue and the decoding budget.
struct Queue {
    items: VecDeque<Work>,
    /// Bytes decoded so far, across all runs and layers.
    decoded: usize,
    /// Most bytes that may be decoded: twice the input.
    budget: usize,
}

impl Queue {
    /// Decodes the Base64 runs of `text` (found outside `consumed`) and queues
    /// the ones worth scanning, one level deeper than `depth`. `inherited` is
    /// the offset of the top-level run `text` came from; for the input itself
    /// each run is its own offset. Rejections go to `det`.
    fn enqueue_runs(
        &mut self,
        text: &[u8],
        consumed: &[Range<usize>],
        depth: u8,
        inherited: Option<usize>,
        det: &mut Detections,
    ) {
        for region in free_regions(text.len(), consumed) {
            // The start of a region counts as a token start even when the
            // byte before it (inside a claimed range) is an alphabet byte.
            let mut i = region.start;
            while i < region.end {
                let Some(&b) = text.get(i) else { break };
                let at_token_start = i == region.start
                    || i.checked_sub(1)
                        .and_then(|p| text.get(p))
                        .is_none_or(|&prev| !is_alphabet(prev));
                if !is_alphabet(b) || !at_token_start {
                    i += 1;
                    continue;
                }
                let first_end = token_end(text, i, region.end);
                if first_end - i < MIN_FIRST_TOKEN_CHARS {
                    i = first_end;
                    continue;
                }
                let run = collect_run(text, i, first_end, region.end);
                let end = run.end;
                if run.chars.len() >= MIN_RUN_CHARS {
                    let offset = inherited.unwrap_or(i);
                    if self.decode(run.chars, offset, depth, det) {
                        det.consumed.push(i..end);
                    }
                    i = end;
                } else {
                    i = first_end;
                }
            }
        }
    }

    /// Decodes one run and queues the result when it is worth scanning.
    /// Returns whether it was queued.
    fn decode(
        &mut self,
        mut chars: Vec<u8>,
        offset: usize,
        depth: u8,
        det: &mut Detections,
    ) -> bool {
        if chars.len() % 4 == 1 {
            // A dangling sixth of a byte is not decodable; take the valid prefix.
            chars.pop();
        }
        let estimate = (chars.len() / 4 + 1).saturating_mul(3);
        if self.decoded.saturating_add(estimate) > self.budget {
            det.reject(offset, RejectReason::TooLarge);
            return false;
        }
        let Ok(text) = LENIENT.decode(&chars) else {
            return false;
        };
        drop(chars);
        self.decoded = self.decoded.saturating_add(text.len());
        if !worth_scanning(&text) {
            return false;
        }
        let Some(next_depth) = depth.checked_add(1) else {
            return false;
        };
        if next_depth > MAX_NESTED_DECODE_DEPTH {
            det.reject(offset, RejectReason::NestingTooDeep);
            return false;
        }
        self.items.push_back(Work {
            text,
            offset,
            depth: next_depth,
        });
        true
    }
}

/// Adds what was found in decoded text to the outer detections: every
/// candidate and diagnostic gets the offset of the top-level run.
fn merge(det: &mut Detections, inner: Detections, offset: usize) {
    for d in inner.diagnostics {
        det.reject(offset, d.reason);
    }
    det.diagnostics_truncated |= inner.diagnostics_truncated;
    det.private_key_blocks_ignored = det
        .private_key_blocks_ignored
        .saturating_add(inner.private_key_blocks_ignored);
    det.truncated |= inner.truncated;
    for c in inner.candidates {
        let candidate = Candidate { offset, ..c };
        if !det.push_candidate(candidate) {
            break;
        }
    }
}

/// Finds Base64 runs outside the `consumed` ranges that decode to text
/// holding certificates, scans that text (and, to a bounded depth, the text
/// decoded from it) with the other detectors, and records everything in
/// `det`. Returns the number of bytes decoded, which never exceeds twice
/// `input.len()`.
pub(crate) fn find_nested_base64(
    input: &[u8],
    consumed: &[Range<usize>],
    limits: &Limits,
    det: &mut Detections,
) -> usize {
    let mut queue = Queue {
        items: VecDeque::new(),
        decoded: 0,
        budget: input.len().saturating_mul(2),
    };
    queue.enqueue_runs(input, consumed, 0, None, det);
    while let Some(work) = queue.items.pop_front() {
        if det.truncated {
            break;
        }
        let mut inner = Detections::new(limits);
        super::scan_flat(&work.text, limits, &mut inner);
        let claimed = inner.consumed.as_slice().to_vec();
        queue.enqueue_runs(
            &work.text,
            &claimed,
            work.depth,
            Some(work.offset),
            &mut inner,
        );
        merge(det, inner, work.offset);
    }
    queue.decoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::CandidateKind;
    use base64::engine::general_purpose::STANDARD;

    fn leaf_pem() -> String {
        let der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/chain-3.der"
        ))
        .unwrap();
        let b64 = STANDARD.encode(der);
        let body: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            body.join("\n")
        )
    }

    fn run(input: &[u8], claimed: &[Range<usize>]) -> (Detections, usize) {
        let mut det = Detections::new(&Limits::default());
        for r in claimed {
            det.consumed.push(r.clone());
        }
        let snapshot = det.consumed.as_slice().to_vec();
        let decoded = find_nested_base64(input, &snapshot, &Limits::default(), &mut det);
        (det, decoded)
    }

    #[test]
    fn quando_corrida_toca_range_consumido_deve_cortar_na_fronteira() {
        let b64 = STANDARD.encode(leaf_pem());
        let text = format!("{b64}ruido");
        let cut = b64.len() / 2;
        let tail = cut..text.len();
        let (det, _) = run(text.as_bytes(), std::slice::from_ref(&tail));
        // Half a PEM does not hold a certificate, and nothing crosses the cut.
        assert_eq!(det.candidates.len(), 0);
        assert!(
            det.consumed
                .as_slice()
                .iter()
                .all(|r| r.end <= cut || r.start >= cut)
        );
    }

    #[test]
    fn quando_corrida_ja_foi_consumida_deve_nao_decodificar_de_novo() {
        let b64 = STANDARD.encode(leaf_pem());
        let claimed = 0..b64.len();
        let (det, decoded) = run(b64.as_bytes(), std::slice::from_ref(&claimed));
        assert_eq!(det.candidates.len(), 0);
        assert_eq!(decoded, 0);
    }

    #[test]
    fn quando_corrida_aninhada_decodifica_deve_herdar_o_offset_do_pai() {
        let b64 = STANDARD.encode(leaf_pem());
        let text = format!("data:\n  tls.crt: {b64}\n");
        let (det, decoded) = run(text.as_bytes(), &[]);
        assert_eq!(det.candidates.len(), 1);
        assert_eq!(det.candidates[0].offset, "data:\n  tls.crt: ".len());
        assert_eq!(det.candidates[0].kind, CandidateKind::Certificate);
        assert!(decoded <= 2 * text.len());
    }

    #[test]
    fn quando_ha_bomba_de_base64_aninhado_deve_decodificar_no_maximo_o_dobro_da_entrada() {
        let mut layer = "A".repeat(1_769_472).into_bytes();
        for _ in 0..3 {
            layer = STANDARD.encode(&layer).into_bytes();
        }
        assert!(layer.len() >= 4 * 1024 * 1024 - 8);
        let started = std::time::Instant::now();
        let (det, decoded) = run(&layer, &[]);
        assert!(
            decoded <= 2 * layer.len(),
            "{decoded} > 2 * {}",
            layer.len()
        );
        assert!(
            decoded > layer.len() / 2,
            "a bomba deve ter sido decodificada"
        );
        let reasons: Vec<RejectReason> = det.diagnostics.iter().map(|d| d.reason).collect();
        assert_eq!(reasons, vec![RejectReason::NestingTooDeep]);
        assert_eq!(det.diagnostics[0].offset, 0);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
