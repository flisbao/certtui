//! Detector of DER certificates written in hexadecimal.
//!
//! A run is the longest sequence of hex digits (`[0-9a-fA-F]`) that may be
//! split in pairs by `:`, spaces, line feeds and carriage returns (a
//! separator is accepted only after a whole pair, never between the two
//! digits of a byte). Separators are dropped, the digits decoded, and the run
//! must start with `30 82` or `30 81` (a DER `SEQUENCE` with a long length);
//! it is cut at the length that header declares. A run may span lines.
//!
//! Known limit: a hex certificate that is truncated, with another hex
//! certificate on the following line(s), is read as one run. The first header
//! declares more bytes than the truncated text holds, so the cut falls inside
//! the second certificate and the result is garbage. The garbage is a
//! `Candidate` like any other and is rejected downstream (the X.509 parse, and
//! the structural check of the deduplication step).
//!
//! Not supported: hexdumps with an offset column or an ASCII column
//! (`00000000: 3082 02ee ...  0...`); those extra columns end the run.
//!
//! A run is only attempted at the start of a hex token (the previous byte is
//! not a hex digit), so words made of hex letters ("deadbeef", "face") cost
//! one comparison. The cursor only moves forward, a failed attempt reads at
//! most a few digits (a bad prefix) or the run itself (which is then
//! claimed), and a run never crosses ranges claimed by earlier detectors, so
//! the cost is linear.

use std::ops::Range;

use super::der_len::der_total_len;
use super::free_regions;
use super::{Candidate, CandidateKind, Detections, RejectReason};
use crate::limits::Limits;

/// Fewer hex digits than this is not worth a diagnostic: it cannot be a
/// certificate and is most likely a hash, an identifier or prose.
pub(crate) const MIN_HEX_DIGITS: usize = 200;

/// A header declaring a `SEQUENCE` smaller than this (in bytes) is not a
/// certificate; the run is skipped without a diagnostic.
const MIN_HEX_DER_BYTES: usize = 100;

/// Value of the hex digit `b`.
fn nibble(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|v| u8::try_from(v).ok())
}

/// Separators accepted between pairs of hex digits.
const fn is_separator(b: u8) -> bool {
    matches!(b, b':' | b' ' | b'\n' | b'\r')
}

/// Hex digits of the run starting at `start`, as `(offset, value)`. Separators
/// are skipped (only between pairs); the iterator ends at any other byte or at
/// `limit`.
struct HexDigits<'a> {
    input: &'a [u8],
    pos: usize,
    limit: usize,
    count: usize,
}

impl Iterator for HexDigits<'_> {
    type Item = (usize, u8);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos >= self.limit {
                return None;
            }
            let b = *self.input.get(self.pos)?;
            if let Some(v) = nibble(b) {
                self.pos += 1;
                self.count += 1;
                return Some((self.pos - 1, v));
            }
            if is_separator(b) && self.count.is_multiple_of(2) {
                self.pos += 1;
            } else {
                return None;
            }
        }
    }
}

/// End of the maximal run of hex digits that starts at `from`, never past
/// `limit`.
fn token_end(input: &[u8], from: usize, limit: usize) -> usize {
    let mut j = from;
    while j < limit && input.get(j).is_some_and(u8::is_ascii_hexdigit) {
        j += 1;
    }
    j
}

/// How an attempt at a run ended.
enum Attempt {
    /// A certificate was found; the scan resumes where it ends, and a new run
    /// may start there even in the middle of a hex token.
    Found(usize),
    /// Nothing usable; the scan resumes here.
    Skip(usize),
    /// The per-source candidate limit was reached.
    Stop,
}

/// Rejects a certificate whose declared size is over the limit and claims the
/// part of the run that was read, so the sequences nested inside it are not
/// taken for certificates of their own.
fn reject_oversize(det: &mut Detections, start: usize, end: usize) -> Attempt {
    det.reject(start, RejectReason::TooLarge);
    det.consumed.push(start..end);
    Attempt::Skip(end)
}

/// Examines the run that starts at `start`, a hex digit at the start of a hex
/// token.
fn try_run(
    input: &[u8],
    start: usize,
    limit: usize,
    limits: &Limits,
    det: &mut Detections,
) -> Attempt {
    let mut bytes: Vec<u8> = Vec::new();
    let mut high: Option<u8> = None;
    let mut digits = 0usize;
    let mut last_end = start;
    // Bytes the DER header declares, once its first bytes are known.
    let mut total: Option<usize> = None;
    // Set when the declared size is over the limit: the bytes are no longer
    // kept, but the whole declared extent is still claimed.
    let mut oversize = false;

    let run = HexDigits {
        input,
        pos: start,
        limit,
        count: 0,
    };
    for (pos, value) in run {
        digits += 1;
        last_end = pos + 1;
        let Some(h) = high.take() else {
            high = Some(value);
            continue;
        };
        if oversize {
            let declared = total.unwrap_or(0).saturating_mul(2);
            if digits >= declared {
                return reject_oversize(det, start, last_end);
            }
            continue;
        }
        bytes.push((h << 4) | value);
        match bytes.as_slice() {
            // Not `30 82` / `30 81`: only the first token is condemned, so a
            // certificate that starts at the next token is still found.
            [first] if *first != 0x30 => {
                return Attempt::Skip(token_end(input, start, limit).max(start + 1));
            }
            [_, second] if !matches!(*second, 0x81 | 0x82) => {
                return Attempt::Skip(token_end(input, start, limit).max(start + 1));
            }
            _ => {}
        }
        if total.is_none() {
            total = der_total_len(&bytes);
            if let Some(t) = total {
                if t < MIN_HEX_DER_BYTES {
                    return Attempt::Skip(last_end);
                }
                oversize = t > limits.max_cert_der_bytes;
            }
        }
        if oversize {
            continue;
        }
        if let Some(t) = total
            && bytes.len() >= t
        {
            bytes.truncate(t);
            det.consumed.push(start..last_end);
            let pushed = det.push_candidate(Candidate {
                offset: start,
                kind: CandidateKind::Certificate,
                der: bytes,
            });
            return if pushed {
                Attempt::Found(last_end)
            } else {
                Attempt::Stop
            };
        }
    }

    if oversize {
        return reject_oversize(det, start, last_end);
    }
    // The run ended before the declared length (or before the header was
    // complete): a truncated or odd-length certificate, or just hex-looking
    // prose when it is short.
    if digits >= MIN_HEX_DIGITS {
        det.reject(start, RejectReason::LengthMismatch);
        det.consumed.push(start..last_end);
    }
    Attempt::Skip(last_end)
}

/// Finds DER certificates written in hex outside the `consumed` ranges
/// (sorted, non-overlapping, as claimed by earlier detectors) and records
/// candidates, rejections and the ranges it claims in `det`.
pub(crate) fn find_hex_der(
    input: &[u8],
    consumed: &[Range<usize>],
    limits: &Limits,
    det: &mut Detections,
) {
    for region in free_regions(input.len(), consumed) {
        // Where a run may start even in the middle of a hex token: the start
        // of the region and the end of a certificate just found.
        let mut fresh = region.start;
        let mut i = region.start;
        while i < region.end {
            let Some(&b) = input.get(i) else { break };
            let at_token_start = i == fresh
                || i.checked_sub(1)
                    .and_then(|p| input.get(p))
                    .is_none_or(|prev| !prev.is_ascii_hexdigit());
            if !b.is_ascii_hexdigit() || !at_token_start {
                i += 1;
                continue;
            }
            match try_run(input, i, region.end, limits, det) {
                Attempt::Found(end) => {
                    i = end.max(i + 1);
                    fresh = i;
                }
                Attempt::Skip(resume) => i = resume.max(i + 1),
                Attempt::Stop => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_der() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/chain-3.der"
        ))
        .unwrap()
    }

    fn hex(bytes: &[u8], sep: &str) -> String {
        let pairs: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
        pairs.join(sep)
    }

    fn run(input: &[u8], claimed: &[Range<usize>]) -> Detections {
        let mut det = Detections::new(&Limits::default());
        for r in claimed {
            det.consumed.push(r.clone());
        }
        let snapshot = det.consumed.as_slice().to_vec();
        find_hex_der(input, &snapshot, &Limits::default(), &mut det);
        det
    }

    #[test]
    fn quando_corrida_toca_range_consumido_deve_cortar_na_fronteira() {
        let text = format!("{}ruido", hex(&leaf_der(), ""));
        let cut = text.len() / 2;
        let tail = cut..text.len();
        let det = run(text.as_bytes(), std::slice::from_ref(&tail));
        assert_eq!(det.candidates.len(), 0);
        let reasons: Vec<RejectReason> = det.diagnostics.iter().map(|d| d.reason).collect();
        assert_eq!(reasons, vec![RejectReason::LengthMismatch]);
        assert_eq!(det.consumed.as_slice(), &[0..cut, tail]);
    }

    #[test]
    fn quando_corrida_comeca_dentro_de_range_consumido_deve_pular() {
        let text = format!("xx {}", hex(&leaf_der(), ""));
        let claimed = 3..text.len();
        let det = run(text.as_bytes(), std::slice::from_ref(&claimed));
        assert_eq!(det.candidates.len(), 0);
        assert_eq!(det.diagnostics.len(), 0);
        assert_eq!(det.consumed.as_slice(), &[claimed]);
    }

    #[test]
    fn quando_corrida_termina_antes_de_range_consumido_deve_achar_o_certificado() {
        let h = hex(&leaf_der(), ":");
        let text = format!("{h}\nXXXXXXXXXXXX");
        let tail = h.len() + 1..text.len();
        let det = run(text.as_bytes(), std::slice::from_ref(&tail));
        assert_eq!(det.candidates.len(), 1);
        assert_eq!(det.candidates[0].offset, 0);
        assert_eq!(det.consumed.as_slice(), &[0..h.len(), tail]);
    }

    #[test]
    fn quando_der_acaba_no_meio_do_token_deve_reiniciar_no_resto() {
        let h = hex(&leaf_der(), "");
        let text = format!("{h}{h}");
        let det = run(text.as_bytes(), &[]);
        assert_eq!(det.candidates.len(), 2);
        assert_eq!(det.candidates[1].offset, h.len());
    }

    #[test]
    fn quando_separador_vem_no_meio_do_par_deve_encerrar_a_corrida() {
        // `3 0` is not a pair: the run ends after the first digit.
        let det = run(
            format!("3 0 82 {}", hex(&leaf_der()[3..], "")).as_bytes(),
            &[],
        );
        assert_eq!(det.candidates.len(), 0);
        assert_eq!(det.diagnostics.len(), 0);
    }
}
