//! Detector of bare Base64 DER certificates in free text (no PEM header).
//!
//! A "run" starts at a token (a maximal sequence of Base64 characters) that
//! begins with `MI` (the first bytes of any DER `SEQUENCE` with a long length)
//! and continues across spaces, line breaks and literal `\n` / `\r` escapes.
//! The cursor only moves forward and every byte is examined a bounded number
//! of times, so the cost is linear. Runs never cross ranges already claimed by
//! the PEM detector.

use std::ops::Range;

use base64::Engine as _;

use super::der_len::der_total_len;
use super::pem::{LENIENT, body_bound, decode_der};
use super::{Candidate, CandidateKind, Detections, RejectReason};
use crate::limits::Limits;

/// Fewer alphabet characters than this is not worth a diagnostic: it cannot be
/// a certificate and is most likely an ordinary word or identifier.
pub(crate) const MIN_BARE_BASE64_CHARS: usize = 200;

/// A run is only attempted when its first token (up to the first whitespace,
/// line break or non-alphabet byte) has at least this many characters; shorter
/// `MI...` words ("MIT", "MIME", "MICROSOFT") are prose.
const MIN_FIRST_TOKEN_CHARS: usize = 16;

/// Base64 characters needed to decode the 6 bytes of the longest DER header
/// this module accepts (`30 84 xx xx xx xx`).
const HEADER_CHARS: usize = 8;

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

/// Whether a literal `\n` or `\r` escape starts at `i`.
fn is_literal_break(input: &[u8], i: usize) -> bool {
    input.get(i) == Some(&b'\\') && matches!(input.get(i + 1), Some(b'n' | b'r'))
}

/// Alphabet characters of the run starting at `start`, as `(offset, byte)`.
/// Whitespace and literal line-break escapes between them are skipped; the
/// iterator ends at any other byte or at `limit`.
struct RunChars<'a> {
    input: &'a [u8],
    pos: usize,
    limit: usize,
}

fn run_chars(input: &[u8], start: usize, limit: usize) -> RunChars<'_> {
    RunChars {
        input,
        pos: start,
        limit,
    }
}

impl Iterator for RunChars<'_> {
    type Item = (usize, u8);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pos >= self.limit {
                return None;
            }
            let b = *self.input.get(self.pos)?;
            if is_alphabet(b) {
                self.pos += 1;
                return Some((self.pos - 1, b));
            }
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else if is_literal_break(self.input, self.pos) && self.pos + 2 <= self.limit {
                self.pos += 2;
            } else {
                return None;
            }
        }
    }
}

/// End of the token (maximal alphabet sequence) that contains or touches
/// `from`, never past `limit`.
fn token_end(input: &[u8], from: usize, limit: usize) -> usize {
    let mut j = from;
    while j < limit && input.get(j).is_some_and(|&c| is_alphabet(c)) {
        j += 1;
    }
    j
}

/// Rejects only the first token of a run whose first bytes are not a DER
/// header, so a real certificate on a following line is still found. Reported
/// (and claimed) only when the token alone is long enough to be worth it.
/// Returns where the scan resumes: the end of that token.
fn reject_first_token(input: &[u8], start: usize, limit: usize, det: &mut Detections) -> usize {
    let end = token_end(input, start, limit);
    if end.saturating_sub(start) >= MIN_BARE_BASE64_CHARS {
        det.reject(start, RejectReason::NotDerSequence);
        det.consumed.push(start..end);
    }
    end
}

/// Characters of Base64 holding `total` bytes.
fn chars_for(total: usize) -> usize {
    total.saturating_mul(8).div_ceil(6)
}

/// From the first characters of a run: `Some(n)` when they decode to a DER
/// header declaring a certificate that needs `n` characters, `None` when they
/// are not a DER `SEQUENCE` header.
fn declared_chars(head: &[u8]) -> Option<usize> {
    let bytes = LENIENT.decode(head).ok()?;
    der_total_len(&bytes).map(chars_for)
}

/// Examines the run that starts at `start` (a token beginning with `MI`).
///
/// Returns where the scan resumes, or `None` when the per-source candidate
/// limit was reached and the scan must stop.
fn try_run(
    input: &[u8],
    start: usize,
    limit: usize,
    limits: &Limits,
    det: &mut Detections,
) -> Option<usize> {
    let bound = body_bound(CandidateKind::Certificate, limits);
    let mut buf: Vec<u8> = Vec::new();
    let mut chars = 0usize;
    let mut last_end = start;
    let mut capped = false;
    // Characters the DER header declares, once its first bytes are known.
    let mut header: Option<usize> = None;

    // Stop as soon as the outcome is settled and the run is long enough to be
    // reported, so a run followed by more certificates is not scanned again
    // for each of them.
    for (pos, b) in run_chars(input, start, limit) {
        chars += 1;
        last_end = pos + 1;
        if b == b'=' {
            break;
        }
        if buf.len() < bound {
            buf.push(normalize(b));
            if header.is_none()
                && let Some(head) = buf.get(..HEADER_CHARS)
            {
                // The first token has at least `MIN_FIRST_TOKEN_CHARS` > header
                // characters, so a bad header condemns that token only.
                let Some(needed) = declared_chars(head) else {
                    return Some(reject_first_token(input, start, limit, det));
                };
                header = Some(needed);
            }
        } else {
            capped = true;
        }
        let settled = capped || header.is_some_and(|needed| buf.len() >= needed);
        if settled && chars >= MIN_BARE_BASE64_CHARS {
            break;
        }
    }

    if chars < MIN_BARE_BASE64_CHARS {
        return Some(token_end(input, last_end, limit).max(last_end));
    }
    if buf.len() % 4 == 1 {
        // A dangling sixth of a byte is not decodable; take the valid prefix.
        buf.pop();
    }
    match decode_der(&buf, CandidateKind::Certificate, limits) {
        Ok(der) => {
            let used = chars_for(der.len());
            let end = used
                .checked_sub(1)
                .and_then(|n| run_chars(input, start, limit).nth(n))
                .map_or(last_end, |(pos, _)| pos + 1);
            // Padding glued to the data belongs to the certificate.
            let padding = input
                .get(end..limit)
                .map_or(0, |t| t.iter().take(2).take_while(|&&c| c == b'=').count());
            let end = end + padding;
            det.consumed.push(start..end);
            let pushed = det.push_candidate(Candidate {
                offset: start,
                kind: CandidateKind::Certificate,
                der,
            });
            pushed.then_some(end)
        }
        Err(reason) => {
            let reason = match reason {
                // The run was cut at the size bound, so the rest was not read.
                RejectReason::LengthMismatch if capped => RejectReason::TooLarge,
                other => other,
            };
            det.reject(start, reason);
            det.consumed.push(start..last_end);
            Some(token_end(input, last_end, limit).max(last_end))
        }
    }
}

/// Finds bare Base64 DER certificates outside the `consumed` ranges (sorted,
/// non-overlapping, as claimed by earlier detectors) and records candidates,
/// rejections and the ranges it claims in `det`.
pub(crate) fn find_bare_base64(
    input: &[u8],
    consumed: &[Range<usize>],
    limits: &Limits,
    det: &mut Detections,
) {
    let mut i = 0;
    let mut ri = 0;
    while let Some(&b) = input.get(i) {
        while consumed.get(ri).is_some_and(|r| r.end <= i) {
            ri += 1;
        }
        let next = consumed.get(ri);
        if let Some(r) = next
            && r.start <= i
        {
            i = r.end;
            continue;
        }
        let limit = next.map_or(input.len(), |r| r.start);
        if is_literal_break(input, i) {
            i += 2;
        } else if is_alphabet(b) {
            // Cheap tests first: a success that ends mid-token must resume in
            // O(1), so the token is measured only when it is skipped.
            let rest = input.get(i..limit).unwrap_or_default();
            let attempt = rest.starts_with(b"MI")
                && rest
                    .get(..MIN_FIRST_TOKEN_CHARS)
                    .is_some_and(|head| head.iter().all(|&c| is_alphabet(c)));
            if attempt {
                let Some(resume) = try_run(input, i, limit, limits, det) else {
                    return;
                };
                i = resume.max(i + 1);
            } else {
                i = token_end(input, i, limit).max(i + 1);
            }
        } else {
            i += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_b64() -> String {
        let der = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/chain-3.der"
        ))
        .unwrap();
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    fn run(input: &[u8], claimed: &[Range<usize>]) -> Detections {
        let mut det = Detections::new(&Limits::default());
        for r in claimed {
            det.consumed.push(r.clone());
        }
        let snapshot = det.consumed.as_slice().to_vec();
        find_bare_base64(input, &snapshot, &Limits::default(), &mut det);
        det
    }

    #[test]
    fn quando_corrida_toca_range_consumido_deve_cortar_na_fronteira() {
        let b64 = leaf_b64();
        let text = format!("{b64}ruido");
        let cut = b64.len() / 2;
        let tail = cut..text.len();
        let det = run(text.as_bytes(), std::slice::from_ref(&tail));
        assert_eq!(det.candidates.len(), 0);
        let reasons: Vec<RejectReason> = det.diagnostics.iter().map(|d| d.reason).collect();
        assert_eq!(reasons, vec![RejectReason::LengthMismatch]);
        // Only the first half was claimed; nothing crosses the boundary.
        assert_eq!(det.consumed.as_slice(), &[0..cut, tail]);
    }

    #[test]
    fn quando_corrida_comeca_dentro_de_range_consumido_deve_pular() {
        let b64 = leaf_b64();
        let text = format!("xx {b64}");
        let claimed = 3..text.len();
        let det = run(text.as_bytes(), std::slice::from_ref(&claimed));
        assert_eq!(det.candidates.len(), 0);
        assert_eq!(det.diagnostics.len(), 0);
        assert_eq!(det.consumed.as_slice(), &[claimed]);
    }

    #[test]
    fn quando_corrida_termina_antes_de_range_consumido_deve_achar_o_certificado() {
        let b64 = leaf_b64();
        let text = format!("{b64}\nXXXXXXXXXXXX");
        let tail = b64.len() + 1..text.len();
        let det = run(text.as_bytes(), std::slice::from_ref(&tail));
        assert_eq!(det.candidates.len(), 1);
        assert_eq!(det.candidates[0].offset, 0);
        assert_eq!(det.consumed.as_slice(), &[0..b64.len(), tail]);
    }

    #[test]
    fn quando_der_acaba_no_meio_do_token_deve_reiniciar_no_resto() {
        let b64 = leaf_b64();
        let text = format!("{b64}{b64}");
        let det = run(text.as_bytes(), &[]);
        assert_eq!(det.candidates.len(), 2);
        assert_eq!(det.candidates[1].offset, b64.len());
    }

    /// A DER `SEQUENCE` of `total` bytes (`total >= 260`), as a Base64 string.
    fn synthetic_b64(total: usize) -> String {
        let content = total - 4;
        let len = u16::try_from(content).unwrap_or(u16::MAX).to_be_bytes();
        let mut der = vec![0x30, 0x82, len[0], len[1]];
        der.extend(std::iter::repeat_n(0x05, content));
        base64::engine::general_purpose::STANDARD.encode(der)
    }

    #[test]
    fn quando_base64_tem_padding_colado_no_proximo_deve_reclamar_o_padding_com_o_certificado() {
        for (total, pad) in [(301, "=="), (302, "="), (300, "")] {
            let one = synthetic_b64(total);
            assert!(
                one.ends_with(pad) && !one.ends_with(&format!("{pad}=")),
                "{total}"
            );
            let det = run(format!("{one}{one}{one}").as_bytes(), &[]);
            let offsets: Vec<usize> = det.candidates.iter().map(|c| c.offset).collect();
            assert_eq!(offsets, vec![0, one.len(), 2 * one.len()], "{total}");
        }
    }
}
