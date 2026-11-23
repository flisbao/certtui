//! PEM detector tolerant to noise around and inside the blocks.
//!
//! One forward pass over the input: the cursor always advances, a `BEGIN`
//! looks for its `END` only up to the next `BEGIN` or the end of the input,
//! and no consumed byte is read again, so the cost is linear.

use base64::Engine as _;
use base64::alphabet::STANDARD as STANDARD_ALPHABET;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

use super::der_len::der_total_len;
use super::lines::split_lines;
use super::{Candidate, CandidateKind, Detections, RejectReason};
use crate::limits::Limits;

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";
const MAX_LABEL_LEN: usize = 64;

/// Standard alphabet, padding optional, trailing bits tolerated.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &STANDARD_ALPHABET,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Marker {
    Begin,
    End,
}

/// First `-----BEGIN ` or `-----END ` at or after `from`.
fn find_marker(input: &[u8], from: usize) -> Option<(usize, Marker)> {
    let mut i = from;
    while let Some(rest) = input.get(i..) {
        i += rest.iter().position(|&b| b == b'-')?;
        let at = input.get(i..)?;
        if at.starts_with(BEGIN) {
            return Some((i, Marker::Begin));
        }
        if at.starts_with(END) {
            return Some((i, Marker::End));
        }
        i += 1;
    }
    None
}

/// Parses `LABEL-----` right after a marker prefix. Returns the label and the
/// position just after the closing dashes.
fn parse_label(input: &[u8], label_start: usize) -> Option<(&[u8], usize)> {
    let tail = input.get(label_start..)?;
    let len = tail
        .iter()
        .take(MAX_LABEL_LEN + 1)
        .take_while(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || **b == b' ')
        .count();
    if len == 0 || len > MAX_LABEL_LEN {
        return None;
    }
    let label = tail.get(..len)?;
    tail.get(len..)?
        .starts_with(DASHES)
        .then(|| (label, label_start + len + DASHES.len()))
}

fn kind_for(label: &[u8]) -> Option<CandidateKind> {
    match label {
        b"CERTIFICATE" | b"TRUSTED CERTIFICATE" | b"X509 CERTIFICATE" => {
            Some(CandidateKind::Certificate)
        }
        b"PKCS7" | b"CMS" => Some(CandidateKind::Pkcs7),
        _ => None,
    }
}

const fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
}

/// Upper bound on the Base64 characters of a body for `kind`.
fn body_bound(kind: CandidateKind, limits: &Limits) -> usize {
    let max_der = match kind {
        CandidateKind::Certificate => limits.max_cert_der_bytes,
        CandidateKind::Pkcs7 => limits.max_input_file_bytes,
    };
    (max_der.saturating_mul(4) / 3).saturating_add(4)
}

/// Collects the Base64 characters of `body`, line by line: noise before the
/// first and after the last Base64 character of a line is dropped, spaces
/// inside are ignored and any other byte is an error.
fn collect_base64(body: &[u8], bound: usize) -> Result<Vec<u8>, RejectReason> {
    let mut out: Vec<u8> = Vec::new();
    for (_, line) in split_lines(body) {
        let Some(first) = line.iter().position(|&b| is_b64(b)) else {
            continue;
        };
        let Some(last) = line.iter().rposition(|&b| is_b64(b)) else {
            continue;
        };
        let mut core = line.get(first..=last).unwrap_or_default();
        // A `// ` comment prefix is made of Base64 characters; it stands
        // alone before a trailing `END` marker.
        if core.starts_with(b"//") && core.get(2).is_none_or(u8::is_ascii_whitespace) {
            core = core.get(2..).unwrap_or_default();
        }
        for &b in core {
            if is_b64(b) {
                if out.len() >= bound {
                    return Err(RejectReason::TooLarge);
                }
                out.push(b);
            } else if !b.is_ascii_whitespace() {
                return Err(RejectReason::InvalidBase64);
            }
        }
    }
    Ok(out)
}

/// Decodes a collected body and cuts it at the DER length it declares.
fn decode_der(b64: &[u8], kind: CandidateKind, limits: &Limits) -> Result<Vec<u8>, RejectReason> {
    let mut der = LENIENT
        .decode(b64)
        .map_err(|_| RejectReason::InvalidBase64)?;
    let total = der_total_len(&der).ok_or(RejectReason::NotDerSequence)?;
    if total > der.len() {
        return Err(RejectReason::LengthMismatch);
    }
    if kind == CandidateKind::Certificate && total > limits.max_cert_der_bytes {
        return Err(RejectReason::TooLarge);
    }
    der.truncate(total);
    Ok(der)
}

/// Finds every PEM block in `input` and records candidates, rejections and
/// consumed ranges in `det`.
pub(super) fn detect(input: &[u8], limits: &Limits, det: &mut Detections) {
    let mut cursor = 0;
    while let Some((begin, marker)) = find_marker(input, cursor) {
        if marker == Marker::End {
            // A stray END: nothing to open, move past it.
            cursor = begin + END.len();
            continue;
        }
        let Some((label, body_start)) = parse_label(input, begin + BEGIN.len()) else {
            cursor = begin + BEGIN.len();
            continue;
        };
        let kind = kind_for(label);

        // Look for the matching END, stopping at the next BEGIN or at EOF.
        let (body_end, resume, result) = match find_marker(input, body_start) {
            Some((pos, Marker::End)) => match parse_label(input, pos + END.len()) {
                Some((end_label, after)) if end_label == label => (pos, after, Ok(())),
                Some((_, after)) => (pos, after, Err(RejectReason::LabelMismatch)),
                None => (pos, pos + END.len(), Err(RejectReason::UnterminatedPem)),
            },
            Some((pos, Marker::Begin)) => (pos, pos, Err(RejectReason::UnterminatedPem)),
            None => (input.len(), input.len(), Err(RejectReason::UnterminatedPem)),
        };
        det.consumed.push(begin..resume);
        cursor = resume;

        let Some(kind) = kind else {
            det.reject(begin, RejectReason::UnsupportedLabel);
            continue;
        };
        if let Err(reason) = result {
            det.reject(begin, reason);
            continue;
        }
        let body = input.get(body_start..body_end).unwrap_or_default();
        let decoded = collect_base64(body, body_bound(kind, limits))
            .and_then(|b64| decode_der(&b64, kind, limits));
        match decoded {
            Ok(der) => {
                if !det.push_candidate(Candidate {
                    offset: begin,
                    kind,
                    der,
                }) {
                    return;
                }
            }
            Err(reason) => det.reject(begin, reason),
        }
    }
}
