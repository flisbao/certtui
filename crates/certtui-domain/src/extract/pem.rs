//! PEM detector tolerant to noise around and inside the blocks.
//!
//! One forward pass over the input: the cursor always advances, a `BEGIN`
//! looks for its `END` only up to the next `BEGIN` or the end of the input,
//! and no consumed byte is read again, so the cost is linear.
//!
//! Private key blocks are skipped whole and never decoded (see
//! `is_private_key_label`). Their range is claimed through the matching `END`
//! or, when there is none, through the next `BEGIN` or the end of the input,
//! whatever the body looks like: a body interrupted by headers, blank lines or
//! prose is still the key. The price is deliberate: a certificate that sits
//! inside a broken (unterminated) key block, without a `BEGIN` line of its
//! own, is not found. A `BEGIN` line whose label is not upper case but names a
//! private key (`private key`, `RSA-PRIVATE-KEY`) is treated the same way.

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
pub(super) const LENIENT: GeneralPurpose = GeneralPurpose::new(
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

/// Whether `label` names a private key (`PRIVATE KEY`, `RSA PRIVATE KEY`,
/// `ENCRYPTED PRIVATE KEY`, ...). Such blocks are skipped, never decoded.
fn is_private_key_label(label: &[u8]) -> bool {
    let label = label.trim_ascii_end();
    label == b"PRIVATE KEY" || label.ends_with(b" PRIVATE KEY")
}

/// How far past `BEGIN ` the fallback looks for a private key label.
const FALLBACK_WINDOW: usize = 100;

/// Defense in depth for a `BEGIN` line whose label [`parse_label`] rejects
/// (lower case, `-` instead of a space, ...): when `PRIVATE` appears, in any
/// case, before the closing dashes within [`FALLBACK_WINDOW`] bytes of the
/// same line, the block is a private key. Returns where its body starts.
fn private_key_fallback(input: &[u8], label_start: usize) -> Option<usize> {
    let tail = input.get(label_start..)?;
    let line_len = tail
        .iter()
        .take(FALLBACK_WINDOW)
        .take_while(|&&b| b != b'\n' && b != b'\r')
        .count();
    let line = tail.get(..line_len)?;
    let dashes = line.windows(DASHES.len()).position(|w| w == DASHES);
    let head = line.get(..dashes.unwrap_or(line_len))?;
    head.windows(b"PRIVATE".len())
        .any(|w| w.eq_ignore_ascii_case(b"PRIVATE"))
        .then(|| label_start + dashes.map_or(line_len, |p| p + DASHES.len()))
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
pub(super) fn body_bound(kind: CandidateKind, limits: &Limits) -> usize {
    let max_der = match kind {
        CandidateKind::Certificate => limits.max_cert_der_bytes,
        CandidateKind::Pkcs7 => limits.max_input_file_bytes,
    };
    (max_der.saturating_mul(4) / 3).saturating_add(4)
}

/// The part of `line` that can hold Base64: noise before the first and after
/// the last Base64 character is dropped, and so is a `// ` comment prefix (it
/// is made of Base64 characters; it can stand alone before a trailing `END`
/// marker). `None` when nothing is left.
fn line_core(line: &[u8]) -> Option<&[u8]> {
    let first = line.iter().position(|&b| is_b64(b))?;
    let last = line.iter().rposition(|&b| is_b64(b))?;
    let mut core = line.get(first..=last)?;
    if core.starts_with(b"//") && core.get(2).is_none_or(u8::is_ascii_whitespace) {
        core = core.get(2..)?;
    }
    let core = core.trim_ascii_start();
    (!core.is_empty()).then_some(core)
}

/// One byte of a line core: a Base64 character (JSON `\/` counts as `/`), a
/// space to ignore, or an invalid byte.
enum CoreByte {
    Char(u8),
    Space,
    Invalid,
}

fn core_bytes(core: &[u8]) -> impl Iterator<Item = CoreByte> + '_ {
    let mut i = 0;
    std::iter::from_fn(move || {
        let b = *core.get(i)?;
        i += 1;
        Some(if is_b64(b) {
            CoreByte::Char(b)
        } else if b == b'\\' && core.get(i) == Some(&b'/') {
            i += 1;
            CoreByte::Char(b'/')
        } else if b.is_ascii_whitespace() {
            CoreByte::Space
        } else {
            CoreByte::Invalid
        })
    })
}

/// Collects the Base64 characters of `body`, line by line (see
/// [`line_core`]): spaces inside a line are ignored and any other byte is an
/// error.
fn collect_base64(body: &[u8], bound: usize) -> Result<Vec<u8>, RejectReason> {
    let mut out: Vec<u8> = Vec::new();
    for (_, line) in split_lines(body) {
        let Some(core) = line_core(line) else {
            continue;
        };
        for byte in core_bytes(core) {
            match byte {
                CoreByte::Char(b) => {
                    if out.len() >= bound {
                        return Err(RejectReason::TooLarge);
                    }
                    out.push(b);
                }
                CoreByte::Space => {}
                CoreByte::Invalid => return Err(RejectReason::InvalidBase64),
            }
        }
    }
    Ok(out)
}

/// End of the contiguous run of Base64-looking lines at the start of `body`
/// (`input[body_start..body_end]`), as an absolute offset; `body_start` when
/// there is none. Blank lines are skipped but do not extend the run. A line
/// belongs to the run only when its core is made of Base64 characters alone
/// (so prose with spaces or punctuation stops it).
fn base64_run_end(input: &[u8], body_start: usize, body_end: usize) -> usize {
    let body = input.get(body_start..body_end).unwrap_or_default();
    let mut end = body_start;
    for (offset, line) in split_lines(body) {
        let Some(core) = line_core(line) else {
            continue;
        };
        if !core_bytes(core).all(|b| matches!(b, CoreByte::Char(_))) {
            break;
        }
        end = body_start + offset + line.len();
    }
    end
}

/// Decodes a collected body and cuts it at the DER length it declares.
pub(super) fn decode_der(
    b64: &[u8],
    kind: CandidateKind,
    limits: &Limits,
) -> Result<Vec<u8>, RejectReason> {
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
        let label_start = begin + BEGIN.len();
        let (label, body_start, private_key) =
            if let Some((label, after)) = parse_label(input, label_start) {
                (label, after, is_private_key_label(label))
            } else if let Some(after) = private_key_fallback(input, label_start) {
                (&b""[..], after, true)
            } else {
                cursor = label_start;
                continue;
            };
        let kind = kind_for(label);

        // Look for the matching END, stopping at the next BEGIN or at EOF.
        // `resume` is where the search continues; `claimed` is what later
        // detectors must not read again. An unterminated block claims only
        // its run of Base64-looking lines, so text after a prose mention of
        // a BEGIN line stays visible to them.
        let (body_end, resume, claimed, result) = match find_marker(input, body_start) {
            Some((pos, Marker::End)) => match parse_label(input, pos + END.len()) {
                Some((end_label, after)) if end_label == label => (pos, after, after, Ok(())),
                Some((_, after)) => (pos, after, after, Err(RejectReason::LabelMismatch)),
                None => (
                    pos,
                    pos + END.len(),
                    base64_run_end(input, body_start, pos),
                    Err(RejectReason::UnterminatedPem),
                ),
            },
            Some((pos, Marker::Begin)) => (
                pos,
                pos,
                base64_run_end(input, body_start, pos),
                Err(RejectReason::UnterminatedPem),
            ),
            None => (
                input.len(),
                input.len(),
                base64_run_end(input, body_start, input.len()),
                Err(RejectReason::UnterminatedPem),
            ),
        };
        // A private key is claimed whole, up to the END or the next BEGIN/EOF,
        // so no detector can read any part of its body.
        let claimed = if private_key {
            claimed.max(body_end)
        } else {
            claimed
        };
        det.consumed.push(begin..claimed.max(body_start));
        cursor = resume;

        // Principle 6: a private key is never extracted, shown or logged. Its
        // whole range is claimed above, and the body is not collected or decoded,
        // so no byte of it reaches a candidate, a diagnostic or a note. Only
        // the counter changes, and no rejection is recorded either.
        if private_key {
            det.private_key_blocks_ignored = det.private_key_blocks_ignored.saturating_add(1);
            continue;
        }
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

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;

    /// `30 03 01 01 00`: the smallest well-formed SEQUENCE.
    const TINY: &str = "MAMBAQA=";

    fn run(input: &[u8], limits: &Limits) -> Detections {
        let mut det = Detections::new(limits);
        detect(input, limits, &mut det);
        det
    }

    fn at(text: &str, needle: &str) -> usize {
        text.find(needle).unwrap()
    }

    #[test]
    fn quando_ha_blocos_de_todos_os_tipos_deve_registrar_os_ranges_consumidos_exatos() {
        let valid = format!("-----BEGIN CERTIFICATE-----\n{TINY}\n-----END CERTIFICATE-----\n");
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let mismatch = format!("-----BEGIN CERTIFICATE-----\n{TINY}\n-----END PKCS7-----\n");
        let open = format!("-----BEGIN CERTIFICATE-----\n{TINY}\nAAAA\nfim, obrigado.\n");
        let text = format!("prosa\n{valid}{key}{mismatch}ruido\n{open}");

        let det = run(text.as_bytes(), &Limits::default());

        let v = at(&text, &valid);
        let k = at(&text, key);
        let m = at(&text, &mismatch);
        let o = at(&text, &open);
        let open_run_end = o + "-----BEGIN CERTIFICATE-----\nMAMBAQA=\nAAAA".len();
        let expected: Vec<Range<usize>> = vec![
            v..v + valid.len() - 1,
            k..k + key.len() - 1,
            m..m + mismatch.len() - 1,
            o..open_run_end,
        ];
        assert_eq!(det.consumed.as_slice(), expected.as_slice());
        assert_eq!(det.candidates.len(), 1);
        assert_eq!(det.candidates[0].offset, v);
        assert_eq!(det.private_key_blocks_ignored, 1);
        let diags: Vec<(usize, RejectReason)> = det
            .diagnostics
            .iter()
            .map(|d| (d.offset, d.reason))
            .collect();
        assert_eq!(
            diags,
            vec![
                (m, RejectReason::LabelMismatch),
                (o, RejectReason::UnterminatedPem),
            ]
        );
    }

    #[test]
    fn quando_chave_privada_nao_tem_end_deve_consumir_ate_o_proximo_begin_ou_o_fim() {
        let key = "-----BEGIN PRIVATE KEY-----\nAAAA\nprosa qualquer\nBBBB\n";
        let cert = format!("-----BEGIN CERTIFICATE-----\n{TINY}\n-----END CERTIFICATE-----\n");
        let text = format!("{key}{cert}");
        let det = run(text.as_bytes(), &Limits::default());
        assert_eq!(det.consumed.as_slice()[0], 0..key.len());
        assert_eq!(det.candidates.len(), 1);
        assert_eq!(det.candidates[0].offset, key.len());
        assert_eq!(det.private_key_blocks_ignored, 1);
        assert_eq!(det.diagnostics.len(), 0);

        let det = run(key.as_bytes(), &Limits::default());
        assert_eq!(det.consumed.as_slice().len(), 1);
        assert_eq!(det.consumed.as_slice()[0], 0..key.len());
    }

    #[test]
    fn quando_begin_solto_e_seguido_de_prosa_deve_consumir_so_ate_antes_da_prosa() {
        let text =
            format!("-----BEGIN CERTIFICATE-----\nveja o certificado abaixo, valeu.\n{TINY}\n");
        let det = run(text.as_bytes(), &Limits::default());
        assert_eq!(det.diagnostics.len(), 1);
        assert_eq!(det.diagnostics[0].reason, RejectReason::UnterminatedPem);
        let begin_end = "-----BEGIN CERTIFICATE-----".len();
        assert_eq!(det.consumed.as_slice().len(), 1);
        assert_eq!(det.consumed.as_slice()[0], 0..begin_end);
        let bare = at(&text, TINY);
        assert!(!det.consumed.contains(bare));
    }

    #[test]
    fn quando_begin_solto_e_seguido_de_outro_begin_deve_consumir_so_o_corpo_base64() {
        let text = format!(
            "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\nprosa qualquer\n\
             -----BEGIN CERTIFICATE-----\n{TINY}\n-----END CERTIFICATE-----\n"
        );
        let det = run(text.as_bytes(), &Limits::default());
        let second = at(&text, "-----BEGIN CERTIFICATE-----\nMAMB");
        let first_run_end = "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB".len();
        assert_eq!(det.consumed.as_slice()[0], 0..first_run_end);
        assert_eq!(det.candidates.len(), 1);
        assert_eq!(det.candidates[0].offset, second);
    }

    #[test]
    fn quando_fixture_truncada_deve_consumir_o_corpo_parcial_ate_o_fim() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/messy/truncated.txt"
        );
        let input = std::fs::read(path).unwrap();
        let det = run(&input, &Limits::default());
        assert_eq!(det.candidates.len(), 2);
        assert_eq!(det.consumed.as_slice().len(), 3);
        let last_begin = input
            .windows(BEGIN.len())
            .rposition(|w| w == BEGIN)
            .unwrap();
        assert_eq!(
            det.consumed.as_slice()[2],
            last_begin..input.trim_ascii_end().len()
        );
    }

    #[test]
    fn quando_end_solto_vem_antes_do_begin_deve_ignorar_o_end_e_achar_o_bloco() {
        let text = format!(
            "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n{TINY}\n-----END CERTIFICATE-----\n"
        );
        let det = run(text.as_bytes(), &Limits::default());
        assert_eq!(det.diagnostics.len(), 0);
        assert_eq!(det.candidates.len(), 1);
        assert_eq!(
            det.candidates[0].offset,
            "-----END CERTIFICATE-----\n".len()
        );
        assert_eq!(det.consumed.as_slice().len(), 1);
    }

    /// PEM whose body is a SEQUENCE of exactly `total` bytes.
    fn pem_with_der_total(total: usize) -> String {
        let mut der = vec![0x30, u8::try_from(total - 2).unwrap()];
        der.resize(total, 0);
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD_FOR_TESTS.encode(der)
        )
    }

    const STANDARD_FOR_TESTS: base64::engine::GeneralPurpose =
        base64::engine::general_purpose::STANDARD;

    #[test]
    fn quando_der_declarado_passa_do_limite_deve_dar_too_large_e_no_limite_deve_aceitar() {
        let limits = Limits {
            max_cert_der_bytes: 100,
            ..Limits::default()
        };
        // 136 Base64 characters for 101 bytes: under the pre-decode bound
        // (100 * 4 / 3 + 4 = 137), so only the post-decode check can reject.
        let over = run(pem_with_der_total(101).as_bytes(), &limits);
        assert_eq!(over.candidates.len(), 0);
        assert_eq!(over.diagnostics.len(), 1);
        assert_eq!(over.diagnostics[0].reason, RejectReason::TooLarge);

        let exact = run(pem_with_der_total(100).as_bytes(), &limits);
        assert_eq!(exact.diagnostics.len(), 0);
        assert_eq!(exact.candidates.len(), 1);
        assert_eq!(exact.candidates[0].der.len(), 100);
    }

    #[test]
    fn quando_corpo_tem_barra_escapada_de_json_deve_tratar_como_barra() {
        // 0xff bytes encode to `/` characters.
        let der_body = STANDARD_FOR_TESTS.encode([0x30, 0x04, 0xff, 0xff, 0xff, 0xff]);
        assert!(der_body.contains('/'));
        let escaped = der_body.replace('/', "\\/");
        let text =
            format!("\"-----BEGIN CERTIFICATE-----\\n{escaped}\\n-----END CERTIFICATE-----\\n\"");
        let det = run(text.as_bytes(), &Limits::default());
        assert_eq!(det.diagnostics.len(), 0);
        assert_eq!(
            det.candidates[0].der,
            vec![0x30, 0x04, 0xff, 0xff, 0xff, 0xff]
        );
    }
}
