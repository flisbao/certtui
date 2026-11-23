//! Helpers shared by the scanner integration tests: fixture loaders, the
//! reference chain and small builders for PEM, Base64 and hex text.

// Justificativa: every test file is its own crate and includes this module
// whole, but each one uses only some of the helpers.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use certtui_domain::extract::{RejectReason, ScanOutcome, scan_text};
use certtui_domain::limits::Limits;

pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

// Justificativa: a helper outside #[test] fns; a missing fixture must fail the
// test loudly, and clippy's allow-in-tests covers only the test fns themselves.
#[allow(clippy::unwrap_used)]
pub fn read(rel: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{rel}")).unwrap()
}

pub fn scan(input: &[u8]) -> ScanOutcome {
    scan_text(input, &Limits::default())
}

pub fn reasons(out: &ScanOutcome) -> Vec<RejectReason> {
    out.diagnostics.iter().map(|d| d.reason).collect()
}

/// The three certificates of `chain-3.pem` (leaf, intermediate, root).
pub fn reference_chain() -> Vec<Vec<u8>> {
    let out = scan(&read("chain-3.pem"));
    assert_eq!(out.candidates.len(), 3);
    out.candidates.into_iter().map(|c| c.der).collect()
}

/// Base64 body of the leaf of `chain-3.pem`, wrapped at 64 columns.
// Justificativa: the chunks of a Base64 string are ASCII, so `from_utf8` cannot
// fail; the helper lives outside the #[test] fns that clippy exempts.
#[allow(clippy::unwrap_used)]
pub fn leaf_body_lines() -> Vec<String> {
    let leaf = reference_chain().remove(0);
    STANDARD
        .encode(leaf)
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect()
}

pub fn pem(label: &str, body_lines: &[String]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        body_lines.join("\n")
    )
}

/// Base64 (standard, padded) of the leaf of `chain-3.pem`, in one line.
pub fn leaf_base64() -> String {
    STANDARD.encode(reference_chain().remove(0))
}

pub fn ders(out: &ScanOutcome) -> Vec<&Vec<u8>> {
    out.candidates.iter().map(|c| &c.der).collect()
}

pub fn assert_fast(input: &[u8]) -> ScanOutcome {
    let started = std::time::Instant::now();
    let out = scan(input);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "demorou {:?}",
        started.elapsed()
    );
    out
}

pub const FOUR_MIB: usize = 4 * 1024 * 1024;

/// A fake private key that IS valid DER (`30 82 01 2c` + 300 pseudo-random
/// bytes), so its Base64 starts with `MII` and the bare-Base64 detector would
/// turn it into a candidate if any part of it were exposed. THROWAWAY FAKE
/// DATA, not a key.
pub fn fake_key_der() -> Vec<u8> {
    let mut der = vec![0x30, 0x82, 0x01, 0x2c];
    let mut x: u32 = 0x1234_5678;
    for _ in 0..300 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        der.push(x.to_be_bytes()[1]);
    }
    der
}

pub fn fake_key_lines() -> Vec<String> {
    STANDARD
        .encode(fake_key_der())
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

/// Hex of `bytes`, two digits per byte, joined with `sep`.
pub fn hex_of(bytes: &[u8], sep: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(sep)
}

/// Standard Base64 of `text`, in one line.
pub fn b64(text: impl AsRef<[u8]>) -> String {
    STANDARD.encode(text)
}

pub fn secret_with(value: &str) -> String {
    format!("apiVersion: v1\nkind: Secret\ndata:\n  tls.crt: {value}\n  other: xyz\n")
}
