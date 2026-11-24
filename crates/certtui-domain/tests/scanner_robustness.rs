//! Resource and robustness guarantees of `scan_text` (RF3): linear time on
//! pathological inputs, bounded output, no panic on arbitrary bytes.
//!
//! Every timing test runs in the debug test profile and must finish in under
//! five seconds.

mod support;

use std::time::Instant;

use certtui_domain::extract::{CandidateKind, ScanOutcome, scan_text};
use certtui_domain::limits::Limits;
use certtui_domain::model::parse_der_cert;
use proptest::prelude::*;
use support::*;

/// Scans `input` with the default limits and fails when it takes 5 s or more.
fn scan_within_budget(input: &[u8]) -> ScanOutcome {
    let started = Instant::now();
    let out = scan_text(input, &Limits::default());
    assert_within_budget(started, input.len());
    out
}

/// Everything `scan_text` promises about the shape of an outcome, whatever the
/// input was.
fn check_outcome(input: &[u8], limits: &Limits, out: &ScanOutcome) -> Result<(), TestCaseError> {
    prop_assert_eq!(out.cert_limit, limits.max_certs_per_source);
    prop_assert_eq!(out.diagnostics_limit, limits.max_scan_diagnostics);
    prop_assert!(out.candidates.len() <= out.cert_limit);
    prop_assert!(out.diagnostics.len() <= out.diagnostics_limit);
    prop_assert!(out.private_key_blocks_ignored <= input.len());
    for c in &out.candidates {
        prop_assert!(
            c.offset < input.len(),
            "offset {} fora da entrada",
            c.offset
        );
        prop_assert!(!c.der.is_empty());
        if c.kind == CandidateKind::Certificate {
            prop_assert!(
                c.der.len() <= limits.max_cert_der_bytes,
                "der de {} bytes passa do limite",
                c.der.len()
            );
        }
    }
    prop_assert!(
        out.candidates
            .windows(2)
            .all(|w| matches!(w, [a, b] if a.offset <= b.offset)),
        "candidatos fora da ordem do texto"
    );
    for (i, a) in out.candidates.iter().enumerate() {
        prop_assert!(
            out.candidates.iter().skip(i + 1).all(|b| a.der != b.der),
            "candidatos repetidos"
        );
    }
    for d in &out.diagnostics {
        prop_assert!(
            d.offset < input.len(),
            "offset {} fora da entrada",
            d.offset
        );
    }
    prop_assert!(
        out.diagnostics
            .windows(2)
            .all(|w| matches!(w, [a, b] if a.offset <= b.offset))
    );
    // A flagged cut means the cap was really reached.
    if out.diagnostics_truncated {
        prop_assert_eq!(out.diagnostics.len(), out.diagnostics_limit);
    }
    Ok(())
}

#[test]
fn quando_entrada_de_4mib_so_com_a_e_tem_de_terminar_rapido() {
    let out = scan_within_budget("A".repeat(FOUR_MIB).as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_begin_repetido_ate_4mib_deve_terminar_rapido_e_limitar_diagnosticos() {
    let line = "-----BEGIN CERTIFICATE-----\n";
    let out = scan_within_budget(line.repeat(FOUR_MIB / line.len()).as_bytes());
    let limit = Limits::default().max_scan_diagnostics;
    assert!(out.diagnostics.len() <= limit);
    assert!(out.diagnostics_truncated);
    assert_eq!(out.candidates.len(), 0);
}

#[test]
fn quando_mi_repetido_ate_4mib_deve_terminar_rapido() {
    let out = scan_within_budget("MI".repeat(FOUR_MIB / 2).as_bytes());
    assert_eq!(out.candidates.len(), 0);
}

#[test]
fn quando_hex_gigante_sem_separador_deve_terminar_rapido() {
    let out = scan_within_budget("ab".repeat(FOUR_MIB / 2).as_bytes());
    assert_eq!(out.candidates.len(), 0);
    // Starting like a DER header, so the detector really reads the run.
    let giant = format!("3082ffff{}", "ab".repeat(FOUR_MIB / 2));
    let out = scan_within_budget(giant.as_bytes());
    assert_eq!(out.candidates.len(), 0);
}

#[test]
fn quando_mesmo_cert_em_pem_e_hex_no_mesmo_arquivo_deve_dar_um_candidato() {
    // RF5: the same certificate in several encodings is one certificate.
    let leaf = reference_chain().remove(0);
    let as_pem = pem("CERTIFICATE", &leaf_body_lines());
    let as_hex = hex_of(&leaf, ":");
    let as_b64 = leaf_base64();
    for (name, text) in [
        ("pem e hex", format!("{as_pem}\nhex: {as_hex}\n")),
        ("hex e pem", format!("hex: {as_hex}\n{as_pem}")),
        (
            "pem, hex e base64",
            format!("{as_pem}\n{as_hex}\n\nraw: {as_b64}\n"),
        ),
    ] {
        let out = scan(text.as_bytes());
        assert_eq!(ders(&out), vec![&leaf], "{name}");
        assert_eq!(out.diagnostics.len(), 0, "{name}: {:?}", out.diagnostics);
        assert!(!out.truncated, "{name}");
    }
}

/// Pieces that touch the edges of the detectors: PEM markers, the `MI` start of
/// a Base64 DER, line breaks (real and literal), padding, quotes, hex bytes of
/// a DER header, Base64 and hex alphabets, NUL and 0xFF, and whole real
/// certificates in each encoding.
fn fragment() -> impl Strategy<Value = Vec<u8>> {
    let leaf = reference_chain().remove(0);
    let words = [
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
        "-----BEGIN ",
        "-----END ",
        "-----",
        "CERTIFICATE",
        "PRIVATE KEY",
        "MI",
        "MII",
        "MIIC",
        "MIAAAAAAAAAAAAAAAAAAAA",
        "\n",
        "\r\n",
        "\r",
        "\\n",
        "\\r\\n",
        "=",
        "==",
        "\"",
        "'",
        ",",
        " ",
        "  ",
        "\t",
        ":",
        "30 82",
        "30:82:",
        "3082",
        "3081",
        "30 82 01 00 ",
        "0x",
        "ab",
        "AB:cd",
        "-",
        "_",
        "+",
        "/",
        "A",
        "AAAA",
        "QUFB",
    ];
    let mut options: Vec<BoxedStrategy<Vec<u8>>> = words
        .iter()
        .map(|w| Just(w.as_bytes().to_vec()).boxed())
        .collect();
    options.push(Just(vec![0x00]).boxed());
    options.push(Just(vec![0xff]).boxed());
    options.push(Just(vec![0x30, 0x82]).boxed());
    options.push(Just(leaf_base64().into_bytes()).boxed());
    options.push(Just(hex_of(&leaf, ":").into_bytes()).boxed());
    options.push(Just(hex_of(&leaf, "").into_bytes()).boxed());
    options.push(Just(pem("CERTIFICATE", &leaf_body_lines()).into_bytes()).boxed());
    options.push(
        // Prefixes of a real certificate, so truncated headers and bodies
        // show up at every length.
        (0..leaf.len())
            .prop_map(move |n| leaf.get(..n).map(<[u8]>::to_vec).unwrap_or_default())
            .boxed(),
    );
    options.push(proptest::collection::vec(any::<u8>(), 0..8).boxed());
    options.push(
        proptest::collection::vec(
            prop::sample::select(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_".to_vec(),
            ),
            1..300,
        )
        .boxed(),
    );
    proptest::strategy::Union::new(options)
}

proptest! {
    #[test]
    fn quando_bytes_arbitrarios_deve_nunca_dar_panic_e_der_nunca_passar_do_limite(
        input in proptest::collection::vec(any::<u8>(), 0..=65_536)
    ) {
        let limits = Limits::default();
        let out = scan_text(&input, &limits);
        check_outcome(&input, &limits, &out)?;
    }

    #[test]
    fn quando_fragmentos_de_pem_base64_e_hex_se_misturam_deve_manter_o_outcome_consistente(
        parts in proptest::collection::vec(fragment(), 0..400)
    ) {
        let mut input: Vec<u8> = parts.concat();
        input.truncate(65_536);
        let limits = Limits::default();
        let out = scan_text(&input, &limits);
        check_outcome(&input, &limits, &out)?;
        // The same input with tight limits must stay inside them too.
        let tight = Limits {
            max_certs_per_source: 2,
            max_scan_diagnostics: 3,
            max_cert_der_bytes: 400,
            ..Limits::default()
        };
        let out = scan_text(&input, &tight);
        check_outcome(&input, &tight, &out)?;
    }

    #[test]
    fn quando_entrada_e_binaria_aleatoria_deve_dar_outcome_vazio_ou_candidatos_validos(
        input in proptest::collection::vec(any::<u8>(), 0..=65_536)
    ) {
        let limits = Limits::default();
        let out = scan_text(&input, &limits);
        check_outcome(&input, &limits, &out)?;
        // Random bytes hold no armor, so whatever comes out was found as a
        // bare DER and must really be a certificate.
        for c in &out.candidates {
            prop_assert!(parse_der_cert(&c.der, &limits).is_ok());
        }
    }
}
