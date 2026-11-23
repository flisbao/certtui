//! Final pass of `scan_text`: corpus rows, deduplication, caps and notes.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use certtui_domain::extract::{RejectReason, ScanOutcome, scan_text};
use certtui_domain::limits::Limits;
use certtui_domain::model::LoadNote;

mod support;

use support::*;

/// The note kinds of `out` as named in `expected.tsv`, sorted.
fn note_kinds(out: &ScanOutcome) -> Vec<String> {
    let mut kinds: Vec<String> = out
        .diagnostics
        .iter()
        .map(|d| format!("{:?}", d.reason))
        .collect();
    if out.private_key_blocks_ignored > 0 {
        kinds.push("PrivateKeyBlocksIgnored".to_owned());
    }
    kinds.sort();
    kinds.dedup();
    kinds
}

/// What the file loader hands to `scan_text`: UTF-16 (with BOM) transcoded to
/// UTF-8, as the loader does before scanning.
fn as_loader_text(bytes: Vec<u8>) -> Vec<u8> {
    let big_endian = bytes.starts_with(&[0xFE, 0xFF]);
    if !big_endian && !bytes.starts_with(&[0xFF, 0xFE]) {
        return bytes;
    }
    let units = bytes
        .get(2..)
        .unwrap_or_default()
        .chunks(2)
        .filter_map(|p| <[u8; 2]>::try_from(p).ok())
        .map(|p| {
            if big_endian {
                u16::from_be_bytes(p)
            } else {
                u16::from_le_bytes(p)
            }
        });
    char::decode_utf16(units)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .into_bytes()
}

#[test]
fn quando_bundle_mixed_deve_bater_com_expected_tsv() {
    let tsv = String::from_utf8(read("messy/expected.tsv")).unwrap();
    let mut rows = 0;
    for line in tsv.lines().filter(|l| !l.trim().is_empty()) {
        let cols: Vec<&str> = line.split('\t').collect();
        let (file, count, kinds) = (cols[0], cols[1], cols[2]);
        let mut expected: Vec<String> = if kinds == "-" {
            vec![]
        } else {
            kinds.split(',').map(str::to_owned).collect()
        };
        expected.sort();
        let out = scan(&as_loader_text(read(&format!("messy/{file}"))));
        assert_eq!(
            out.candidates.len(),
            count.parse::<usize>().unwrap(),
            "{file}: candidatos"
        );
        assert_eq!(note_kinds(&out), expected, "{file}: tipos de nota");
        let notes = Vec::<LoadNote>::from(&out);
        // `expected.tsv` names note kinds, not counts or order, so each row is
        // limited to one kind and the count is pinned here: a row that grows
        // a second kind, or a second note of the same kind, must fail loudly
        // instead of being matched by a lenient construction.
        assert!(
            expected.len() <= 1,
            "{file}: expected.tsv tem um tipo de nota por linha"
        );
        let expected_notes: Vec<LoadNote> = match expected.first().map(String::as_str) {
            None => vec![],
            Some("UnterminatedPem") => {
                assert_eq!(out.diagnostics.len(), 1, "{file}: uma so rejeicao");
                assert_eq!(out.private_key_blocks_ignored, 0, "{file}");
                vec![LoadNote::Rejected {
                    offset: out.diagnostics[0].offset,
                    reason: RejectReason::UnterminatedPem,
                }]
            }
            Some("PrivateKeyBlocksIgnored") => {
                assert!(out.diagnostics.is_empty(), "{file}: sem rejeicoes");
                vec![LoadNote::PrivateKeyBlocksIgnored { count: 1 }]
            }
            Some(other) => panic!("tipo de nota desconhecido: {other}"),
        };
        assert_eq!(notes, expected_notes, "{file}: LoadNote");
        assert!(!out.truncated && !out.diagnostics_truncated, "{file}");
        rows += 1;
    }
    assert_eq!(rows, 20, "todas as linhas de expected.tsv");
}

#[test]
fn quando_arquivo_tem_repeticao_deve_dar_a_contagem_pos_dedupe() {
    let cases = [
        ("messy/duplicates.txt", 1),
        ("messy/k8s-secret.yaml", 3),
        ("messy/s_client-output.txt", 3),
    ];
    for (file, count) in cases {
        let out = scan(&read(file));
        assert_eq!(out.candidates.len(), count, "{file}");
    }
}

#[test]
fn quando_entrada_vazia_deve_dar_outcome_vazio() {
    let limits = Limits::default();
    let out = scan_text(b"", &limits);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.diagnostics.len(), 0);
    assert_eq!(out.private_key_blocks_ignored, 0);
    assert!(!out.truncated && !out.diagnostics_truncated);
    assert_eq!(Vec::<LoadNote>::from(&out), vec![]);
}

#[test]
fn quando_candidatos_passam_do_limite_deve_truncar_e_marcar() {
    let reference = reference_chain();
    for (name, text) in [
        ("pem", String::from_utf8(read("chain-3.pem")).unwrap()),
        (
            "base64 solto",
            reference
                .iter()
                .map(|d| STANDARD.encode(d))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    ] {
        let limits = Limits {
            max_certs_per_source: 2,
            ..Limits::default()
        };
        let out = scan_text(text.as_bytes(), &limits);
        assert_eq!(ders(&out), vec![&reference[0], &reference[1]], "{name}");
        assert!(out.truncated, "{name}");
        assert_eq!(
            Vec::<LoadNote>::from(&out),
            vec![LoadNote::TruncatedAtCertLimit { limit: 2 }],
            "{name}"
        );
        // Exactly at the limit nothing is lost, so nothing is flagged.
        let limits = Limits {
            max_certs_per_source: 3,
            ..Limits::default()
        };
        let out = scan_text(text.as_bytes(), &limits);
        assert_eq!(out.candidates.len(), 3, "{name}");
        assert!(!out.truncated, "{name}");
    }
}

#[test]
fn quando_excesso_do_limite_e_repeticao_nao_deve_marcar_truncado() {
    let leaf = leaf_base64();
    let limits = Limits {
        max_certs_per_source: 2,
        ..Limits::default()
    };
    let text = format!(
        "{}\n{leaf}\n{leaf}\n",
        pem("CERTIFICATE", &leaf_body_lines())
    );
    let out = scan_text(text.as_bytes(), &limits);
    assert_eq!(out.candidates.len(), 1);
    assert!(!out.truncated);
}

#[test]
fn quando_diagnosticos_passam_do_limite_deve_cortar() {
    let text = "-----BEGIN CERTIFICATE-----\nAAAA\n".repeat(10);
    let limits = Limits {
        max_scan_diagnostics: 3,
        ..Limits::default()
    };
    let out = scan_text(text.as_bytes(), &limits);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.diagnostics.len(), 3);
    assert!(out.diagnostics_truncated);
    assert!(
        out.diagnostics
            .windows(2)
            .all(|w| w[0].offset <= w[1].offset)
    );
    let notes = Vec::<LoadNote>::from(&out);
    assert_eq!(notes.len(), 4);
    assert_eq!(notes[3], LoadNote::DiagnosticsTruncated { limit: 3 });
}

#[test]
fn quando_scan_gera_notas_deve_converter_sem_conteudo() {
    let out = scan(&read("messy/with-private-key.txt"));
    assert_eq!(
        Vec::<LoadNote>::from(&out),
        vec![LoadNote::PrivateKeyBlocksIgnored { count: 1 }]
    );
    let out = scan(&read("messy/truncated.txt"));
    let notes = Vec::<LoadNote>::from(&out);
    assert_eq!(notes.len(), 1);
    assert!(matches!(
        notes[0],
        LoadNote::Rejected {
            reason: RejectReason::UnterminatedPem,
            ..
        }
    ));
    assert_eq!(Vec::<LoadNote>::from(&scan(&read("chain-3.pem"))), vec![]);
}
