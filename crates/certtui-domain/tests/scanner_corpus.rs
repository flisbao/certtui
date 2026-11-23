//! PEM detector of `scan_text` over the messy-text corpus and edge cases.
//!
//! Counts here are RAW candidates (before deduplication, done in a later
//! task), so they can differ from `messy/expected.tsv`, which is post-dedupe.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use certtui_domain::extract::{Candidate, CandidateKind, RejectReason, scan_text};
use certtui_domain::limits::Limits;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

// Justificativa: a helper outside #[test] fns; a missing fixture must fail the
// test loudly, and clippy's allow-in-tests covers only the test fns themselves.
#[allow(clippy::unwrap_used)]
fn read(rel: &str) -> Vec<u8> {
    std::fs::read(format!("{FIXTURES}/{rel}")).unwrap()
}

fn scan(input: &[u8]) -> certtui_domain::extract::ScanOutcome {
    scan_text(input, &Limits::default())
}

fn reasons(out: &certtui_domain::extract::ScanOutcome) -> Vec<RejectReason> {
    out.diagnostics.iter().map(|d| d.reason).collect()
}

/// The three certificates of `chain-3.pem` (leaf, intermediate, root).
fn reference_chain() -> Vec<Vec<u8>> {
    let out = scan(&read("chain-3.pem"));
    assert_eq!(out.candidates.len(), 3);
    out.candidates.into_iter().map(|c| c.der).collect()
}

/// Base64 body of the leaf of `chain-3.pem`, wrapped at 64 columns.
// Justificativa: the chunks of a Base64 string are ASCII, so `from_utf8` cannot
// fail; the helper lives outside the #[test] fns that clippy exempts.
#[allow(clippy::unwrap_used)]
fn leaf_body_lines() -> Vec<String> {
    let leaf = reference_chain().remove(0);
    STANDARD
        .encode(leaf)
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect()
}

fn pem(label: &str, body_lines: &[String]) -> String {
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        body_lines.join("\n")
    )
}

/// Rows of `messy/expected.tsv` as `(file, expected count, note kinds)`.
fn expected_row(file: &str) -> Result<(usize, Vec<RejectReason>), String> {
    let tsv = String::from_utf8(read("messy/expected.tsv")).unwrap_or_default();
    let row = tsv
        .lines()
        .find_map(|l| {
            let cols: Vec<&str> = l.split('\t').collect();
            (cols.first() == Some(&file)).then_some(cols)
        })
        .unwrap_or_default();
    let count = row
        .get(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(usize::MAX);
    let reasons = match row.get(2).copied() {
        Some("-") => vec![],
        Some("UnterminatedPem") => vec![RejectReason::UnterminatedPem],
        other => return Err(format!("unexpected note kinds for {file}: {other:?}")),
    };
    Ok((count, reasons))
}

#[test]
fn quando_arquivo_de_pem_sujo_deve_contar_candidatos_brutos_e_motivos() {
    // expected.tsv counts are post-dedupe; for these files they equal the raw
    // PEM count, except s_client-output, which prints the leaf twice (4 raw
    // blocks for 3 certificates).
    for file in [
        "pem-indented.txt",
        "pem-email-quoted.txt",
        "pem-crlf.txt",
        "pem-json-escaped.json",
        "pem-one-line.txt",
        "openssl-x509-text.txt",
        "s_client-output.txt",
        "truncated.txt",
        "garbage-between.txt",
    ] {
        let (mut count, expected_reasons) = expected_row(file).unwrap();
        if file == "s_client-output.txt" {
            assert_eq!(count, 3, "expected.tsv still says 3 after dedupe");
            count = 4;
        }
        let out = scan(&read(&format!("messy/{file}")));
        assert_eq!(out.candidates.len(), count, "{file}: candidatos");
        assert_eq!(reasons(&out), expected_reasons, "{file}: motivos");
        assert!(!out.truncated, "{file}");
        assert!(
            out.candidates
                .iter()
                .all(|c| c.kind == CandidateKind::Certificate)
        );
    }
}

#[test]
fn quando_arquivo_sujo_deve_extrair_os_mesmos_der_da_cadeia_de_referencia() {
    let reference = reference_chain();
    for file in [
        "pem-indented.txt",
        "pem-email-quoted.txt",
        "pem-crlf.txt",
        "pem-json-escaped.json",
        "pem-one-line.txt",
        "garbage-between.txt",
        "truncated.txt",
        "openssl-x509-text.txt",
        "s_client-output.txt",
    ] {
        let out = scan(&read(&format!("messy/{file}")));
        for c in &out.candidates {
            assert!(
                reference.contains(&c.der),
                "{file}: DER fora da cadeia de referencia"
            );
        }
    }
    let leaf_der = read("chain-3.der");
    assert_eq!(reference.first(), Some(&leaf_der));
}

#[test]
fn quando_s_client_tem_4_blocos_deve_preservar_ordem_do_texto() {
    // The brief says 3 certs; the output has 4 raw blocks because the leaf
    // is printed again at the end. Dedupe is a later task.
    let reference = reference_chain();
    let out = scan(&read("messy/s_client-output.txt"));
    let ders: Vec<&Vec<u8>> = out.candidates.iter().map(|c| &c.der).collect();
    assert_eq!(
        ders,
        vec![&reference[0], &reference[1], &reference[2], &reference[0]]
    );
    let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
    assert!(offsets.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn quando_label_diferente_no_end_deve_dar_label_mismatch() {
    let body = leaf_body_lines();
    let text = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END TRUSTED CERTIFICATE-----\n{}",
        body.join("\n"),
        pem("CERTIFICATE", &body)
    );
    let out = scan(text.as_bytes());
    assert_eq!(reasons(&out), vec![RejectReason::LabelMismatch]);
    assert_eq!(out.diagnostics[0].offset, 0);
    assert_eq!(out.candidates.len(), 1, "o bloco seguinte continua valido");
}

#[test]
fn quando_csr_no_texto_deve_dar_unsupported_label() {
    let body = leaf_body_lines();
    let text = format!("antes\n{}depois\n", pem("CERTIFICATE REQUEST", &body));
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::UnsupportedLabel]);
    assert_eq!(out.diagnostics[0].offset, "antes\n".len());
}

#[test]
fn quando_labels_aceitos_deve_classificar_o_tipo() {
    let body = leaf_body_lines();
    for (label, kind) in [
        ("CERTIFICATE", CandidateKind::Certificate),
        ("TRUSTED CERTIFICATE", CandidateKind::Certificate),
        ("X509 CERTIFICATE", CandidateKind::Certificate),
        ("PKCS7", CandidateKind::Pkcs7),
        ("CMS", CandidateKind::Pkcs7),
    ] {
        let out = scan(pem(label, &body).as_bytes());
        let kinds: Vec<CandidateKind> = out.candidates.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, vec![kind], "{label}");
    }
}

#[test]
fn quando_corpo_tem_byte_estranho_deve_dar_invalid_base64() {
    let mut body = leaf_body_lines();
    body[1].insert(10, '!');
    let out = scan(pem("CERTIFICATE", &body).as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::InvalidBase64]);
}

#[test]
fn quando_corpo_nao_e_der_deve_dar_not_der_sequence() {
    let body = vec![STANDARD.encode(b"hello world, not a sequence")];
    let out = scan(pem("CERTIFICATE", &body).as_bytes());
    assert_eq!(reasons(&out), vec![RejectReason::NotDerSequence]);
}

#[test]
fn quando_der_declara_mais_do_que_tem_deve_dar_length_mismatch() {
    let body: Vec<String> = leaf_body_lines().into_iter().take(5).collect();
    let out = scan(pem("CERTIFICATE", &body).as_bytes());
    assert_eq!(reasons(&out), vec![RejectReason::LengthMismatch]);
}

#[test]
fn quando_ha_bytes_depois_do_der_deve_cortar_no_tamanho_declarado() {
    let leaf = reference_chain().remove(0);
    let mut padded = leaf.clone();
    padded.extend_from_slice(&[0, 0, 0, 0, 0]);
    let out = scan(pem("CERTIFICATE", &[STANDARD.encode(&padded)]).as_bytes());
    let ders: Vec<&Vec<u8>> = out.candidates.iter().map(|c| &c.der).collect();
    assert_eq!(ders, vec![&leaf]);
}

#[test]
fn quando_corpo_passa_do_limite_deve_dar_too_large_sem_decodificar() {
    let limits = Limits {
        max_cert_der_bytes: 100,
        ..Limits::default()
    };
    let out = scan_text(pem("CERTIFICATE", &leaf_body_lines()).as_bytes(), &limits);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::TooLarge]);
}

#[test]
fn quando_passa_do_limite_de_certs_deve_parar_e_marcar_truncado() {
    let limits = Limits {
        max_certs_per_source: 2,
        ..Limits::default()
    };
    let out = scan_text(&read("chain-3.pem"), &limits);
    assert_eq!(out.candidates.len(), 2);
    assert!(out.truncated);
}

#[test]
fn quando_entrada_tem_utf8_invalido_deve_achar_o_pem_mesmo_assim() {
    let mut input = vec![0xff, 0xfe, 0x80, b'\n'];
    input.extend_from_slice(pem("CERTIFICATE", &leaf_body_lines()).as_bytes());
    input.extend_from_slice(&[0xc3, 0x28, 0xff]);
    let out = scan(&input);
    assert_eq!(out.candidates.len(), 1);
    assert_eq!(out.candidates[0].offset, 4);
}

#[test]
fn quando_linhas_tem_prefixo_de_comentario_deve_ignorar_o_prefixo() {
    for prefix in ["// ", "# ", "* ", "| ", "> ", "  "] {
        let body: Vec<String> = leaf_body_lines()
            .into_iter()
            .map(|l| format!("{prefix}{l}"))
            .collect();
        let text = format!(
            "{prefix}-----BEGIN CERTIFICATE-----\n{}\n{prefix}-----END CERTIFICATE-----\n",
            body.join("\n")
        );
        let out = scan(text.as_bytes());
        assert_eq!(out.candidates.len(), 1, "prefixo {prefix:?}");
    }
}

#[test]
fn quando_linhas_tem_aspas_e_virgula_deve_ignorar_o_ruido() {
    let body: Vec<String> = leaf_body_lines()
        .into_iter()
        .map(|l| format!("  \"{l}\","))
        .collect();
    let out = scan(pem("CERTIFICATE", &body).as_bytes());
    assert_eq!(out.candidates.len(), 1);
}

#[test]
fn quando_base64_sem_padding_deve_decodificar_mesmo_assim() {
    let leaf = reference_chain().remove(0);
    let encoded = STANDARD.encode(&leaf);
    let unpadded = encoded.trim_end_matches('=').to_owned();
    let out = scan(pem("CERTIFICATE", &[unpadded]).as_bytes());
    let ders: Vec<&Vec<u8>> = out.candidates.iter().map(|c| &c.der).collect();
    assert_eq!(ders, vec![&leaf]);
}

#[test]
fn quando_begin_vem_seguido_de_outro_begin_deve_dar_unterminated_so_no_primeiro() {
    let body = leaf_body_lines();
    let text = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n{}",
        body[..3].join("\n"),
        pem("CERTIFICATE", &body)
    );
    let out = scan(text.as_bytes());
    assert_eq!(reasons(&out), vec![RejectReason::UnterminatedPem]);
    assert_eq!(out.candidates.len(), 1);
}

#[test]
fn quando_diagnostico_e_formatado_deve_ter_so_offset_e_motivo() {
    let body = leaf_body_lines();
    let out = scan(pem("CERTIFICATE REQUEST", &body).as_bytes());
    let shown = format!("{:?}", out.diagnostics);
    assert_eq!(
        shown,
        "[ScanDiagnostic { offset: 0, reason: UnsupportedLabel }]"
    );
    assert!(!shown.contains("CERTIFICATE"));
}

#[test]
fn quando_muitos_begin_sem_end_deve_terminar_em_tempo_linear() {
    let line = "-----BEGIN CERTIFICATE-----\n";
    let input = line.repeat(50_000);
    let started = std::time::Instant::now();
    let out = scan(input.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(
        out.diagnostics.len(),
        Limits::default().max_scan_diagnostics
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn quando_corpo_enorme_sem_end_deve_terminar_em_tempo_linear() {
    let mut input = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    input.extend(std::iter::repeat_n(b'A', 5_000_000));
    let started = std::time::Instant::now();
    let out = scan(&input);
    assert_eq!(reasons(&out), vec![RejectReason::UnterminatedPem]);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn quando_json_escapa_barra_deve_tratar_como_barra_no_corpo() {
    let leaf = reference_chain().remove(0);
    let body = leaf_body_lines();
    assert!(body.iter().any(|l| l.contains('/')));
    let escaped: Vec<String> = body.iter().map(|l| l.replace('/', "\\/")).collect();
    let text = format!(
        "{{\"pem\":\"-----BEGIN CERTIFICATE-----\\n{}\\n-----END CERTIFICATE-----\\n\"}}",
        escaped.join("\\n")
    );
    let out = scan(text.as_bytes());
    let ders: Vec<&Vec<u8>> = out.candidates.iter().map(|c| &c.der).collect();
    assert_eq!(ders, vec![&leaf]);
}

#[test]
fn quando_muitos_begin_com_corpo_parcial_sem_end_deve_terminar_em_tempo_linear() {
    let block = "-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    let input = block.repeat(50_000);
    let started = std::time::Instant::now();
    let out = scan(input.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert!(out.diagnostics_truncated);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn quando_diagnosticos_estouram_o_limite_deve_marcar_diagnostics_truncated() {
    let limits = Limits {
        max_scan_diagnostics: 3,
        ..Limits::default()
    };
    let input = "-----BEGIN CERTIFICATE-----\n".repeat(10);
    let out = scan_text(input.as_bytes(), &limits);
    assert_eq!(out.diagnostics.len(), 3);
    assert!(out.diagnostics_truncated);
    assert!(!out.truncated);
}

#[test]
fn quando_candidato_e_formatado_com_debug_nao_deve_vazar_der() {
    let c = Candidate {
        offset: 3,
        kind: CandidateKind::Certificate,
        der: vec![0x30, 0x00],
    };
    assert_eq!(
        format!("{c:?}"),
        "Candidate { offset: 3, kind: Certificate, der_len: 2 }"
    );
}
