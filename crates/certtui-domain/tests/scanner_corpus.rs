//! PEM and bare-Base64 detectors of `scan_text` over the messy-text corpus and
//! edge cases.
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

// ---- bare Base64 detector -------------------------------------------------

/// Base64 (standard, padded) of the leaf of `chain-3.pem`, in one line.
fn leaf_base64() -> String {
    STANDARD.encode(reference_chain().remove(0))
}

fn ders(out: &certtui_domain::extract::ScanOutcome) -> Vec<&Vec<u8>> {
    out.candidates.iter().map(|c| &c.der).collect()
}

#[test]
fn quando_base64_solto_em_arquivo_sujo_deve_achar_os_tres_certificados() {
    let reference = reference_chain();
    for file in ["bare-base64-wrapped.txt", "jwk-x5c.json"] {
        let out = scan(&read(&format!("messy/{file}")));
        assert_eq!(out.candidates.len(), 3, "{file}");
        assert_eq!(out.diagnostics.len(), 0, "{file}: {:?}", out.diagnostics);
        for c in &out.candidates {
            assert!(reference.contains(&c.der), "{file}");
            assert_eq!(c.kind, CandidateKind::Certificate, "{file}");
        }
        let mut found: Vec<&Vec<u8>> = ders(&out);
        found.sort();
        found.dedup();
        assert_eq!(found.len(), 3, "{file}: tres certificados distintos");
    }
}

#[test]
fn quando_base64_atravessa_linhas_deve_juntar() {
    let leaf = reference_chain().remove(0);
    let lines = leaf_body_lines();
    let prefix = "texto antes\n";
    let seps: [(&str, &str); 4] = [
        ("\n", "lf"),
        ("\r\n", "crlf"),
        ("\\n", "literal"),
        ("\n    ", "indented"),
    ];
    for (sep, name) in seps {
        let text = format!("{prefix}{}\nfim\n", lines.join(sep));
        let out = scan(text.as_bytes());
        assert_eq!(ders(&out), vec![&leaf], "{name}");
        assert_eq!(out.candidates[0].offset, prefix.len(), "{name}");
        assert_eq!(out.diagnostics.len(), 0, "{name}");
    }
}

#[test]
fn quando_base64_url_safe_deve_decodificar() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let leaf = reference_chain().remove(0);
    let encoded = URL_SAFE_NO_PAD.encode(&leaf);
    assert!(encoded.contains(['-', '_']), "o fixture deve exercitar -/_");
    let text = format!("{{\"x5c\": \"{encoded}\"}}");
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
}

#[test]
fn quando_corrida_base64_tem_menos_de_200_chars_deve_ignorar_sem_diagnostico() {
    let short = format!("\"MIA{}\"", "A".repeat(196));
    let out = scan(short.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.diagnostics.len(), 0, "{:?}", out.diagnostics);
}

#[test]
fn quando_corrida_base64_comeca_com_mi_mas_nao_e_der_deve_dar_not_der_sequence() {
    let text = format!("prosa\n\"MIA{}\"", "A".repeat(197));
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::NotDerSequence]);
    assert_eq!(out.diagnostics[0].offset, "prosa\n\"".len());
}

#[test]
fn quando_corrida_base64_nao_comeca_com_mi_deve_ignorar_sem_diagnostico() {
    let text = format!("\"AAAA{}\"", "A".repeat(400));
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_ha_lixo_depois_do_padding_base64_deve_cortar_no_tamanho_declarado() {
    let leaf = reference_chain().remove(0);
    // Trailing zero bytes inside the Base64 data.
    let mut padded = leaf.clone();
    padded.extend_from_slice(&[0, 0, 0, 0, 0]);
    let out = scan(format!("[{}]", STANDARD.encode(&padded)).as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    // Text glued after the Base64, with and without padding.
    let encoded = leaf_base64();
    let out = scan(format!("{encoded}\nGARBAGEGARBAGE e mais lixo").as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    let out = scan(format!("{encoded}GARBAGEGARBAGE e mais lixo").as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
}

#[test]
fn quando_base64_declara_mais_do_que_tem_deve_dar_length_mismatch() {
    let encoded = leaf_base64();
    let cut = &encoded[..encoded.len() / 2];
    let out = scan(format!("\"{cut}\"").as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::LengthMismatch]);
}

#[test]
fn quando_base64_passa_do_limite_de_tamanho_deve_dar_too_large() {
    let limits = Limits {
        max_cert_der_bytes: 100,
        ..Limits::default()
    };
    let out = scan_text(format!("\"{}\"", leaf_base64()).as_bytes(), &limits);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::TooLarge]);
}

#[test]
fn quando_corrida_ja_foi_consumida_por_pem_deve_nao_duplicar_base64() {
    // The PEM bodies are claimed by the PEM detector and must not be read
    // again as bare Base64. `s_client-output.txt` prints the leaf twice.
    let expected = [
        ("chain-3.pem", 3),
        ("messy/s_client-output.txt", 4),
        ("messy/pem-indented.txt", 3),
    ];
    for (file, count) in expected {
        let out = scan(&read(file));
        assert_eq!(out.candidates.len(), count, "{file}");
        assert_eq!(out.diagnostics.len(), 0, "{file}");
    }
    let body = leaf_body_lines();
    let text = format!(
        "{}\nsolto: {}\n",
        pem("CERTIFICATE", &body),
        body.join("\n")
    );
    let out = scan(text.as_bytes());
    assert_eq!(
        out.candidates.len(),
        2,
        "o PEM e o base64 solto, uma vez cada"
    );
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_pem_sem_end_deixa_sobra_base64_deve_achar_o_certificado_da_sobra() {
    // The unterminated PEM claims only its Base64-looking lines; the full
    // body after the prose stays visible and is found as bare Base64
    // (deduplication is a later task).
    let leaf = reference_chain().remove(0);
    let body = leaf_body_lines();
    let head = format!(
        "-----BEGIN CERTIFICATE-----\n{}\nfim da mensagem\n",
        body[..3].join("\n")
    );
    let text = format!("{head}{}\n", body.join("\n"));
    let out = scan(text.as_bytes());
    assert_eq!(reasons(&out), vec![RejectReason::UnterminatedPem]);
    assert_eq!(out.diagnostics[0].offset, 0);
    assert_eq!(ders(&out), vec![&leaf]);
    assert_eq!(out.candidates[0].offset, head.len());
}

#[test]
fn quando_base64_solto_passa_do_limite_de_certs_deve_marcar_truncado() {
    let limits = Limits {
        max_certs_per_source: 2,
        ..Limits::default()
    };
    let out = scan_text(&read("messy/jwk-x5c.json"), &limits);
    assert_eq!(out.candidates.len(), 2);
    assert!(out.truncated);
}

#[test]
fn quando_diagnostico_base64_e_formatado_deve_ter_so_offset_e_motivo() {
    let text = format!("\"MIA{}\"", "A".repeat(300));
    let out = scan(text.as_bytes());
    assert_eq!(
        format!("{:?}", out.diagnostics),
        "[ScanDiagnostic { offset: 1, reason: NotDerSequence }]"
    );
}

fn assert_fast(input: &[u8]) -> certtui_domain::extract::ScanOutcome {
    let started = std::time::Instant::now();
    let out = scan(input);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "demorou {:?}",
        started.elapsed()
    );
    out
}

const FOUR_MIB: usize = 4 * 1024 * 1024;

#[test]
fn quando_mi_repetido_por_4_mib_deve_terminar_em_tempo_linear_base64() {
    let input = "MI".repeat(FOUR_MIB / 2);
    let _ = assert_fast(input.as_bytes());
}

#[test]
fn quando_alfabeto_base64_sem_mi_por_4_mib_deve_terminar_em_tempo_linear() {
    let _ = assert_fast("AB+/ cd_-\n".repeat(FOUR_MIB / 10).as_bytes());
    let _ = assert_fast("A".repeat(FOUR_MIB).as_bytes());
}

#[test]
fn quando_ha_muitas_corridas_curtas_deve_terminar_em_tempo_linear_base64() {
    let _ = assert_fast("\"MI\",".repeat(FOUR_MIB / 5).as_bytes());
    let _ = assert_fast("MI ".repeat(FOUR_MIB / 3).as_bytes());
    let _ = assert_fast("MI\\n".repeat(FOUR_MIB / 4).as_bytes());
    let _ = assert_fast(
        format!("\"MIA{}\"\n", "A".repeat(210))
            .repeat(FOUR_MIB / 216)
            .as_bytes(),
    );
}

#[test]
fn quando_ha_muitos_certs_colados_deve_terminar_em_tempo_linear_base64() {
    let leaf = leaf_base64();
    let input = format!("{leaf}\n").repeat(FOUR_MIB / (leaf.len() + 1));
    let out = assert_fast(input.as_bytes());
    assert_eq!(out.candidates.len(), Limits::default().max_certs_per_source);
    assert!(out.truncated);
}

#[test]
fn quando_palavra_mi_precede_o_certificado_deve_achar_o_certificado_base64() {
    let leaf = reference_chain().remove(0);
    let lines = leaf_body_lines().join("\n");
    for prefix in [
        "MICROSOFT ROOT CERTIFICATE AUTHORITY\n",
        "MICROSOFTROOTCERTIFICATEAUTHORITY\n",
        "MIME Type\n",
        "MIT\n\n",
    ] {
        let out = scan(format!("{prefix}{lines}\n").as_bytes());
        assert_eq!(ders(&out), vec![&leaf], "{prefix:?}");
        assert_eq!(out.candidates[0].offset, prefix.len(), "{prefix:?}");
        assert_eq!(out.diagnostics.len(), 0, "{prefix:?}");
    }
}

#[test]
fn quando_primeiro_token_mi_tem_menos_de_16_chars_nao_deve_dar_diagnostico_base64() {
    let text = format!("MIT\n{}\n", "A".repeat(400));
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_primeiro_token_mi_nao_e_der_deve_reportar_so_o_primeiro_token_base64() {
    // First token has >= 200 chars and is not a DER header: one diagnostic at
    // its offset; the certificate on the next line is still found.
    let leaf = reference_chain().remove(0);
    let first = format!("MIA{}", "A".repeat(297));
    let text = format!("ruido\n{first}\n{}\n", leaf_body_lines().join("\n"));
    let out = scan(text.as_bytes());
    assert_eq!(reasons(&out), vec![RejectReason::NotDerSequence]);
    assert_eq!(out.diagnostics[0].offset, "ruido\n".len());
    assert_eq!(ders(&out), vec![&leaf]);
}

#[test]
fn quando_base64_tem_quebras_cr_e_crlf_e_literais_deve_juntar() {
    let leaf = reference_chain().remove(0);
    let lines = leaf_body_lines();
    for (sep, name) in [
        ("\r", "cr"),
        ("\r\n", "crlf"),
        ("\\r", "literal cr"),
        ("\\r\\n", "literal crlf"),
        ("\\n", "literal lf"),
        (" \t ", "espacos"),
    ] {
        let text = format!("x {}", lines.join(sep));
        assert_eq!(ders(&scan(text.as_bytes())), vec![&leaf], "{name}");
    }
}

#[test]
fn quando_quebra_literal_vem_logo_depois_de_barra_deve_achar_o_certificado_base64() {
    let leaf = reference_chain().remove(0);
    let b64 = leaf_base64();
    for sep in ["\\\\n", "ab\\n", "ab\\r\\n", "\\\\r"] {
        let text = format!("x{sep}{b64}");
        let out = scan(text.as_bytes());
        assert_eq!(ders(&out), vec![&leaf], "{sep:?}");
        assert_eq!(out.candidates[0].offset, 1 + sep.len(), "{sep:?}");
    }
}

/// A DER `SEQUENCE` of `total` bytes (`total >= 260`), as a Base64 string.
fn synthetic_b64(total: usize) -> String {
    let content = total - 4;
    let len = u16::try_from(content).unwrap_or(u16::MAX).to_be_bytes();
    let mut der = vec![0x30, 0x82, len[0], len[1]];
    der.extend(std::iter::repeat_n(0x05, content));
    STANDARD.encode(der)
}

#[test]
fn quando_base64_tem_padding_colado_no_proximo_deve_reclamar_o_padding_com_o_certificado() {
    for (total, pad) in [(301, "=="), (302, "="), (300, "")] {
        let one = synthetic_b64(total);
        assert!(
            one.ends_with(pad) && !one.ends_with(&format!("{pad}=")),
            "{total}"
        );
        let out = scan(format!("{one}{one}{one}").as_bytes());
        let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
        assert_eq!(offsets, vec![0, one.len(), 2 * one.len()], "{total}");
    }
}

#[test]
fn quando_ha_muitos_certs_base64_colados_sem_separador_deve_ser_linear_e_truncar() {
    let limits = Limits {
        max_certs_per_source: 5000,
        ..Limits::default()
    };
    let leaf = leaf_base64();
    let input = leaf.repeat(6000);
    assert!(input.len() > 4 * 1024 * 1024);
    let started = std::time::Instant::now();
    let out = scan_text(input.as_bytes(), &limits);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "demorou {:?}",
        started.elapsed()
    );
    assert_eq!(out.candidates.len(), 5000);
    assert!(out.truncated);
}

#[test]
fn quando_ha_inundacao_de_tokens_mi_deve_terminar_em_tempo_linear_base64() {
    let _ = assert_fast("MI-".repeat(FOUR_MIB / 3).as_bytes());
    let _ = assert_fast("MIIC\n".repeat(FOUR_MIB / 5).as_bytes());
    let _ = assert_fast("MI ".repeat(FOUR_MIB / 3).as_bytes());
    let _ = assert_fast(
        "MICROSOFTROOTCERTIFICATE\n"
            .repeat(FOUR_MIB / 25)
            .as_bytes(),
    );
    let _ = assert_fast(
        format!("MIA{}\n", "A".repeat(20))
            .repeat(FOUR_MIB / 24)
            .as_bytes(),
    );
}
