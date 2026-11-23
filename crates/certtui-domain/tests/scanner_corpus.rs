//! PEM and bare-Base64 detectors of `scan_text` over the messy-text corpus and
//! edge cases.
//!
//! Candidates are the final ones: deduplicated by DER, in text order, and
//! (when not from a PEM block) structurally checked as certificates, so the
//! counts match `messy/expected.tsv`.

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
    // s_client-output prints the leaf twice (4 raw blocks): 3 after dedupe.
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
        let (count, expected_reasons) = expected_row(file).unwrap();
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
    // The output has 4 raw blocks because the leaf is printed again at the
    // end; the repeat is dropped and the first occurrence stays in place.
    let reference = reference_chain();
    let out = scan(&read("messy/s_client-output.txt"));
    let ders: Vec<&Vec<u8>> = out.candidates.iter().map(|c| &c.der).collect();
    assert_eq!(ders, vec![&reference[0], &reference[1], &reference[2]]);
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
    // again as bare Base64 (that would add diagnostics or candidates).
    // `s_client-output.txt` prints the leaf twice (deduplicated to 3).
    let expected = [
        ("chain-3.pem", 3),
        ("messy/s_client-output.txt", 3),
        ("messy/pem-indented.txt", 3),
    ];
    for (file, count) in expected {
        let out = scan(&read(file));
        assert_eq!(out.candidates.len(), count, "{file}");
        assert_eq!(out.diagnostics.len(), 0, "{file}");
    }
    let body = leaf_body_lines();
    let other = STANDARD.encode(&reference_chain()[1]);
    let text = format!("{}\nsolto: {other}\n", pem("CERTIFICATE", &body));
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
    // The detectors stop at their own bound (truncated); all copies are one.
    assert_eq!(out.candidates.len(), 1);
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

#[test]
fn quando_ha_muitos_certs_base64_colados_sem_separador_deve_ser_linear_e_deduplicar() {
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
    assert_eq!(out.candidates.len(), 1, "6000 copias do mesmo certificado");
    assert!(!out.truncated);
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

// ---- private keys are never read ---------------------------------------------

// THROWAWAY FAKE DATA: random bytes encoded as Base64, not valid key material
// of any kind. They exist only to give the private-key tests a body to skip.
const FAKE_KEY_A: [&str; 4] = [
    "eisdt0HYIdcSzWeBo2rpKhaWcZPMLTfqgS5i2WBGf/NCPJJBBOL1bPtXcPOdkhs1",
    "UVVIauW8lbY1gidgE3Zud+nIyPtRcwO+duiIjFRIDgAn+ryrpWB6zo00aJYj8vcS",
    "TnVihHkxU0u1LOWZcFD+N5TxHh8iG4BUwA3Jf8Kx1fECN8ccyM1xkbC/m0vNhjNC",
    "y9TgaNdu",
];
const FAKE_KEY_B: [&str; 4] = [
    "n7fN2BbJ9xvD+fiKmLgsBGI+bipBhbgZ8IuRWXpHmgeQbnhO4e9evMRGd8u1R8Wy",
    "BbDqRPGnUzuhsrfb8uHKq/1xT6OCuDndeimDRe79V/pp2xwOBxO/4Tp9O4fm09tq",
    "FowObHDph9y4QNXvxMGxVWnjqsZt+2WLjE1IkUcRi6FskwEps87iRhGAzmdVqcZv",
    "4E3FHOdP",
];

const PRIVATE_KEY_LABELS: [&str; 6] = [
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "DSA PRIVATE KEY",
];

fn lines_of(body: &[&str]) -> Vec<String> {
    body.iter().map(|l| (*l).to_owned()).collect()
}

/// Every 16-character window of `body`, joined and line by line.
fn windows_16(body: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for text in std::iter::once(body.concat()).chain(body.iter().cloned()) {
        let chars: Vec<char> = text.chars().collect();
        out.extend(chars.windows(16).map(|w| w.iter().collect::<String>()));
    }
    out
}

#[test]
fn quando_texto_tem_chave_privada_deve_contar_e_nao_devolver_candidato() {
    let reference = reference_chain();
    let out = scan(&read("messy/with-private-key.txt"));
    assert_eq!(out.candidates.len(), 2);
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(reasons(&out), vec![]);
    assert!(out.candidates.iter().all(|c| reference.contains(&c.der)));
    assert!(!out.truncated && !out.diagnostics_truncated);
}

#[test]
fn quando_chave_privada_tem_qualquer_variante_de_label_deve_ignorar_sem_diagnostico() {
    for label in PRIVATE_KEY_LABELS {
        let text = format!("antes\n{}depois\n", pem(label, &lines_of(&FAKE_KEY_A)));
        let out = scan(text.as_bytes());
        assert_eq!(out.private_key_blocks_ignored, 1, "{label}");
        assert_eq!(out.candidates.len(), 0, "{label}");
        assert_eq!(reasons(&out), vec![], "{label}");
    }
}

#[test]
fn quando_ha_varias_chaves_privadas_deve_contar_cada_uma() {
    let text = format!(
        "{}{}{}",
        pem("RSA PRIVATE KEY", &lines_of(&FAKE_KEY_A)),
        pem("CERTIFICATE", &leaf_body_lines()),
        pem("EC PRIVATE KEY", &lines_of(&FAKE_KEY_B)),
    );
    let out = scan(text.as_bytes());
    assert_eq!(out.private_key_blocks_ignored, 2);
    assert_eq!(out.candidates.len(), 1);
    assert_eq!(reasons(&out), vec![]);
}

#[test]
fn quando_label_so_parece_chave_privada_deve_continuar_nao_suportado() {
    for label in [
        "PUBLIC KEY",
        "PRIVATE KEYS",
        "PRIVATE",
        "CERTIFICATE REQUEST",
    ] {
        let out = scan(pem(label, &lines_of(&FAKE_KEY_A)).as_bytes());
        assert_eq!(out.private_key_blocks_ignored, 0, "{label}");
        assert_eq!(
            reasons(&out),
            vec![RejectReason::UnsupportedLabel],
            "{label}"
        );
    }
}

/// A fake private key that IS valid DER (`30 82 01 2c` + 300 pseudo-random
/// bytes), so its Base64 starts with `MII` and the bare-Base64 detector would
/// turn it into a candidate if any part of it were exposed. THROWAWAY FAKE
/// DATA, not a key.
fn fake_key_der() -> Vec<u8> {
    let mut der = vec![0x30, 0x82, 0x01, 0x2c];
    let mut x: u32 = 0x1234_5678;
    for _ in 0..300 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        der.push(x.to_be_bytes()[1]);
    }
    der
}

fn fake_key_lines() -> Vec<String> {
    STANDARD
        .encode(fake_key_der())
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect()
}

/// The ways a key block can be laid out in a text. `body` has at least 3 lines.
fn key_layouts(label: &str, body: &[String]) -> Vec<(&'static str, String)> {
    let begin = format!("-----BEGIN {label}-----\n");
    let end = format!("-----END {label}-----\n");
    let (first, rest) = body.split_at(1);
    vec![
        ("terminado", format!("{begin}{}\n{end}", body.join("\n"))),
        ("sem END", format!("{begin}{}\n", body.join("\n"))),
        (
            "sem END com cabecalho",
            format!(
                "{begin}Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0A1B2C3D\n\n{}\n",
                body.join("\n")
            ),
        ),
        (
            "sem END com linha em branco e prosa",
            format!(
                "{begin}{}\n\nisto e prosa, nao base64.\n{}\n",
                first.join("\n"),
                rest.join("\n")
            ),
        ),
        (
            "sem END com continuacao por barra invertida",
            format!(
                "{begin}Proc-Type: 4,ENCRYPTED \\\n{}\n",
                body.iter()
                    .map(|l| format!("{l}\\"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        ),
    ]
}

#[test]
fn quando_chave_privada_deve_nao_aparecer_no_debug_do_outcome() {
    let fixture = String::from_utf8(read("messy/with-private-key.txt")).unwrap();
    let fixture_body: Vec<String> = fixture
        .split("-----BEGIN PRIVATE KEY-----")
        .nth(1)
        .and_then(|rest| rest.split("-----END PRIVATE KEY-----").next())
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    assert!(fixture_body.len() > 2);
    let der = fake_key_der();
    let key_b64 = STANDARD.encode(&der);
    let bodies = [
        lines_of(&FAKE_KEY_A),
        lines_of(&FAKE_KEY_B),
        fixture_body,
        fake_key_lines(),
    ];

    for body in bodies {
        let windows = windows_16(&body);
        assert!(windows.len() > 16);
        for label in ["PRIVATE KEY", "RSA PRIVATE KEY"] {
            for (name, key_block) in key_layouts(label, &body) {
                let text = format!("{}{key_block}", pem("CERTIFICATE", &leaf_body_lines()));
                // The body really is in the input, so the checks are meaningful.
                assert!(body.iter().all(|l| text.contains(l.as_str())), "{name}");
                let out = scan(text.as_bytes());
                assert_eq!(out.private_key_blocks_ignored, 1, "{name}");
                // Only the real certificate comes out, never the key.
                assert_eq!(out.candidates.len(), 1, "{name}");
                assert_eq!(out.candidates[0].der, reference_chain().remove(0), "{name}");
                assert_eq!(reasons(&out), vec![], "{name}");

                let shown = format!(
                    "{out:?}\n{out:#?}\n{}",
                    serde_json::to_string(&out.diagnostics).unwrap()
                );
                for w in &windows {
                    assert!(!shown.contains(w.as_str()), "{name}: vazou um trecho");
                }
                for c in &out.candidates {
                    let c_b64 = STANDARD.encode(&c.der);
                    for w in &windows {
                        assert!(!c_b64.contains(w.as_str()), "{name}: der tem a chave");
                    }
                    for w in der.windows(16) {
                        assert!(
                            !c.der.windows(16).any(|d| d == w),
                            "{name}: der tem a chave"
                        );
                    }
                    assert!(!c_b64.contains(&key_b64[..32]), "{name}");
                }
            }
        }
    }
}

#[test]
fn quando_corpo_da_chave_parece_cert_deve_nao_ser_detectado_pelo_base64_solto() {
    // The body is a whole real certificate (starts with `MI`, 200+ chars).
    for label in ["PRIVATE KEY", "ENCRYPTED PRIVATE KEY"] {
        let text = format!("x\n{}y\n", pem(label, &leaf_body_lines()));
        let out = scan(text.as_bytes());
        assert_eq!(out.private_key_blocks_ignored, 1, "{label}");
        assert_eq!(out.candidates.len(), 0, "{label}");
        assert_eq!(reasons(&out), vec![], "{label}");
    }
    // One-line variant, and no END at all.
    let one_line = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        leaf_base64()
    );
    let out = scan(one_line.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    let open = format!("-----BEGIN PRIVATE KEY-----\n{}\n", leaf_base64());
    let out = scan(open.as_bytes());
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![]);
}

#[test]
fn quando_chave_privada_nao_tem_end_deve_pular_ate_o_proximo_begin() {
    let text = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{}\n{}",
        leaf_body_lines().join("\n"),
        pem("CERTIFICATE", &leaf_body_lines()),
    );
    let out = scan(text.as_bytes());
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(out.candidates.len(), 1);
    assert_eq!(reasons(&out), vec![]);
    assert_eq!(
        out.candidates[0].offset,
        text.rfind("-----BEGIN CERTIFICATE-----").unwrap()
    );
}

#[test]
fn quando_chave_privada_nao_tem_end_deve_reivindicar_tudo_ate_o_fim_mesmo_depois_de_prosa() {
    // Deliberate trade-off: a certificate that starts inside a broken key block
    // (no BEGIN line of its own) is hidden together with the key.
    let text = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\nfim da chave, obrigado.\n{}\n",
        FAKE_KEY_A.join("\n"),
        leaf_base64()
    );
    let out = scan(text.as_bytes());
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![]);
}

#[test]
fn quando_chave_privada_nao_tem_end_e_certificado_vem_depois_de_novo_begin_deve_achar_o_certificado()
 {
    let text = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\nfim da chave, obrigado.\n{}",
        FAKE_KEY_A.join("\n"),
        pem("CERTIFICATE", &leaf_body_lines()),
    );
    let out = scan(text.as_bytes());
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(out.candidates.len(), 1);
    assert_eq!(reasons(&out), vec![]);
    assert_eq!(out.candidates[0].der, reference_chain().remove(0));
}

#[test]
fn quando_chave_privada_sem_end_e_interrompida_deve_nao_devolver_candidato() {
    for label in PRIVATE_KEY_LABELS {
        for (name, block) in key_layouts(label, &fake_key_lines()) {
            let text = format!("antes\n{block}");
            let out = scan(text.as_bytes());
            assert_eq!(out.private_key_blocks_ignored, 1, "{label} {name}");
            assert_eq!(out.candidates.len(), 0, "{label} {name}");
            assert_eq!(reasons(&out), vec![], "{label} {name}");
        }
    }
}

#[test]
fn quando_label_da_chave_tem_espaco_no_fim_deve_contar_como_chave_privada() {
    let text = format!(
        "-----BEGIN PRIVATE KEY -----\n{}\n",
        fake_key_lines().join("\n")
    );
    let out = scan(text.as_bytes());
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![]);
}

#[test]
fn quando_label_da_chave_nao_esta_em_maiusculas_deve_tratar_como_chave_privada() {
    let body = fake_key_lines();
    for (begin, end) in [
        ("private key", "private key"),
        ("Rsa Private Key", "Rsa Private Key"),
        ("RSA-PRIVATE-KEY", "RSA-PRIVATE-KEY"),
        ("PrIvAtE_kEy", "PrIvAtE_kEy"),
    ] {
        let terminated = format!(
            "-----BEGIN {begin}-----\n{}\n-----END {end}-----\n{}",
            body.join("\n"),
            pem("CERTIFICATE", &leaf_body_lines()),
        );
        let out = scan(terminated.as_bytes());
        assert_eq!(out.private_key_blocks_ignored, 1, "{begin}");
        assert_eq!(out.candidates.len(), 1, "{begin}: so o cert depois do END");
        assert_eq!(reasons(&out), vec![], "{begin}");

        let open = format!("-----BEGIN {begin}-----\nX: y\n{}\n", body.join("\n"));
        let out = scan(open.as_bytes());
        assert_eq!(out.private_key_blocks_ignored, 1, "{begin}");
        assert_eq!(out.candidates.len(), 0, "{begin}");
        assert_eq!(reasons(&out), vec![], "{begin}");
    }
}

#[test]
fn quando_begin_com_label_estranho_sem_private_deve_continuar_ignorado_sem_contar() {
    for label in ["certificate", "weird label!", "PUBLIC-KEY"] {
        let out = scan(format!("-----BEGIN {label}-----\nAAAA\n").as_bytes());
        assert_eq!(out.private_key_blocks_ignored, 0, "{label}");
        assert_eq!(reasons(&out), vec![], "{label}");
    }
}

#[test]
fn quando_end_da_chave_tem_outro_label_deve_pular_ate_ele_sem_diagnostico() {
    let text = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END CERTIFICATE-----\n{}",
        leaf_body_lines().join("\n"),
        pem("CERTIFICATE", &leaf_body_lines()),
    );
    let out = scan(text.as_bytes());
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(out.candidates.len(), 1);
    assert_eq!(reasons(&out), vec![]);
}

#[test]
fn quando_ha_inundacao_de_begin_private_key_deve_terminar_em_tempo_linear() {
    let line = "-----BEGIN PRIVATE KEY-----\n";
    let out = assert_fast(line.repeat(FOUR_MIB / line.len()).as_bytes());
    assert_eq!(out.private_key_blocks_ignored, FOUR_MIB / line.len());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![]);

    let block = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
    let out = assert_fast(block.repeat(FOUR_MIB / block.len()).as_bytes());
    assert_eq!(out.private_key_blocks_ignored, FOUR_MIB / block.len());
}

// ---- hex DER detector --------------------------------------------------------

/// Hex of `bytes`, two digits per byte, joined with `sep`.
fn hex_of(bytes: &[u8], sep: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(sep)
}

#[test]
fn quando_hex_com_dois_pontos_e_continuo_deve_achar_a_cadeia_de_referencia() {
    let reference = reference_chain();
    for file in ["hex-colon.txt", "hex-plain.txt"] {
        let out = scan(&read(&format!("messy/{file}")));
        assert_eq!(ders(&out), reference.iter().collect::<Vec<_>>(), "{file}");
        assert_eq!(out.diagnostics.len(), 0, "{file}: {:?}", out.diagnostics);
        assert!(!out.truncated, "{file}");
        let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
        assert!(offsets.windows(2).all(|w| w[0] < w[1]), "{file}");
        assert!(
            out.candidates
                .iter()
                .all(|c| c.kind == CandidateKind::Certificate)
        );
    }
}

#[test]
fn quando_hex_tem_caixa_mista_deve_decodificar() {
    let leaf = reference_chain().remove(0);
    let mixed: String = hex_of(&leaf, ":")
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 3 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    assert!(mixed.chars().any(|c| c.is_ascii_uppercase()));
    assert!(mixed.chars().any(|c| c.is_ascii_lowercase()));
    let out = scan(format!("serial: {mixed}\n").as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    assert_eq!(out.candidates[0].offset, "serial: ".len());
}

#[test]
fn quando_hex_atravessa_linhas_e_separadores_deve_juntar() {
    let leaf = reference_chain().remove(0);
    let plain = hex_of(&leaf, "");
    let wrapped: Vec<String> = plain
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    // Indentation is made of spaces, which are separators too.
    for (sep, name) in [
        ("\n", "lf"),
        ("\r\n", "crlf"),
        ("\n  ", "lf com indentacao"),
    ] {
        let text = format!("hex:\n{}\nfim", wrapped.join(sep));
        let out = scan(text.as_bytes());
        assert_eq!(ders(&out), vec![&leaf], "{name}");
        assert_eq!(out.candidates[0].offset, "hex:\n".len(), "{name}");
    }
    let spaced = hex_of(&leaf, " ");
    assert_eq!(ders(&scan(spaced.as_bytes())), vec![&leaf]);
}

#[test]
fn quando_hex_nao_comeca_com_3082_ou_3081_deve_ignorar() {
    let leaf = reference_chain().remove(0);
    let body = hex_of(&leaf[2..], "");
    for head in ["3183", "3083", "0230", "a082", "3182", "3080", "ff"] {
        let text = format!("x = {head}{body}\n");
        let out = scan(text.as_bytes());
        assert_eq!(out.candidates.len(), 0, "{head}");
        assert_eq!(out.diagnostics.len(), 0, "{head}: {:?}", out.diagnostics);
    }
}

#[test]
fn quando_ha_bytes_depois_do_der_em_hex_deve_cortar_no_tamanho_declarado() {
    let leaf = reference_chain().remove(0);
    let mut padded = leaf.clone();
    padded.extend_from_slice(&[0, 0, 0, 0, 0]);
    let out = scan(hex_of(&padded, ":").as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
}

#[test]
fn quando_hex_tem_certificados_colados_deve_achar_todos() {
    let reference = reference_chain();
    let glued: String = reference.iter().map(|d| hex_of(d, "")).collect();
    let out = scan(glued.as_bytes());
    assert_eq!(ders(&out), reference.iter().collect::<Vec<_>>());
    let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
    assert_eq!(
        offsets,
        vec![
            0,
            2 * reference[0].len(),
            2 * (reference[0].len() + reference[1].len())
        ]
    );
}

#[test]
fn quando_hex_tem_comprimento_impar_ou_curto_deve_dar_length_mismatch() {
    let leaf = reference_chain().remove(0);
    let plain = hex_of(&leaf, "");
    // One digit missing at the end: odd number of digits.
    let odd = &plain[..plain.len() - 1];
    assert_eq!(odd.len() % 2, 1);
    let out = scan(format!("x {odd}\n").as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::LengthMismatch]);
    assert_eq!(out.diagnostics[0].offset, 2);
    // Even but truncated.
    let out = scan(format!("x {}\n", &plain[..plain.len() / 2]).as_bytes());
    assert_eq!(reasons(&out), vec![RejectReason::LengthMismatch]);
}

#[test]
fn quando_hex_curto_parece_hash_deve_ignorar_sem_diagnostico() {
    // A SHA-256 fingerprint that happens to start with 3082.
    let hash = format!("3082{}", "ab".repeat(30));
    for text in [
        hash.clone(),
        format!("SHA256: {}", hex_of(&hex_bytes(&hash), ":")),
    ] {
        let out = scan(text.as_bytes());
        assert_eq!(out.candidates.len(), 0);
        assert_eq!(out.diagnostics.len(), 0);
    }
}

fn hex_bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|p| u8::from_str_radix(&String::from_utf8_lossy(p), 16).ok())
        .collect()
}

#[test]
fn quando_hex_vem_depois_de_palavra_hex_deve_achar_o_certificado() {
    let leaf = reference_chain().remove(0);
    let h = hex_of(&leaf, ":");
    for prefix in ["deadbeef ", "cert1: ", "face\n", "0x", "de ad be ef\n"] {
        let out = scan(format!("{prefix}{h}").as_bytes());
        assert_eq!(ders(&out), vec![&leaf], "{prefix:?}");
        assert_eq!(out.candidates[0].offset, prefix.len(), "{prefix:?}");
    }
}

#[test]
fn quando_hex_passa_do_limite_de_tamanho_deve_dar_too_large() {
    let limits = Limits {
        max_cert_der_bytes: 100,
        ..Limits::default()
    };
    let leaf = reference_chain().remove(0);
    let out = scan_text(hex_of(&leaf, ":").as_bytes(), &limits);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::TooLarge]);
}

#[test]
fn quando_hex_passa_do_limite_de_certs_deve_marcar_truncado() {
    let limits = Limits {
        max_certs_per_source: 2,
        ..Limits::default()
    };
    let out = scan_text(&read("messy/hex-colon.txt"), &limits);
    assert_eq!(out.candidates.len(), 2);
    assert!(out.truncated);
}

#[test]
fn quando_corpo_de_bloco_pem_tem_hex_de_certificado_deve_nao_ser_relido_como_hex() {
    // If the claimed range of a block were not respected, the hex certificate
    // inside the body would come out as a candidate.
    let leaf = reference_chain().remove(0);
    let hex_line = hex_of(&leaf, ":");
    for (label, key_count) in [("CERTIFICATE REQUEST", 0), ("PRIVATE KEY", 1)] {
        let text = format!(
            "antes\n{}depois\n",
            pem(label, std::slice::from_ref(&hex_line))
        );
        let out = scan(text.as_bytes());
        assert_eq!(out.candidates.len(), 0, "{label}");
        assert_eq!(out.private_key_blocks_ignored, key_count, "{label}");
    }
    // And the hex after the block is still found, exactly once.
    let text = format!(
        "{}{hex_line}\n",
        pem("CERTIFICATE REQUEST", std::slice::from_ref(&hex_line))
    );
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    assert_eq!(out.candidates[0].offset, text.rfind(&hex_line).unwrap());
    assert_eq!(reasons(&out), vec![RejectReason::UnsupportedLabel]);
}

#[test]
fn quando_pem_valido_tem_corpo_base64_deve_dar_so_os_candidatos_do_pem() {
    let out = scan(&read("chain-3.pem"));
    assert_eq!(out.candidates.len(), 3);
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_hex_truncado_tem_199_ou_200_digitos_deve_diagnosticar_so_a_partir_de_200() {
    // `30 82 04 00` declares 1028 bytes; the run has `digits` hex digits and
    // ends at `!`.
    let run = |digits: usize| {
        let body: String = "ab".repeat(digits).chars().take(digits - 8).collect();
        scan(format!("x 30820400{body}!").as_bytes())
    };
    let short = run(199);
    assert_eq!(short.candidates.len(), 0);
    assert_eq!(short.diagnostics.len(), 0, "{:?}", short.diagnostics);
    let long = run(200);
    assert_eq!(long.candidates.len(), 0);
    assert_eq!(reasons(&long), vec![RejectReason::LengthMismatch]);
    assert_eq!(long.diagnostics[0].offset, 2);
}

// ---- order of nested candidates -------------------------------------------

/// PEM of an arbitrary DER, wrapped at 64 columns.
fn pem_of_der(der: &[u8]) -> String {
    let lines: Vec<String> = STANDARD
        .encode(der)
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    pem("CERTIFICATE", &lines)
}

#[test]
fn quando_secret_decodifica_para_hex_e_depois_pem_deve_seguir_a_ordem_do_texto() {
    let chain = reference_chain();
    let decoded = format!("{}\n{}", hex_of(&chain[0], ":"), pem_of_der(&chain[1]));
    let out = scan(secret_with(&b64(decoded)).as_bytes());
    assert_eq!(ders(&out), vec![&chain[0], &chain[1]]);
}

#[test]
fn quando_secret_decodifica_para_pem_e_depois_hex_deve_seguir_a_ordem_do_texto() {
    let chain = reference_chain();
    let decoded = format!("{}\n{}\n", pem_of_der(&chain[1]), hex_of(&chain[0], ":"));
    let out = scan(secret_with(&b64(decoded)).as_bytes());
    assert_eq!(ders(&out), vec![&chain[1], &chain[0]]);
}

#[test]
fn quando_camada_filha_esta_em_qualquer_posicao_do_texto_decodificado_deve_ficar_la() {
    let chain = reference_chain();
    let (a, b, c) = (&chain[0], &chain[1], &chain[2]);
    // `A` always comes from a Base64 layer inside the decoded text; the header
    // line keeps every inner offset away from 0, so a key that forgot the
    // path of the layer would not tie by luck.
    let layer = b64(pem_of_der(a));
    let cases = [
        (
            "no meio",
            [pem_of_der(b), layer.clone(), pem_of_der(c)],
            [b, a, c],
        ),
        (
            "primeira",
            [layer.clone(), pem_of_der(b), pem_of_der(c)],
            [a, b, c],
        ),
        ("ultima", [pem_of_der(b), pem_of_der(c), layer], [b, c, a]),
    ];
    for (name, parts, expected) in cases {
        let decoded = format!("# header\n{}\n{}\n{}", parts[0], parts[1], parts[2]);
        let out = scan(secret_with(&b64(decoded)).as_bytes());
        assert_eq!(ders(&out), expected.to_vec(), "{name}");
        assert_eq!(out.diagnostics.len(), 0, "{name}: {:?}", out.diagnostics);
        // All three inherit the offset of the one top-level run.
        let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
        assert!(offsets.windows(2).all(|w| w[0] == w[1]), "{name}");
    }
}

#[test]
fn quando_dois_secrets_tem_camada_filha_no_meio_deve_manter_a_ordem_dos_runs_de_topo() {
    let chain = reference_chain();
    let (a, b, c) = (&chain[0], &chain[1], &chain[2]);
    // Other certificates for the second run (deduplication would hide it).
    let (rsa, ec, san) = (
        read("rsa2048-leaf.der"),
        read("ec-p256-leaf.der"),
        read("san-multi.der"),
    );
    let secret = |first: &[u8], child: &[u8], last: &[u8]| {
        b64(format!(
            "# header\n{}\n{}\n{}",
            pem_of_der(first),
            b64(pem_of_der(child)),
            pem_of_der(last)
        ))
    };
    // First run: [B, A, C]; second run: [SAN, EC, RSA].
    let text = format!(
        "data:\n  x: {}\n  y: {}\n",
        secret(b, a, c),
        secret(&san, &ec, &rsa)
    );
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![b, a, c, &san, &ec, &rsa]);
    let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
    assert!(offsets[..3].iter().all(|&o| o == offsets[0]));
    assert!(offsets[3..].iter().all(|&o| o == offsets[3]));
    assert!(offsets[0] < offsets[3]);
}

#[test]
fn quando_ha_dois_secrets_deve_manter_a_ordem_dos_runs_de_topo() {
    let chain = reference_chain();
    // The first run holds hex B then PEM C (detector order would give C, B).
    let first = b64(format!(
        "{}\n{}",
        hex_of(&chain[1], ":"),
        pem_of_der(&chain[2])
    ));
    let second = b64(pem_of_der(&chain[0]));
    let text = format!("data:\n  a: {first}\n  b: {second}\n");
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&chain[1], &chain[2], &chain[0]]);
    let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
    assert_eq!(offsets[0], offsets[1]);
    assert!(offsets[1] < offsets[2]);
}

#[test]
fn quando_arquivo_mistura_pem_base64_e_hex_deve_achar_os_tres_em_ordem() {
    let reference = reference_chain();
    let out = scan(&read("messy/bundle-mixed.txt"));
    assert_eq!(ders(&out), reference.iter().collect::<Vec<_>>());
    assert_eq!(out.diagnostics.len(), 0, "{:?}", out.diagnostics);
    let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
    assert!(offsets.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn quando_mesmo_cert_em_pem_e_hex_deve_aparecer_uma_vez() {
    let leaf = reference_chain().remove(0);
    let out = scan(&read("messy/duplicates.txt"));
    assert_eq!(ders(&out), vec![&leaf]);
    assert_eq!(out.diagnostics.len(), 0, "{:?}", out.diagnostics);
}

#[test]
fn quando_hex_diagnostico_e_formatado_deve_ter_so_offset_e_motivo() {
    let leaf = reference_chain().remove(0);
    let plain = hex_of(&leaf, "");
    let out = scan(format!("x {}", &plain[..plain.len() / 2]).as_bytes());
    assert_eq!(
        format!("{:?}", out.diagnostics),
        "[ScanDiagnostic { offset: 2, reason: LengthMismatch }]"
    );
}

#[test]
fn quando_ha_inundacao_de_palavras_hex_por_4_mib_deve_terminar_em_tempo_linear() {
    let _ = assert_fast("deadbeef cafe face ".repeat(FOUR_MIB / 19).as_bytes());
    let _ = assert_fast("0123456789abcdef".repeat(FOUR_MIB / 16).as_bytes());
    let _ = assert_fast("ab:cd:ef:01\n".repeat(FOUR_MIB / 12).as_bytes());
    let _ = assert_fast("a".repeat(FOUR_MIB).as_bytes());
    let _ = assert_fast("30 30 ".repeat(FOUR_MIB / 6).as_bytes());
    let _ = assert_fast("3 0 8 2 ".repeat(FOUR_MIB / 8).as_bytes());
    let _ = assert_fast(format!("30{}30", " ".repeat(FOUR_MIB)).as_bytes());
}

#[test]
fn quando_hex_repete_30_82_por_4_mib_deve_terminar_em_tempo_linear() {
    let out = assert_fast("30 82 ".repeat(FOUR_MIB / 6).as_bytes());
    assert!(out.candidates.len() <= Limits::default().max_certs_per_source);
    for filler in [
        "30 82 ff ff ",
        "30 81 00 ",
        "30:82:00:01:",
        "3082",
        "30 82\n",
    ] {
        let _ = assert_fast(filler.repeat(FOUR_MIB / filler.len()).as_bytes());
    }
}

// ---- nested Base64 (Kubernetes Secret) ---------------------------------------

/// Standard Base64 of `text`, in one line.
fn b64(text: impl AsRef<[u8]>) -> String {
    STANDARD.encode(text)
}

fn secret_with(value: &str) -> String {
    format!("apiVersion: v1\nkind: Secret\ndata:\n  tls.crt: {value}\n  other: xyz\n")
}

#[test]
fn quando_secret_k8s_deve_extrair_os_certificados_dos_dois_campos_sem_repetir() {
    // tls.crt holds the 3-cert chain and ca.crt the root: 4 raw candidates
    // (the root twice), 3 after deduplication (the first root stays).
    let reference = reference_chain();
    let input = read("messy/k8s-secret.yaml");
    let out = scan(&input);
    assert_eq!(
        ders(&out),
        vec![&reference[0], &reference[1], &reference[2]]
    );
    assert_eq!(out.diagnostics.len(), 0, "{:?}", out.diagnostics);
    assert_eq!(out.private_key_blocks_ignored, 0);
    // Offsets inherit the Base64 run of each field.
    let text = String::from_utf8(input).unwrap();
    let tls = text.find("tls.crt: ").unwrap() + "tls.crt: ".len();
    let ca = text.find("ca.crt: ").unwrap() + "ca.crt: ".len();
    let offsets: Vec<usize> = out.candidates.iter().map(|c| c.offset).collect();
    assert_eq!(offsets, vec![tls, tls, tls]);
    assert!(tls < ca);
}

#[test]
fn quando_base64_de_pem_tem_um_nivel_deve_extrair() {
    let leaf = reference_chain().remove(0);
    let value = b64(pem("CERTIFICATE", &leaf_body_lines()));
    let text = secret_with(&value);
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    assert_eq!(out.candidates[0].offset, text.find(&value).unwrap());
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_base64_de_base64_de_pem_deve_extrair_com_profundidade_2() {
    let leaf = reference_chain().remove(0);
    let value = b64(b64(pem("CERTIFICATE", &leaf_body_lines())));
    let text = secret_with(&value);
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    assert_eq!(out.candidates[0].offset, text.find(&value).unwrap());
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_aninhamento_passa_de_2_deve_dar_nesting_too_deep() {
    let value = b64(b64(b64(pem("CERTIFICATE", &leaf_body_lines()))));
    let text = secret_with(&value);
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::NestingTooDeep]);
    assert_eq!(out.diagnostics[0].offset, text.find(&value).unwrap());
    let shown = format!("{:?}", out.diagnostics);
    assert!(!shown.contains("BEGIN") && !shown.contains(&value[..16]));
}

#[test]
fn quando_aninhado_nao_contem_begin_deve_ignorar_sem_diagnostico() {
    let prose = "isto nao e um certificado, e so uma frase longa o bastante para ter mais de sessenta e quatro caracteres.";
    for inner in [
        prose.as_bytes().to_vec(),
        (0..=255u8).cycle().take(300).collect::<Vec<u8>>(),
        b"-----BEGIN-----".repeat(10),
    ] {
        let text = secret_with(&b64(&inner));
        let out = scan(text.as_bytes());
        assert_eq!(out.candidates.len(), 0);
        assert_eq!(out.diagnostics.len(), 0, "{:?}", out.diagnostics);
    }
}

#[test]
fn quando_secret_tem_chave_privada_e_cert_deve_devolver_so_o_cert_e_contar_a_chave() {
    let leaf = reference_chain().remove(0);
    let key = fake_key_lines();
    let key_der = fake_key_der();
    let inner = format!(
        "{}{}",
        pem("PRIVATE KEY", &key),
        pem("CERTIFICATE", &leaf_body_lines())
    );
    for (layers, value) in [(1, b64(&inner)), (2, b64(b64(&inner)))] {
        let text = secret_with(&value);
        let out = scan(text.as_bytes());
        assert_eq!(ders(&out), vec![&leaf], "camadas {layers}");
        assert_eq!(out.private_key_blocks_ignored, 1, "camadas {layers}");
        assert_eq!(out.diagnostics.len(), 0, "camadas {layers}");
        for c in &out.candidates {
            assert!(
                !c.der
                    .windows(16)
                    .any(|w| key_der.windows(16).any(|k| k == w)),
                "camadas {layers}: a chave vazou para um candidato"
            );
        }
        let shown = format!("{out:?}");
        assert!(!shown.contains(&key[0][..16]), "camadas {layers}");
    }
}

#[test]
fn quando_secret_so_tem_chave_privada_deve_contar_e_nao_devolver_nada() {
    let text = secret_with(&b64(pem("RSA PRIVATE KEY", &fake_key_lines())));
    let out = scan(text.as_bytes());
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_base64_aninhado_esta_quebrado_em_linhas_deve_juntar() {
    let leaf = reference_chain().remove(0);
    let wrapped: Vec<String> = b64(pem("CERTIFICATE", &leaf_body_lines()))
        .as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    assert!(wrapped.len() > 2);
    let yaml = format!(
        "data:\n  tls.crt: |\n    {}\n  ca.crt: abc\n",
        wrapped.join("\n    ")
    );
    assert_eq!(ders(&scan(yaml.as_bytes())), vec![&leaf]);
    let plain = format!("antes\n{}\ndepois\n", wrapped.join("\r\n"));
    assert_eq!(ders(&scan(plain.as_bytes())), vec![&leaf]);
    let escaped = format!("{{\"v\":\"{}\"}}", wrapped.join("\\n"));
    assert_eq!(ders(&scan(escaped.as_bytes())), vec![&leaf]);
}

#[test]
fn quando_base64_aninhado_tem_base64_solto_dentro_deve_achar_o_certificado() {
    // The Secret holds a bare Base64 DER (no PEM headers).
    let leaf = reference_chain().remove(0);
    let text = secret_with(&b64(format!("{}\n", b64(&leaf))));
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
}

#[test]
fn quando_candidatos_aninhados_passam_do_limite_deve_marcar_truncado() {
    let limits = Limits {
        max_certs_per_source: 2,
        ..Limits::default()
    };
    let out = scan_text(&read("messy/k8s-secret.yaml"), &limits);
    assert_eq!(out.candidates.len(), 2);
    assert!(out.truncated);
}

#[test]
fn quando_corrida_base64_aninhada_ja_foi_reivindicada_deve_nao_ser_decodificada_de_novo() {
    // A bare Base64 certificate is claimed by the bare detector; the nested
    // detector must not decode it again (a DER is not text anyway).
    let leaf = reference_chain().remove(0);
    let out = scan(secret_with(&b64(&leaf)).as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    assert_eq!(out.diagnostics.len(), 0);
}

#[test]
fn quando_ha_inundacao_de_base64_por_4_mib_deve_terminar_em_tempo_linear_aninhado() {
    let _ = assert_fast("A".repeat(FOUR_MIB).as_bytes());
    let _ = assert_fast(
        format!("{}\n", "QUFB".repeat(16))
            .repeat(FOUR_MIB / 65)
            .as_bytes(),
    );
    let _ = assert_fast(
        format!("{} ", "A".repeat(64))
            .repeat(FOUR_MIB / 65)
            .as_bytes(),
    );
    let _ = assert_fast(
        format!("{} ", "A".repeat(15))
            .repeat(FOUR_MIB / 16)
            .as_bytes(),
    );
    let _ = assert_fast("a\n".repeat(FOUR_MIB / 2).as_bytes());
    let _ = assert_fast(
        format!("A\n{}", " ".repeat(255))
            .repeat(FOUR_MIB / 257)
            .as_bytes(),
    );
    let _ = assert_fast("-".repeat(FOUR_MIB).as_bytes());
}

#[test]
fn quando_ha_bomba_de_base64_aninhado_de_4_mib_deve_terminar_em_tempo_linear() {
    let mut layer = "A".repeat(1_769_472).into_bytes();
    for _ in 0..3 {
        layer = STANDARD.encode(&layer).into_bytes();
    }
    assert!(layer.len() >= FOUR_MIB - 8);
    let out = assert_fast(&layer);
    assert_eq!(reasons(&out), vec![RejectReason::NestingTooDeep]);
    assert_eq!(out.candidates.len(), 0);
}

#[test]
fn quando_ha_muitas_corridas_aninhadas_pequenas_deve_terminar_em_tempo_linear() {
    // Each run decodes to Base64 text, so each one is queued and scanned.
    let inner = b64("A".repeat(60));
    assert!(inner.len() >= 64);
    let _ = assert_fast(
        format!("{inner}\n")
            .repeat(FOUR_MIB / (inner.len() + 1))
            .as_bytes(),
    );
    let pem_inner = b64(pem("CERTIFICATE", &["AAAA".to_owned()]));
    let _ = assert_fast(
        format!("{pem_inner}\n")
            .repeat(FOUR_MIB / (pem_inner.len() + 1))
            .as_bytes(),
    );
}

// ---- final pass: corpus, dedupe, caps, notes, structural check --------------

use certtui_domain::extract::ScanOutcome;
use certtui_domain::model::LoadNote;

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

// -- structural check of unarmored candidates (private keys, CSRs) --

/// A PKCS#8-shaped DER (`SEQUENCE { INTEGER 0, SEQUENCE { rsaEncryption, NULL
/// }, OCTET STRING }`): well-formed DER, starts with `30 82` (`MII` in
/// Base64) like a certificate, but is not a certificate.
fn pkcs8_like_der() -> Vec<u8> {
    let mut der = vec![0x30, 0x82, 0x01, 0x16, 0x02, 0x01, 0x00];
    der.extend([
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ]);
    der.extend([0x05, 0x00, 0x04, 0x82, 0x01, 0x00]);
    let mut x: u32 = 0x9e37_79b9;
    for _ in 0..256 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        der.push(x.to_be_bytes()[2]);
    }
    der
}

fn wrapped_b64(der: &[u8]) -> String {
    STANDARD
        .encode(der)
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Nothing of `key` may be left in what the scan returned.
fn assert_key_not_in(out: &ScanOutcome, key: &[u8]) {
    let shown = format!("{out:?}");
    let needles = [
        STANDARD.encode(key),
        wrapped_b64(key)
            .lines()
            .nth(1)
            .unwrap_or_default()
            .to_owned(),
        hex_of(key.get(8..40).unwrap_or_default(), ""),
        hex_of(key.get(8..40).unwrap_or_default(), ":"),
        format!("{:?}", key.get(8..40).unwrap_or_default()),
    ];
    for needle in needles {
        assert!(!needle.is_empty() && !shown.contains(&needle), "{needle}");
    }
    assert!(
        out.candidates
            .iter()
            .all(|c| !c.der.windows(32).any(|w| key.windows(32).any(|k| k == w)))
    );
}

#[test]
fn quando_chave_tem_cabecalho_mutilado_deve_dar_so_not_der_sequence_e_nao_vazar() {
    let key = pkcs8_like_der();
    let body = wrapped_b64(&key);
    for begin in [
        "----BEGIN PRIVATE KEY-----",
        "-----BEGIN\tPRIVATE KEY-----",
        "BEGIN PRIVATE KEY",
    ] {
        let text = format!("antes\n{begin}\n{body}\n-----END PRIVATE KEY-----\ndepois\n");
        let out = scan(text.as_bytes());
        assert_eq!(out.candidates.len(), 0, "{begin:?}");
        assert_eq!(
            reasons(&out),
            vec![RejectReason::NotDerSequence],
            "{begin:?}"
        );
        assert_key_not_in(&out, &key);
    }
    // Other mangled headers are claimed by the PEM or key detectors (as an
    // unsupported label or a counted key); either way, no candidate and no
    // key bytes.
    let text = format!("-----BEGIN  PRIVATE  KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_key_not_in(&out, &key);
    let text = format!("-----BEGIN PRIVATE KEY----\n{body}\n-----END PRIVATE KEY-----\n");
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_key_not_in(&out, &key);
}

#[test]
fn quando_corpo_da_chave_vem_em_hex_deve_dar_so_not_der_sequence_e_nao_vazar() {
    let key = pkcs8_like_der();
    for sep in ["", ":", " "] {
        let text = format!("key = {}\n", hex_of(&key, sep));
        let out = scan(text.as_bytes());
        assert_eq!(out.candidates.len(), 0, "{sep:?}");
        assert_eq!(reasons(&out), vec![RejectReason::NotDerSequence], "{sep:?}");
        assert_key_not_in(&out, &key);
    }
}

#[test]
fn quando_corpo_da_chave_esta_dentro_de_secret_deve_dar_so_not_der_sequence() {
    let key = pkcs8_like_der();
    let inner = format!("----BEGIN PRIVATE KEY-----\n{}\n", wrapped_b64(&key));
    let out = scan(secret_with(&STANDARD.encode(inner)).as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(reasons(&out), vec![RejectReason::NotDerSequence]);
    assert_key_not_in(&out, &key);
}

#[test]
fn quando_chave_mutilada_e_certificado_reais_estao_no_mesmo_texto_deve_achar_os_certificados() {
    let chain = reference_chain();
    let key = pkcs8_like_der();
    let text = format!(
        "----BEGIN PRIVATE KEY-----\n{}\n\n{}\nkey={}\n{}",
        wrapped_b64(&key),
        STANDARD.encode(&chain[1]),
        hex_of(&key, ":"),
        pem("CERTIFICATE", &leaf_body_lines()),
    );
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&chain[1], &chain[0]]);
    assert_eq!(
        reasons(&out),
        vec![RejectReason::NotDerSequence, RejectReason::NotDerSequence]
    );
    assert_key_not_in(&out, &key);
}

#[test]
fn quando_chave_tem_cabecalho_correto_deve_continuar_so_contada() {
    let key = pkcs8_like_der();
    let text = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        wrapped_b64(&key)
    );
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.private_key_blocks_ignored, 1);
    assert_eq!(reasons(&out), vec![]);
}

#[test]
fn quando_pem_certificate_tem_corpo_que_nao_e_cert_deve_manter_o_comportamento_anterior() {
    // Labelled PEM certificates are validated downstream (app parse).
    let key = pkcs8_like_der();
    let text = pem(
        "CERTIFICATE",
        &wrapped_b64(&key)
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
    );
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&key]);
    assert_eq!(reasons(&out), vec![]);
}

/// Many `MII...` runs shaped like DER but not certificates, as Base64.
fn garbage_runs_b64(total: usize, der_len: usize) -> String {
    let content = der_len - 4;
    let len = u16::try_from(content).unwrap_or(u16::MAX).to_be_bytes();
    let mut der = vec![0x30, 0x82, len[0], len[1]];
    der.extend(std::iter::repeat_n(0x05, content));
    let one = format!("{}\n", STANDARD.encode(der));
    one.repeat(total / one.len())
}

#[test]
fn quando_ha_4_mib_de_corridas_mii_que_nao_sao_certificado_deve_terminar_em_tempo_linear() {
    for der_len in [300, 4000, 60_000] {
        let input = garbage_runs_b64(FOUR_MIB, der_len);
        let out = assert_fast(input.as_bytes());
        assert_eq!(out.candidates.len(), 0, "{der_len}");
        // 500 failures is the bound; only the small runs reach it in 4 MiB.
        assert_eq!(out.truncated, der_len <= 4000, "{der_len}");
        assert!(out.diagnostics.len() <= Limits::default().max_scan_diagnostics);
        assert!(
            out.diagnostics
                .iter()
                .all(|d| d.reason == RejectReason::NotDerSequence)
        );
    }
}

#[test]
fn quando_ha_4_mib_de_hex_der_que_nao_e_certificado_deve_terminar_em_tempo_linear() {
    let mut der = vec![0x30, 0x82, 0x01, 0x00];
    der.extend(std::iter::repeat_n(0x05, 0x100));
    let one = format!("{}\n", hex_of(&der, ""));
    let input = one.repeat(FOUR_MIB / one.len());
    let out = assert_fast(input.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert!(out.truncated);
}

#[test]
fn quando_lixo_precede_o_certificado_dentro_do_limite_deve_achar_o_certificado() {
    let leaf = reference_chain().remove(0);
    let garbage = garbage_runs_b64(20_000, 300);
    let text = format!("{garbage}{}", pem("CERTIFICATE", &leaf_body_lines()));
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    assert!(!out.truncated);
    assert!(
        out.diagnostics
            .iter()
            .all(|d| d.reason == RejectReason::NotDerSequence)
    );
}
