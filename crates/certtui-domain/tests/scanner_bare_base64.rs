//! Bare Base64 detector of `scan_text` (certificates without PEM headers).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use certtui_domain::extract::{CandidateKind, RejectReason, scan_text};
use certtui_domain::limits::Limits;

mod support;

use support::*;

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

/// The leaf as Base64 whose first line has `first` characters; the rest is on
/// the next line (and does not itself start with `MI`).
fn leaf_with_first_line(first: usize) -> String {
    let b64 = leaf_base64();
    let (head, rest) = b64.split_at(first);
    assert!(
        !rest.starts_with("MI"),
        "o resto nao pode virar outra corrida"
    );
    format!("{head}\n{rest}\n")
}

#[test]
fn quando_primeiro_token_mi_tem_15_chars_deve_pular_sem_diagnostico() {
    // 15 characters: below `MIN_FIRST_TOKEN_CHARS`, so the run is not even
    // attempted and the certificate is not found, silently.
    let out = scan(leaf_with_first_line(15).as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert_eq!(out.diagnostics.len(), 0, "{:?}", out.diagnostics);
}

#[test]
fn quando_primeiro_token_mi_tem_16_chars_deve_tentar_a_corrida() {
    // 16 characters: attempted, and the run continues across the line break.
    let leaf = reference_chain().remove(0);
    let out = scan(leaf_with_first_line(16).as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    assert_eq!(out.candidates[0].offset, 0);
    assert_eq!(out.diagnostics.len(), 0, "{:?}", out.diagnostics);
}
