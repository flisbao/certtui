//! Hex DER detector of `scan_text`.

use certtui_domain::extract::{CandidateKind, RejectReason, scan_text};
use certtui_domain::limits::Limits;

mod support;

use support::*;

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
