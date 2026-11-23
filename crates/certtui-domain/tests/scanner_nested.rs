//! Base64 that decodes to text (Kubernetes Secrets and the like): nesting,
//! ordering of nested candidates and resource bounds.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use certtui_domain::extract::{RejectReason, scan_text};
use certtui_domain::limits::Limits;

mod support;

use support::*;

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
