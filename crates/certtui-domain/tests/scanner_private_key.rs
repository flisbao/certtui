//! Private key blocks: skipped whole, counted, never decoded or leaked.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use certtui_domain::extract::RejectReason;

mod support;

use support::*;

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
