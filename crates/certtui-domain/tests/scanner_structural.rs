//! Structural check of unarmored candidates: key bodies and CSRs that look
//! like DER are rejected without leaking, and failures are bounded.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use certtui_domain::extract::{RejectReason, ScanOutcome};
use certtui_domain::limits::Limits;

mod support;

use support::*;

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

#[test]
fn quando_lixo_passa_do_limite_de_falhas_e_vem_pem_depois_deve_manter_o_pem() {
    let leaf = reference_chain().remove(0);
    // 600 > the default cap (500) of structural failures.
    let garbage = garbage_runs_b64(600 * 401, 300);
    let text = format!("{garbage}{}", pem("CERTIFICATE", &leaf_body_lines()));
    let out = scan(text.as_bytes());
    assert_eq!(ders(&out), vec![&leaf]);
    assert!(out.truncated);
    assert!(
        out.diagnostics
            .iter()
            .all(|d| d.reason == RejectReason::NotDerSequence)
    );
}

#[test]
fn quando_lixo_passa_do_limite_de_falhas_e_vem_base64_solto_depois_pode_perder_o_certificado() {
    // Documented limitation: past `max_certs_per_source` structural
    // failures, later candidates that would need a parse are dropped
    // unparsed (the scan reports `truncated`); only PEM certificates and
    // PKCS#7 are still kept.
    // Control: the leaf alone is found, so the loss below is caused by the
    // bound on structural failures and not by the leaf itself.
    let alone = scan(format!("{}\n", leaf_base64()).as_bytes());
    assert_eq!(alone.candidates.len(), 1);
    assert!(!alone.truncated);
    let garbage = garbage_runs_b64(600 * 401, 300);
    let text = format!("{garbage}{}\n", leaf_base64());
    let out = scan(text.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert!(out.truncated);
}

/// A certificate DER that fails `parse_der_cert` only deep inside (a corrupted
/// byte as far from the start as possible), same length as the original.
fn late_failing_cert() -> Vec<u8> {
    let der = reference_chain().remove(0);
    let limits = Limits::default();
    // The tail is the signature, which is not parsed: the failing byte
    // closest to the end lies at the end of the extensions.
    for pos in (0..der.len()).rev() {
        let mut bad = der.clone();
        if let Some(b) = bad.get_mut(pos) {
            *b = 0xff;
        }
        if certtui_domain::model::parse_der_cert(&bad, &limits).is_err() {
            assert!(pos > der.len() / 2, "falha tarde: {pos} de {}", der.len());
            return bad;
        }
    }
    Vec::new()
}

#[test]
fn quando_ha_4_mib_de_certificados_que_falham_tarde_no_parse_deve_terminar_em_tempo_linear() {
    let bad = late_failing_cert();
    assert_ne!(bad.len(), 0);
    let one = format!("{}\n", STANDARD.encode(&bad));
    let input = one.repeat(FOUR_MIB / one.len());
    let out = assert_fast(input.as_bytes());
    assert_eq!(out.candidates.len(), 0);
    assert!(out.truncated);
    assert!(
        out.diagnostics
            .iter()
            .all(|d| d.reason == RejectReason::NotDerSequence)
    );
}
