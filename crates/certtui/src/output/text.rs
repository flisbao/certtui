//! `--text`: a readable block per certificate.
//!
//! Every piece of text that comes from a certificate goes through
//! [`sanitize_display`] so a hostile certificate cannot drive the terminal.

use std::fmt::Write as _;
use std::io::{self, Write};

use certtui_domain::model::{
    CertificateRecord, FingerprintAlgorithm, FingerprintFormat, InspectionReport, TrustVerdict,
};

use super::{View, labels};

const INDENT: &str = "    ";

/// Writes the text report: one block per selected certificate, a `Notes:`
/// section when the load produced diagnostics, and, for a network target, the
/// TLS session footer.
///
/// # Errors
///
/// Any I/O error of `out`.
pub fn write(out: &mut dyn Write, view: &View<'_>) -> io::Result<()> {
    for (position, (index, record)) in view.certs().enumerate() {
        if position > 0 {
            writeln!(out)?;
        }
        write_certificate(out, index, record, view.fingerprint_format)?;
    }
    if !view.report.notes.is_empty() {
        writeln!(out)?;
        writeln!(out, "Notes:")?;
        for note in &view.report.notes {
            writeln!(out, "  - {}", labels::note_text(note))?;
        }
    }
    write_validation(out, view.report)?;
    write_session(out, view.report)
}

/// The trust verdict and the findings, once the chain has been evaluated.
fn write_validation(out: &mut dyn Write, report: &InspectionReport) -> io::Result<()> {
    if report.trust == TrustVerdict::NotEvaluated {
        return Ok(());
    }
    writeln!(out)?;
    writeln!(out, "Trust: {}", labels::trust_text(&report.trust))?;
    if report.findings.is_empty() {
        return writeln!(out, "Findings: none");
    }
    writeln!(out, "Findings:")?;
    for finding in &report.findings {
        writeln!(out, "  - {}", labels::finding_text(finding))?;
    }
    Ok(())
}

/// Separator of the footer segments (U+00B7).
const SEPARATOR: &str = " \u{b7} ";

/// The TLS footer: `TLSv1.3 · <cipher> · <peer ip> · handshake <n>ms`, then
/// an optional line with the key exchange group, ALPN protocol and OCSP
/// staple. Nothing for targets without a TLS session.
fn write_session(out: &mut dyn Write, report: &InspectionReport) -> io::Result<()> {
    let Some(tls) = &report.tls else {
        return Ok(());
    };
    let mut footer = vec![
        tls.version.clone(),
        tls.cipher_suite.clone(),
        tls.peer_ip.to_string(),
    ];
    if let Some(handshake) = report.timings.handshake {
        footer.push(format!("handshake {}ms", handshake.as_millis()));
    }
    writeln!(out)?;
    writeln!(out, "{}", labels::single_line(&footer.join(SEPARATOR)))?;
    let mut details = Vec::new();
    if let Some(group) = &tls.key_exchange_group {
        details.push(format!("key exchange {group}"));
    }
    if let Some(alpn) = &tls.alpn {
        details.push(format!("ALPN {alpn}"));
    }
    if let Some(staple) = &report.ocsp_staple {
        details.push(format!("OCSP staple {} bytes", staple.len()));
    }
    if details.is_empty() {
        return Ok(());
    }
    writeln!(out, "{}", labels::single_line(&details.join(SEPARATOR)))
}

fn line(out: &mut dyn Write, label: &str, value: &str) -> io::Result<()> {
    writeln!(out, "{INDENT}{label}: {}", labels::single_line(value))
}

/// Escapes `\` and `,` so that an item can never contain the `", "`
/// separator: a value such as `x, DNS:evil` cannot pass for two entries.
fn escape_list_item(value: &str) -> String {
    value.replace('\\', r"\\").replace(',', r"\,")
}

fn list(out: &mut dyn Write, label: &str, values: &[String]) -> io::Result<()> {
    if values.is_empty() {
        return Ok(());
    }
    let items: Vec<String> = values
        .iter()
        .map(|value| labels::single_line(&escape_list_item(value)))
        .collect();
    line(out, label, &items.join(", "))
}

fn write_certificate(
    out: &mut dyn Write,
    index: usize,
    record: &CertificateRecord,
    format: FingerprintFormat,
) -> io::Result<()> {
    let summary = &record.summary;
    writeln!(
        out,
        "[{index}] Subject: {}",
        labels::single_line(&summary.subject.rfc4514)
    )?;
    line(out, "Issuer", &summary.issuer.rfc4514)?;
    line(out, "Origin", &labels::origin_text(&record.origin))?;
    line(out, "Version", &summary.version.to_string())?;
    line(out, "Serial", &summary.serial.to_hex())?;
    line(out, "Not Before", &summary.not_before.to_string())?;
    line(out, "Not After", &summary.not_after.to_string())?;
    line(out, "Public Key", &public_key_text(record))?;
    line(
        out,
        "Signature Algorithm",
        &summary.signature_algorithm.name,
    )?;
    write_usage(out, record)?;
    write_identifiers(out, record)?;
    write_extensions(out, record)?;
    write_fingerprints(out, record, format)
}

/// SANs, basic constraints, key usage and extended key usage.
fn write_usage(out: &mut dyn Write, record: &CertificateRecord) -> io::Result<()> {
    let summary = &record.summary;
    let sans: Vec<String> = summary
        .subject_alt_names
        .iter()
        .map(labels::san_text)
        .collect();
    list(out, "Subject Alt Names", &sans)?;
    if let Some(constraints) = &summary.basic_constraints {
        let mut text = format!("CA:{}", if constraints.ca { "TRUE" } else { "FALSE" });
        if let Some(path_len) = constraints.path_len {
            // Writing to a `String` cannot fail.
            let _ = write!(text, ", pathlen:{path_len}");
        }
        line(out, "Basic Constraints", &text)?;
    }
    if let Some(usage) = &summary.key_usage {
        let names: Vec<String> = labels::key_usage_names(usage)
            .into_iter()
            .map(str::to_owned)
            .collect();
        list(out, "Key Usage", &names)?;
    }
    let purposes: Vec<String> = summary
        .extended_key_usage
        .iter()
        .map(labels::extended_key_usage)
        .collect();
    list(out, "Extended Key Usage", &purposes)
}

/// Key identifiers, AIA, CRL distribution points and SCT count.
fn write_identifiers(out: &mut dyn Write, record: &CertificateRecord) -> io::Result<()> {
    let summary = &record.summary;
    if let Some(id) = &summary.subject_key_id {
        line(out, "Subject Key ID", &id.to_hex())?;
    }
    if let Some(id) = &summary.authority_key_id {
        line(out, "Authority Key ID", &id.to_hex())?;
    }
    list(out, "OCSP", &summary.aia.ocsp)?;
    list(out, "CA Issuers", &summary.aia.ca_issuers)?;
    list(
        out,
        "CRL Distribution Points",
        &summary.crl_distribution_points,
    )?;
    if !summary.embedded_scts.is_empty() {
        line(
            out,
            "Embedded SCTs",
            &summary.embedded_scts.len().to_string(),
        )?;
    }
    Ok(())
}

fn write_extensions(out: &mut dyn Write, record: &CertificateRecord) -> io::Result<()> {
    let extensions = &record.summary.extensions;
    if extensions.is_empty() {
        return Ok(());
    }
    writeln!(out, "{INDENT}Extensions:")?;
    for extension in extensions {
        let critical = if extension.critical {
            " (critical)"
        } else {
            ""
        };
        let undecodable = if extension.decode_error {
            " [could not be decoded]"
        } else {
            ""
        };
        writeln!(
            out,
            "{INDENT}  {} {}{critical}{undecodable}",
            labels::single_line(&extension.oid),
            labels::single_line(&extension.name),
        )?;
    }
    Ok(())
}

fn write_fingerprints(
    out: &mut dyn Write,
    record: &CertificateRecord,
    format: FingerprintFormat,
) -> io::Result<()> {
    writeln!(out, "{INDENT}Fingerprints:")?;
    for (label, algorithm) in [
        ("SHA-1:  ", FingerprintAlgorithm::Sha1),
        ("SHA-256:", FingerprintAlgorithm::Sha256),
        ("SHA-512:", FingerprintAlgorithm::Sha512),
    ] {
        writeln!(
            out,
            "{INDENT}  {label} {}",
            record.fingerprints.format(algorithm, format)
        )?;
    }
    Ok(())
}

fn public_key_text(record: &CertificateRecord) -> String {
    let key = &record.summary.public_key;
    let mut text = labels::public_key_algorithm(&key.algorithm);
    if key.bits > 0 {
        // Writing to a `String` cannot fail.
        let _ = write!(text, " {} bits", key.bits);
    }
    if let Some(curve) = &key.curve {
        let _ = write!(text, " ({curve})");
    }
    text
}

#[cfg(test)]
mod tests {
    use certtui_domain::model::LoadNote;

    use super::super::testing::{make_hostile, network_report, report, report_with};
    use super::*;

    fn render(view: &View<'_>) -> String {
        let mut out = Vec::new();
        write(&mut out, view).unwrap();
        String::from_utf8(out).unwrap()
    }

    fn view(report: &certtui_domain::model::InspectionReport) -> View<'_> {
        View {
            report,
            only: None,
            fingerprint_format: FingerprintFormat::default(),
        }
    }

    #[test]
    fn quando_dois_certs_deve_ter_um_bloco_por_cert_com_os_tres_fingerprints() {
        let report = report(&["rsa2048-leaf", "expired"], Vec::new());
        let text = render(&view(&report));
        assert!(text.starts_with("[0] Subject: "));
        assert!(text.contains("\n[1] Subject: "));
        for label in ["SHA-1:", "SHA-256:", "SHA-512:"] {
            assert_eq!(text.matches(label).count(), 2, "{label}");
        }
        assert!(!text.contains("Notes:"));
    }

    #[test]
    fn quando_ha_notas_deve_fechar_com_secao_notes() {
        let report = report(
            &["rsa2048-leaf"],
            vec![LoadNote::PrivateKeyBlocksIgnored { count: 1 }],
        );
        let text = render(&view(&report));
        assert!(text.ends_with("\nNotes:\n  - 1 private key block(s) ignored\n"));
    }

    #[test]
    fn quando_only_deve_mostrar_so_aquele_cert_com_o_indice_original() {
        let report = report(&["rsa2048-leaf", "expired"], Vec::new());
        let mut v = view(&report);
        v.only = Some(1);
        let text = render(&v);
        assert!(text.starts_with("[1] Subject: "));
        assert!(!text.contains("[0]"));
    }

    #[test]
    fn quando_formato_hex_deve_refletir_nos_fingerprints() {
        let report = report(&["rsa2048-leaf"], Vec::new());
        let mut v = view(&report);
        v.fingerprint_format = FingerprintFormat::HexLower;
        assert!(
            render(&v).contains(
                "SHA-256: dddb9b863347fc84961030c3f4c57c66cabf921ed4b43a15ce41b79f39a663bb"
            )
        );
    }

    /// Every line is either blank, indented, a `[N] Subject:` header or `Notes:`.
    fn assert_layout_intact(text: &str, headers: usize) {
        let mut seen = 0;
        for line in text.lines() {
            if line.starts_with("[0] Subject: ") {
                seen += 1;
            } else {
                assert!(
                    line.is_empty()
                        || line.starts_with("    ")
                        || line == "Notes:"
                        || line.starts_with("  - "),
                    "forged layout line: {line:?}"
                );
                assert!(!line.starts_with('['), "forged header: {line:?}");
            }
        }
        assert_eq!(seen, headers);
    }

    #[test]
    fn quando_texto_do_cert_tem_newline_e_tab_nao_deve_forjar_linhas() {
        let report = report_with("rsa2048-leaf", make_hostile);
        let text = render(&view(&report));
        assert_layout_intact(&text, 1);
        // Nothing is silently dropped: the controls are shown escaped.
        assert!(text.contains(r"x\n[1] Subject: CN=Trusted Root CA\n    Issuer: evil\ty"));
        assert!(!text.contains('\t'));
    }

    #[test]
    fn quando_cada_campo_hostil_deve_ficar_em_uma_so_linha() {
        let report = report_with("rsa2048-leaf", make_hostile);
        let text = render(&view(&report));
        for label in [
            "Subject Alt Names: ",
            "OCSP: ",
            "CA Issuers: ",
            "CRL Distribution Points: ",
            "Issuer: ",
            "Origin: ",
            "Public Key: ",
            "Signature Algorithm: ",
        ] {
            let lines: Vec<&str> = text
                .lines()
                .filter(|l| l.trim_start().starts_with(label))
                .collect();
            assert_eq!(lines.len(), 1, "{label}: {lines:?}");
            assert!(lines[0].contains(r"\n"), "{label}: {}", lines[0]);
        }
    }

    #[test]
    fn quando_san_contem_separador_de_lista_nao_deve_forjar_outro_san() {
        let mut report = report(&["rsa2048-leaf"], Vec::new());
        let mut record = report.chain.get(0).unwrap().clone();
        record.summary.subject_alt_names = vec![
            certtui_domain::model::SubjectAltName::Dns("a.test".to_owned()),
            certtui_domain::model::SubjectAltName::Dns("x, DNS:evil.test".to_owned()),
            certtui_domain::model::SubjectAltName::Dns(r"back\slash".to_owned()),
        ];
        report.chain = certtui_domain::model::Chain::new(
            vec![record],
            &certtui_domain::limits::Limits::default(),
        )
        .unwrap();
        let text = render(&view(&report));
        assert!(
            text.contains(
                r"    Subject Alt Names: DNS:a.test, DNS:x\, DNS:evil.test, DNS:back\\slash"
            ),
            "{text}"
        );
    }

    #[test]
    fn quando_texto_do_cert_tem_controle_deve_sair_sanitizado() {
        let mut report = report(&["rsa2048-leaf"], Vec::new());
        let record = report.chain.get(0).unwrap().clone();
        let mut hostile = record;
        hostile.summary.subject.rfc4514 = "CN=a\u{1b}[31mb".to_owned();
        hostile.summary.issuer.rfc4514 = "CN=\u{9b}x\u{202E}y".to_owned();
        hostile.summary.crl_distribution_points = vec!["http://a/\u{7}b".to_owned()];
        report.chain = certtui_domain::model::Chain::new(
            vec![hostile],
            &certtui_domain::limits::Limits::default(),
        )
        .unwrap();
        let text = render(&view(&report));
        assert!(text.contains("[0] Subject: CN=a[31mb\n"));
        assert!(text.contains("Issuer: CN=xy\n"));
        assert!(text.contains("CRL Distribution Points: http://a/b\n"));
        assert_layout_intact(&text, 1);
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
    }

    #[test]
    fn quando_alvo_de_rede_deve_fechar_com_o_rodape_de_tls() {
        let report = network_report(&["rsa2048-leaf"]);
        let text = render(&view(&report));
        assert!(
            text.ends_with(
                "\nTLSv1.3 \u{b7} TLS_AES_256_GCM_SHA384 \u{b7} 93.184.216.34 \u{b7} handshake 41ms\n\
                 key exchange X25519 \u{b7} ALPN h2\n"
            ),
            "{text}"
        );
    }

    #[test]
    fn quando_alvo_de_rede_tem_staple_deve_citar_o_tamanho() {
        let mut report = network_report(&["rsa2048-leaf"]);
        report.ocsp_staple = Some(vec![0; 1500]);
        assert!(render(&view(&report)).contains("ALPN h2 \u{b7} OCSP staple 1500 bytes\n"));
    }

    #[test]
    fn quando_sem_handshake_nem_detalhes_deve_ter_so_tres_segmentos() {
        let mut report = network_report(&["rsa2048-leaf"]);
        report.timings.handshake = None;
        if let Some(tls) = &mut report.tls {
            tls.key_exchange_group = None;
            tls.alpn = None;
        }
        let text = render(&view(&report));
        assert!(
            text.ends_with("\nTLSv1.3 \u{b7} TLS_AES_256_GCM_SHA384 \u{b7} 93.184.216.34\n"),
            "{text}"
        );
    }

    #[test]
    fn quando_rodape_vem_depois_das_notas() {
        let mut report = network_report(&["rsa2048-leaf"]);
        report.notes = vec![LoadNote::Unparsable { offset: None }];
        let text = render(&view(&report));
        let notes = text.find("Notes:").unwrap();
        let footer = text.find("TLSv1.3 ").unwrap();
        assert!(notes < footer, "{text}");
    }

    #[test]
    fn quando_tls_tem_controles_deve_sair_em_uma_linha_so() {
        let mut report = network_report(&["rsa2048-leaf"]);
        if let Some(tls) = &mut report.tls {
            tls.cipher_suite = "X\n[9] Subject: forged\t".to_owned();
        }
        let text = render(&view(&report));
        assert!(!text.contains("\n[9]"), "{text}");
        assert!(text.contains("X\\n[9] Subject: forged\\t"), "{text}");
    }

    #[test]
    fn quando_alvo_local_nao_deve_ter_rodape() {
        let text = render(&view(&report(&["rsa2048-leaf"], Vec::new())));
        assert!(!text.contains("TLSv"), "{text}");
    }
}
