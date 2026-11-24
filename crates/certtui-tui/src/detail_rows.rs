//! The rows of the details pane: the single source for drawing and copying.

use std::fmt::Write as _;

use certtui_app::present::{labels, pem};
use certtui_domain::finding::{Finding, Severity};
use certtui_domain::model::{
    CertificateRecord, FingerprintAlgorithm, FingerprintFormat, InspectionReport, RevocationStatus,
};
use certtui_domain::sanitize::sanitize_display;

use crate::app_state::Tab;

/// One selectable line of the details pane.
///
/// An empty `label` marks an item of the list started by the row above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailRow {
    /// Field name.
    pub label: String,
    /// Text drawn: sanitized and on one line.
    pub value: String,
    /// Text copied: sanitized, with the full value (never cut to the screen).
    pub copy_text: String,
}

impl DetailRow {
    /// A row whose drawn and copied text both come from `raw`.
    #[must_use]
    pub fn new(label: &str, raw: &str) -> Self {
        Self {
            label: label.to_owned(),
            value: labels::single_line(raw),
            copy_text: sanitize_display(raw).into_owned(),
        }
    }

    /// A row drawn as `shown` but copied as `copied`.
    #[must_use]
    pub fn with_copy(label: &str, shown: &str, copied: &str) -> Self {
        Self {
            label: label.to_owned(),
            value: labels::single_line(shown),
            copy_text: sanitize_display(copied).into_owned(),
        }
    }

    /// A list item that belongs to the row above.
    #[must_use]
    pub fn item(raw: &str) -> Self {
        Self::new("", raw)
    }
}

/// Health of a certificate, from the worst finding that names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertStatus {
    /// No warning or error.
    Ok,
    /// At least one warning.
    Warning,
    /// At least one error.
    Error,
}

impl CertStatus {
    /// The icon drawn in the chain tree.
    #[must_use]
    pub const fn icon(self) -> &'static str {
        match self {
            CertStatus::Ok => "\u{2714}",
            CertStatus::Warning => "\u{26a0}",
            CertStatus::Error => "\u{2716}",
        }
    }
}

/// Status of the certificate at `index`.
#[must_use]
pub fn cert_status(report: &InspectionReport, index: usize) -> CertStatus {
    let worst = report
        .findings
        .iter()
        .filter(|finding| finding.cert_index == Some(index))
        .map(|finding| finding.severity)
        .max();
    match worst {
        Some(Severity::Error) => CertStatus::Error,
        Some(Severity::Warning) => CertStatus::Warning,
        Some(Severity::Info) | None => CertStatus::Ok,
    }
}

/// The rows of `tab` for the certificate at `cert`.
///
/// Used both to draw the pane and to build what `y` and `Y` copy.
#[must_use]
pub fn rows_for_tab(
    report: &InspectionReport,
    cert: usize,
    tab: Tab,
    format: FingerprintFormat,
) -> Vec<DetailRow> {
    if tab == Tab::Findings {
        return finding_rows(report, cert);
    }
    match report.chain.get(cert) {
        Some(record) => match tab {
            Tab::Overview => overview_rows(report, cert, record, format),
            Tab::SubjectIssuer => subject_issuer_rows(record),
            Tab::Sans => san_rows(record),
            Tab::Extensions => extension_rows(record),
            Tab::Fingerprints => fingerprint_rows(record, format),
            Tab::Revocation => revocation_rows(report, cert),
            Tab::Raw => raw_rows(record),
            Tab::Findings => Vec::new(),
        },
        None => note_rows(report),
    }
}

fn overview_rows(
    report: &InspectionReport,
    cert: usize,
    record: &CertificateRecord,
    format: FingerprintFormat,
) -> Vec<DetailRow> {
    let summary = &record.summary;
    let mut rows = vec![
        DetailRow::new("Subject", &summary.subject.rfc4514),
        DetailRow::new("Issuer", &summary.issuer.rfc4514),
        DetailRow::new("Serial", &summary.serial.to_hex()),
        DetailRow::new("Not Before", &summary.not_before.to_string()),
        DetailRow::new("Not After", &summary.not_after.to_string()),
        DetailRow::new("Public Key", &public_key_text(record)),
        DetailRow::new("Signature", &summary.signature_algorithm.name),
        DetailRow::with_copy(
            "SHA-256",
            &record.fingerprints.sha256.short(),
            &record
                .fingerprints
                .format(FingerprintAlgorithm::Sha256, format),
        ),
        DetailRow::new("Origin", &labels::origin_text(&record.origin)),
    ];
    if cert == 0 {
        rows.push(DetailRow::new("Trust", &labels::trust_text(&report.trust)));
    }
    rows
}

fn subject_issuer_rows(record: &CertificateRecord) -> Vec<DetailRow> {
    let summary = &record.summary;
    let mut rows = vec![DetailRow::new("Subject", &summary.subject.rfc4514)];
    if let Some(cn) = &summary.subject.common_name {
        rows.push(DetailRow::new("Subject CN", cn));
    }
    rows.push(DetailRow::new("Issuer", &summary.issuer.rfc4514));
    if let Some(cn) = &summary.issuer.common_name {
        rows.push(DetailRow::new("Issuer CN", cn));
    }
    rows
}

fn san_rows(record: &CertificateRecord) -> Vec<DetailRow> {
    record
        .summary
        .subject_alt_names
        .iter()
        .map(|san| {
            let (kind, value) = labels::san_parts(san);
            DetailRow::new(kind, &value)
        })
        .collect()
}

/// A header row followed by one item row per value; nothing when empty.
fn list_rows(label: &str, values: &[String]) -> Vec<DetailRow> {
    if values.is_empty() {
        return Vec::new();
    }
    let mut rows = vec![DetailRow::with_copy(label, "", &values.join("\n"))];
    rows.extend(values.iter().map(|value| DetailRow::item(value)));
    rows
}

fn extension_rows(record: &CertificateRecord) -> Vec<DetailRow> {
    let summary = &record.summary;
    let mut rows = Vec::new();
    if let Some(constraints) = &summary.basic_constraints {
        let mut text = format!("CA:{}", if constraints.ca { "TRUE" } else { "FALSE" });
        if let Some(path_len) = constraints.path_len {
            // Writing to a `String` cannot fail.
            let _ = write!(text, ", pathlen:{path_len}");
        }
        rows.push(DetailRow::new("Basic Constraints", &text));
    }
    if let Some(usage) = &summary.key_usage {
        let names: Vec<String> = labels::key_usage_names(usage)
            .into_iter()
            .map(str::to_owned)
            .collect();
        rows.extend(list_rows("Key Usage", &names));
    }
    let purposes: Vec<String> = summary
        .extended_key_usage
        .iter()
        .map(labels::extended_key_usage)
        .collect();
    rows.extend(list_rows("Extended Key Usage", &purposes));
    if let Some(id) = &summary.subject_key_id {
        rows.push(DetailRow::new("Subject Key ID", &id.to_hex()));
    }
    if let Some(id) = &summary.authority_key_id {
        rows.push(DetailRow::new("Authority Key ID", &id.to_hex()));
    }
    rows.extend(list_rows("OCSP", &summary.aia.ocsp));
    rows.extend(list_rows("CA Issuers", &summary.aia.ca_issuers));
    rows.extend(list_rows(
        "CRL Distribution Points",
        &summary.crl_distribution_points,
    ));
    if !summary.embedded_scts.is_empty() {
        rows.push(DetailRow::new(
            "Embedded SCTs",
            &summary.embedded_scts.len().to_string(),
        ));
    }
    let extensions: Vec<String> = summary
        .extensions
        .iter()
        .map(|extension| {
            let critical = if extension.critical {
                " (critical)"
            } else {
                ""
            };
            let broken = if extension.decode_error {
                " [could not be decoded]"
            } else {
                ""
            };
            format!("{} {}{critical}{broken}", extension.oid, extension.name)
        })
        .collect();
    rows.extend(list_rows("Extensions", &extensions));
    rows
}

fn fingerprint_rows(record: &CertificateRecord, format: FingerprintFormat) -> Vec<DetailRow> {
    [
        ("SHA-1", FingerprintAlgorithm::Sha1),
        ("SHA-256", FingerprintAlgorithm::Sha256),
        ("SHA-512", FingerprintAlgorithm::Sha512),
    ]
    .into_iter()
    .map(|(label, algorithm)| DetailRow::new(label, &record.fingerprints.format(algorithm, format)))
    .collect()
}

fn revocation_rows(report: &InspectionReport, cert: usize) -> Vec<DetailRow> {
    let text = match report.revocation.get(cert) {
        None => "not evaluated".to_owned(),
        Some(RevocationStatus::Good) => "good".to_owned(),
        Some(RevocationStatus::Revoked { reason, at }) => {
            let mut text = "revoked".to_owned();
            if let Some(reason) = reason {
                // Writing to a `String` cannot fail.
                let _ = write!(text, " ({reason})");
            }
            if let Some(at) = at {
                // Writing to a `String` cannot fail.
                let _ = write!(text, " at {at}");
            }
            text
        }
        Some(RevocationStatus::Unknown { why }) => format!("unknown ({why})"),
    };
    vec![DetailRow::new("Status", &text)]
}

fn finding_rows(report: &InspectionReport, cert: usize) -> Vec<DetailRow> {
    let rows: Vec<DetailRow> = report
        .findings
        .iter()
        .filter(|finding| finding.cert_index.is_none_or(|index| index == cert))
        .map(finding_row)
        .collect();
    if rows.is_empty() {
        return vec![DetailRow::new("Findings", "none")];
    }
    rows
}

fn finding_row(finding: &Finding) -> DetailRow {
    let severity = labels::severity_text(finding.severity);
    DetailRow::with_copy(
        finding.code.as_str(),
        &format!("{severity}: {}", finding.message),
        &format!("{} {severity}: {}", finding.code.as_str(), finding.message),
    )
}

/// One row per PEM line, so the pane scrolls and every line is selectable.
fn raw_rows(record: &CertificateRecord) -> Vec<DetailRow> {
    pem::encode(&record.der)
        .lines()
        .map(DetailRow::item)
        .collect()
}

/// What to show when the chain has no certificate to describe.
fn note_rows(report: &InspectionReport) -> Vec<DetailRow> {
    if report.notes.is_empty() {
        return vec![DetailRow::new("Certificates", "none")];
    }
    report
        .notes
        .iter()
        .map(|note| DetailRow::new("Note", &labels::note_text(note)))
        .collect()
}

fn public_key_text(record: &CertificateRecord) -> String {
    let key = &record.summary.public_key;
    format!(
        "{} ({} bits)",
        labels::public_key_algorithm(&key.algorithm),
        key.bits
    )
}

/// The label of a certificate in the chain tree: its CN, or its subject DN.
#[must_use]
pub fn cert_title(record: &CertificateRecord) -> String {
    let subject = &record.summary.subject;
    let title = subject.common_name.as_deref().unwrap_or(&subject.rfc4514);
    labels::single_line(title)
}

#[cfg(test)]
mod tests {
    use certtui_domain::finding::{FindingCode, Severity};

    use super::*;
    use crate::test_fixtures::{finding, record_with_cn, report_of, sample_report};

    #[test]
    fn quando_aba_fingerprints_deve_ter_tres_linhas_sha1_sha256_sha512() {
        let report = sample_report();
        let rows = rows_for_tab(
            &report,
            0,
            Tab::Fingerprints,
            FingerprintFormat::ColonHexUpper,
        );
        let labels: Vec<&str> = rows.iter().map(|row| row.label.as_str()).collect();
        assert_eq!(labels, ["SHA-1", "SHA-256", "SHA-512"]);
    }

    #[test]
    fn quando_overview_deve_mostrar_sha256_abreviado_e_copiar_o_completo() {
        let report = sample_report();
        let rows = rows_for_tab(&report, 0, Tab::Overview, FingerprintFormat::ColonHexUpper);
        let sha = rows.iter().find(|row| row.label == "SHA-256").unwrap();
        let record = report.chain.get(0).unwrap();
        assert_eq!(sha.value, record.fingerprints.sha256.short());
        assert_eq!(
            sha.copy_text,
            record.fingerprints.format(
                FingerprintAlgorithm::Sha256,
                FingerprintFormat::ColonHexUpper
            )
        );
    }

    #[test]
    fn quando_certificado_pior_achado_deve_definir_o_icone() {
        let report = sample_report();
        assert_eq!(cert_status(&report, 0), CertStatus::Warning);
        assert_eq!(cert_status(&report, 1), CertStatus::Ok);
        assert_eq!(cert_status(&report, 2), CertStatus::Error);
    }

    #[test]
    fn quando_aba_findings_deve_listar_codigo_severidade_e_mensagem() {
        let report = sample_report();
        let rows = rows_for_tab(&report, 2, Tab::Findings, FingerprintFormat::default());
        let codes: Vec<&str> = rows.iter().map(|row| row.label.as_str()).collect();
        assert_eq!(codes, ["EXPIRED", "TRUST_UNTRUSTED"]);
        assert_eq!(
            rows.first().map(|row| row.copy_text.as_str()),
            Some("EXPIRED error: EXPIRED happened")
        );
    }

    #[test]
    fn quando_sem_achados_deve_dizer_none() {
        let report = report_of(vec![record_with_cn("a", 0)]);
        let rows = rows_for_tab(&report, 0, Tab::Findings, FingerprintFormat::default());
        assert_eq!(rows, vec![DetailRow::new("Findings", "none")]);
    }

    #[test]
    fn quando_revogacao_nao_avaliada_deve_dizer_not_evaluated() {
        let report = sample_report();
        let rows = rows_for_tab(&report, 0, Tab::Revocation, FingerprintFormat::default());
        assert_eq!(rows, vec![DetailRow::new("Status", "not evaluated")]);
    }

    #[test]
    fn quando_aba_raw_deve_ter_uma_linha_por_linha_do_pem() {
        let report = sample_report();
        let rows = rows_for_tab(&report, 0, Tab::Raw, FingerprintFormat::default());
        assert_eq!(
            rows.first().map(|row| row.value.as_str()),
            Some("-----BEGIN CERTIFICATE-----")
        );
        assert_eq!(
            rows.last().map(|row| row.value.as_str()),
            Some("-----END CERTIFICATE-----")
        );
    }

    #[test]
    fn quando_cn_tem_esc_deve_sanitizar_tela_e_copia() {
        let report = report_of(vec![record_with_cn("a\u{1b}[31mb", 0)]);
        let rows = rows_for_tab(&report, 0, Tab::SubjectIssuer, FingerprintFormat::default());
        let cn = rows.iter().find(|row| row.label == "Subject CN").unwrap();
        assert!(!cn.value.contains('\u{1b}'));
        assert!(!cn.copy_text.contains('\u{1b}'));
    }

    #[test]
    fn quando_cert_fora_da_cadeia_deve_mostrar_notas_ou_none() {
        let report = report_of(Vec::new());
        let rows = rows_for_tab(&report, 0, Tab::Overview, FingerprintFormat::default());
        assert_eq!(rows, vec![DetailRow::new("Certificates", "none")]);
    }

    #[test]
    fn quando_findings_de_outro_cert_deve_ficar_de_fora() {
        let mut report = report_of(vec![record_with_cn("a", 0), record_with_cn("b", 1)]);
        report.findings = vec![finding(FindingCode::WeakKey, Severity::Warning, Some(1))];
        let rows = rows_for_tab(&report, 0, Tab::Findings, FingerprintFormat::default());
        assert_eq!(rows, vec![DetailRow::new("Findings", "none")]);
    }

    #[test]
    fn quando_extensoes_deve_ter_lista_com_cabecalho_e_itens() {
        let report = sample_report();
        let rows = rows_for_tab(&report, 0, Tab::Extensions, FingerprintFormat::default());
        let header = rows
            .iter()
            .position(|row| row.label == "Extensions")
            .unwrap();
        assert!(rows.get(header + 1).is_some_and(|row| row.label.is_empty()));
        assert!(
            rows.get(header)
                .is_some_and(|row| row.copy_text.contains('\n') || rows.len() == header + 2)
        );
    }
}
