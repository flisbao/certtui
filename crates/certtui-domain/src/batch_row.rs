//! The compact per-target result of a batch run (spec section 6.5).
//!
//! A batch keeps one [`BatchRow`] per target and never the report or the
//! chain it came from, so memory grows with the number of rows only.

use serde::Serialize;

use crate::finding::Severity;
use crate::model::InspectionReport;
use crate::sanitize::sanitize_display;
use crate::time::Timestamp;

/// Longest failure summary kept in a row, in characters.
const MAX_FAILURE_CHARS: usize = 120;

/// The worst outcome of a target. Ordered `Ok < Warning < Error < Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RowStatus {
    /// Inspected, with at most informational findings.
    Ok,
    /// Inspected, worst finding is a warning.
    Warning,
    /// Inspected, worst finding is an error.
    Error,
    /// No certificate could be inspected (network or I/O failure).
    Failed,
}

impl RowStatus {
    /// The lowercase name used in JSON and CSV.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RowStatus::Ok => "ok",
            RowStatus::Warning => "warning",
            RowStatus::Error => "error",
            RowStatus::Failed => "failed",
        }
    }
}

/// One line of a batch result.
///
/// Strings that come from a certificate or from the network are sanitized
/// when the row is built, so a row is safe to print or copy as it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BatchRow {
    /// The target as the user wrote it, normalized (`host:port`).
    pub target: String,
    /// Worst outcome.
    pub status: RowStatus,
    /// Whole days until the leaf expires; negative once expired.
    pub days_to_expiry: Option<i64>,
    /// Common name of the leaf's subject.
    pub subject_cn: Option<String>,
    /// Common name of the leaf's issuer.
    pub issuer_cn: Option<String>,
    /// Number of error findings.
    pub errors: u32,
    /// Number of warning findings.
    pub warnings: u32,
    /// Number of informational findings.
    pub infos: u32,
    /// Short reason, only when `status` is [`RowStatus::Failed`].
    pub failure: Option<String>,
}

impl BatchRow {
    /// Summarizes `report`; the leaf is the first certificate of the chain.
    #[must_use]
    pub fn from_report(target: &str, report: &InspectionReport, now: Timestamp) -> BatchRow {
        let (mut errors, mut warnings, mut infos) = (0_u32, 0_u32, 0_u32);
        for finding in &report.findings {
            let counter = match finding.severity {
                Severity::Error => &mut errors,
                Severity::Warning => &mut warnings,
                Severity::Info => &mut infos,
            };
            *counter = counter.saturating_add(1);
        }
        let status = if errors > 0 {
            RowStatus::Error
        } else if warnings > 0 {
            RowStatus::Warning
        } else {
            RowStatus::Ok
        };
        let leaf = report.chain.records().first().map(|record| &record.summary);
        BatchRow {
            target: sanitize_display(target).into_owned(),
            status,
            days_to_expiry: leaf.map(|s| now.days_until(s.not_after)),
            subject_cn: leaf
                .and_then(|s| s.subject.common_name.as_deref())
                .map(clean),
            issuer_cn: leaf
                .and_then(|s| s.issuer.common_name.as_deref())
                .map(clean),
            errors,
            warnings,
            infos,
            failure: None,
        }
    }

    /// A row for a target that could not be inspected. `reason` is cut to
    /// 120 characters, sanitized and folded to a single line.
    #[must_use]
    pub fn failed(target: &str, reason: &str) -> BatchRow {
        let failure: String = sanitize_display(reason)
            .chars()
            .map(|c| if c == '\n' || c == '\t' { ' ' } else { c })
            .take(MAX_FAILURE_CHARS)
            .collect();
        BatchRow {
            target: sanitize_display(target).into_owned(),
            status: RowStatus::Failed,
            days_to_expiry: None,
            subject_cn: None,
            issuer_cn: None,
            errors: 0,
            warnings: 0,
            infos: 0,
            failure: Some(failure),
        }
    }
}

fn clean(text: &str) -> String {
    sanitize_display(text).into_owned()
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use time::OffsetDateTime;

    use super::*;
    use crate::finding::{Finding, FindingCategory, FindingCode};
    use crate::limits::Limits;
    use crate::model::{CertOrigin, CertificateRecord, Chain, StapleState, Timings, TrustVerdict};
    use crate::target::{NetworkTarget, Target};

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn record(cn: Option<&str>, not_after: i64) -> CertificateRecord {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        if let Some(cn) = cn {
            params.distinguished_name.push(DnType::CommonName, cn);
        } else {
            params
                .distinguished_name
                .push(DnType::OrganizationName, "NoCommonName Org");
        }
        params.not_before = OffsetDateTime::from_unix_timestamp(NOW - 400 * DAY).unwrap();
        params.not_after = OffsetDateTime::from_unix_timestamp(not_after).unwrap();
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        CertificateRecord::from_der(
            cert.der(),
            CertOrigin::Presented { position: 0 },
            &Limits::default(),
        )
        .unwrap()
    }

    fn finding(severity: Severity) -> Finding {
        Finding {
            code: FindingCode::Expired,
            severity,
            category: FindingCategory::Quality,
            cert_index: Some(0),
            message: "x".to_owned(),
        }
    }

    fn report(records: Vec<CertificateRecord>, findings: Vec<Finding>) -> InspectionReport {
        InspectionReport {
            target: Target::Network(NetworkTarget {
                host: "example.com".to_owned(),
                port: 443,
                sni: None,
                connect_to: None,
            }),
            tls: None,
            ocsp_staple: None,
            chain: Chain::new(records, &Limits::default()).unwrap(),
            trust: TrustVerdict::NotEvaluated,
            revocation: Vec::new(),
            staple: StapleState::NotApplicable,
            findings,
            timings: Timings::default(),
            notes: Vec::new(),
        }
    }

    fn now() -> Timestamp {
        Timestamp::from_unix(NOW).unwrap()
    }

    #[test]
    fn dias_negativos_para_expirado() {
        let rep = report(vec![record(Some("a"), NOW - 3 * DAY)], Vec::new());
        let row = BatchRow::from_report("a.com:443", &rep, now());
        assert_eq!(row.days_to_expiry, Some(-3));
    }

    #[test]
    fn dias_positivos_para_valido() {
        let rep = report(vec![record(Some("a"), NOW + 30 * DAY + 60)], Vec::new());
        let row = BatchRow::from_report("a.com:443", &rep, now());
        assert_eq!(row.days_to_expiry, Some(30));
        assert_eq!(row.status, RowStatus::Ok);
        assert_eq!(row.failure, None);
        assert_eq!(row.target, "a.com:443");
    }

    #[test]
    fn contagem_por_severidade() {
        let findings = vec![
            finding(Severity::Error),
            finding(Severity::Error),
            finding(Severity::Warning),
            finding(Severity::Info),
            finding(Severity::Info),
            finding(Severity::Info),
        ];
        let rep = report(vec![record(Some("a"), NOW + DAY)], findings);
        let row = BatchRow::from_report("a.com:443", &rep, now());
        assert_eq!((row.errors, row.warnings, row.infos), (2, 1, 3));
        assert_eq!(row.status, RowStatus::Error);
    }

    #[test]
    fn status_e_a_pior_severidade() {
        let cases = [
            (vec![], RowStatus::Ok),
            (vec![Severity::Info], RowStatus::Ok),
            (vec![Severity::Info, Severity::Warning], RowStatus::Warning),
            (vec![Severity::Warning, Severity::Error], RowStatus::Error),
        ];
        for (severities, expected) in cases {
            let findings = severities.into_iter().map(finding).collect();
            let rep = report(vec![record(Some("a"), NOW + DAY)], findings);
            let row = BatchRow::from_report("t:443", &rep, now());
            assert_eq!(row.status, expected);
        }
    }

    #[test]
    fn cn_ausente_deve_ser_none() {
        let rep = report(vec![record(None, NOW + DAY)], Vec::new());
        let row = BatchRow::from_report("a.com:443", &rep, now());
        assert_eq!(row.subject_cn, None);
        assert_eq!(row.issuer_cn, None);
    }

    #[test]
    fn cn_presente_deve_vir_do_leaf_indice_zero() {
        let rep = report(
            vec![
                record(Some("leaf.example"), NOW + DAY),
                record(Some("other"), NOW),
            ],
            Vec::new(),
        );
        let row = BatchRow::from_report("a.com:443", &rep, now());
        assert_eq!(row.subject_cn.as_deref(), Some("leaf.example"));
        assert_eq!(row.issuer_cn.as_deref(), Some("leaf.example"));
    }

    #[test]
    fn cn_com_esc_deve_ser_sanitizado() {
        let rep = report(vec![record(Some("ev\u{1b}[31mil"), NOW + DAY)], Vec::new());
        let row = BatchRow::from_report("a.com:443", &rep, now());
        assert_eq!(row.subject_cn.as_deref(), Some("ev[31mil"));
    }

    #[test]
    fn cadeia_vazia_deve_dar_dias_none() {
        let rep = report(Vec::new(), Vec::new());
        let row = BatchRow::from_report("a.com:443", &rep, now());
        assert_eq!(row.days_to_expiry, None);
        assert_eq!(row.subject_cn, None);
    }

    #[test]
    fn failed_deve_cortar_em_120_chars_e_sanitizar() {
        let reason = format!("boom\u{1b}[0m\nline2\t{}", "é".repeat(200));
        let row = BatchRow::failed("a.com:443", &reason);
        assert_eq!(row.status, RowStatus::Failed);
        let failure = row.failure.unwrap();
        assert_eq!(failure.chars().count(), 120);
        assert!(failure.starts_with("boom[0m line2 "), "{failure}");
        assert!(!failure.contains(['\n', '\t', '\u{1b}']));
        assert_eq!((row.errors, row.warnings, row.infos), (0, 0, 0));
        assert_eq!(row.days_to_expiry, None);
    }

    #[test]
    fn status_deve_ordenar_ok_warning_error_failed() {
        assert!(RowStatus::Ok < RowStatus::Warning);
        assert!(RowStatus::Warning < RowStatus::Error);
        assert!(RowStatus::Error < RowStatus::Failed);
    }

    #[test]
    fn status_deve_ter_nome_minusculo_estavel() {
        let names: Vec<&str> = [
            RowStatus::Ok,
            RowStatus::Warning,
            RowStatus::Error,
            RowStatus::Failed,
        ]
        .iter()
        .map(|status| status.as_str())
        .collect();
        assert_eq!(names, ["ok", "warning", "error", "failed"]);
    }

    #[test]
    fn row_deve_serializar_em_json_com_status_minusculo() {
        let row = BatchRow::failed("a.com:443", "timeout");
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["status"], "failed");
        assert_eq!(json["failure"], "timeout");
        assert_eq!(json["days_to_expiry"], serde_json::Value::Null);
    }
}
