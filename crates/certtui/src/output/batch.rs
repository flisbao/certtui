//! Renderers of `certtui batch`: one entry per target, in input order.

use std::io::{self, Write};

use certtui_app::batch_format::rows_as_csv;
use certtui_domain::batch_input::SkippedLine;
use certtui_domain::batch_row::{BatchRow, RowStatus};
use serde::Serialize;

use super::json::SCHEMA_VERSION;

/// How many rows ended in each status.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Rows in the batch.
    pub total: usize,
    /// Rows with [`RowStatus::Ok`].
    pub ok: usize,
    /// Rows with [`RowStatus::Warning`].
    pub warning: usize,
    /// Rows with [`RowStatus::Error`].
    pub error: usize,
    /// Rows with [`RowStatus::Failed`].
    pub failed: usize,
}

/// Counts `rows` by status.
#[must_use]
pub fn summarize(rows: &[BatchRow]) -> Summary {
    let mut summary = Summary {
        total: rows.len(),
        ..Summary::default()
    };
    for row in rows {
        let counter = match row.status {
            RowStatus::Ok => &mut summary.ok,
            RowStatus::Warning => &mut summary.warning,
            RowStatus::Error => &mut summary.error,
            RowStatus::Failed => &mut summary.failed,
        };
        *counter = counter.saturating_add(1);
    }
    summary
}

#[derive(Serialize)]
struct Document<'a> {
    schema_version: u8,
    summary: Summary,
    rows: &'a [BatchRow],
    skipped: Vec<JsonSkipped>,
}

#[derive(Serialize)]
struct JsonSkipped {
    line: usize,
    reason: String,
}

/// Writes the JSON document (pretty-printed, newline-terminated).
///
/// # Errors
///
/// Any I/O error of `out`.
pub fn write_json(
    out: &mut dyn Write,
    rows: &[BatchRow],
    skipped: &[SkippedLine],
) -> io::Result<()> {
    let document = Document {
        schema_version: SCHEMA_VERSION,
        summary: summarize(rows),
        rows,
        skipped: skipped
            .iter()
            .map(|entry| JsonSkipped {
                line: entry.line,
                reason: entry.reason.to_string(),
            })
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &document).map_err(io::Error::from)?;
    writeln!(out)
}

/// Writes the CSV: the header and one line per row.
///
/// # Errors
///
/// Any I/O error of `out`.
pub fn write_csv(out: &mut dyn Write, rows: &[BatchRow]) -> io::Result<()> {
    out.write_all(rows_as_csv(rows).as_bytes())
}

#[cfg(test)]
mod tests {
    use certtui_domain::batch_input::SkippedLine;
    use certtui_domain::batch_row::{BatchRow, RowStatus};
    use certtui_domain::target::TargetError;
    use serde_json::Value;

    use super::*;

    fn rows() -> Vec<BatchRow> {
        let ok = BatchRow {
            target: "a.com:443".to_owned(),
            status: RowStatus::Ok,
            days_to_expiry: Some(40),
            subject_cn: Some("a.com".to_owned()),
            issuer_cn: Some("CA".to_owned()),
            errors: 0,
            warnings: 0,
            infos: 1,
            failure: None,
        };
        let warning = BatchRow {
            status: RowStatus::Warning,
            warnings: 2,
            ..ok.clone()
        };
        vec![
            ok,
            warning,
            BatchRow::failed("c.com:443", "connection refused"),
        ]
    }

    #[test]
    fn quando_json_deve_ter_schema_resumo_rows_e_skipped() {
        let skipped = [SkippedLine {
            line: 4,
            reason: TargetError::InvalidHost,
        }];
        let mut out = Vec::new();
        write_json(&mut out, &rows(), &skipped).unwrap();
        let json: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["summary"]["total"], 3);
        assert_eq!(json["summary"]["ok"], 1);
        assert_eq!(json["summary"]["warning"], 1);
        assert_eq!(json["summary"]["error"], 0);
        assert_eq!(json["summary"]["failed"], 1);
        assert_eq!(json["rows"].as_array().unwrap().len(), 3);
        assert_eq!(json["rows"][0]["target"], "a.com:443");
        assert_eq!(json["rows"][0]["days_to_expiry"], 40);
        assert_eq!(json["rows"][2]["status"], "failed");
        assert_eq!(json["skipped"][0]["line"], 4);
        assert_eq!(json["skipped"][0]["reason"], "invalid host name");
        assert!(out.ends_with(b"\n"));
    }

    #[test]
    fn quando_csv_deve_ser_o_mesmo_texto_da_biblioteca() {
        let rows = rows();
        let mut out = Vec::new();
        write_csv(&mut out, &rows).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            certtui_app::batch_format::rows_as_csv(&rows)
        );
    }
}
