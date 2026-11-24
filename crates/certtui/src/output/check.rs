//! Renderers of `certtui check`: one entry per target, in the order given.

use std::borrow::Cow;
use std::io::{self, Write};

use certtui_domain::model::InspectionReport;
use serde::Serialize;

use super::json::{self, JsonFinding, JsonTrust, SCHEMA_VERSION};
use super::labels;

/// The outcome of checking one target.
#[derive(Debug)]
pub struct TargetResult<'a> {
    /// The target as the user typed it.
    pub target: &'a str,
    /// The validated report, or why the target could not be checked.
    pub outcome: Result<&'a InspectionReport, &'a str>,
}

/// Writes the text report: a verdict line per checked target followed by its
/// findings. Targets that could not be checked are reported on stderr only.
///
/// # Errors
///
/// Any I/O error of `out`.
pub fn write_text(out: &mut dyn Write, results: &[TargetResult<'_>]) -> io::Result<()> {
    for result in results {
        let Ok(report) = result.outcome else {
            continue;
        };
        writeln!(
            out,
            "{}: {}",
            labels::single_line(result.target),
            labels::trust_text(&report.trust)
        )?;
        if report.findings.is_empty() {
            writeln!(out, "  no findings")?;
        }
        for finding in &report.findings {
            writeln!(out, "  {}", labels::finding_text(finding))?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct Document<'a> {
    schema_version: u8,
    results: Vec<JsonResult<'a>>,
}

#[derive(Serialize)]
struct JsonResult<'a> {
    target: Cow<'a, str>,
    error: Option<Cow<'a, str>>,
    trust: Option<JsonTrust<'a>>,
    findings: Vec<JsonFinding<'a>>,
}

/// Writes the JSON document (pretty-printed, newline-terminated): per target,
/// `trust` and `findings`, or an `error` when it could not be checked.
///
/// # Errors
///
/// Any I/O error of `out`.
pub fn write_json(out: &mut dyn Write, results: &[TargetResult<'_>]) -> io::Result<()> {
    let document = Document {
        schema_version: SCHEMA_VERSION,
        results: results.iter().map(json_result).collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &document).map_err(io::Error::from)?;
    writeln!(out)
}

fn json_result<'a>(result: &'a TargetResult<'a>) -> JsonResult<'a> {
    let target = json::clean(result.target);
    match result.outcome {
        Ok(report) => JsonResult {
            target,
            error: None,
            trust: Some(json::trust(&report.trust)),
            findings: report.findings.iter().map(json::finding).collect(),
        },
        Err(message) => JsonResult {
            target,
            error: Some(json::clean(message)),
            trust: None,
            findings: Vec::new(),
        },
    }
}
