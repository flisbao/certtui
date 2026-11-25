//! Text formats of batch rows, shared by `certtui batch --csv` and the
//! clipboard of the batch screen so both produce the same bytes.

use certtui_domain::batch_row::BatchRow;

/// The first line of every CSV, without the line break.
pub const CSV_HEADER: &str = "target,status,days,cn,issuer,errors,warnings,infos,failure";

/// Makes a text cell safe for a spreadsheet: a cell that starts with `=`,
/// `+`, `-`, `@`, a tab or a carriage return would be run as a formula, so
/// it gets a leading `'`.
#[must_use]
pub fn formula_guard(cell: &str) -> String {
    if cell.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{cell}")
    } else {
        cell.to_owned()
    }
}

/// One CSV cell (RFC 4180): [`formula_guard`], then quotes around a cell
/// with a comma, a quote or a line break, doubling inner quotes.
#[must_use]
pub fn escape_cell(cell: &str) -> String {
    let guarded = formula_guard(cell);
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

/// The CSV line of `row`, without the line break. The number of days is
/// written as it is: it is not text, and a negative value must stay a number.
#[must_use]
pub fn csv_line(row: &BatchRow) -> String {
    let days = row
        .days_to_expiry
        .map_or_else(String::new, |days| days.to_string());
    let optional = |value: &Option<String>| value.as_deref().map_or_else(String::new, escape_cell);
    [
        escape_cell(&row.target),
        row.status.as_str().to_owned(),
        days,
        optional(&row.subject_cn),
        optional(&row.issuer_cn),
        row.errors.to_string(),
        row.warnings.to_string(),
        row.infos.to_string(),
        optional(&row.failure),
    ]
    .join(",")
}

/// The header and one line per row, each ended by `\n`.
#[must_use]
pub fn rows_as_csv<'a>(rows: impl IntoIterator<Item = &'a BatchRow>) -> String {
    let mut csv = String::from(CSV_HEADER);
    csv.push('\n');
    for row in rows {
        csv.push_str(&csv_line(row));
        csv.push('\n');
    }
    csv
}

#[cfg(test)]
mod tests {
    use certtui_domain::batch_row::RowStatus;

    use super::*;

    fn row(target: &str, cn: Option<&str>) -> BatchRow {
        BatchRow {
            target: target.to_owned(),
            status: RowStatus::Warning,
            days_to_expiry: Some(-3),
            subject_cn: cn.map(str::to_owned),
            issuer_cn: Some("Issuer, Inc".to_owned()),
            errors: 0,
            warnings: 2,
            infos: 1,
            failure: None,
        }
    }

    #[test]
    fn escape_cell_deve_seguir_a_tabela() {
        let cases = [
            ("plain", "plain"),
            ("", ""),
            ("a,b", "\"a,b\""),
            ("say \"hi\"", "\"say \"\"hi\"\"\""),
            ("=1+1", "'=1+1"),
            ("+1", "'+1"),
            ("-1", "'-1"),
            ("@x", "'@x"),
            ("\tx", "'\tx"),
            ("\rx", "\"'\rx\""),
            ("linha1\nlinha2", "\"linha1\nlinha2\""),
            (
                "=HYPERLINK(\"http://x\",\"c\")",
                "\"'=HYPERLINK(\"\"http://x\"\",\"\"c\"\")\"",
            ),
            ("a=b", "a=b"),
            ("ção", "ção"),
        ];
        for (input, expected) in cases {
            assert_eq!(escape_cell(input), expected, "{input:?}");
        }
    }

    #[test]
    fn formula_guard_so_prefixa_sem_escapar_virgulas() {
        assert_eq!(formula_guard("=1,2"), "'=1,2");
        assert_eq!(formula_guard("ok,fine"), "ok,fine");
        assert_eq!(formula_guard(""), "");
    }

    #[test]
    fn csv_line_deve_seguir_a_ordem_do_cabecalho() {
        let line = csv_line(&row("a.com:443", Some("a.com")));
        assert_eq!(line, "a.com:443,warning,-3,a.com,\"Issuer, Inc\",0,2,1,");
    }

    #[test]
    fn csv_line_com_falha_e_sem_dados_deve_deixar_vazio() {
        let failed = BatchRow::failed("b.com:443", "connection refused");
        assert_eq!(
            csv_line(&failed),
            "b.com:443,failed,,,,0,0,0,connection refused"
        );
    }

    #[test]
    fn quando_cn_malicioso_deve_prefixar_apostrofo_na_linha() {
        let line = csv_line(&row("a.com:443", Some("=HYPERLINK(\"x\")")));
        assert!(line.contains(",\"'=HYPERLINK(\"\"x\"\")\","), "{line}");
    }

    #[test]
    fn rows_as_csv_deve_ter_cabecalho_e_uma_linha_por_row() {
        let rows = [row("a:443", Some("a")), row("b:443", None)];
        let csv = rows_as_csv(&rows);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], CSV_HEADER);
        assert!(csv.ends_with('\n'));
        assert_eq!(rows_as_csv(&[] as &[BatchRow]), format!("{CSV_HEADER}\n"));
    }
}
