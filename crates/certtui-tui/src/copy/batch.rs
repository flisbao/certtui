//! Text of batch rows for the clipboard: TSV for a row, CSV for a table.

use certtui_app::batch_format::formula_guard;
use certtui_domain::batch_row::BatchRow;

/// The row as one tab-separated line, in the column order of the CSV.
///
/// A tab or line break inside a cell becomes a space, so the line always has
/// nine cells; a cell that would run as a spreadsheet formula gets a leading
/// `'`.
#[must_use]
pub fn row_as_tsv(row: &BatchRow) -> String {
    let optional = |value: &Option<String>| value.as_deref().map_or_else(String::new, cell);
    [
        cell(&row.target),
        row.status.as_str().to_owned(),
        row.days_to_expiry
            .map_or_else(String::new, |days| days.to_string()),
        optional(&row.subject_cn),
        optional(&row.issuer_cn),
        row.errors.to_string(),
        row.warnings.to_string(),
        row.infos.to_string(),
        optional(&row.failure),
    ]
    .join("\t")
}

/// One TSV cell: tabs and line breaks folded to spaces, then the formula
/// guard.
fn cell(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| {
            if matches!(c, '\t' | '\n' | '\r') {
                ' '
            } else {
                c
            }
        })
        .collect();
    formula_guard(&flat)
}

/// The CSV of `rows`, header included: the same text as `certtui batch --csv`.
#[must_use]
pub fn rows_as_csv(rows: &[&BatchRow]) -> String {
    certtui_app::batch_format::rows_as_csv(rows.iter().copied())
}

#[cfg(test)]
mod tests {
    use certtui_domain::batch_row::RowStatus;

    use super::*;

    fn row(cn: Option<&str>) -> BatchRow {
        BatchRow {
            target: "a.com:443".to_owned(),
            status: RowStatus::Error,
            days_to_expiry: Some(-2),
            subject_cn: cn.map(str::to_owned),
            issuer_cn: Some("CA".to_owned()),
            errors: 1,
            warnings: 2,
            infos: 3,
            failure: None,
        }
    }

    #[test]
    fn quando_row_tem_tab_no_cn_deve_trocar_por_espaco() {
        let tsv = row_as_tsv(&row(Some("a\tb\nc\rd")));
        assert_eq!(tsv.split('\t').count(), 9, "{tsv:?}");
        assert!(tsv.contains("a b c d"), "{tsv:?}");
        assert!(!tsv.contains('\n'));
    }

    #[test]
    fn quando_row_normal_deve_seguir_a_ordem_do_csv() {
        assert_eq!(
            row_as_tsv(&row(Some("a.com"))),
            "a.com:443\terror\t-2\ta.com\tCA\t1\t2\t3\t"
        );
    }

    #[test]
    fn quando_cn_comeca_com_igual_deve_prefixar_apostrofo() {
        let tsv = row_as_tsv(&row(Some("=HYPERLINK(\"x\")")));
        assert!(tsv.contains("\t'=HYPERLINK(\"x\")\t"), "{tsv:?}");
        let tsv = row_as_tsv(&row(Some("@x")));
        assert!(tsv.contains("\t'@x\t"), "{tsv:?}");
        let tsv = row_as_tsv(&row(Some("-x")));
        assert!(tsv.contains("\t'-x\t"), "{tsv:?}");
    }

    #[test]
    fn quando_csv_da_tui_e_do_cli_deve_ser_identico() {
        let rows = [row(Some("a.com")), row(Some("=1+1")), row(None)];
        let refs: Vec<&BatchRow> = rows.iter().collect();
        assert_eq!(
            rows_as_csv(&refs),
            certtui_app::batch_format::rows_as_csv(&rows)
        );
        assert!(rows_as_csv(&refs).contains("'=1+1"));
    }
}
