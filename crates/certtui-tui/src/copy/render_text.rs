//! The text copied by `Y`: one `Label: value` line per field.

use certtui_app::present::labels;

use crate::detail_rows::DetailRow;

/// `rows` as plain text.
///
/// - A row with a label and a value is `Label: value`; a copy text that
///   already starts with its label (a finding: `CODE severity: message`) is
///   used as it is.
/// - A row with only a label starts a list: `Label:`.
/// - A row without a label is a list item, indented by two spaces.
///
/// The full copy text is used, never the shortened text drawn on screen, and
/// each field stays on one line.
#[must_use]
pub fn view_as_text(rows: &[DetailRow]) -> String {
    let mut out = String::new();
    for row in rows {
        let line = if row.label.is_empty() {
            format!("  {}", row.value)
        } else if row.value.is_empty() {
            format!("{}:", row.label)
        } else if row.copy_text.starts_with(&row.label) {
            labels::single_line(&row.copy_text)
        } else {
            format!("{}: {}", row.label, labels::single_line(&row.copy_text))
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_campo_simples_deve_ser_label_dois_pontos_valor() {
        let rows = [DetailRow::new("Serial", "01AB")];
        assert_eq!(view_as_text(&rows), "Serial: 01AB\n");
    }

    #[test]
    fn quando_lista_deve_ter_cabecalho_e_itens_indentados() {
        let rows = [
            DetailRow::with_copy("Key Usage", "", "a\nb"),
            DetailRow::item("digitalSignature"),
            DetailRow::item("keyEncipherment"),
        ];
        assert_eq!(
            view_as_text(&rows),
            "Key Usage:\n  digitalSignature\n  keyEncipherment\n"
        );
    }

    #[test]
    fn quando_copy_text_ja_comeca_com_o_label_deve_nao_repetir() {
        let rows = [DetailRow::with_copy(
            "EXPIRED",
            "error: gone",
            "EXPIRED error: gone",
        )];
        assert_eq!(view_as_text(&rows), "EXPIRED error: gone\n");
    }

    #[test]
    fn quando_valor_resumido_na_tela_deve_copiar_o_completo() {
        let rows = [DetailRow::with_copy(
            "SHA-256",
            "AB:CD\u{2026}12:34",
            "AB:CD:EF:12:34",
        )];
        assert_eq!(view_as_text(&rows), "SHA-256: AB:CD:EF:12:34\n");
    }
}
