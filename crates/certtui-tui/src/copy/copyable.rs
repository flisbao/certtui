//! What each view can put on the clipboard.

use certtui_app::present::{View, json, pem};
use certtui_domain::model::FingerprintFormat;
use certtui_domain::sanitize::sanitize_display;

use super::CopyPayload;
use super::render_text::view_as_text;
use crate::app_state::{InspectState, Pane, Tab};
use crate::detail_rows::{DetailRow, rows_for_tab};

/// Data a view can copy: the datum under the cursor and the whole view.
pub trait Copyable {
    /// `y`: the datum under the cursor.
    fn copy_focused(&self) -> Option<CopyPayload>;
    /// `Y`: everything the view shows.
    fn copy_view(&self) -> Option<CopyPayload>;
}

/// The Inspect screen seen as something copyable.
#[derive(Debug, Clone, Copy)]
pub struct InspectCopy<'a> {
    /// The screen state.
    pub inspect: &'a InspectState,
    /// Fingerprint format the rows are built in.
    pub format: FingerprintFormat,
}

fn payload(label: &str, text: &str) -> Option<CopyPayload> {
    let text = sanitize_display(text);
    if text.is_empty() {
        return None;
    }
    Some(CopyPayload {
        label: label.to_owned(),
        text: text.into_owned(),
    })
}

impl InspectCopy<'_> {
    fn rows(&self) -> Vec<DetailRow> {
        self.inspect.report().map_or_else(Vec::new, |report| {
            rows_for_tab(
                report,
                self.inspect.selected_cert,
                self.inspect.tab,
                self.format,
            )
        })
    }

    /// `c`: the selected certificate as PEM.
    #[must_use]
    pub fn copy_pem(&self) -> Option<CopyPayload> {
        let record = self
            .inspect
            .report()?
            .chain
            .get(self.inspect.selected_cert)?;
        payload("certificate PEM", &pem::encode(&record.der))
    }

    /// `C`: every certificate as PEM, in the order the chain holds them
    /// (the order presented by the server).
    #[must_use]
    pub fn copy_chain_pem(&self) -> Option<CopyPayload> {
        let report = self.inspect.report()?;
        let text: String = report
            .chain
            .records()
            .iter()
            .map(|record| pem::encode(&record.der))
            .collect();
        payload("chain PEM", &text)
    }

    /// `J`: the report as JSON, the same document `--json` prints.
    #[must_use]
    pub fn copy_json(&self) -> Option<CopyPayload> {
        let report = self.inspect.report()?;
        let view = View {
            report,
            only: None,
            fingerprint_format: self.format,
        };
        let mut buffer = Vec::new();
        json::write(&mut buffer, &view).ok()?;
        payload("report JSON", &String::from_utf8_lossy(&buffer))
    }
}

impl Copyable for InspectCopy<'_> {
    fn copy_focused(&self) -> Option<CopyPayload> {
        let report = self.inspect.report()?;
        match self.inspect.pane {
            Pane::Chain => {
                let record = report.chain.get(self.inspect.selected_cert)?;
                payload("Subject", &record.summary.subject.rfc4514)
            }
            Pane::Details => {
                let rows = self.rows();
                let row = rows.get(self.inspect.row_cursor)?;
                let label = if row.label.is_empty() {
                    self.inspect.tab.title()
                } else {
                    &row.label
                };
                payload(label, &row.copy_text)
            }
        }
    }

    fn copy_view(&self) -> Option<CopyPayload> {
        if self.inspect.tab == Tab::Raw {
            return self.copy_pem();
        }
        payload(self.inspect.tab.title(), &view_as_text(&self.rows()))
    }
}

#[cfg(test)]
mod tests {
    use certtui_app::present::pem;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::app_state::{AppState, Modal};
    use crate::msg::{Command, Msg};
    use crate::test_fixtures::{inspect_state, record_with_cn, report_of, sample_report};
    use crate::toast::ToastKind;
    use crate::update::update;

    fn key(c: char) -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    fn down(state: &mut AppState, times: usize) {
        for _ in 0..times {
            update(state, key('j'));
        }
    }

    /// The single copy command a key produced.
    fn copied(state: &mut AppState, c: char) -> CopyPayload {
        let mut commands = update(state, key(c));
        assert_eq!(commands.len(), 1, "{commands:?}");
        match commands.remove(0) {
            Command::CopyToClipboard(payload) => payload,
            other => unreachable!("expected a copy, got {other:?}"),
        }
    }

    #[test]
    fn quando_y_no_detalhe_deve_emitir_copy_do_valor_do_campo() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('l'));
        down(&mut state, 2);
        let serial = state
            .inspect
            .as_ref()
            .and_then(InspectState::report)
            .and_then(|report| report.chain.get(0))
            .map(|record| record.summary.serial.to_hex())
            .unwrap();
        let payload = copied(&mut state, 'y');
        assert_eq!(payload.label, "Serial");
        assert_eq!(payload.text, serial);
    }

    #[test]
    fn quando_y_em_sha256_do_overview_deve_copiar_o_valor_completo_nao_o_abreviado() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('l'));
        down(&mut state, 7);
        let payload = copied(&mut state, 'y');
        assert_eq!(payload.label, "SHA-256");
        assert_eq!(payload.text.len(), 95);
        assert!(!payload.text.contains('\u{2026}'));
    }

    #[test]
    fn quando_y_na_arvore_deve_copiar_subject_dn() {
        let mut state = inspect_state(sample_report());
        down(&mut state, 1);
        let payload = copied(&mut state, 'y');
        assert_eq!(payload.label, "Subject");
        assert!(
            payload.text.starts_with("CN=ec-p256.example.test"),
            "{payload:?}"
        );
    }

    #[test]
    fn quando_y_maiusculo_deve_copiar_aba_como_label_valor() {
        let mut state = inspect_state(sample_report());
        let payload = copied(&mut state, 'Y');
        assert_eq!(payload.label, "Overview");
        insta::assert_snapshot!(payload.text);
    }

    #[test]
    fn quando_y_maiusculo_na_aba_raw_deve_copiar_o_pem_exato() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('['));
        let payload = copied(&mut state, 'Y');
        let der = state
            .inspect
            .as_ref()
            .and_then(InspectState::report)
            .and_then(|report| report.chain.get(0))
            .map(|record| record.der.clone())
            .unwrap();
        assert_eq!(payload.text, pem::encode(&der));
    }

    #[test]
    fn quando_c_deve_copiar_pem_do_cert() {
        let mut state = inspect_state(sample_report());
        down(&mut state, 2);
        let payload = copied(&mut state, 'c');
        let der = state
            .inspect
            .as_ref()
            .and_then(InspectState::report)
            .and_then(|report| report.chain.get(2))
            .map(|record| record.der.clone())
            .unwrap();
        assert_eq!(payload.label, "certificate PEM");
        assert_eq!(payload.text, pem::encode(&der));
    }

    #[test]
    fn quando_c_maiusculo_deve_copiar_cadeia_na_ordem_apresentada() {
        let mut state = inspect_state(sample_report());
        let payload = copied(&mut state, 'C');
        let expected: String = state
            .inspect
            .as_ref()
            .and_then(InspectState::report)
            .unwrap()
            .chain
            .records()
            .iter()
            .map(|record| pem::encode(&record.der))
            .collect();
        assert_eq!(payload.text, expected);
        assert_eq!(payload.text.matches("BEGIN CERTIFICATE").count(), 3);
    }

    #[test]
    fn quando_j_deve_copiar_json_com_schema_version_1() {
        let mut state = inspect_state(sample_report());
        let payload = copied(&mut state, 'J');
        let json: serde_json::Value = serde_json::from_str(&payload.text).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["certificates"].as_array().map(Vec::len), Some(3));
    }

    #[test]
    fn quando_y_em_findings_deve_copiar_codigo_severidade_mensagem() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('l'));
        for _ in 0..6 {
            update(&mut state, key(']'));
        }
        let payload = copied(&mut state, 'y');
        assert_eq!(payload.label, "MISSING_SAN");
        assert_eq!(payload.text, "MISSING_SAN warning: MISSING_SAN happened");
    }

    #[test]
    fn quando_valor_tem_esc_deve_copiar_sanitizado() {
        let mut state = inspect_state(report_of(vec![record_with_cn("a\u{1b}[31mb\u{9b}c", 0)]));
        for action in ['y', 'Y', 'c', 'C', 'J'] {
            let payload = copied(&mut state, action);
            assert!(
                !payload
                    .text
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t'),
                "{action}: {:?}",
                payload.text
            );
        }
        update(&mut state, key('l'));
        let payload = copied(&mut state, 'y');
        assert!(!payload.text.contains('\u{1b}'), "{payload:?}");
    }

    #[test]
    fn quando_texto_passa_do_limite_deve_nao_emitir_command_e_mostrar_toast() {
        let mut state = inspect_state(sample_report());
        state.max_clipboard_bytes = 10;
        assert_eq!(update(&mut state, key('C')), Vec::new());
        let toast = state.toast.as_ref().unwrap();
        assert_eq!(toast.kind, ToastKind::Error);
        assert!(
            toast.text.starts_with("too large to copy ("),
            "{}",
            toast.text
        );
        assert!(
            toast.text.ends_with("KiB); press e to export"),
            "{}",
            toast.text
        );
    }

    #[test]
    fn quando_texto_cabe_exatamente_no_limite_deve_copiar() {
        let mut state = inspect_state(sample_report());
        let size = copied(&mut state, 'c').text.len();
        state.max_clipboard_bytes = size;
        assert_eq!(update(&mut state, key('c')).len(), 1);
    }

    #[test]
    fn quando_nada_selecionado_deve_nao_emitir_command() {
        // No certificate in the chain: the cursor has nothing under it.
        let mut state = inspect_state(report_of(Vec::new()));
        for action in ['c', 'C', 'J'] {
            let commands = update(&mut state, key(action));
            assert_eq!(commands.len(), usize::from(action == 'J'), "{action}");
        }
        assert_eq!(update(&mut state, key('y')), Vec::new());
    }

    #[test]
    fn quando_relatorio_nao_esta_pronto_deve_nao_emitir_command() {
        let mut state = inspect_state(sample_report());
        if let Some(inspect) = state.inspect.as_mut() {
            inspect.phase = crate::app_state::Phase::Loading;
        }
        for action in ['y', 'Y', 'c', 'C', 'J'] {
            assert_eq!(update(&mut state, key(action)), Vec::new(), "{action}");
        }
    }

    #[test]
    fn quando_modal_aberto_deve_nao_copiar_nada() {
        let mut state = inspect_state(sample_report());
        state.modal = Some(Modal::Help);
        for action in ['y', 'Y', 'c', 'C', 'J'] {
            assert_eq!(update(&mut state, key(action)), Vec::new(), "{action}");
        }
    }
}
