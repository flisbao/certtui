//! The Inspect screen: chain tree on the left, detail tabs on the right.

use certtui_app::present::labels;
use certtui_domain::model::InspectionReport;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use super::tabs::{RowsView, fit, render_rows, render_tab_bar};
use crate::app_state::{AppState, InspectState, Pane, Phase, Tab};
use crate::detail_rows::{CertStatus, cert_status, cert_title, rows_for_tab};
use crate::keymap::{Action, Keymap};
use crate::theme::Theme;

/// Draws the Inspect screen.
pub fn render(state: &AppState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let Some(inspect) = state.inspect.as_ref() else {
        return;
    };
    let [main, footer] = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);
    match &inspect.phase {
        Phase::Loading => render_message(frame, main, "Inspecting\u{2026}", theme.dim, theme),
        Phase::Failed(message) => {
            render_message(
                frame,
                main,
                &format!("Failed: {message}"),
                theme.error,
                theme,
            );
        }
        Phase::Ready(report) => render_ready(state, inspect, report, frame, main, theme),
    }
    render_footer(inspect, &state.keymap, frame, footer, theme);
}

fn render_message(
    frame: &mut Frame,
    area: Rect,
    text: &str,
    style: ratatui::style::Style,
    theme: &Theme,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border)
        .title(" certtui ")
        .title_style(theme.title);
    frame.render_widget(
        Paragraph::new(text.to_owned())
            .style(style)
            .wrap(ratatui::widgets::Wrap { trim: true })
            .block(block),
        area,
    );
}

fn render_ready(
    state: &AppState,
    inspect: &InspectState,
    report: &InspectionReport,
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
) {
    let [chain_area, details_area] =
        Layout::horizontal([Constraint::Percentage(34), Constraint::Min(1)]).areas(area);
    render_chain(inspect, report, frame, chain_area, theme);

    let focus_style = |pane: Pane| {
        if inspect.pane == pane {
            theme.title
        } else {
            theme.border
        }
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(focus_style(Pane::Details))
        .title(" Details ")
        .title_style(theme.title);
    let inner = block.inner(details_area);
    frame.render_widget(block, details_area);
    let [tabs_area, rows_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(inner);
    render_tab_bar(frame, tabs_area, inspect.tab, theme);
    let rows = rows_for_tab(
        report,
        inspect.selected_cert,
        inspect.tab,
        state.fingerprint_format,
    );
    let view = RowsView {
        rows: &rows,
        scroll: usize::from(inspect.scroll),
        cursor: inspect.row_cursor,
        focused: inspect.pane == Pane::Details,
        wrap: inspect.tab == Tab::Fingerprints,
    };
    render_rows(frame, rows_area, &view, theme);
}

fn render_chain(
    inspect: &InspectState,
    report: &InspectionReport,
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
) {
    let border = if inspect.pane == Pane::Chain {
        theme.title
    } else {
        theme.border
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(" Chain ")
        .title_style(theme.title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let width = usize::from(inner.width);
    let mut lines: Vec<Line> = Vec::new();
    for (index, record) in report.chain.records().iter().enumerate() {
        let status = cert_status(report, index);
        let status_style = match status {
            CertStatus::Ok => theme.ok,
            CertStatus::Warning => theme.warn,
            CertStatus::Error => theme.error,
        };
        let selected = index == inspect.selected_cert;
        let title_style = if selected && inspect.pane == Pane::Chain {
            theme.selected
        } else {
            theme.base
        };
        let marker = if selected { "\u{25b8}" } else { " " };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(status.icon(), status_style),
            Span::raw(" "),
            Span::styled(
                fit(&cert_title(record), width.saturating_sub(4)),
                title_style,
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!(
                "    {}",
                fit(
                    &labels::single_line(&labels::origin_text(&record.origin)),
                    width.saturating_sub(4)
                )
            ),
            theme.dim,
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("(no certificates)", theme.dim)));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// `? help · TLSv1.3 · cipher · IP · handshake 42ms`, or a short hint when
/// there is no session. The help key comes first so a narrow terminal never
/// cuts it.
fn render_footer(
    inspect: &InspectState,
    keymap: &Keymap,
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
) {
    let help = keymap.label(Action::Help);
    let text = match inspect.report() {
        Some(report) => footer_text(report, &help),
        None => format!("Esc back \u{b7} {help} help"),
    };
    let text = fit(&text, usize::from(area.width));
    frame.render_widget(Paragraph::new(text).style(theme.dim), area);
}

fn footer_text(report: &InspectionReport, help: &str) -> String {
    let Some(tls) = &report.tls else {
        return labels::single_line(&format!(
            "no TLS session \u{b7} Esc back \u{b7} {help} help"
        ));
    };
    let mut parts = vec![
        format!("{help} help"),
        tls.version.clone(),
        tls.cipher_suite.clone(),
        tls.peer_ip.to_string(),
    ];
    if let Some(handshake) = report.timings.handshake {
        parts.push(format!("handshake {}ms", handshake.as_millis()));
    }
    if let Some(total) = report.timings.total {
        parts.push(format!("total {}ms", total.as_millis()));
    }
    labels::single_line(&parts.join(" \u{b7} "))
}

#[cfg(test)]
mod tests {
    use ratatui::buffer::Buffer;

    use crate::app_state::{Pane, Tab};
    use crate::test_fixtures::{inspect_state, record_with_cn, report_of, sample_report};
    use crate::view::test_support::{render, text};

    /// The right border of the details pane must stay on column `width - 1`.
    fn assert_frame_intact(buffer: &Buffer) {
        let right = buffer.area.width - 1;
        let bottom = buffer.area.height - 2;
        for y in 1..bottom {
            let symbol = buffer.cell((right, y)).unwrap().symbol();
            assert_eq!(symbol, "\u{2502}", "right border broken on row {y}");
        }
    }

    fn assert_no_control_chars(buffer: &Buffer) {
        for cell in &buffer.content {
            assert!(
                !cell.symbol().chars().any(char::is_control),
                "control character on screen: {:?}",
                cell.symbol()
            );
        }
    }

    fn state_with_cn(cn: &str) -> crate::app_state::AppState {
        let mut state = inspect_state(report_of(vec![record_with_cn(cn, 0)]));
        if let Some(inspect) = state.inspect.as_mut() {
            inspect.pane = Pane::Details;
        }
        state
    }

    #[test]
    fn quando_relatorio_tem_sessao_tls_deve_mostrar_a_tecla_de_ajuda_primeiro() {
        let text = super::footer_text(&sample_report(), "?");
        assert!(text.starts_with("? help \u{b7} TLSv1.3"), "{text}");
    }

    #[test]
    fn quando_ajuda_foi_remapeada_deve_mostrar_a_tecla_nova_sem_sessao() {
        let mut report = sample_report();
        report.tls = None;
        let text = super::footer_text(&report, "F1");
        assert!(text.contains("F1 help"), "{text}");
        assert!(!text.contains("? help"), "{text}");
    }

    #[test]
    fn quando_cn_tem_10000_chars_deve_renderizar_sem_panic_e_dentro_do_painel() {
        let state = state_with_cn(&"A".repeat(10_000));
        for (w, h) in [(80, 24), (120, 40)] {
            let buffer = render(&state, w, h);
            assert_frame_intact(&buffer);
        }
    }

    #[test]
    fn quando_cn_tem_esc_deve_renderizar_sem_byte_de_controle() {
        let state = state_with_cn("a\u{1b}[31mb\u{7}c\u{9b}d");
        let buffer = render(&state, 80, 24);
        assert_no_control_chars(&buffer);
        assert_frame_intact(&buffer);
    }

    #[test]
    fn quando_cn_tem_cjk_deve_respeitar_largura_2() {
        let state = state_with_cn(&"\u{65e5}\u{672c}\u{8a9e}".repeat(60));
        let buffer = render(&state, 80, 24);
        assert_frame_intact(&buffer);
        let screen = text(&buffer);
        assert!(screen.contains('\u{65e5}'), "{screen}");
    }

    #[test]
    fn quando_cn_tem_emoji_e_quebra_de_linha_deve_ficar_em_uma_linha() {
        let state = state_with_cn("a\u{1f600}b\nc\td");
        let buffer = render(&state, 80, 24);
        assert_frame_intact(&buffer);
        assert_no_control_chars(&buffer);
    }

    #[test]
    fn quando_relatorio_sem_certificados_deve_renderizar_sem_panic() {
        let state = inspect_state(report_of(Vec::new()));
        let screen = text(&render(&state, 80, 24));
        assert!(screen.contains("no certificates"), "{screen}");
    }

    #[test]
    fn quando_carregando_deve_mostrar_inspecting() {
        let mut state = inspect_state(sample_report());
        if let Some(inspect) = state.inspect.as_mut() {
            inspect.phase = crate::app_state::Phase::Loading;
        }
        assert!(text(&render(&state, 80, 24)).contains("Inspecting"));
    }

    #[test]
    fn quando_falhou_deve_mostrar_a_mensagem() {
        let mut state = inspect_state(sample_report());
        if let Some(inspect) = state.inspect.as_mut() {
            inspect.phase = crate::app_state::Phase::Failed("connection refused".to_owned());
        }
        assert!(text(&render(&state, 80, 24)).contains("Failed: connection refused"));
    }

    #[test]
    fn quando_overview_80x24_deve_bater_com_o_snapshot() {
        insta::assert_snapshot!(text(&render(&inspect_state(sample_report()), 80, 24)));
    }

    #[test]
    fn quando_overview_120x40_deve_bater_com_o_snapshot() {
        insta::assert_snapshot!(text(&render(&inspect_state(sample_report()), 120, 40)));
    }

    #[test]
    fn quando_findings_80x24_deve_bater_com_o_snapshot() {
        let mut state = inspect_state(sample_report());
        if let Some(inspect) = state.inspect.as_mut() {
            inspect.tab = Tab::Findings;
            inspect.selected_cert = 2;
            inspect.pane = Pane::Details;
        }
        insta::assert_snapshot!(text(&render(&state, 80, 24)));
    }

    #[test]
    fn quando_findings_120x40_deve_bater_com_o_snapshot() {
        let mut state = inspect_state(sample_report());
        if let Some(inspect) = state.inspect.as_mut() {
            inspect.tab = Tab::Findings;
            inspect.selected_cert = 2;
        }
        insta::assert_snapshot!(text(&render(&state, 120, 40)));
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use certtui_domain::model::FingerprintFormat;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use crate::app_state::{Pane, Tab};
    use crate::msg::Msg;
    use crate::test_fixtures::{inspect_state, sample_report};
    use crate::update::update;
    use crate::update_inspect::current_rows;
    use crate::view::test_support::{render, text};

    fn fingerprints_state() -> crate::app_state::AppState {
        let mut state = inspect_state(sample_report());
        if let Some(inspect) = state.inspect.as_mut() {
            inspect.tab = Tab::Fingerprints;
            inspect.pane = Pane::Details;
        }
        state
    }

    fn key(c: char) -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    #[test]
    fn quando_largura_nao_cabe_deve_quebrar_na_tela_mas_copy_text_continua_sem_quebra() {
        let state = fingerprints_state();
        let screen = text(&render(&state, 80, 24));
        // The SHA-512 (191 characters) takes several screen lines.
        let sha512 = current_rows(&state)
            .into_iter()
            .find(|row| row.label == "SHA-512")
            .unwrap();
        assert_eq!(sha512.copy_text.len(), 191);
        assert!(!sha512.copy_text.contains('\n'));
        assert!(!screen.contains(&sha512.value), "unwrapped value on screen");
        // Every character of the digest is on screen, only split across lines.
        let on_screen: String = screen
            .lines()
            .filter_map(|line| line.split('\u{2502}').nth(3))
            .collect::<String>()
            .replace([' ', ':'], "");
        let digest_chars: String = sha512.copy_text.replace(':', "");
        assert!(on_screen.contains(&digest_chars[..20]), "{screen}");
    }

    #[test]
    fn quando_x_deve_mudar_formato_do_copy_text_para_hex_minusculo_e_depois_base64() {
        let mut state = fingerprints_state();
        let sha256 = |state: &crate::app_state::AppState| {
            current_rows(state)
                .into_iter()
                .find(|row| row.label == "SHA-256")
                .unwrap()
                .copy_text
        };
        assert!(sha256(&state).contains(':'));
        update(&mut state, key('x'));
        assert_eq!(state.fingerprint_format, FingerprintFormat::HexLower);
        assert_eq!(sha256(&state).len(), 64);
        assert!(!sha256(&state).contains(':'));
        update(&mut state, key('x'));
        assert_eq!(sha256(&state).len(), 44);
        assert!(sha256(&state).ends_with('='));
    }

    #[test]
    fn quando_fingerprints_em_colon_deve_bater_com_o_snapshot() {
        insta::assert_snapshot!(text(&render(&fingerprints_state(), 80, 24)));
    }

    #[test]
    fn quando_fingerprints_em_base64_deve_bater_com_o_snapshot() {
        let mut state = fingerprints_state();
        update(&mut state, key('x'));
        update(&mut state, key('x'));
        insta::assert_snapshot!(text(&render(&state, 80, 24)));
    }

    #[test]
    fn quando_alias_do_keystore_tem_bidi_e_controle_deve_nao_chegar_ao_terminal() {
        let mut record = crate::test_fixtures::fixture_record("rsa2048-leaf", 0);
        record.origin = certtui_domain::model::CertOrigin::Keystore {
            path: "store.jks".into(),
            alias: "\u{202e}\u{2066}\u{7}\u{1b}ok".to_owned(),
        };
        let screen = text(&render(
            &inspect_state(crate::test_fixtures::report_of(vec![record])),
            200,
            24,
        ));
        for forbidden in ['\u{202e}', '\u{2066}', '\u{7}', '\u{1b}'] {
            assert!(
                !screen.contains(forbidden),
                "{forbidden:?} reached the screen"
            );
        }
        assert!(
            screen.contains("alias"),
            "the alias line is on screen:\n{screen}"
        );
    }
}
