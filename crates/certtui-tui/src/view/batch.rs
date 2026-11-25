//! The Batch screen.

use certtui_domain::batch_row::{BatchRow, RowStatus};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::app_state::{AppState, BatchPhase, BatchState};
use crate::text::display;
use crate::theme::Theme;
use crate::view::batch_viewport_rows;

/// Width of the progress bar, in cells.
const BAR_WIDTH: usize = 20;

/// Draws the Batch screen.
pub fn render(state: &AppState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let Some(batch) = state.batch.as_ref() else {
        return;
    };
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border)
        .title(format!(" Batch \u{b7} {} ", phase_text(batch.phase)))
        .title_style(theme.title);
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let [table_area, progress_area, hint_area] = Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    render_table(state, batch, frame, table_area, theme);
    render_progress(batch, frame, progress_area, theme);
    let hint = if batch.filter_editing {
        "Enter keep filter \u{b7} Esc clear filter"
    } else if batch.is_running() {
        "Esc cancel \u{b7} Enter inspect \u{b7} s sort \u{b7} / filter \u{b7} y row \u{b7} Y table \u{b7} ? help"
    } else {
        "Enter inspect \u{b7} s sort \u{b7} S reverse \u{b7} / filter \u{b7} y row \u{b7} Y table \u{b7} Esc back"
    };
    frame.render_widget(Paragraph::new(hint).style(theme.dim), hint_area);
}

fn phase_text(phase: BatchPhase) -> &'static str {
    match phase {
        BatchPhase::Running => "running",
        BatchPhase::Done => "done",
        BatchPhase::Cancelled => "cancelled",
    }
}

fn render_table(
    state: &AppState,
    batch: &BatchState,
    frame: &mut Frame,
    area: Rect,
    theme: &Theme,
) {
    let viewport = batch_viewport_rows(state.size).max(usize::from(area.height.saturating_sub(1)));
    let header = Row::new(["Target", "Status", "Days", "CN", "Issuer", "E/W/I"].map(Cell::from))
        .style(theme.title);
    let rows: Vec<Row> = batch
        .view
        .iter()
        .enumerate()
        .skip(batch.scroll)
        .take(viewport)
        .filter_map(|(position, index)| {
            let row = batch.rows.get(*index)?.as_ref()?;
            let style = if position == batch.selected {
                theme.selected
            } else {
                theme.base
            };
            Some(table_row(row, theme).style(style))
        })
        .collect();
    let widths = [
        Constraint::Fill(3),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Fill(2),
        Constraint::Fill(2),
        Constraint::Length(8),
    ];
    frame.render_widget(Table::new(rows, widths).header(header), area);
}

fn table_row<'a>(row: &'a BatchRow, theme: &Theme) -> Row<'a> {
    let status_style = match row.status {
        RowStatus::Ok => theme.ok,
        RowStatus::Warning => theme.warn,
        RowStatus::Error | RowStatus::Failed => theme.error,
    };
    let text = |value: Option<&str>| {
        value.map_or_else(|| "-".to_owned(), |value| display(value).into_owned())
    };
    // A failed target shows why where the CN would be.
    let cn = if row.status == RowStatus::Failed {
        text(row.failure.as_deref())
    } else {
        text(row.subject_cn.as_deref())
    };
    Row::new([
        Cell::from(display(&row.target).into_owned()),
        Cell::from(Span::styled(row.status.as_str(), status_style)),
        Cell::from(Line::from(
            row.days_to_expiry
                .map_or_else(|| "-".to_owned(), |days| days.to_string()),
        )),
        Cell::from(cn),
        Cell::from(text(row.issuer_cn.as_deref())),
        Cell::from(format!("{}/{}/{}", row.errors, row.warnings, row.infos)),
    ])
}

fn render_progress(batch: &BatchState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let total = batch.total();
    let done = batch.done.min(total);
    let percent = (done * 100).checked_div(total).unwrap_or(100);
    let filled = BAR_WIDTH * percent / 100;
    let bar = format!(
        "[{}{}]",
        "\u{2588}".repeat(filled),
        "\u{2591}".repeat(BAR_WIDTH.saturating_sub(filled))
    );
    let sort = if batch.sort == crate::app_state::SortKey::Input {
        String::new()
    } else {
        let arrow = if batch.descending {
            "\u{2193}"
        } else {
            "\u{2191}"
        };
        format!("  sort: {} {arrow}", batch.sort.title())
    };
    let mut spans = vec![Span::styled(
        format!("{bar} {percent}% {done}/{total}{sort}"),
        theme.base,
    )];
    if batch.filter_editing || !batch.filter.is_empty() {
        let filter = display(&batch.filter).into_owned();
        spans.push(Span::styled(format!("  filter: {filter}"), theme.title));
        spans.push(Span::styled(
            format!(" ({} shown)", batch.view.len()),
            theme.dim,
        ));
    }
    let line = Line::from(spans);
    let width = u16::try_from(line.width()).unwrap_or(u16::MAX);
    frame.render_widget(Paragraph::new(line).style(Style::new()), area);
    if batch.filter_editing {
        // The cursor goes right after the typed filter, which ends the
        // `filter: …` span; the " (n shown)" tail is not part of the input.
        let tail = u16::try_from(format!(" ({} shown)", batch.view.len()).chars().count())
            .unwrap_or(u16::MAX);
        let x = area
            .x
            .saturating_add(width.saturating_sub(tail))
            .min(area.right().saturating_sub(1));
        frame.set_cursor_position(Position::new(x, area.y));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use certtui_app::batch::BatchEvent;
    use certtui_domain::batch_row::{BatchRow, RowStatus};
    use certtui_domain::target::NetworkTarget;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use crate::app_state::AppState;
    use crate::msg::{Command, Msg};
    use crate::update::update;
    use crate::update_batch::{on_events, start_batch};
    use crate::view::test_support::{render, text};

    fn target(host: &str) -> NetworkTarget {
        NetworkTarget {
            host: host.to_owned(),
            port: 443,
            sni: None,
            connect_to: None,
        }
    }

    fn row(host: &str, days: Option<i64>, cn: Option<&str>) -> BatchRow {
        BatchRow {
            target: format!("{host}:443"),
            status: if days.is_some_and(|d| d < 0) {
                RowStatus::Error
            } else {
                RowStatus::Ok
            },
            days_to_expiry: days,
            subject_cn: cn.map(str::to_owned),
            issuer_cn: Some("Test CA".to_owned()),
            errors: u32::from(days.is_some_and(|d| d < 0)),
            warnings: 0,
            infos: 1,
            failure: None,
        }
    }

    /// A batch of `total` targets of which the first `arrived` have rows.
    fn batch_state(total: usize, arrived: usize) -> AppState {
        let mut state = AppState::new(Instant::now());
        let targets: Vec<NetworkTarget> =
            (0..total).map(|i| target(&format!("h{i}.test"))).collect();
        let commands = start_batch(&mut state, targets);
        let Some(Command::RunBatch { id, .. }) = commands.into_iter().next() else {
            panic!("no job");
        };
        let mut events: Vec<BatchEvent> = (0..arrived)
            .map(|i| BatchEvent::Row {
                index: i,
                row: row(
                    &format!("h{i}.test"),
                    Some(i64::try_from(i).unwrap() * 30 - 20),
                    Some(&format!("host{i}.example")),
                ),
            })
            .collect();
        events.push(BatchEvent::Progress {
            done: arrived,
            total,
        });
        on_events(&mut state, id, events);
        state
    }

    fn key(c: char) -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    #[test]
    fn quando_batch_vazio_deve_mostrar_progresso_zero_e_o_cabecalho() {
        let state = batch_state(5, 0);
        let screen = text(&render(&state, 80, 24));
        assert!(screen.contains("0% 0/5"), "{screen}");
        assert!(screen.contains("Target"), "{screen}");
        assert!(screen.contains("running"), "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn quando_batch_rodando_a_40_por_cento_deve_mostrar_barra_e_linhas() {
        let state = batch_state(5, 2);
        let screen = text(&render(&state, 80, 24));
        assert!(screen.contains("40% 2/5"), "{screen}");
        assert!(screen.contains("h0.test:443"), "{screen}");
        assert!(screen.contains("host1.example"), "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn quando_filtrado_deve_mostrar_so_o_que_casa_e_o_filtro() {
        let mut state = batch_state(5, 5);
        update(&mut state, key('/'));
        for c in "host3".chars() {
            update(&mut state, key(c));
        }
        update(
            &mut state,
            Msg::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        );
        let screen = text(&render(&state, 80, 24));
        assert!(screen.contains("filter: host3"), "{screen}");
        assert!(screen.contains("(1 shown)"), "{screen}");
        assert!(screen.contains("h3.test:443"), "{screen}");
        assert!(!screen.contains("h1.test:443"), "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn quando_ordenado_deve_mostrar_a_coluna_e_a_direcao() {
        let mut state = batch_state(3, 3);
        update(&mut state, key('s'));
        update(&mut state, key('S'));
        let screen = text(&render(&state, 80, 24));
        assert!(screen.contains("sort: days \u{2193}"), "{screen}");
    }

    #[test]
    fn quando_falhou_deve_mostrar_o_motivo_no_lugar_do_cn() {
        let mut state = AppState::new(Instant::now());
        let commands = start_batch(&mut state, vec![target("down.test")]);
        let Some(Command::RunBatch { id, .. }) = commands.into_iter().next() else {
            panic!("no job");
        };
        on_events(
            &mut state,
            id,
            vec![BatchEvent::Row {
                index: 0,
                row: BatchRow::failed("down.test:443", "connection refused"),
            }],
        );
        let screen = text(&render(&state, 80, 24));
        assert!(screen.contains("failed"), "{screen}");
        // The reason takes the CN column, so a long one is cut by the table.
        assert!(screen.contains("connection ref"), "{screen}");
    }

    #[test]
    fn quando_cn_tem_esc_e_cjk_deve_renderizar_sem_controle_e_sem_panic() {
        let mut state = AppState::new(Instant::now());
        let commands = start_batch(&mut state, vec![target("evil.test")]);
        let Some(Command::RunBatch { id, .. }) = commands.into_iter().next() else {
            panic!("no job");
        };
        let mut evil = row(
            "evil.test",
            Some(3),
            Some("\u{4e2d}\u{6587}\u{1b}[31mred\u{202e}\u{7ec8}\u{7aef}"),
        );
        evil.issuer_cn = Some("\u{1b}]52;c;AAAA\u{7}\u{65e5}\u{672c}\u{8a9e}".to_owned());
        evil.target = "\u{1b}[2Jevil.test:443".to_owned();
        on_events(
            &mut state,
            id,
            vec![BatchEvent::Row {
                index: 0,
                row: evil,
            }],
        );
        for (width, height) in [(80, 24), (100, 30), (200, 50), (80, 24)] {
            let buffer = render(&state, width, height);
            for cell in &buffer.content {
                assert!(
                    !cell.symbol().chars().any(char::is_control),
                    "control character on screen: {:?}",
                    cell.symbol()
                );
            }
        }
        // A wide character takes two cells, so look at the symbols, not the
        // joined text.
        let buffer = render(&state, 80, 24);
        let symbols: Vec<&str> = buffer
            .content
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect();
        assert!(symbols.contains(&"\u{4e2d}") && symbols.contains(&"\u{6587}"));
        assert!(!text(&buffer).contains('\u{202e}'));
    }

    #[test]
    fn quando_10000_rows_e_selecao_no_fim_deve_manter_a_linha_selecionada_visivel() {
        let mut state = batch_state(100, 100);
        for _ in 0..99 {
            update(&mut state, key('j'));
        }
        let screen = text(&render(&state, 80, 24));
        assert!(screen.contains("h99.test:443"), "{screen}");
        update(&mut state, key('k'));
        let screen = text(&render(&state, 80, 24));
        assert!(
            screen.contains("h99.test:443"),
            "scroll must not jump: {screen}"
        );
    }

    #[test]
    fn quando_terminal_pequeno_deve_mostrar_too_small() {
        let state = batch_state(3, 3);
        let screen = text(&render(&state, 79, 24));
        assert!(screen.contains("terminal too small"), "{screen}");
    }
}
