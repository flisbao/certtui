//! The Home screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::app_state::AppState;
use crate::theme::Theme;

const PLACEHOLDER: &str = "host[:port], https://host, a file or directory, or - for stdin";

/// Draws the Home screen.
pub fn render(state: &AppState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border)
        .title(" certtui ")
        .title_style(theme.title);
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let [input_area, lists_area, hint_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    render_input(state, frame, input_area, theme);
    render_lists(state, frame, lists_area, theme);
    let hint = if state.home.editing {
        "Enter inspect · Esc stop typing"
    } else {
        "o new target · Enter inspect · ? help · q quit"
    };
    frame.render_widget(Paragraph::new(hint).style(theme.dim), hint_area);
}

fn render_input(state: &AppState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let border = if state.home.editing {
        theme.title
    } else {
        theme.border
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(" Target ");
    let line = if state.home.input.is_empty() {
        Line::from(Span::styled(PLACEHOLDER, theme.dim))
    } else {
        Line::from(Span::styled(state.home.input.as_str(), theme.base))
    };
    let inner = block.inner(area);
    frame.render_widget(Paragraph::new(line).block(block), area);
    if state.home.editing {
        let offset = u16::try_from(state.home.cursor).unwrap_or(u16::MAX);
        let x = inner
            .x
            .saturating_add(offset)
            .min(inner.right().saturating_sub(1));
        frame.set_cursor_position(Position::new(x, inner.y));
    }
}

fn render_lists(state: &AppState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let [recents_area, favorites_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    let favorites = state.home.favorites.len();
    let list = |title: &'static str, rows: &[String], offset: usize| {
        let items: Vec<ListItem> = if rows.is_empty() {
            vec![ListItem::new(Span::styled("(none yet)", theme.dim))]
        } else {
            rows.iter()
                .enumerate()
                .map(|(i, row)| {
                    let style = if state.home.selected == Some(offset + i) {
                        theme.selected
                    } else {
                        theme.base
                    };
                    ListItem::new(Span::styled(crate::text::display(row).into_owned(), style))
                })
                .collect()
        };
        List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.border)
                .title(title),
        )
    };
    frame.render_widget(
        list(" Recent ", &state.home.recents, favorites),
        recents_area,
    );
    frame.render_widget(
        list(" Favorites ", &state.home.favorites, 0),
        favorites_area,
    );
}
