//! The Home screen.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::app_state::{AppState, HomeMode};
use crate::keymap::Action;
use crate::theme::Theme;

const PLACEHOLDER: &str = "host[:port], https://host, a file or directory, or - for stdin";
const BATCH_PLACEHOLDER: &str = "path of a file with one target per line, or a JSON array";

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
    let hint = match (state.home.editing, state.home.mode) {
        (true, HomeMode::BatchFile) => "Enter open the list · Esc stop typing".to_owned(),
        (true, HomeMode::Target) => "Enter inspect · Esc stop typing".to_owned(),
        (false, _) => {
            let keys = &state.keymap;
            let label = |action| keys.label(action);
            format!(
                "{} new target · {} batch list · {} inspect · {} help · {} quit",
                label(Action::NewTarget),
                label(Action::OpenBatch),
                label(Action::Enter),
                label(Action::Help),
                label(Action::Quit),
            )
        }
    };
    frame.render_widget(Paragraph::new(hint).style(theme.dim), hint_area);
}

/// The known targets that match what is typed, in place of the two lists.
fn render_suggestions(state: &AppState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let items: Vec<ListItem> = state
        .home
        .suggestions
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let style = if i == 0 { theme.selected } else { theme.base };
            let star = if state.history.is_favorite(row) {
                "\u{2605} "
            } else {
                "  "
            };
            let text = format!("{star}{}", crate::text::display(row));
            ListItem::new(Span::styled(text, style))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme.border)
            .title(" Suggestions (Tab completes) "),
    );
    frame.render_widget(list, area);
}

fn render_input(state: &AppState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let border = if state.home.editing {
        theme.title
    } else {
        theme.border
    };
    let (title, placeholder) = match state.home.mode {
        HomeMode::Target => (" Target ", PLACEHOLDER),
        HomeMode::BatchFile => (" Batch list file ", BATCH_PLACEHOLDER),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(title);
    let line = if state.home.input.is_empty() {
        Line::from(Span::styled(placeholder, theme.dim))
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
    if !state.home.suggestions.is_empty() {
        render_suggestions(state, frame, area, theme);
        return;
    }
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
