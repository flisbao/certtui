//! The tab bar and the detail rows of the Inspect screen.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app_state::{Pane, Tab};
use crate::detail_rows::DetailRow;
use crate::theme::Theme;

/// Width of the label column, separator included.
const LABEL_WIDTH: usize = 17;

/// Draws the tab titles, the active one highlighted.
///
/// When they do not all fit, the bar starts at the first tab that lets the
/// active one be visible and marks the cut with `‹`.
pub fn render_tab_bar(frame: &mut Frame, area: Rect, active: Tab, theme: &Theme) {
    let width = usize::from(area.width);
    let title = |tab: Tab| format!(" {} ", tab.title());
    let active_at = Tab::ALL.iter().position(|tab| *tab == active).unwrap_or(0);
    let mut start = 0;
    while start < active_at {
        let needed: usize = Tab::ALL
            .iter()
            .skip(start)
            .take(active_at + 1 - start)
            .map(|tab| title(*tab).chars().count())
            .sum::<usize>()
            + usize::from(start > 0);
        if needed <= width {
            break;
        }
        start += 1;
    }
    let mut spans = Vec::new();
    if start > 0 {
        spans.push(Span::styled("\u{2039}", theme.dim));
    }
    for tab in Tab::ALL.iter().skip(start) {
        let style = if *tab == active {
            theme.selected
        } else {
            theme.dim
        };
        spans.push(Span::styled(title(*tab), style));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Draws `rows` from `scroll`, the one at `cursor` highlighted when `focused`.
pub fn render_rows(
    frame: &mut Frame,
    area: Rect,
    rows: &[DetailRow],
    scroll: usize,
    cursor: usize,
    pane: Pane,
    theme: &Theme,
) {
    let width = usize::from(area.width);
    let lines: Vec<Line> = rows
        .iter()
        .enumerate()
        .skip(scroll)
        .take(usize::from(area.height))
        .map(|(index, row)| {
            let selected = pane == Pane::Details && index == cursor;
            row_line(row, width, selected, theme)
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), area);
}

fn row_line(row: &DetailRow, width: usize, selected: bool, theme: &Theme) -> Line<'static> {
    let (label, value) = if row.label.is_empty() {
        (String::from("  "), fit(&row.value, width.saturating_sub(2)))
    } else {
        (
            format!("{:<LABEL_WIDTH$}", format!("{}:", row.label)),
            fit(&row.value, width.saturating_sub(LABEL_WIDTH)),
        )
    };
    let (label_style, value_style) = if selected {
        (theme.selected, theme.selected)
    } else {
        (theme.dim, theme.base)
    };
    Line::from(vec![
        Span::styled(label, label_style),
        Span::styled(value, value_style),
    ])
}

/// `text` cut to at most `max` terminal columns, ending in `…` when cut.
///
/// Wide characters (CJK, emoji) count as two columns.
#[must_use]
pub fn fit(text: &str, max: usize) -> String {
    if text.chars().count() <= max && display_width(text) <= max {
        return text.to_owned();
    }
    let budget = max.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0;
    for c in text.chars() {
        let width = char_width(c);
        if used + width > budget {
            break;
        }
        out.push(c);
        used += width;
    }
    if max > 0 {
        out.push('\u{2026}');
    }
    out
}

fn char_width(c: char) -> usize {
    let mut buffer = [0; 4];
    Span::raw(&*c.encode_utf8(&mut buffer)).width()
}

fn display_width(text: &str) -> usize {
    Span::raw(text).width()
}
