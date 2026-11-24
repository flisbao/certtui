//! The tab bar and the detail rows of the Inspect screen.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app_state::Tab;
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

/// What [`render_rows`] draws.
#[derive(Debug, Clone, Copy)]
pub struct RowsView<'a> {
    /// All the rows of the tab.
    pub rows: &'a [DetailRow],
    /// First row drawn.
    pub scroll: usize,
    /// Row under the cursor.
    pub cursor: usize,
    /// Whether the details pane has focus (the cursor row is highlighted).
    pub focused: bool,
    /// Break long values over several lines instead of cutting them.
    ///
    /// Only the drawing breaks: the copied text is never touched.
    pub wrap: bool,
}

/// Draws the rows of `view` in `area`.
pub fn render_rows(frame: &mut Frame, area: Rect, view: &RowsView<'_>, theme: &Theme) {
    let width = usize::from(area.width);
    let height = usize::from(area.height);
    let mut lines: Vec<Line> = Vec::new();
    for (index, row) in view.rows.iter().enumerate().skip(view.scroll) {
        if lines.len() >= height {
            break;
        }
        let selected = view.focused && index == view.cursor;
        lines.extend(row_lines(row, width, selected, view.wrap, theme));
    }
    lines.truncate(height);
    frame.render_widget(Paragraph::new(lines), area);
}

fn row_lines(
    row: &DetailRow,
    width: usize,
    selected: bool,
    wrap: bool,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let (label, value_width) = if row.label.is_empty() {
        (String::from("  "), width.saturating_sub(2))
    } else {
        (
            format!("{:<LABEL_WIDTH$}", format!("{}:", row.label)),
            width.saturating_sub(LABEL_WIDTH),
        )
    };
    let (label_style, value_style) = if selected {
        (theme.selected, theme.selected)
    } else {
        (theme.dim, theme.base)
    };
    let pieces = if wrap {
        wrap_fixed(&row.value, value_width)
    } else {
        vec![fit(&row.value, value_width)]
    };
    let indent = " ".repeat(label.chars().count());
    pieces
        .into_iter()
        .enumerate()
        .map(|(i, piece)| {
            let lead = if i == 0 {
                label.clone()
            } else {
                indent.clone()
            };
            Line::from(vec![
                Span::styled(lead, label_style),
                Span::styled(piece, value_style),
            ])
        })
        .collect()
}

/// `text` split into pieces of at most `width` characters (at least one piece).
///
/// Meant for ASCII values (hex and Base64 digests), where a character is one
/// column.
#[must_use]
pub fn wrap_fixed(text: &str, width: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    if chars.is_empty() || width == 0 {
        return vec![String::new()];
    }
    chars
        .chunks(width)
        .map(|chunk| chunk.iter().collect())
        .collect()
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
