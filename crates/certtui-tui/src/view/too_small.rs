//! The message shown when the terminal is below the minimum size.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Paragraph, Wrap};

use crate::terminal::MIN_SIZE;
use crate::theme::Theme;

/// Draws "terminal too small" with the sizes involved.
pub fn render(frame: &mut Frame, area: Rect, theme: &Theme) {
    let text = format!(
        "terminal too small\nneed at least {}x{}, have {}x{}",
        MIN_SIZE.0, MIN_SIZE.1, area.width, area.height
    );
    frame.render_widget(
        Paragraph::new(text)
            .style(theme.error)
            .wrap(Wrap { trim: true }),
        area,
    );
}
