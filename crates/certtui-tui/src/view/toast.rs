//! The toast: a small box over the bottom right corner.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::Text;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::tabs::fit;
use crate::theme::Theme;
use crate::toast::{Toast, ToastKind};

/// Draws `toast` over `area` without taking any key.
pub fn render(toast: &Toast, frame: &mut Frame, area: Rect, theme: &Theme) {
    let max_text = usize::from(area.width).saturating_sub(6).max(1);
    let text = fit(&toast.text, max_text);
    let width = u16::try_from(Text::raw(text.as_str()).width() + 4)
        .unwrap_or(area.width)
        .min(area.width);
    let height = 3.min(area.height);
    let rect = Rect::new(
        area.right().saturating_sub(width + 2),
        area.bottom().saturating_sub(height + 2),
        width,
        height,
    );
    let style = match toast.kind {
        ToastKind::Info => theme.ok,
        ToastKind::Error => theme.error,
    };
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(text)
            .style(style)
            .block(Block::default().borders(Borders::ALL).border_style(style)),
        rect,
    );
}
