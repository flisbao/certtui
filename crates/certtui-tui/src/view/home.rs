//! The Home screen.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app_state::AppState;
use crate::theme::Theme;

/// Draws the Home screen.
pub fn render(state: &AppState, frame: &mut Frame, area: Rect, theme: &Theme) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme.border)
        .title(" certtui ")
        .title_style(theme.title);
    let body = if state.home.input.is_empty() {
        "Target: (press o to type a host, file or - for stdin)".to_owned()
    } else {
        format!("Target: {}", state.home.input)
    };
    frame.render_widget(Paragraph::new(body).style(theme.base).block(block), area);
}
