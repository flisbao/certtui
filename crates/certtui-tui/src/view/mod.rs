//! Pure rendering of [`AppState`].

pub mod help;
pub mod home;
pub mod inspect;
pub mod tabs;
pub mod toast;
pub mod too_small;

use ratatui::Frame;

use crate::app_state::{AppState, Modal, Screen};
use crate::terminal::MIN_SIZE;
use crate::theme::Theme;

/// Rows of the details pane that fit on a terminal of `size`.
///
/// The pane loses two rows to its border, one to the tab bar and one to the
/// footer line.
#[must_use]
pub fn details_viewport_rows(size: (u16, u16)) -> usize {
    usize::from(size.1.saturating_sub(4))
}

/// Draws the whole screen for `state`.
///
/// Below [`MIN_SIZE`] only the "terminal too small" message is drawn.
pub fn view(state: &AppState, frame: &mut Frame) {
    let area = frame.area();
    let theme = Theme::for_kind(state.theme, false);
    if area.width < MIN_SIZE.0 || area.height < MIN_SIZE.1 {
        too_small::render(frame, area, &theme);
        return;
    }
    match state.screen {
        Screen::Home => home::render(state, frame, area, &theme),
        Screen::Inspect => inspect::render(state, frame, area, &theme),
    }
    if state.modal == Some(Modal::Help) {
        help::render(frame, area, state.help_scroll, &theme);
    }
    if let Some(toast) = &state.toast {
        toast::render(toast, frame, area, &theme);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::time::Instant;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    use super::view;
    use crate::app_state::AppState;

    /// Renders `state` on a `width`×`height` test terminal.
    pub fn render(state: &AppState, width: u16, height: u16) -> Buffer {
        let mut terminal = match Terminal::new(TestBackend::new(width, height)) {
            Ok(terminal) => terminal,
            Err(error) => unreachable!("test backend cannot fail: {error}"),
        };
        if let Err(error) = terminal.draw(|frame| view(state, frame)) {
            unreachable!("test backend cannot fail: {error}");
        }
        terminal.backend().buffer().clone()
    }

    /// The text of `buffer`, one line per row, trailing blanks trimmed.
    pub fn text(buffer: &Buffer) -> String {
        let width = usize::from(buffer.area.width);
        buffer
            .content
            .chunks(width.max(1))
            .map(|row| {
                row.iter()
                    .map(ratatui::buffer::Cell::symbol)
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// A fresh state.
    pub fn state() -> AppState {
        AppState::new(Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use ratatui::style::Color;

    use super::test_support::{render, state, text};
    use crate::theme::ThemeKind;

    #[test]
    fn quando_80x24_deve_renderizar_a_home() {
        let s = state();
        insta::assert_snapshot!(text(&render(&s, 80, 24)));
    }

    #[test]
    fn quando_79x24_deve_mostrar_terminal_too_small() {
        let s = state();
        let screen = text(&render(&s, 79, 24));
        assert!(screen.contains("terminal too small"), "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn quando_80x23_deve_mostrar_terminal_too_small() {
        let s = state();
        let screen = text(&render(&s, 80, 23));
        assert!(screen.contains("terminal too small"), "{screen}");
    }

    #[test]
    fn quando_tema_mono_deve_nao_usar_cores() {
        let mut s = state();
        s.theme = ThemeKind::Mono;
        for (width, height) in [(80, 24), (79, 24)] {
            let buffer = render(&s, width, height);
            for cell in &buffer.content {
                assert_eq!(cell.fg, Color::Reset);
                assert_eq!(cell.bg, Color::Reset);
            }
        }
    }
}
