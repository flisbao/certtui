//! The help dialog (`?`): every key, built from the [`Keymap`], and how
//! copying reaches the clipboard.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::keymap::Keymap;
use crate::theme::Theme;

/// Tallest the dialog gets, borders included.
const MAX_HEIGHT: u16 = 30;
/// Widest the dialog gets, borders included.
const MAX_WIDTH: u16 = 78;
/// Width of the key column.
const KEYS_WIDTH: usize = 14;

/// The text of the dialog, one string per line.
#[must_use]
pub fn help_lines(keymap: &Keymap) -> Vec<String> {
    let mut lines = vec!["Keys".to_owned()];
    for entry in keymap.help_entries() {
        lines.push(format!(
            "  {:<KEYS_WIDTH$}{}",
            entry.keys,
            entry.action.description()
        ));
    }
    lines.push(format!("  {:<KEYS_WIDTH$}quit", "Ctrl-C"));
    lines.push(String::new());
    lines.push("Clipboard".to_owned());
    for line in [
        "Copy keys try OSC 52 (the terminal sets its clipboard) and the system",
        "clipboard. Over SSH, OSC 52 goes first.",
        "OSC 52 is not confirmed by the terminal, so the toast says \"Sent via",
        "OSC 52\", not \"Copied\". Enable it in your terminal if nothing arrives.",
        "tmux: add `set -g set-clipboard on` to ~/.tmux.conf.",
        "X11/Wayland: this program serves the clipboard; the text is lost when it",
        "exits unless a clipboard manager keeps it.",
        "Nothing over 256 KiB is copied; press e to export instead.",
    ] {
        lines.push(format!("  {line}"));
    }
    lines
}

/// How many lines of the dialog fit on a terminal of `size`.
#[must_use]
pub fn viewport_rows(size: (u16, u16)) -> usize {
    usize::from(dialog_height(size.1).saturating_sub(2))
}

fn dialog_height(rows: u16) -> u16 {
    rows.saturating_sub(2).min(MAX_HEIGHT)
}

/// Draws the dialog centered over `area`, scrolled by `scroll` lines.
pub fn render(frame: &mut Frame, area: Rect, scroll: u16, theme: &Theme) {
    let width = area.width.saturating_sub(2).min(MAX_WIDTH);
    let height = dialog_height(area.height);
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );
    let text = help_lines(&Keymap::new()).join("\n");
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(text)
            .style(theme.base)
            .scroll((scroll, 0))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme.title)
                    .title(" Help \u{b7} j/k scroll \u{b7} Esc closes ")
                    .title_style(theme.title),
            ),
        rect,
    );
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::keymap::Action;
    use crate::msg::Msg;
    use crate::update::update;
    use crate::view::test_support::{render as render_state, state, text};

    #[test]
    fn quando_ajuda_deve_listar_todas_as_actions_do_keymap() {
        let lines = help_lines(&Keymap::new()).join("\n");
        for entry in Keymap::new().help_entries() {
            assert!(
                lines.contains(entry.action.description()),
                "{:?}",
                entry.action
            );
            assert!(lines.contains(&entry.keys), "{:?}", entry.keys);
        }
        assert_eq!(Action::ALL.len(), 22);
    }

    #[test]
    fn quando_ajuda_deve_explicar_osc52_tmux_e_x11_wayland() {
        let lines = help_lines(&Keymap::new()).join("\n");
        assert!(lines.contains("OSC 52"));
        assert!(lines.contains("set -g set-clipboard on"));
        assert!(lines.contains("X11/Wayland"));
    }

    #[test]
    fn quando_modal_help_aberto_deve_bater_com_o_snapshot() {
        let mut s = state();
        update(
            &mut s,
            Msg::Key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE)),
        );
        insta::assert_snapshot!(text(&render_state(&s, 80, 24)));
    }

    #[test]
    fn quando_rola_a_ajuda_deve_mostrar_o_fim_e_nao_passar_do_limite() {
        let mut s = state();
        let key = |c| Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        update(&mut s, key('?'));
        for _ in 0..200 {
            update(&mut s, key('j'));
        }
        let screen = text(&render_state(&s, 80, 24));
        assert!(
            screen.contains("exits unless a clipboard manager"),
            "{screen}"
        );
        assert!(!screen.contains("Keys\n"), "scrolled past the top");
        for _ in 0..200 {
            update(&mut s, key('k'));
        }
        assert!(text(&render_state(&s, 80, 24)).contains("Keys"));
    }

    #[test]
    fn quando_fecha_a_ajuda_deve_zerar_a_rolagem() {
        let mut s = state();
        let key = |c| Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        update(&mut s, key('?'));
        update(&mut s, key('j'));
        update(
            &mut s,
            Msg::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
        );
        assert_eq!(s.help_scroll, 0);
    }
}
