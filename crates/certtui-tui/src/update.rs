//! The pure state transition.

use crossterm::event::KeyEvent;

use crate::app_state::{AppState, Modal, Screen};
use crate::keymap::{Action, Keymap};
use crate::msg::{Command, Msg};
use crate::{update_home, update_inspect};
use certtui_domain::model::FingerprintFormat;

/// Applies `msg` to `state` and returns the side effects to run.
///
/// Pure: no I/O and no clock; time arrives through [`Msg::Tick`].
pub fn update(state: &mut AppState, msg: Msg) -> Vec<Command> {
    match msg {
        Msg::Key(key) => on_key(state, key),
        Msg::Paste(text) => {
            if state.modal.is_none() && state.screen == Screen::Home {
                update_home::on_paste(state, &text);
            }
            Vec::new()
        }
        Msg::Resize(columns, rows) => {
            state.size = (columns, rows);
            Vec::new()
        }
        Msg::Tick(now) => {
            state.now = now;
            Vec::new()
        }
        Msg::InspectDone { id, result } => {
            update_inspect::on_inspect_done(state, id, result);
            Vec::new()
        }
        Msg::Copied { .. } | Msg::CopyFailed { .. } => Vec::new(),
    }
}

fn on_key(state: &mut AppState, key: KeyEvent) -> Vec<Command> {
    if state.modal.is_none()
        && state.screen == Screen::Home
        && state.home.editing
        && let Some(commands) = update_home::on_edit_key(state, key)
    {
        return commands;
    }
    match Keymap::new().resolve(key) {
        Some(action) => on_action(state, action),
        None => Vec::new(),
    }
}

fn on_action(state: &mut AppState, action: Action) -> Vec<Command> {
    if state.modal.is_some() {
        return on_modal_action(state, action);
    }
    match state.screen {
        Screen::Home => update_home::on_action(state, action),
        Screen::Inspect => update_inspect::on_action(state, action),
    }
}

/// Actions that mean the same on every screen.
pub(crate) fn on_global_action(state: &mut AppState, action: Action) -> Vec<Command> {
    match action {
        Action::Quit => state.should_quit = true,
        Action::Help => state.modal = Some(Modal::Help),
        Action::ToggleFingerprintFormat => {
            state.fingerprint_format = next_format(state.fingerprint_format);
        }
        _ => {}
    }
    Vec::new()
}

fn on_modal_action(state: &mut AppState, action: Action) -> Vec<Command> {
    if matches!(action, Action::Back | Action::Help | Action::Quit) {
        state.modal = None;
    }
    Vec::new()
}

fn next_format(format: FingerprintFormat) -> FingerprintFormat {
    match format {
        FingerprintFormat::ColonHexUpper => FingerprintFormat::HexLower,
        FingerprintFormat::HexLower => FingerprintFormat::Base64,
        FingerprintFormat::Base64 => FingerprintFormat::ColonHexUpper,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::app_state::Screen;

    fn key(c: char) -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    fn esc() -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
    }

    fn state() -> AppState {
        AppState::new(Instant::now())
    }

    #[test]
    fn quando_q_na_home_deve_marcar_should_quit() {
        let mut s = state();
        assert_eq!(s.screen, Screen::Home);
        let commands = update(&mut s, key('q'));
        assert!(s.should_quit);
        assert_eq!(commands, Vec::new());
    }

    #[test]
    fn quando_interrogacao_deve_abrir_modal_help_e_esc_fechar() {
        let mut s = state();
        update(&mut s, key('?'));
        assert_eq!(s.modal, Some(Modal::Help));
        update(&mut s, esc());
        assert_eq!(s.modal, None);
        assert!(!s.should_quit);
    }

    #[test]
    fn quando_resize_deve_guardar_tamanho() {
        let mut s = state();
        update(&mut s, Msg::Resize(120, 40));
        assert_eq!(s.size, (120, 40));
    }

    #[test]
    fn quando_tecla_sem_mapeamento_deve_nao_mudar_estado() {
        let mut s = state();
        let before = format!("{s:?}");
        let commands = update(&mut s, key('z'));
        assert_eq!(commands, Vec::new());
        assert_eq!(format!("{s:?}"), before);
    }

    #[test]
    fn quando_x_deve_alternar_formato_de_fingerprint_na_ordem_colon_hex_base64() {
        let mut s = state();
        assert_eq!(s.fingerprint_format, FingerprintFormat::ColonHexUpper);
        update(&mut s, key('x'));
        assert_eq!(s.fingerprint_format, FingerprintFormat::HexLower);
        update(&mut s, key('x'));
        assert_eq!(s.fingerprint_format, FingerprintFormat::Base64);
        update(&mut s, key('x'));
        assert_eq!(s.fingerprint_format, FingerprintFormat::ColonHexUpper);
    }

    #[test]
    fn quando_ctrl_c_deve_marcar_should_quit() {
        let mut s = state();
        update(
            &mut s,
            Msg::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        );
        assert!(s.should_quit);
    }

    #[test]
    fn quando_tick_deve_guardar_o_relogio() {
        let mut s = state();
        let later = s.now + std::time::Duration::from_secs(3);
        update(&mut s, Msg::Tick(later));
        assert_eq!(s.now, later);
    }
}
