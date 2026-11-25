//! The pure state transition.

use crossterm::event::KeyEvent;

use crate::app_state::{AppState, Modal, Screen};
use crate::copy::CopyPayload;
use crate::keymap::Action;
use crate::msg::{Command, Msg};
use crate::toast::{Toast, ToastKind};
use crate::view::help;
use crate::{update_batch, update_home, update_inspect, update_modal};
use certtui_domain::model::FingerprintFormat;

/// Applies `msg` to `state` and returns the side effects to run.
///
/// Pure: no I/O and no clock; time arrives through [`Msg::Tick`].
pub fn update(state: &mut AppState, msg: Msg) -> Vec<Command> {
    match msg {
        Msg::Key(key) => on_key(state, key),
        Msg::Paste(text) => {
            if state.modal.is_some() {
                update_modal::on_paste(state, &text);
            } else if state.screen == Screen::Home {
                update_home::on_paste(state, &text);
            }
            Vec::new()
        }
        Msg::Batch { id, events } => {
            update_batch::on_events(state, id, events);
            Vec::new()
        }
        Msg::PasswordNeeded { id, wrong } => {
            update_modal::on_password_needed(state, id, wrong);
            Vec::new()
        }
        Msg::ExportDone { path } => {
            update_modal::on_export_done(state, &path);
            Vec::new()
        }
        Msg::ExportFailed(failure) => {
            update_modal::on_export_failed(state, failure);
            Vec::new()
        }
        Msg::Resize(columns, rows) => {
            state.size = (columns, rows);
            Vec::new()
        }
        Msg::Tick(now) => {
            state.now = now;
            if state
                .toast
                .as_ref()
                .is_some_and(|toast| toast.expires_at <= now)
            {
                state.toast = None;
            }
            Vec::new()
        }
        Msg::InspectDone { id, result } => {
            update_inspect::on_inspect_done(state, id, result);
            Vec::new()
        }
        Msg::Copied {
            label,
            bytes,
            method,
        } => {
            let toast = Toast::copied(&label, bytes, method, state.now);
            state.set_toast(toast);
            Vec::new()
        }
        Msg::CopyFailed { reason } => {
            let toast = Toast::copy_failed(&reason, state.now);
            state.set_toast(toast);
            Vec::new()
        }
        Msg::HistorySaveFailed => {
            let toast = Toast::new("could not save history", ToastKind::Error, state.now);
            state.set_toast(toast);
            Vec::new()
        }
    }
}

fn on_key(state: &mut AppState, key: KeyEvent) -> Vec<Command> {
    // A dialog that takes text owns every key: nothing may reach the keymap.
    if state.modal.as_ref().is_some_and(Modal::takes_text) {
        return update_modal::on_key(state, key);
    }
    if state.modal.is_none()
        && state.screen == Screen::Batch
        && state
            .batch
            .as_ref()
            .is_some_and(|batch| batch.filter_editing)
    {
        return update_batch::on_filter_key(state, key);
    }
    if state.modal.is_none()
        && state.screen == Screen::Home
        && state.home.editing
        && let Some(commands) = update_home::on_edit_key(state, key)
    {
        return commands;
    }
    match state.keymap.resolve(key) {
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
        Screen::Batch => update_batch::on_action(state, action),
    }
}

/// Asks for `payload` to be copied, or explains why it will not be: text
/// above `max_clipboard_bytes` is never copied.
pub(crate) fn request_copy(state: &mut AppState, payload: CopyPayload) -> Vec<Command> {
    if payload.text.len() > state.max_clipboard_bytes {
        let kib = payload.text.len().div_ceil(1024);
        let toast = Toast::new(
            format!("too large to copy ({kib} KiB); press e to export"),
            ToastKind::Error,
            state.now,
        );
        state.set_toast(toast);
        return Vec::new();
    }
    vec![Command::CopyToClipboard(payload)]
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
    match action {
        Action::Back | Action::Help | Action::Quit => {
            state.modal = None;
            state.help_scroll = 0;
        }
        Action::Down | Action::Up if state.modal.as_ref().is_some_and(Modal::is_help) => {
            scroll_help(state, action);
        }
        _ => {}
    }
    Vec::new()
}

fn scroll_help(state: &mut AppState, action: Action) {
    let lines = help::help_lines(&state.keymap).len();
    let last = lines.saturating_sub(help::viewport_rows(state.size));
    let scroll = usize::from(state.help_scroll);
    let scroll = if action == Action::Down {
        scroll.saturating_add(1).min(last)
    } else {
        scroll.saturating_sub(1)
    };
    state.help_scroll = u16::try_from(scroll).unwrap_or(u16::MAX);
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
    use crate::keymap::Keymap;

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
    fn quando_keymap_do_estado_foi_remapeado_deve_resolver_a_tecla_nova() {
        let mut s = state();
        s.keymap = Keymap::from_overrides(&std::collections::BTreeMap::from([(
            "quit".to_owned(),
            "z".to_owned(),
        )]))
        .unwrap();
        update(&mut s, key('q'));
        assert!(!s.should_quit);
        update(&mut s, key('z'));
        assert!(s.should_quit);
    }

    #[test]
    fn quando_quit_remapeado_ctrl_c_deve_sair_mesmo_assim() {
        let mut s = state();
        s.keymap = Keymap::from_overrides(&std::collections::BTreeMap::from([(
            "quit".to_owned(),
            "z".to_owned(),
        )]))
        .unwrap();
        update(
            &mut s,
            Msg::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        );
        assert!(s.should_quit);
    }

    #[test]
    fn quando_interrogacao_deve_abrir_modal_help_e_esc_fechar() {
        let mut s = state();
        update(&mut s, key('?'));
        assert!(matches!(s.modal, Some(Modal::Help)));
        update(&mut s, esc());
        assert!(s.modal.is_none());
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

#[cfg(test)]
mod toast_tests {
    use std::time::{Duration, Instant};

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::clipboard::CopyMethod;
    use crate::test_fixtures::{inspect_state, sample_report};
    use crate::toast::ToastKind;
    use crate::view::test_support::{render, text};

    fn copied(method: CopyMethod) -> Msg {
        Msg::Copied {
            label: "SHA-256".to_owned(),
            bytes: 64,
            method,
        }
    }

    #[test]
    fn quando_copied_via_osc52_deve_dizer_sent_via_osc_52_e_nao_copied() {
        let mut s = AppState::new(Instant::now());
        update(&mut s, copied(CopyMethod::Osc52));
        let toast = s.toast.unwrap();
        assert_eq!(toast.text, "Sent SHA-256 via OSC 52 (64 B)");
        assert!(!toast.text.contains("Copied"));
        assert_eq!(toast.kind, ToastKind::Info);
    }

    #[test]
    fn quando_copied_nativo_deve_dizer_copied() {
        let mut s = AppState::new(Instant::now());
        update(&mut s, copied(CopyMethod::Native));
        assert_eq!(s.toast.unwrap().text, "Copied SHA-256 (64 B)");
    }

    #[test]
    fn quando_copy_failed_deve_mostrar_motivo() {
        let mut s = AppState::new(Instant::now());
        update(
            &mut s,
            Msg::CopyFailed {
                reason: "clipboard timed out".to_owned(),
            },
        );
        let toast = s.toast.unwrap();
        assert_eq!(toast.text, "Copy failed: clipboard timed out");
        assert_eq!(toast.kind, ToastKind::Error);
    }

    #[test]
    fn quando_copy_failed_tem_motivo_enorme_ou_com_controle_deve_limitar_e_sanitizar() {
        let mut s = AppState::new(Instant::now());
        let reason = format!("\u{1b}[31m{}", "x".repeat(5000));
        update(&mut s, Msg::CopyFailed { reason });
        let text = s.toast.unwrap().text;
        assert!(!text.contains('\u{1b}'));
        assert!(text.chars().count() < 200, "{}", text.len());
    }

    #[test]
    fn quando_tick_passa_de_2s_deve_remover_toast() {
        let start = Instant::now();
        let mut s = AppState::new(start);
        update(&mut s, copied(CopyMethod::Native));
        update(&mut s, Msg::Tick(start + Duration::from_millis(1999)));
        assert!(s.toast.is_some());
        update(&mut s, Msg::Tick(start + Duration::from_secs(2)));
        assert!(s.toast.is_none());
    }

    #[test]
    fn quando_10_copias_seguidas_deve_manter_um_unico_toast() {
        let start = Instant::now();
        let mut s = AppState::new(start);
        for i in 0..10_u64 {
            update(&mut s, Msg::Tick(start + Duration::from_millis(i * 10)));
            update(&mut s, copied(CopyMethod::Osc52));
        }
        assert_eq!(
            s.toast.map(|t| t.text),
            Some("Sent SHA-256 via OSC 52 (64 B)".to_owned())
        );
    }

    #[test]
    fn quando_toast_novo_deve_substituir_e_reiniciar_o_prazo() {
        let start = Instant::now();
        let mut s = AppState::new(start);
        update(&mut s, copied(CopyMethod::Native));
        update(&mut s, Msg::Tick(start + Duration::from_millis(1500)));
        update(&mut s, copied(CopyMethod::Osc52));
        update(&mut s, Msg::Tick(start + Duration::from_millis(2500)));
        assert!(s.toast.is_some(), "the new toast restarts its two seconds");
    }

    #[test]
    fn quando_toast_ativo_e_tecla_de_navegacao_deve_continuar_navegando() {
        let mut s = inspect_state(sample_report());
        update(&mut s, copied(CopyMethod::Native));
        update(
            &mut s,
            Msg::Key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)),
        );
        assert_eq!(s.inspect.as_ref().map(|i| i.selected_cert), Some(1));
        assert!(s.toast.is_some());
    }

    #[test]
    fn quando_toast_ativo_deve_bater_com_o_snapshot() {
        let mut s = inspect_state(sample_report());
        update(&mut s, copied(CopyMethod::Osc52));
        insta::assert_snapshot!(text(&render(&s, 80, 24)));
    }

    #[test]
    fn quando_toast_na_home_deve_caber_em_80x24() {
        let mut s = AppState::new(Instant::now());
        update(
            &mut s,
            Msg::CopyFailed {
                reason: "y".repeat(500),
            },
        );
        let screen = text(&render(&s, 80, 24));
        assert!(screen.contains("Copy failed:"), "{screen}");
    }
}
