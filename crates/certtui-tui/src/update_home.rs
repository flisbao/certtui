//! Keys and pastes on the Home screen.

use certtui_domain::target::Target;
use certtui_domain::target_parse::parse_network_target;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app_state::{AppState, InspectState, Screen};
use crate::keymap::Action;
use crate::msg::Command;
use crate::toast::{Toast, ToastKind};

/// Most characters the target field accepts.
pub const MAX_INPUT_CHARS: usize = 2048;

/// Parser used when none is injected: `-` is standard input, anything else
/// must be a network target. The binary injects one that also knows files.
///
/// # Errors
///
/// The domain's message for an invalid network target.
pub fn default_target_parser(text: &str) -> Result<Target, String> {
    if text == "-" {
        return Ok(Target::Stdin);
    }
    parse_network_target(text)
        .map(Target::Network)
        .map_err(|error| error.to_string())
}

/// Handles a key while the target field has focus; `None` when the key is
/// not an editing key and should go through the keymap.
pub fn on_edit_key(state: &mut AppState, key: KeyEvent) -> Option<Vec<Command>> {
    if key.kind == KeyEventKind::Release {
        return Some(Vec::new());
    }
    let ctrl_or_alt = key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
    match key.code {
        KeyCode::Char(c) if !ctrl_or_alt => insert(state, c),
        KeyCode::Enter => return Some(submit(state)),
        KeyCode::Esc => state.home.editing = false,
        KeyCode::Backspace => backspace(state),
        KeyCode::Delete => delete(state),
        KeyCode::Left => state.home.cursor = state.home.cursor.saturating_sub(1),
        KeyCode::Right => {
            state.home.cursor = (state.home.cursor + 1).min(state.home.input.chars().count());
        }
        KeyCode::Home => state.home.cursor = 0,
        KeyCode::End => state.home.cursor = state.home.input.chars().count(),
        _ => return None,
    }
    Some(Vec::new())
}

/// Handles pasted text: control characters (newlines included) are dropped.
pub fn on_paste(state: &mut AppState, text: &str) {
    if !state.home.editing {
        return;
    }
    for c in text.chars().filter(|c| !c.is_control()) {
        insert(state, c);
    }
}

/// Handles an action while no field has focus.
pub fn on_action(state: &mut AppState, action: Action) -> Vec<Command> {
    match action {
        Action::NewTarget => {
            state.home.editing = true;
            state.home.cursor = state.home.input.chars().count();
        }
        Action::Enter => return submit(state),
        Action::Down => move_selection(state, true),
        Action::Up => move_selection(state, false),
        _ => return crate::update::on_global_action(state, action),
    }
    Vec::new()
}

fn move_selection(state: &mut AppState, down: bool) {
    let rows = state.home.recents.len() + state.home.favorites.len();
    if rows == 0 {
        state.home.selected = None;
        return;
    }
    let last = rows - 1;
    state.home.selected = Some(match (state.home.selected, down) {
        (None, true) => 0,
        (None, false) => last,
        (Some(i), true) => (i + 1).min(last),
        (Some(i), false) => i.saturating_sub(1),
    });
}

fn selected_row(state: &AppState) -> Option<&String> {
    let i = state.home.selected?;
    let favorites = state.home.favorites.len();
    if i < favorites {
        state.home.favorites.get(i)
    } else {
        state.home.recents.get(i - favorites)
    }
}

fn insert(state: &mut AppState, c: char) {
    if c.is_control() || state.home.input.chars().count() >= MAX_INPUT_CHARS {
        return;
    }
    let at = byte_index(&state.home.input, state.home.cursor);
    state.home.input.insert(at, c);
    state.home.cursor += 1;
}

fn backspace(state: &mut AppState) {
    if state.home.cursor == 0 {
        return;
    }
    state.home.cursor -= 1;
    let at = byte_index(&state.home.input, state.home.cursor);
    state.home.input.remove(at);
}

fn delete(state: &mut AppState) {
    let at = byte_index(&state.home.input, state.home.cursor);
    if at < state.home.input.len() {
        state.home.input.remove(at);
    }
}

/// Byte offset of the `chars`-th character (end of text when past it).
fn byte_index(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map_or(text.len(), |(index, _)| index)
}

/// Opens the Inspect screen on `target` and asks for the job that feeds it.
///
/// Also what the binary uses to start on a target given on the command line.
pub fn start_inspect(state: &mut AppState, target: Target) -> Vec<Command> {
    let id = state.jobs.start();
    state.screen = Screen::Inspect;
    state.inspect = Some(InspectState::loading(id));
    state.home.editing = false;
    vec![Command::Inspect { id, target }]
}

fn submit(state: &mut AppState) -> Vec<Command> {
    let text = if state.home.input.trim().is_empty() {
        selected_row(state).cloned().unwrap_or_default()
    } else {
        state.home.input.trim().to_owned()
    };
    if text.is_empty() {
        return Vec::new();
    }
    match (state.target_parser)(&text) {
        Ok(target) => start_inspect(state, target),
        Err(message) => {
            let toast = Toast::new(message, ToastKind::Error, state.now);
            state.set_toast(toast);
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use certtui_domain::target::NetworkTarget;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::msg::Msg;
    use crate::update::update;

    fn key(code: KeyCode) -> Msg {
        Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn type_text(state: &mut AppState, text: &str) {
        for c in text.chars() {
            update(state, key(KeyCode::Char(c)));
        }
    }

    fn editing_state() -> AppState {
        let mut state = AppState::new(Instant::now());
        update(&mut state, key(KeyCode::Char('o')));
        assert!(state.home.editing);
        state
    }

    #[test]
    fn quando_digita_alvo_e_enter_deve_emitir_command_inspect() {
        let mut state = editing_state();
        type_text(&mut state, "example.com:8443");
        let commands = update(&mut state, key(KeyCode::Enter));
        let Some(Command::Inspect { id, target }) = commands.first() else {
            unreachable!("expected an inspect command, got {commands:?}");
        };
        assert_eq!(
            *target,
            Target::Network(NetworkTarget {
                host: "example.com".to_owned(),
                port: 8443,
                sni: None,
                connect_to: None,
            })
        );
        assert_eq!(state.screen, Screen::Inspect);
        assert_eq!(state.inspect.as_ref().map(|i| i.job), Some(*id));
        assert!(state.jobs.is_active(*id));
        assert_eq!(commands.len(), 1);
    }

    #[test]
    fn quando_alvo_invalido_deve_mostrar_toast_de_erro_e_nao_emitir_command() {
        let mut state = editing_state();
        type_text(&mut state, "ftp://example.com");
        let commands = update(&mut state, key(KeyCode::Enter));
        assert_eq!(commands, Vec::new());
        assert_eq!(state.screen, Screen::Home);
        let toast = state.toast.as_ref();
        assert_eq!(toast.map(|t| t.kind), Some(ToastKind::Error));
        assert!(
            toast.is_some_and(|t| t.text.contains("scheme")),
            "{toast:?}"
        );
    }

    #[test]
    fn quando_backspace_deve_apagar_no_cursor_inclusive_multibyte() {
        let mut state = editing_state();
        type_text(&mut state, "caf\u{e9}x");
        update(&mut state, key(KeyCode::Left));
        update(&mut state, key(KeyCode::Backspace));
        assert_eq!(state.home.input, "cafx");
        assert_eq!(state.home.cursor, 3);
        update(&mut state, key(KeyCode::Backspace));
        update(&mut state, key(KeyCode::Backspace));
        update(&mut state, key(KeyCode::Backspace));
        update(&mut state, key(KeyCode::Backspace));
        assert_eq!(state.home.input, "x");
        assert_eq!(state.home.cursor, 0);
    }

    #[test]
    fn quando_cola_texto_com_newline_deve_ignorar_o_newline() {
        let mut state = editing_state();
        update(&mut state, Msg::Paste("exam\nple.com\r\n".to_owned()));
        assert_eq!(state.home.input, "example.com");
        assert_eq!(state.home.cursor, 11);
    }

    #[test]
    fn quando_q_digitado_no_campo_deve_inserir_e_nao_sair() {
        let mut state = editing_state();
        type_text(&mut state, "quad9.net");
        assert_eq!(state.home.input, "quad9.net");
        assert!(!state.should_quit);
    }

    #[test]
    fn quando_esc_no_campo_deve_voltar_ao_modo_comando() {
        let mut state = editing_state();
        update(&mut state, key(KeyCode::Esc));
        assert!(!state.home.editing);
    }

    #[test]
    fn quando_entrada_passa_do_limite_deve_truncar() {
        let mut state = editing_state();
        update(&mut state, Msg::Paste("a".repeat(MAX_INPUT_CHARS + 50)));
        assert_eq!(state.home.input.chars().count(), MAX_INPUT_CHARS);
    }

    #[test]
    fn quando_enter_com_campo_vazio_deve_nao_fazer_nada() {
        let mut state = editing_state();
        assert_eq!(update(&mut state, key(KeyCode::Enter)), Vec::new());
        assert_eq!(state.screen, Screen::Home);
        assert!(state.toast.is_none());
    }

    #[test]
    fn quando_hifen_deve_pedir_stdin() {
        let mut state = editing_state();
        type_text(&mut state, "-");
        let commands = update(&mut state, key(KeyCode::Enter));
        assert!(matches!(
            commands.first(),
            Some(Command::Inspect {
                target: Target::Stdin,
                ..
            })
        ));
    }
}
