//! Keys and pastes on the Home screen.

use certtui_domain::target::{NetworkTarget, Target};
use certtui_domain::target_parse::parse_network_target;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app_state::{AppState, HomeMode, InspectState, Screen};
use crate::keymap::Action;
use crate::msg::Command;
use crate::toast::{Toast, ToastKind};

/// Most characters the target field accepts.
pub const MAX_INPUT_CHARS: usize = 2048;

/// Most suggestions shown under the target field.
const MAX_SUGGESTIONS: usize = 8;

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

/// Loader used when none is injected: a build without a file system cannot
/// read a list. The binary injects one that can.
///
/// # Errors
///
/// Always.
pub fn default_batch_loader(_path: &str) -> Result<Vec<NetworkTarget>, String> {
    Err("this build cannot read a list of targets".to_owned())
}

/// Handles a key while the target field has focus; `None` when the key is
/// not an editing key and should go through the keymap.
pub fn on_edit_key(state: &mut AppState, key: KeyEvent) -> Option<Vec<Command>> {
    let handled = edit_key(state, key);
    refresh_suggestions(state);
    handled
}

fn edit_key(state: &mut AppState, key: KeyEvent) -> Option<Vec<Command>> {
    if key.kind == KeyEventKind::Release {
        return Some(Vec::new());
    }
    let ctrl_or_alt = key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
    match key.code {
        KeyCode::Char(c) if !ctrl_or_alt => insert(state, c),
        KeyCode::Enter => return Some(submit(state)),
        KeyCode::Esc => stop_editing(state),
        KeyCode::Tab if !state.home.suggestions.is_empty() => complete(state),
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
    refresh_suggestions(state);
}

/// Recomputes the suggestions for what is typed: only while typing a target.
fn refresh_suggestions(state: &mut AppState) {
    state.home.suggestions = if state.home.editing && state.home.mode == HomeMode::Target {
        state
            .history
            .suggestions(&state.home.input, MAX_SUGGESTIONS)
    } else {
        Vec::new()
    };
}

/// Replaces the text with the first suggestion.
fn complete(state: &mut AppState) {
    if let Some(first) = state.home.suggestions.first() {
        state.home.input = first.chars().take(MAX_INPUT_CHARS).collect();
        state.home.cursor = state.home.input.chars().count();
    }
}

/// Handles an action while no field has focus.
pub fn on_action(state: &mut AppState, action: Action) -> Vec<Command> {
    match action {
        Action::NewTarget => {
            state.home.mode = HomeMode::Target;
            state.home.editing = true;
            state.home.cursor = state.home.input.chars().count();
        }
        Action::OpenBatch => {
            state.home.mode = HomeMode::BatchFile;
            state.home.input.clear();
            state.home.cursor = 0;
            state.home.editing = true;
        }
        Action::Enter => return submit(state),
        Action::Favorite => return favorite_selected(state),
        Action::Down => move_selection(state, true),
        Action::Up => move_selection(state, false),
        _ => return crate::update::on_global_action(state, action),
    }
    Vec::new()
}

/// Toggles the favorite mark of the selected row and asks to save it.
fn favorite_selected(state: &mut AppState) -> Vec<Command> {
    let Some(target) = selected_row(state).cloned() else {
        return Vec::new();
    };
    state.history.toggle_favorite(&target);
    state.sync_history_lists();
    vec![Command::SaveHistory(state.history.clone())]
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
    state.inspect = Some(InspectState::loading(id, target.clone()));
    state.home.editing = false;
    vec![Command::Inspect { id, target }]
}

/// Leaves the field; a path typed for a batch does not stay behind as a
/// target.
fn stop_editing(state: &mut AppState) {
    state.home.editing = false;
    if state.home.mode == HomeMode::BatchFile {
        state.home.mode = HomeMode::Target;
        state.home.input.clear();
        state.home.cursor = 0;
    }
}

/// Reads the list named in the field and opens the batch, or says why not.
fn submit_batch(state: &mut AppState) -> Vec<Command> {
    let path = state.home.input.trim().to_owned();
    if path.is_empty() {
        return Vec::new();
    }
    let loaded = (state.batch_loader)(&path).and_then(|targets| {
        if targets.is_empty() {
            Err("no targets in the list".to_owned())
        } else {
            Ok(targets)
        }
    });
    match loaded {
        Ok(targets) => {
            stop_editing(state);
            crate::update_batch::start_batch(state, targets)
        }
        Err(message) => {
            let toast = Toast::new(message, ToastKind::Error, state.now);
            state.set_toast(toast);
            Vec::new()
        }
    }
}

fn submit(state: &mut AppState) -> Vec<Command> {
    if state.home.mode == HomeMode::BatchFile {
        return submit_batch(state);
    }
    let text = if state.home.input.trim().is_empty() {
        selected_row(state).cloned().unwrap_or_default()
    } else {
        state.home.input.trim().to_owned()
    };
    if text.is_empty() {
        return Vec::new();
    }
    match (state.target_parser)(&text) {
        Ok(target) => {
            let now = (state.wall_clock)();
            state.history.record(&text, now, state.history_max_entries);
            state.sync_history_lists();
            let mut commands = start_inspect(state, target);
            commands.push(Command::SaveHistory(state.history.clone()));
            refresh_suggestions(state);
            commands
        }
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
        // The inspection, then the history that now holds the target.
        assert_eq!(commands.len(), 2);
        assert!(matches!(commands.get(1), Some(Command::SaveHistory(_))));
    }

    #[test]
    fn quando_enter_deve_registrar_o_alvo_no_historico_e_emitir_save_history() {
        let mut state = editing_state();
        type_text(&mut state, "Example.com");
        let commands = update(&mut state, key(KeyCode::Enter));
        let Some(Command::SaveHistory(history)) = commands.get(1) else {
            unreachable!("expected SaveHistory, got {commands:?}");
        };
        assert_eq!(history, &state.history);
        assert_eq!(state.history.recents.len(), 1);
        assert_eq!(
            state.history.recents.first().map(|e| e.target.as_str()),
            Some("Example.com")
        );
        assert_eq!(state.home.recents, ["Example.com"]);
    }

    #[test]
    fn quando_alvo_invalido_nao_deve_registrar_no_historico() {
        let mut state = editing_state();
        type_text(&mut state, "ftp://example.com");
        let commands = update(&mut state, key(KeyCode::Enter));
        assert_eq!(commands, Vec::new());
        assert_eq!(state.history.recents, []);
    }

    fn state_with_history() -> AppState {
        let mut state = AppState::new(Instant::now());
        let now = (state.wall_clock)();
        for target in ["alpha.example", "alps.example", "beta.example"] {
            state.history.record(target, now, 200);
        }
        state.history.toggle_favorite("alps.example");
        state.sync_history_lists();
        state
    }

    #[test]
    fn quando_digita_prefixo_deve_sugerir_do_historico_e_favoritos() {
        let mut state = state_with_history();
        update(&mut state, key(KeyCode::Char('o')));
        type_text(&mut state, "al");
        assert_eq!(state.home.suggestions, ["alps.example", "alpha.example"]);
        type_text(&mut state, "pha");
        assert_eq!(state.home.suggestions, ["alpha.example"]);
        for _ in 0..5 {
            update(&mut state, key(KeyCode::Backspace));
        }
        assert_eq!(state.home.input, "");
        assert_eq!(state.home.suggestions, Vec::<String>::new());
    }

    #[test]
    fn quando_tab_com_sugestao_deve_completar_o_campo() {
        let mut state = state_with_history();
        update(&mut state, key(KeyCode::Char('o')));
        type_text(&mut state, "be");
        update(&mut state, key(KeyCode::Tab));
        assert_eq!(state.home.input, "beta.example");
        assert_eq!(state.home.cursor, "beta.example".chars().count());
    }

    #[test]
    fn quando_esc_deve_limpar_as_sugestoes() {
        let mut state = state_with_history();
        update(&mut state, key(KeyCode::Char('o')));
        type_text(&mut state, "al");
        assert_ne!(state.home.suggestions, Vec::<String>::new());
        update(&mut state, key(KeyCode::Esc));
        assert_eq!(state.home.suggestions, Vec::<String>::new());
    }

    #[test]
    fn quando_f_deve_favoritar_alvo_selecionado_e_emitir_save_history() {
        let mut state = state_with_history();
        // Rows: favorites first (alps), then recents (beta, alps, alpha).
        update(&mut state, key(KeyCode::Down));
        update(&mut state, key(KeyCode::Down));
        assert_eq!(state.home.selected, Some(1));
        let commands = update(&mut state, key(KeyCode::Char('f')));
        let Some(Command::SaveHistory(history)) = commands.first() else {
            unreachable!("expected SaveHistory, got {commands:?}");
        };
        assert!(history.is_favorite("beta.example"));
        assert_eq!(history, &state.history);
        assert_eq!(state.home.favorites, ["alps.example", "beta.example"]);
        assert_eq!(commands.len(), 1);
    }

    #[test]
    fn quando_f_no_favorito_deve_desfavoritar() {
        let mut state = state_with_history();
        update(&mut state, key(KeyCode::Down));
        assert_eq!(state.home.selected, Some(0));
        let commands = update(&mut state, key(KeyCode::Char('f')));
        assert!(matches!(commands.first(), Some(Command::SaveHistory(_))));
        assert!(!state.history.is_favorite("alps.example"));
        assert_eq!(state.home.favorites, Vec::<String>::new());
    }

    #[test]
    fn quando_f_sem_selecao_nao_deve_emitir_nada() {
        let mut state = state_with_history();
        let commands = update(&mut state, key(KeyCode::Char('f')));
        assert_eq!(commands, Vec::new());
    }

    #[test]
    fn quando_save_history_falha_deve_mostrar_toast_e_manter_estado() {
        let mut state = state_with_history();
        let before = state.history.clone();
        let commands = update(&mut state, Msg::HistorySaveFailed);
        assert_eq!(commands, Vec::new());
        let toast = state.toast.as_ref().unwrap();
        assert_eq!(toast.kind, ToastKind::Error);
        assert_eq!(toast.text, "could not save history");
        assert_eq!(state.history, before);
        assert_eq!(state.home.recents.len(), 3);
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

#[cfg(test)]
mod batch_tests {
    use std::time::Instant;

    use certtui_domain::target::NetworkTarget;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::app_state::HomeMode;
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

    fn target(host: &str) -> NetworkTarget {
        NetworkTarget {
            host: host.to_owned(),
            port: 443,
            sni: None,
            connect_to: None,
        }
    }

    fn fake_loader(path: &str) -> Result<Vec<NetworkTarget>, String> {
        match path {
            "list.txt" => Ok(vec![target("a.test"), target("b.test")]),
            "empty.txt" => Ok(Vec::new()),
            _ => Err(format!("cannot read {path}")),
        }
    }

    fn state() -> AppState {
        let mut state = AppState::new(Instant::now());
        state.batch_loader = fake_loader;
        state
    }

    #[test]
    fn quando_b_na_home_e_caminho_valido_deve_emitir_run_batch() {
        let mut state = state();
        update(&mut state, key(KeyCode::Char('b')));
        assert!(state.home.editing);
        assert_eq!(state.home.mode, HomeMode::BatchFile);
        type_text(&mut state, "list.txt");
        let commands = update(&mut state, key(KeyCode::Enter));
        assert_eq!(state.screen, Screen::Batch);
        let job = state.batch.as_ref().unwrap().job;
        assert_eq!(
            commands,
            vec![Command::RunBatch {
                id: job,
                targets: vec![target("a.test"), target("b.test")]
            }]
        );
        assert!(!state.home.editing);
        assert_eq!(state.home.mode, HomeMode::Target);
    }

    #[test]
    fn quando_caminho_invalido_deve_mostrar_toast() {
        let mut state = state();
        update(&mut state, key(KeyCode::Char('b')));
        type_text(&mut state, "missing.txt");
        let commands = update(&mut state, key(KeyCode::Enter));
        assert_eq!(commands, Vec::new());
        assert_eq!(state.screen, Screen::Home);
        let toast = state.toast.as_ref().unwrap();
        assert_eq!(toast.kind, ToastKind::Error);
        assert!(
            toast.text.contains("cannot read missing.txt"),
            "{}",
            toast.text
        );
        assert!(state.home.editing, "the user can fix the path");
    }

    #[test]
    fn quando_lista_sem_alvos_deve_mostrar_toast_e_nao_abrir_batch() {
        let mut state = state();
        update(&mut state, key(KeyCode::Char('b')));
        type_text(&mut state, "empty.txt");
        let commands = update(&mut state, key(KeyCode::Enter));
        assert_eq!(commands, Vec::new());
        assert_eq!(state.screen, Screen::Home);
        assert!(state.toast.as_ref().unwrap().text.contains("no targets"));
    }

    #[test]
    fn quando_b_e_esc_deve_voltar_ao_modo_alvo_e_limpar_o_campo() {
        let mut state = state();
        update(&mut state, key(KeyCode::Char('b')));
        type_text(&mut state, "list");
        update(&mut state, key(KeyCode::Esc));
        assert!(!state.home.editing);
        assert_eq!(state.home.mode, HomeMode::Target);
        assert_eq!(state.home.input, "");
    }

    #[test]
    fn quando_b_depois_de_digitar_alvo_deve_comecar_com_o_campo_vazio() {
        let mut state = state();
        update(&mut state, key(KeyCode::Char('o')));
        type_text(&mut state, "example.com");
        update(&mut state, key(KeyCode::Esc));
        update(&mut state, key(KeyCode::Char('b')));
        assert_eq!(state.home.input, "");
        update(&mut state, key(KeyCode::Esc));
    }

    #[test]
    fn quando_b_deve_mostrar_o_campo_da_lista_e_a_dica() {
        use crate::view::test_support::{render, text};

        let mut state = state();
        update(&mut state, key(KeyCode::Char('b')));
        let screen = text(&render(&state, 80, 24));
        assert!(screen.contains("Batch list file"), "{screen}");
        assert!(screen.contains("one target per line"), "{screen}");
        assert!(screen.contains("Enter open the list"), "{screen}");
    }

    #[test]
    fn quando_b_no_modo_digitacao_deve_ser_texto_e_nao_comando() {
        let mut state = state();
        update(&mut state, key(KeyCode::Char('o')));
        update(&mut state, key(KeyCode::Char('b')));
        assert_eq!(state.home.mode, HomeMode::Target);
        assert_eq!(state.home.input, "b");
    }
}
