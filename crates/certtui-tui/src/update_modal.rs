//! The dialogs that take typed text: keystore password, export, and the
//! confirmation before replacing a file.
//!
//! While one is open every key goes here, never to the keymap: typing `y` in
//! the password dialog must not copy anything, and the password must never
//! reach the clipboard, a toast or a log.

use std::path::PathBuf;
use std::sync::Arc;

use certtui_app::export::{ExportFormat, ExportSelection, Overwrite};
use certtui_app::present::labels;
use certtui_domain::model::InspectionReport;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app_state::{
    AppState, ExportModal, InspectState, JobId, Masked, Modal, PasswordModal, Phase,
};
use crate::msg::{Command, ExportFailure, ExportRequest};
use crate::toast::{Toast, ToastKind};

/// Shown when the password does not open the keystore.
pub const WRONG_PASSWORD: &str = "wrong password or corrupt keystore";

/// The file name the export dialog starts with.
const DEFAULT_NAME: &str = "certificate";

/// Extension for each format, without the dot.
#[must_use]
pub const fn extension(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Pem => "pem",
        ExportFormat::Der => "der",
        ExportFormat::Json => "json",
    }
}

/// Name of `format` in the dialog.
#[must_use]
pub const fn format_name(format: ExportFormat) -> &'static str {
    match format {
        ExportFormat::Pem => "PEM",
        ExportFormat::Der => "DER",
        ExportFormat::Json => "JSON",
    }
}

/// The format after `format` in the dialog's cycle.
const fn next_format(format: ExportFormat) -> ExportFormat {
    match format {
        ExportFormat::Pem => ExportFormat::Der,
        ExportFormat::Der => ExportFormat::Json,
        ExportFormat::Json => ExportFormat::Pem,
    }
}

/// `name` with its known extension swapped for the one of `format`; a name
/// the user typed with any other ending is left alone.
fn with_extension(name: &str, format: ExportFormat) -> String {
    for known in ["pem", "der", "json"] {
        if let Some(stem) = name.strip_suffix(&format!(".{known}")) {
            return format!("{stem}.{}", extension(format));
        }
    }
    name.to_owned()
}

/// Opens the export dialog on the report of the Inspect screen.
pub fn open_export(state: &mut AppState) {
    let Some(inspect) = state.inspect.as_ref() else {
        return;
    };
    let Some(report) = inspect.report().map(Arc::clone) else {
        return;
    };
    state.modal = Some(Modal::Export(ExportModal {
        report,
        format: ExportFormat::Pem,
        selection: ExportSelection::Index(inspect.selected_cert),
        path: format!("{DEFAULT_NAME}.{}", extension(ExportFormat::Pem)),
        error: None,
    }));
}

/// The job needs a password: show the dialog, over the Inspect screen.
pub fn on_password_needed(state: &mut AppState, id: JobId, wrong: bool) {
    state.jobs.finish(id);
    let Some(inspect) = state.inspect.as_mut() else {
        return;
    };
    if inspect.job != id {
        return;
    }
    inspect.phase = Phase::Failed("a password is required to open this keystore".to_owned());
    state.modal = Some(Modal::Password(PasswordModal {
        target: inspect.target.clone(),
        input: Masked::new(),
        error: wrong.then(|| WRONG_PASSWORD.to_owned()),
    }));
}

/// An export was written.
pub fn on_export_done(state: &mut AppState, path: &str) {
    state.pending_export = None;
    let toast = Toast::new(
        format!("Exported to {}", labels::single_line(path)),
        ToastKind::Info,
        state.now,
    );
    state.set_toast(toast);
}

/// An export failed: ask before replacing, or show why.
pub fn on_export_failed(state: &mut AppState, failure: ExportFailure) {
    let pending = state.pending_export.take();
    match (failure, pending) {
        (ExportFailure::AlreadyExists, Some(request)) => {
            state.pending_export = Some(request.clone());
            state.modal = Some(Modal::ConfirmOverwrite(request));
        }
        (ExportFailure::Message(message), Some(request)) => {
            state.modal = Some(Modal::Export(ExportModal {
                report: request.report,
                format: request.format,
                selection: request.selection,
                path: request.path.to_string_lossy().into_owned(),
                error: Some(labels::single_line(&message)),
            }));
        }
        (failure, None) => {
            let text = match failure {
                ExportFailure::AlreadyExists => "the file already exists".to_owned(),
                ExportFailure::Message(message) => labels::single_line(&message),
            };
            let toast = Toast::new(
                format!("Export failed: {text}"),
                ToastKind::Error,
                state.now,
            );
            state.set_toast(toast);
        }
    }
}

/// Text pasted while a dialog is open goes into its field.
pub fn on_paste(state: &mut AppState, text: &str) {
    match state.modal.as_mut() {
        Some(Modal::Password(dialog)) => {
            for c in text.chars().filter(|c| !c.is_control()) {
                dialog.input.push(c);
            }
        }
        Some(Modal::Export(dialog)) => {
            dialog.path.extend(text.chars().filter(|c| !c.is_control()));
        }
        _ => {}
    }
}

/// Handles a key while a text dialog is open.
pub fn on_key(state: &mut AppState, key: KeyEvent) -> Vec<Command> {
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        state.should_quit = true;
        return Vec::new();
    }
    match state.modal.take() {
        Some(Modal::Password(dialog)) => password_key(state, dialog, key),
        Some(Modal::Export(dialog)) => export_key(state, dialog, key),
        Some(Modal::ConfirmOverwrite(request)) => confirm_key(state, request, key),
        other => {
            state.modal = other;
            Vec::new()
        }
    }
}

/// A printable character typed without Ctrl or Alt.
fn typed_char(key: KeyEvent) -> Option<char> {
    match key.code {
        KeyCode::Char(c)
            if !c.is_control()
                && !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            Some(c)
        }
        _ => None,
    }
}

fn password_key(state: &mut AppState, mut dialog: PasswordModal, key: KeyEvent) -> Vec<Command> {
    match key.code {
        KeyCode::Esc => return Vec::new(),
        KeyCode::Enter => {
            let id = state.jobs.start();
            let target = dialog.target.clone();
            state.inspect = Some(InspectState::loading(id, target.clone()));
            return vec![Command::InspectWithPassword {
                id,
                target,
                password: dialog.input.to_password(),
            }];
        }
        KeyCode::Backspace => dialog.input.pop(),
        _ => {
            if let Some(c) = typed_char(key) {
                dialog.input.push(c);
            }
        }
    }
    dialog.error = None;
    state.modal = Some(Modal::Password(dialog));
    Vec::new()
}

fn export_key(state: &mut AppState, mut dialog: ExportModal, key: KeyEvent) -> Vec<Command> {
    match key.code {
        KeyCode::Esc => return Vec::new(),
        KeyCode::Enter => return submit_export(state, dialog),
        KeyCode::Tab => {
            dialog.format = next_format(dialog.format);
            dialog.path = with_extension(&dialog.path, dialog.format);
        }
        KeyCode::Up | KeyCode::Down => {
            dialog.selection = toggle_selection(&dialog);
        }
        KeyCode::Backspace => {
            dialog.path.pop();
        }
        _ => {
            if let Some(c) = typed_char(key) {
                dialog.path.push(c);
            }
        }
    }
    dialog.error = None;
    state.modal = Some(Modal::Export(dialog));
    Vec::new()
}

/// Switches between "this certificate" and "the whole chain".
fn toggle_selection(dialog: &ExportModal) -> ExportSelection {
    match dialog.selection {
        ExportSelection::Chain => ExportSelection::Index(0),
        ExportSelection::Index(_) => ExportSelection::Chain,
    }
}

fn submit_export(state: &mut AppState, mut dialog: ExportModal) -> Vec<Command> {
    let name = dialog.path.trim().to_owned();
    let problem = if name.is_empty() {
        Some("enter a file name")
    } else if dialog.format == ExportFormat::Der && dialog.selection == ExportSelection::Chain {
        Some("DER holds one certificate: choose PEM or JSON for the chain")
    } else {
        None
    };
    if let Some(problem) = problem {
        dialog.error = Some(problem.to_owned());
        state.modal = Some(Modal::Export(dialog));
        return Vec::new();
    }
    let request = ExportRequest {
        report: Arc::clone(&dialog.report) as Arc<InspectionReport>,
        format: dialog.format,
        selection: dialog.selection,
        path: PathBuf::from(name),
        overwrite: Overwrite::Refuse,
    };
    state.pending_export = Some(request.clone());
    vec![Command::Export(request)]
}

fn confirm_key(state: &mut AppState, mut request: ExportRequest, key: KeyEvent) -> Vec<Command> {
    match key.code {
        KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
            request.overwrite = Overwrite::Allow;
            state.pending_export = Some(request.clone());
            vec![Command::Export(request)]
        }
        _ => {
            state.pending_export = None;
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use certtui_app::keystore::SecretString;
    use certtui_domain::target::Target;
    use crossterm::event::KeyEventKind;

    use super::*;
    use crate::msg::{Msg, Password};
    use crate::test_fixtures::{inspect_state, sample_report};
    use crate::update::update;
    use crate::view::test_support::{render, text};

    fn press(code: KeyCode) -> Msg {
        Msg::Key(KeyEvent::new_with_kind(
            code,
            KeyModifiers::NONE,
            KeyEventKind::Press,
        ))
    }

    fn typed(state: &mut AppState, text: &str) {
        for c in text.chars() {
            update(state, press(KeyCode::Char(c)));
        }
    }

    fn password_of(text: &str) -> Password {
        Password::new(SecretString::from(text.to_owned()))
    }

    /// A state whose keystore job just asked for a password.
    fn asking(wrong: bool) -> (AppState, JobId) {
        let mut state = AppState::new(Instant::now());
        let id = state.jobs.start();
        state.screen = crate::app_state::Screen::Inspect;
        state.inspect = Some(InspectState::loading(id, Target::File("store.p12".into())));
        update(&mut state, Msg::PasswordNeeded { id, wrong });
        (state, id)
    }

    fn password_modal(state: &AppState) -> &PasswordModal {
        match &state.modal {
            Some(Modal::Password(dialog)) => dialog,
            other => panic!("expected the password dialog, got {other:?}"),
        }
    }

    fn export_modal(state: &AppState) -> &ExportModal {
        match &state.modal {
            Some(Modal::Export(dialog)) => dialog,
            other => panic!("expected the export dialog, got {other:?}"),
        }
    }

    // --- password -----------------------------------------------------------

    #[test]
    fn quando_load_pede_senha_deve_abrir_modal_de_senha() {
        let (state, _) = asking(false);

        let dialog = password_modal(&state);
        assert_eq!(dialog.target, Target::File("store.p12".into()));
        assert_eq!(dialog.error, None);
        assert!(dialog.input.is_empty());
        assert!(!state.jobs.any_active(), "the asking job is over");
    }

    #[test]
    fn quando_senha_errada_deve_reabrir_modal_com_erro() {
        let (state, _) = asking(true);
        assert_eq!(
            password_modal(&state).error.as_deref(),
            Some("wrong password or corrupt keystore")
        );
    }

    #[test]
    fn quando_resposta_e_de_outro_job_deve_ignorar_o_pedido_de_senha() {
        let (mut state, id) = asking(false);
        state.modal = None;
        update(
            &mut state,
            Msg::PasswordNeeded {
                id: JobId(id.0 + 99),
                wrong: false,
            },
        );
        assert!(state.modal.is_none());
    }

    #[test]
    fn quando_digita_senha_deve_mascarar_na_view() {
        let (mut state, _) = asking(false);
        // Characters that appear nowhere in the dialog's own text.
        typed(&mut state, "Q#Z%J7");

        let buffer = render(&state, 80, 24);
        let screen = text(&buffer);

        for secret in ['Q', '#', 'Z', '%', 'J', '7'] {
            assert!(!screen.contains(secret), "{secret:?} was drawn:\n{screen}");
        }
        assert_eq!(
            screen.matches('\u{2022}').count(),
            6,
            "one dot per character"
        );
    }

    #[test]
    fn quando_senha_e_longa_deve_nao_passar_da_largura_da_caixa() {
        let (mut state, _) = asking(false);
        typed(&mut state, &"x".repeat(500));
        let screen = text(&render(&state, 80, 24));
        assert!(screen.matches('\u{2022}').count() <= 58, "{screen}");
    }

    #[test]
    fn quando_backspace_deve_apagar_o_ultimo_caractere() {
        let (mut state, _) = asking(false);
        typed(&mut state, "abc");
        update(&mut state, press(KeyCode::Backspace));
        assert_eq!(password_modal(&state).input.len(), 2);
    }

    #[test]
    fn quando_enter_deve_emitir_load_with_password_e_abrir_novo_job() {
        let (mut state, old) = asking(true);
        typed(&mut state, "changeit");

        let commands = update(&mut state, press(KeyCode::Enter));

        assert!(state.modal.is_none());
        let inspect = state.inspect.as_ref().unwrap();
        assert_ne!(inspect.job, old, "a new job");
        assert_eq!(inspect.phase, Phase::Loading);
        assert_eq!(
            commands,
            vec![Command::InspectWithPassword {
                id: inspect.job,
                target: Target::File("store.p12".into()),
                password: password_of("changeit"),
            }]
        );
    }

    #[test]
    fn quando_esc_no_modal_de_senha_deve_fechar_sem_comandos() {
        let (mut state, _) = asking(false);
        typed(&mut state, "abc");

        let commands = update(&mut state, press(KeyCode::Esc));

        assert!(state.modal.is_none());
        assert_eq!(commands, Vec::new());
        assert!(matches!(
            state.inspect.as_ref().map(|i| &i.phase),
            Some(Phase::Failed(_))
        ));
    }

    #[test]
    fn quando_modal_de_senha_e_y_e_q_e_e_deve_nao_copiar_nem_sair_nem_exportar() {
        let (mut state, _) = asking(false);

        for c in ['y', 'Y', 'q', 'e', 'j', 'J', 'p', '?', 'x'] {
            let commands = update(&mut state, press(KeyCode::Char(c)));
            assert_eq!(commands, Vec::new(), "{c}");
        }

        assert!(!state.should_quit);
        assert!(state.toast.is_none(), "no copy toast");
        assert_eq!(password_modal(&state).input.len(), 9, "they were typed");
    }

    #[test]
    fn quando_ctrl_c_no_modal_de_senha_deve_sair() {
        let (mut state, _) = asking(false);
        update(
            &mut state,
            Msg::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        );
        assert!(state.should_quit);
    }

    #[test]
    fn quando_debug_do_state_deve_nao_conter_a_senha() {
        let (mut state, _) = asking(false);
        typed(&mut state, "hunter2-secret");

        let debug = format!("{state:?}");

        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("Masked(14 chars)"), "{debug}");
        let command = Command::InspectWithPassword {
            id: JobId(1),
            target: Target::Stdin,
            password: password_of("hunter2-secret"),
        };
        assert!(!format!("{command:?}").contains("hunter2"));
    }

    #[test]
    fn quando_cola_no_modal_de_senha_deve_entrar_na_senha_sem_controles() {
        let (mut state, _) = asking(false);
        update(&mut state, Msg::Paste("pa\nss\u{1b}word".to_owned()));
        assert_eq!(password_modal(&state).input.len(), 8);
    }

    // --- export -------------------------------------------------------------

    fn ready() -> AppState {
        inspect_state(sample_report())
    }

    #[test]
    fn quando_e_deve_abrir_export_com_formato_pem_e_cert_selecionado() {
        let mut state = ready();
        state.inspect.as_mut().unwrap().selected_cert = 1;

        update(&mut state, press(KeyCode::Char('e')));

        let dialog = export_modal(&state);
        assert_eq!(dialog.format, ExportFormat::Pem);
        assert_eq!(dialog.selection, ExportSelection::Index(1));
        assert_eq!(dialog.path, "certificate.pem");
    }

    #[test]
    fn quando_e_com_job_carregando_deve_nao_abrir_export() {
        let mut state = AppState::new(Instant::now());
        let id = state.jobs.start();
        state.screen = crate::app_state::Screen::Inspect;
        state.inspect = Some(InspectState::loading(id, Target::Stdin));
        update(&mut state, press(KeyCode::Char('e')));
        assert!(state.modal.is_none());
    }

    #[test]
    fn quando_tab_deve_girar_o_formato_e_trocar_a_extensao() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));

        update(&mut state, press(KeyCode::Tab));
        assert_eq!(export_modal(&state).format, ExportFormat::Der);
        assert_eq!(export_modal(&state).path, "certificate.der");
        update(&mut state, press(KeyCode::Tab));
        assert_eq!(export_modal(&state).path, "certificate.json");
        update(&mut state, press(KeyCode::Tab));
        assert_eq!(export_modal(&state).path, "certificate.pem");
    }

    #[test]
    fn quando_nome_tem_outra_extensao_deve_deixar_como_esta_ao_trocar_formato() {
        assert_eq!(with_extension("chain.crt", ExportFormat::Der), "chain.crt");
        assert_eq!(with_extension("out.pem", ExportFormat::Json), "out.json");
        assert_eq!(with_extension("noext", ExportFormat::Der), "noext");
    }

    #[test]
    fn quando_enter_deve_emitir_export_sem_sobrescrever() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));

        let commands = update(&mut state, press(KeyCode::Enter));

        assert!(state.modal.is_none());
        let [Command::Export(request)] = commands.as_slice() else {
            panic!("expected one export, got {commands:?}");
        };
        assert_eq!(request.path, PathBuf::from("certificate.pem"));
        assert_eq!(request.format, ExportFormat::Pem);
        assert_eq!(request.selection, ExportSelection::Index(0));
        assert_eq!(request.overwrite, Overwrite::Refuse);
        assert_eq!(state.pending_export.as_ref(), Some(request));
    }

    #[test]
    fn quando_export_retorna_already_exists_deve_abrir_confirmacao_e_reenviar_com_allow_ao_confirmar()
     {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        update(&mut state, press(KeyCode::Enter));

        update(&mut state, Msg::ExportFailed(ExportFailure::AlreadyExists));

        let Some(Modal::ConfirmOverwrite(request)) = &state.modal else {
            panic!("expected the confirmation, got {:?}", state.modal);
        };
        assert_eq!(request.overwrite, Overwrite::Refuse);
        let commands = update(&mut state, press(KeyCode::Char('y')));
        assert!(state.modal.is_none());
        let [Command::Export(sent)] = commands.as_slice() else {
            panic!("expected one export, got {commands:?}");
        };
        assert_eq!(sent.overwrite, Overwrite::Allow);
        assert_eq!(sent.path, PathBuf::from("certificate.pem"));
    }

    #[test]
    fn quando_confirmacao_recebe_outra_tecla_deve_manter_o_arquivo() {
        for code in [KeyCode::Esc, KeyCode::Char('n'), KeyCode::Char('x')] {
            let mut state = ready();
            update(&mut state, press(KeyCode::Char('e')));
            update(&mut state, press(KeyCode::Enter));
            update(&mut state, Msg::ExportFailed(ExportFailure::AlreadyExists));

            let commands = update(&mut state, press(code));

            assert_eq!(commands, Vec::new(), "{code:?}");
            assert!(state.modal.is_none());
            assert!(state.pending_export.is_none());
        }
    }

    #[test]
    fn quando_enter_com_enter_na_confirmacao_deve_substituir() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        update(&mut state, press(KeyCode::Enter));
        update(&mut state, Msg::ExportFailed(ExportFailure::AlreadyExists));
        let commands = update(&mut state, press(KeyCode::Enter));
        assert!(
            matches!(commands.as_slice(), [Command::Export(r)] if r.overwrite == Overwrite::Allow)
        );
    }

    #[test]
    fn quando_der_com_cadeia_deve_mostrar_erro_sem_comando() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        update(&mut state, press(KeyCode::Tab)); // DER
        update(&mut state, press(KeyCode::Down)); // whole chain

        let commands = update(&mut state, press(KeyCode::Enter));

        assert_eq!(commands, Vec::new());
        assert!(
            export_modal(&state)
                .error
                .as_deref()
                .is_some_and(|e| e.contains("DER holds one"))
        );
        assert!(state.pending_export.is_none());
    }

    #[test]
    fn quando_nome_vazio_deve_mostrar_erro_sem_comando() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        for _ in 0..40 {
            update(&mut state, press(KeyCode::Backspace));
        }
        let commands = update(&mut state, press(KeyCode::Enter));
        assert_eq!(commands, Vec::new());
        assert_eq!(
            export_modal(&state).error.as_deref(),
            Some("enter a file name")
        );
    }

    #[test]
    fn quando_export_falha_com_mensagem_deve_reabrir_o_dialogo_com_o_erro() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        update(&mut state, press(KeyCode::Enter));

        update(
            &mut state,
            Msg::ExportFailed(ExportFailure::Message(
                "the destination directory does not exist".to_owned(),
            )),
        );

        let dialog = export_modal(&state);
        assert_eq!(dialog.path, "certificate.pem");
        assert_eq!(
            dialog.error.as_deref(),
            Some("the destination directory does not exist")
        );
    }

    #[test]
    fn quando_export_conclui_deve_mostrar_toast_com_o_caminho() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        update(&mut state, press(KeyCode::Enter));
        update(
            &mut state,
            Msg::ExportDone {
                path: "certificate.pem".to_owned(),
            },
        );
        assert_eq!(
            state.toast.as_ref().map(|t| t.text.as_str()),
            Some("Exported to certificate.pem")
        );
        assert!(state.pending_export.is_none());
    }

    #[test]
    fn quando_esc_no_export_deve_fechar_sem_comandos() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        let commands = update(&mut state, press(KeyCode::Esc));
        assert!(state.modal.is_none());
        assert_eq!(commands, Vec::new());
    }

    #[test]
    fn quando_digita_no_export_deve_editar_o_nome() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        for _ in 0..40 {
            update(&mut state, press(KeyCode::Backspace));
        }
        typed(&mut state, "my.pem");
        assert_eq!(export_modal(&state).path, "my.pem");
        update(&mut state, Msg::Paste("-copy".to_owned()));
        assert_eq!(export_modal(&state).path, "my.pem-copy");
    }

    // --- views --------------------------------------------------------------

    #[test]
    fn quando_modal_de_senha_deve_bater_com_snapshot() {
        let (state, _) = asking(true);
        insta::assert_snapshot!(text(&render(&state, 80, 24)));
    }

    #[test]
    fn quando_modal_de_senha_tem_texto_digitado_deve_bater_com_snapshot() {
        let (mut state, _) = asking(false);
        typed(&mut state, "abc");
        insta::assert_snapshot!(text(&render(&state, 80, 24)));
    }

    #[test]
    fn quando_digita_depois_do_erro_deve_limpar_o_erro() {
        let (mut state, _) = asking(true);
        assert!(password_modal(&state).error.is_some());
        typed(&mut state, "a");
        assert_eq!(password_modal(&state).error, None);
    }

    #[test]
    fn quando_modal_de_export_deve_bater_com_snapshot() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        insta::assert_snapshot!(text(&render(&state, 80, 24)));
    }

    #[test]
    fn quando_modal_de_confirmacao_deve_bater_com_snapshot() {
        let mut state = ready();
        update(&mut state, press(KeyCode::Char('e')));
        update(&mut state, press(KeyCode::Enter));
        update(&mut state, Msg::ExportFailed(ExportFailure::AlreadyExists));
        insta::assert_snapshot!(text(&render(&state, 80, 24)));
    }

    #[test]
    fn quando_modais_em_terminal_pequeno_deve_nao_dar_panic() {
        let (mut state, _) = asking(false);
        for (w, h) in [(80, 24), (100, 10), (80, 8)] {
            let _ = render(&state, w, h);
        }
        state.modal = None;
        let mut ready_state = ready();
        update(&mut ready_state, press(KeyCode::Char('e')));
        for (w, h) in [(80, 24), (100, 10), (80, 8)] {
            let _ = render(&ready_state, w, h);
        }
    }
}
