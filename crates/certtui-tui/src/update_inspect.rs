//! Keys and job results on the Inspect screen.

use std::sync::Arc;

use certtui_app::present::labels;
use certtui_domain::model::InspectionReport;

use crate::app_state::{AppState, InspectState, Pane, Phase, Screen};
use crate::copy::{Copyable as _, InspectCopy};
use crate::detail_rows::{DetailRow, rows_for_tab};
use crate::keymap::Action;
use crate::msg::Command;
use crate::toast::{Toast, ToastKind};
use crate::update::on_global_action;
use crate::view::details_viewport_rows;

/// Applies the result of an inspect job.
///
/// A result whose `id` is not the job the screen waits for (cancelled or
/// superseded) is dropped, so it can never appear after the user left.
pub fn on_inspect_done(
    state: &mut AppState,
    id: crate::app_state::JobId,
    result: Result<Arc<InspectionReport>, String>,
) {
    state.jobs.finish(id);
    let Some(inspect) = state.inspect.as_mut() else {
        return;
    };
    if inspect.job != id || state.screen != Screen::Inspect {
        return;
    }
    inspect.phase = match result {
        Ok(report) => Phase::Ready(report),
        Err(message) => Phase::Failed(labels::single_line(&message)),
    };
    inspect.selected_cert = 0;
    inspect.row_cursor = 0;
    inspect.scroll = 0;
}

/// Handles an action on the Inspect screen.
pub fn on_action(state: &mut AppState, action: Action) -> Vec<Command> {
    match action {
        Action::Back => return leave(state),
        Action::Quit => {
            if is_loading(state) {
                return leave(state);
            }
            state.should_quit = true;
        }
        Action::NewTarget => {
            let commands = leave(state);
            state.home.editing = true;
            state.home.cursor = state.home.input.chars().count();
            return commands;
        }
        Action::NextPane | Action::PrevPane => toggle_pane(state),
        Action::Enter => focus_details(state),
        Action::Export => crate::update_modal::open_export(state),
        Action::NextTab => change_tab(state, true),
        Action::PrevTab => change_tab(state, false),
        Action::Down => move_cursor(state, true),
        Action::Up => move_cursor(state, false),
        Action::CopyFocused
        | Action::CopyView
        | Action::CopyPem
        | Action::CopyChainPem
        | Action::CopyJson => return copy(state, action),
        _ => return on_global_action(state, action),
    }
    Vec::new()
}

fn is_loading(state: &AppState) -> bool {
    state
        .inspect
        .as_ref()
        .is_some_and(|inspect| inspect.phase == Phase::Loading)
}

/// Goes back to Home, cancelling the job still in flight.
fn leave(state: &mut AppState) -> Vec<Command> {
    let mut commands = Vec::new();
    if let Some(inspect) = state.inspect.take()
        && state.jobs.finish(inspect.job)
    {
        commands.push(Command::CancelJob(inspect.job));
    }
    state.screen = Screen::Home;
    commands
}

fn toggle_pane(state: &mut AppState) {
    if let Some(inspect) = state.inspect.as_mut() {
        inspect.pane = match inspect.pane {
            Pane::Chain => Pane::Details,
            Pane::Details => Pane::Chain,
        };
    }
}

fn focus_details(state: &mut AppState) {
    if let Some(inspect) = state.inspect.as_mut()
        && inspect.report().is_some()
    {
        inspect.pane = Pane::Details;
    }
}

fn change_tab(state: &mut AppState, forward: bool) {
    if let Some(inspect) = state.inspect.as_mut() {
        inspect.tab = if forward {
            inspect.tab.next()
        } else {
            inspect.tab.prev()
        };
        inspect.row_cursor = 0;
        inspect.scroll = 0;
    }
}

/// Builds the copy for `action` and asks for it, or explains why not.
fn copy(state: &mut AppState, action: Action) -> Vec<Command> {
    let payload = {
        let Some(inspect) = state.inspect.as_ref() else {
            return Vec::new();
        };
        let view = InspectCopy {
            inspect,
            format: state.fingerprint_format,
        };
        match action {
            Action::CopyFocused => view.copy_focused(),
            Action::CopyView => view.copy_view(),
            Action::CopyPem => view.copy_pem(),
            Action::CopyChainPem => view.copy_chain_pem(),
            Action::CopyJson => view.copy_json(),
            _ => None,
        }
    };
    let Some(payload) = payload else {
        return Vec::new();
    };
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

/// The rows of the visible tab; empty until the report is ready.
#[must_use]
pub fn current_rows(state: &AppState) -> Vec<DetailRow> {
    let Some(inspect) = state.inspect.as_ref() else {
        return Vec::new();
    };
    inspect.report().map_or_else(Vec::new, |report| {
        rows_for_tab(
            report,
            inspect.selected_cert,
            inspect.tab,
            state.fingerprint_format,
        )
    })
}

fn move_cursor(state: &mut AppState, down: bool) {
    let rows = current_rows(state).len();
    let viewport = details_viewport_rows(state.size);
    let Some(inspect) = state.inspect.as_mut() else {
        return;
    };
    let Some(report) = inspect.report().cloned() else {
        return;
    };
    match inspect.pane {
        Pane::Chain => {
            let last = report.chain.len().saturating_sub(1);
            let next = step(inspect.selected_cert, last, down);
            if next != inspect.selected_cert {
                inspect.selected_cert = next;
                inspect.row_cursor = 0;
                inspect.scroll = 0;
            }
        }
        Pane::Details => {
            inspect.row_cursor = step(inspect.row_cursor, rows.saturating_sub(1), down);
            follow_cursor(inspect, viewport);
        }
    }
}

/// One step up or down inside `0..=last`.
fn step(current: usize, last: usize, down: bool) -> usize {
    if down {
        current.saturating_add(1).min(last)
    } else {
        current.saturating_sub(1)
    }
}

/// Scrolls just enough to keep the cursor row on screen.
fn follow_cursor(inspect: &mut InspectState, viewport: usize) {
    let cursor = inspect.row_cursor;
    let first = usize::from(inspect.scroll);
    let viewport = viewport.max(1);
    let first = if cursor < first {
        cursor
    } else if cursor >= first + viewport {
        cursor + 1 - viewport
    } else {
        first
    };
    inspect.scroll = u16::try_from(first).unwrap_or(u16::MAX);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;
    use crate::app_state::{JobId, Tab};
    use crate::msg::Msg;
    use crate::test_fixtures::{inspect_state, report_of, sample_report};
    use crate::update::update;

    fn key(c: char) -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    fn esc() -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE))
    }

    fn inspect(state: &AppState) -> &InspectState {
        state.inspect.as_ref().unwrap()
    }

    /// A state whose single job is still running.
    fn loading_state() -> (AppState, JobId) {
        let mut state = AppState::new(std::time::Instant::now());
        let id = state.jobs.start();
        state.screen = Screen::Inspect;
        state.inspect = Some(InspectState::loading(
            id,
            certtui_domain::target::Target::Stdin,
        ));
        (state, id)
    }

    #[test]
    fn quando_inspect_done_deve_passar_para_ready_e_selecionar_leaf() {
        let (mut state, id) = loading_state();
        let report = Arc::new(sample_report());
        update(
            &mut state,
            Msg::InspectDone {
                id,
                result: Ok(report.clone()),
            },
        );
        assert_eq!(inspect(&state).phase, Phase::Ready(report));
        assert_eq!(inspect(&state).selected_cert, 0);
        assert!(!state.jobs.any_active());
    }

    #[test]
    fn quando_inspect_done_com_erro_deve_mostrar_failed_com_mensagem() {
        let (mut state, id) = loading_state();
        update(
            &mut state,
            Msg::InspectDone {
                id,
                result: Err("connection refused\u{1b}[31m".to_owned()),
            },
        );
        assert_eq!(
            inspect(&state).phase,
            Phase::Failed("connection refused[31m".to_owned())
        );
    }

    #[test]
    fn quando_inspect_done_de_job_cancelado_ou_antigo_deve_ser_ignorado() {
        let (mut state, id) = loading_state();
        // The user leaves: the job is cancelled and Home is back.
        let commands = update(&mut state, esc());
        assert_eq!(commands, vec![Command::CancelJob(id)]);
        assert_eq!(state.screen, Screen::Home);
        assert!(state.inspect.is_none());
        // The result of the cancelled job still arrives.
        update(
            &mut state,
            Msg::InspectDone {
                id,
                result: Ok(Arc::new(sample_report())),
            },
        );
        assert!(state.inspect.is_none());
        assert_eq!(state.screen, Screen::Home);
        // An older job must not overwrite the one now on screen.
        let (mut state, current) = loading_state();
        let old_job = JobId(current.0 + 99);
        update(
            &mut state,
            Msg::InspectDone {
                id: old_job,
                result: Ok(Arc::new(sample_report())),
            },
        );
        assert_eq!(inspect(&state).phase, Phase::Loading);
    }

    #[test]
    fn quando_q_durante_job_em_voo_deve_cancelar_e_voltar_para_home() {
        let (mut state, id) = loading_state();
        let commands = update(&mut state, key('q'));
        assert_eq!(commands, vec![Command::CancelJob(id)]);
        assert_eq!(state.screen, Screen::Home);
        assert!(!state.should_quit);
        assert!(!state.jobs.any_active());
    }

    #[test]
    fn quando_q_com_relatorio_pronto_deve_sair() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('q'));
        assert!(state.should_quit);
    }

    #[test]
    fn quando_esc_com_relatorio_pronto_deve_voltar_sem_cancelar_nada() {
        let mut state = inspect_state(report_of(vec![]));
        let id = inspect(&state).job;
        state.jobs.finish(id);
        let commands = update(&mut state, esc());
        assert_eq!(commands, Vec::new());
        assert_eq!(state.screen, Screen::Home);
    }

    #[test]
    fn quando_j_k_deve_mover_cursor_de_linha_nos_limites_sem_panic() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('l'));
        assert_eq!(inspect(&state).pane, Pane::Details);
        update(&mut state, key('k'));
        assert_eq!(inspect(&state).row_cursor, 0);
        let rows = current_rows(&state).len();
        assert!(rows > 3);
        for _ in 0..rows + 10 {
            update(&mut state, key('j'));
        }
        assert_eq!(inspect(&state).row_cursor, rows - 1);
        for _ in 0..rows + 10 {
            update(&mut state, key('k'));
        }
        assert_eq!(inspect(&state).row_cursor, 0);
    }

    #[test]
    fn quando_j_k_na_arvore_deve_trocar_de_certificado_nos_limites() {
        let mut state = inspect_state(sample_report());
        for _ in 0..10 {
            update(&mut state, key('j'));
        }
        assert_eq!(inspect(&state).selected_cert, 2);
        for _ in 0..10 {
            update(&mut state, key('k'));
        }
        assert_eq!(inspect(&state).selected_cert, 0);
    }

    #[test]
    fn quando_cursor_passa_da_janela_deve_rolar_para_manter_a_linha_visivel() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('l'));
        update(&mut state, key(']'));
        update(&mut state, key(']'));
        update(&mut state, key(']'));
        // Extensions rows, then walk past the viewport (20 rows at 80x24).
        state.size = (80, 8);
        for _ in 0..6 {
            update(&mut state, key('j'));
        }
        let inspect = inspect(&state);
        let viewport = details_viewport_rows(state.size);
        assert!(usize::from(inspect.scroll) <= inspect.row_cursor);
        assert!(inspect.row_cursor < usize::from(inspect.scroll) + viewport);
    }

    #[test]
    fn quando_h_l_ou_tab_deve_alternar_painel() {
        let mut state = inspect_state(sample_report());
        assert_eq!(inspect(&state).pane, Pane::Chain);
        update(&mut state, key('l'));
        assert_eq!(inspect(&state).pane, Pane::Details);
        update(&mut state, key('h'));
        assert_eq!(inspect(&state).pane, Pane::Chain);
        update(
            &mut state,
            Msg::Key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)),
        );
        assert_eq!(inspect(&state).pane, Pane::Details);
    }

    #[test]
    fn quando_colchetes_deve_trocar_de_aba_circularmente() {
        let mut state = inspect_state(sample_report());
        assert_eq!(inspect(&state).tab, Tab::Overview);
        update(&mut state, key('['));
        assert_eq!(inspect(&state).tab, Tab::Raw);
        update(&mut state, key(']'));
        assert_eq!(inspect(&state).tab, Tab::Overview);
        for _ in 0..8 {
            update(&mut state, key(']'));
        }
        assert_eq!(inspect(&state).tab, Tab::Overview);
    }

    #[test]
    fn quando_troca_de_aba_deve_zerar_cursor_e_rolagem() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('l'));
        update(&mut state, key('j'));
        update(&mut state, key(']'));
        assert_eq!(inspect(&state).row_cursor, 0);
        assert_eq!(inspect(&state).scroll, 0);
    }

    #[test]
    fn quando_o_na_inspect_deve_voltar_para_home_em_edicao() {
        let mut state = inspect_state(sample_report());
        update(&mut state, key('o'));
        assert_eq!(state.screen, Screen::Home);
        assert!(state.home.editing);
    }

    #[test]
    fn quando_j_antes_do_relatorio_estar_pronto_deve_nao_fazer_nada() {
        let (mut state, _) = loading_state();
        update(&mut state, key('j'));
        assert_eq!(inspect(&state).phase, Phase::Loading);
    }

    #[test]
    fn quando_resize_durante_job_em_voo_deve_manter_o_job_e_a_tela() {
        let (mut state, id) = loading_state();
        for (columns, rows) in [(79, 24), (200, 60), (80, 24)] {
            assert_eq!(update(&mut state, Msg::Resize(columns, rows)), Vec::new());
            assert_eq!(state.size, (columns, rows));
        }
        assert_eq!(state.screen, Screen::Inspect);
        assert_eq!(inspect(&state).job, id);
        assert!(state.jobs.is_active(id));
        // The result still lands after the resizes.
        update(
            &mut state,
            Msg::InspectDone {
                id,
                result: Ok(Arc::new(sample_report())),
            },
        );
        assert!(inspect(&state).report().is_some());
    }
}
