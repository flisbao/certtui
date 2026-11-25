//! Keys and job events on the Batch screen.

use std::cmp::Ordering;

use certtui_app::batch::BatchEvent;
use certtui_domain::batch_row::BatchRow;
use certtui_domain::target::{NetworkTarget, Target};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app_state::{AppState, BatchPhase, BatchState, InspectState, JobId, Screen, SortKey};
use crate::copy::CopyPayload;
use crate::copy::batch::{row_as_tsv, rows_as_csv};
use crate::keymap::Action;
use crate::msg::Command;
use crate::update::{on_global_action, request_copy};
use crate::view::batch_viewport_rows;

/// Opens the Batch screen on `targets` and asks for the job that fills it.
pub fn start_batch(state: &mut AppState, targets: Vec<NetworkTarget>) -> Vec<Command> {
    let id = state.jobs.start();
    state.batch = Some(BatchState::new(id, targets.clone()));
    state.screen = Screen::Batch;
    vec![Command::RunBatch { id, targets }]
}

/// Applies the events of job `id`; events of any other job are dropped.
pub fn on_events(state: &mut AppState, id: JobId, events: Vec<BatchEvent>) {
    let viewport = batch_viewport_rows(state.size);
    let mut finished = false;
    {
        let Some(batch) = state.batch.as_mut().filter(|batch| batch.job == id) else {
            return;
        };
        for event in events {
            match event {
                BatchEvent::Row { index, row } => {
                    if let Some(slot) = batch.rows.get_mut(index) {
                        *slot = Some(row);
                    }
                }
                BatchEvent::Progress { done, .. } => batch.done = batch.done.max(done),
                BatchEvent::Finished { cancelled } => {
                    if cancelled {
                        batch.phase = BatchPhase::Cancelled;
                    } else if batch.is_running() {
                        batch.phase = BatchPhase::Done;
                    }
                    finished = true;
                }
            }
        }
        rebuild_view(batch, viewport);
    }
    if finished {
        state.jobs.finish(id);
    }
}

/// Handles an action on the Batch screen.
pub fn on_action(state: &mut AppState, action: Action) -> Vec<Command> {
    let viewport = batch_viewport_rows(state.size);
    match action {
        Action::Down | Action::Up => {
            if let Some(batch) = state.batch.as_mut() {
                move_selection(batch, action == Action::Down, viewport);
            }
        }
        Action::Sort => {
            if let Some(batch) = state.batch.as_mut() {
                batch.sort = batch.sort.next();
                batch.descending = false;
                rebuild_view(batch, viewport);
            }
        }
        Action::ReverseSort => {
            if let Some(batch) = state.batch.as_mut() {
                batch.descending = !batch.descending;
                rebuild_view(batch, viewport);
            }
        }
        Action::Filter => {
            if let Some(batch) = state.batch.as_mut() {
                batch.filter_editing = true;
            }
        }
        Action::Enter => return open_selected(state),
        Action::Back => return back(state, viewport),
        Action::Quit => {
            if is_running(state) {
                return cancel(state);
            }
            state.should_quit = true;
        }
        Action::NewTarget => {
            let commands = leave(state);
            state.home.editing = true;
            state.home.cursor = state.home.input.chars().count();
            return commands;
        }
        Action::CopyFocused => return copy_row(state),
        Action::CopyView => return copy_table(state),
        _ => return on_global_action(state, action),
    }
    Vec::new()
}

/// Handles a key while the filter is being typed: text goes into the filter,
/// `Enter` keeps it and `Esc` throws it away.
pub fn on_filter_key(state: &mut AppState, key: KeyEvent) -> Vec<Command> {
    if key.kind == KeyEventKind::Release {
        return Vec::new();
    }
    let viewport = batch_viewport_rows(state.size);
    let Some(batch) = state.batch.as_mut() else {
        return Vec::new();
    };
    match key.code {
        KeyCode::Enter => batch.filter_editing = false,
        KeyCode::Esc => {
            batch.filter_editing = false;
            batch.filter.clear();
            rebuild_view(batch, viewport);
        }
        KeyCode::Backspace => {
            batch.filter.pop();
            rebuild_view(batch, viewport);
        }
        KeyCode::Char(c)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            batch.filter.push(c);
            rebuild_view(batch, viewport);
        }
        _ => {}
    }
    Vec::new()
}

fn is_running(state: &AppState) -> bool {
    state.batch.as_ref().is_some_and(BatchState::is_running)
}

/// Stops the job and keeps the rows collected so far.
fn cancel(state: &mut AppState) -> Vec<Command> {
    let Some(batch) = state.batch.as_mut().filter(|batch| batch.is_running()) else {
        return Vec::new();
    };
    batch.phase = BatchPhase::Cancelled;
    let id = batch.job;
    state.jobs.finish(id);
    vec![Command::CancelJob(id)]
}

/// `Esc`: cancel a running batch, else drop the filter, else go Home.
fn back(state: &mut AppState, viewport: usize) -> Vec<Command> {
    if is_running(state) {
        return cancel(state);
    }
    if let Some(batch) = state.batch.as_mut()
        && !batch.filter.is_empty()
    {
        batch.filter.clear();
        rebuild_view(batch, viewport);
        return Vec::new();
    }
    leave(state)
}

/// Goes Home, cancelling a running batch and dropping its rows.
fn leave(state: &mut AppState) -> Vec<Command> {
    let commands = cancel(state);
    state.batch = None;
    state.screen = Screen::Home;
    commands
}

/// `Enter`: a fresh inspect of the target of the selected row.
fn open_selected(state: &mut AppState) -> Vec<Command> {
    let Some(target) = state.batch.as_ref().and_then(|batch| {
        let (index, _) = batch.row_at(batch.selected)?;
        batch.targets.get(index).cloned()
    }) else {
        return Vec::new();
    };
    let id = state.jobs.start();
    let target = Target::Network(target);
    let mut inspect = InspectState::loading(id, target.clone());
    inspect.from_batch = true;
    state.inspect = Some(inspect);
    state.screen = Screen::Inspect;
    vec![Command::Inspect { id, target }]
}

fn copy_row(state: &mut AppState) -> Vec<Command> {
    let text = state
        .batch
        .as_ref()
        .and_then(|batch| batch.row_at(batch.selected))
        .map(|(_, row)| row_as_tsv(row));
    text.map_or_else(Vec::new, |text| {
        request_copy(
            state,
            CopyPayload {
                label: "row".to_owned(),
                text,
            },
        )
    })
}

fn copy_table(state: &mut AppState) -> Vec<Command> {
    let text = state.batch.as_ref().and_then(|batch| {
        let rows: Vec<&BatchRow> = batch.visible_rows().collect();
        (!rows.is_empty()).then(|| rows_as_csv(&rows))
    });
    text.map_or_else(Vec::new, |text| {
        request_copy(
            state,
            CopyPayload {
                label: "table".to_owned(),
                text,
            },
        )
    })
}

fn move_selection(batch: &mut BatchState, down: bool, viewport: usize) {
    let last = batch.view.len().saturating_sub(1);
    batch.selected = if down {
        batch.selected.saturating_add(1).min(last)
    } else {
        batch.selected.saturating_sub(1)
    };
    follow_cursor(batch, viewport);
}

/// Scrolls just enough to keep the selected row on screen.
fn follow_cursor(batch: &mut BatchState, viewport: usize) {
    let viewport = viewport.max(1);
    if batch.selected < batch.scroll {
        batch.scroll = batch.selected;
    } else if batch.selected >= batch.scroll.saturating_add(viewport) {
        batch.scroll = batch.selected.saturating_add(1).saturating_sub(viewport);
    }
}

/// Recomputes which rows are shown and in what order, keeping the selection
/// on the same target when it is still shown.
fn rebuild_view(batch: &mut BatchState, viewport: usize) {
    let anchor = batch.row_at(batch.selected).map(|(index, _)| index);
    let needle = batch.filter.to_lowercase();
    let mut view: Vec<usize> = batch
        .rows
        .iter()
        .enumerate()
        .filter_map(|(index, row)| {
            let row = row.as_ref()?;
            matches_filter(row, &needle).then_some(index)
        })
        .collect();
    let (sort, descending) = (batch.sort, batch.descending);
    match sort {
        SortKey::Input => {
            if descending {
                view.reverse();
            }
        }
        SortKey::Target | SortKey::Cn | SortKey::Issuer => {
            sort_by_text(&mut view, &batch.rows, sort, descending);
        }
        SortKey::Days | SortKey::Status | SortKey::Errors => {
            let rows = &batch.rows;
            view.sort_by(|a, b| {
                let a = rows.get(*a).and_then(Option::as_ref);
                let b = rows.get(*b).and_then(Option::as_ref);
                match (a, b) {
                    (Some(a), Some(b)) => compare(sort, a, b, descending),
                    _ => Ordering::Equal,
                }
            });
        }
    }
    batch.view = view;
    batch.selected = anchor
        .and_then(|index| batch.view.iter().position(|shown| *shown == index))
        .unwrap_or_else(|| batch.selected.min(batch.view.len().saturating_sub(1)));
    follow_cursor(batch, viewport);
    let last_first = batch.view.len().saturating_sub(viewport.max(1));
    batch.scroll = batch.scroll.min(last_first);
    follow_cursor(batch, viewport);
}

/// Whether the target, subject CN or issuer CN contains `needle` (already
/// lowercase); an empty needle matches everything.
fn matches_filter(row: &BatchRow, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    let contains = |text: &str| text.to_lowercase().contains(needle);
    contains(&row.target)
        || row.subject_cn.as_deref().is_some_and(contains)
        || row.issuer_cn.as_deref().is_some_and(contains)
}

/// Orders two rows by a numeric column. A row without a value goes last in
/// either direction.
fn compare(sort: SortKey, a: &BatchRow, b: &BatchRow, descending: bool) -> Ordering {
    let directed = |ordering: Ordering| {
        if descending {
            ordering.reverse()
        } else {
            ordering
        }
    };
    match sort {
        SortKey::Days => match (a.days_to_expiry, b.days_to_expiry) {
            (Some(x), Some(y)) => directed(x.cmp(&y)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
        SortKey::Status => directed(a.status.cmp(&b.status)),
        SortKey::Errors => directed((a.errors, a.warnings).cmp(&(b.errors, b.warnings))),
        SortKey::Input | SortKey::Target | SortKey::Cn | SortKey::Issuer => Ordering::Equal,
    }
}

/// Orders `view` by a text column, ignoring case. The lowercase keys are
/// built once, so the sort itself only compares bytes. A row without a value
/// goes last in either direction.
fn sort_by_text(view: &mut Vec<usize>, rows: &[Option<BatchRow>], sort: SortKey, descending: bool) {
    let mut keyed: Vec<(usize, Option<String>)> = view
        .iter()
        .map(|index| {
            let key = rows
                .get(*index)
                .and_then(Option::as_ref)
                .and_then(|row| match sort {
                    SortKey::Target => Some(row.target.to_lowercase()),
                    SortKey::Cn => row.subject_cn.as_deref().map(str::to_lowercase),
                    SortKey::Issuer => row.issuer_cn.as_deref().map(str::to_lowercase),
                    _ => None,
                });
            (*index, key)
        })
        .collect();
    keyed.sort_by(|(_, a), (_, b)| match (a, b) {
        (Some(a), Some(b)) => {
            if descending {
                b.cmp(a)
            } else {
                a.cmp(b)
            }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    });
    *view = keyed.into_iter().map(|(index, _)| index).collect();
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use certtui_domain::batch_row::{BatchRow, RowStatus};
    use certtui_domain::target::Target;
    use crossterm::event::{KeyCode, KeyModifiers};

    use super::*;
    use crate::app_state::Screen;
    use crate::copy::CopyPayload;
    use crate::msg::Msg;
    use crate::toast::ToastKind;
    use crate::update::update;

    fn key(c: char) -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    fn special(code: KeyCode) -> Msg {
        Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn target(host: &str) -> NetworkTarget {
        NetworkTarget {
            host: host.to_owned(),
            port: 443,
            sni: None,
            connect_to: None,
        }
    }

    pub(crate) fn row(host: &str, days: Option<i64>, cn: Option<&str>) -> BatchRow {
        BatchRow {
            target: format!("{host}:443"),
            status: if days.is_some_and(|d| d < 0) {
                RowStatus::Error
            } else {
                RowStatus::Ok
            },
            days_to_expiry: days,
            subject_cn: cn.map(str::to_owned),
            issuer_cn: Some("Test CA".to_owned()),
            errors: u32::from(days.is_some_and(|d| d < 0)),
            warnings: 0,
            infos: 1,
            failure: None,
        }
    }

    fn row_event(index: usize, row: BatchRow) -> BatchEvent {
        BatchEvent::Row { index, row }
    }

    /// A batch of `hosts` whose rows all arrived: days are 10, 30, 20, ...
    fn loaded(hosts: &[(&str, Option<i64>, Option<&str>)]) -> (AppState, JobId) {
        let mut state = AppState::new(Instant::now());
        let targets: Vec<NetworkTarget> = hosts.iter().map(|(h, _, _)| target(h)).collect();
        let commands = start_batch(&mut state, targets);
        let Some(Command::RunBatch { id, .. }) = commands.into_iter().next() else {
            panic!("start_batch must ask for a job");
        };
        let events = hosts
            .iter()
            .enumerate()
            .map(|(i, (h, d, cn))| row_event(i, row(h, *d, *cn)))
            .collect();
        on_events(&mut state, id, events);
        (state, id)
    }

    fn three() -> (AppState, JobId) {
        loaded(&[
            ("a.test", Some(10), Some("alpha")),
            ("b.test", Some(-5), Some("Bravo")),
            ("c.test", None, None),
        ])
    }

    fn shown(state: &AppState) -> Vec<String> {
        state
            .batch
            .as_ref()
            .unwrap()
            .visible_rows()
            .map(|r| r.target.clone())
            .collect()
    }

    #[test]
    fn quando_start_deve_abrir_a_tela_e_pedir_o_job() {
        let mut state = AppState::new(Instant::now());
        let commands = start_batch(&mut state, vec![target("a.test"), target("b.test")]);
        assert_eq!(state.screen, Screen::Batch);
        let batch = state.batch.as_ref().unwrap();
        assert_eq!(
            (batch.total(), batch.done, batch.is_running()),
            (2, 0, true)
        );
        assert_eq!(
            commands,
            vec![Command::RunBatch {
                id: batch.job,
                targets: vec![target("a.test"), target("b.test")]
            }]
        );
        assert!(state.jobs.is_active(batch.job));
    }

    #[test]
    fn quando_batch_event_row_deve_inserir_na_posicao_e_atualizar_progresso() {
        let mut state = AppState::new(Instant::now());
        let commands = start_batch(&mut state, vec![target("a"), target("b"), target("c")]);
        let Some(Command::RunBatch { id, .. }) = commands.into_iter().next() else {
            panic!("no job");
        };
        on_events(
            &mut state,
            id,
            vec![
                row_event(2, row("c", Some(5), None)),
                BatchEvent::Progress { done: 1, total: 3 },
            ],
        );
        let batch = state.batch.as_ref().unwrap();
        assert!(batch.rows[0].is_none() && batch.rows[2].is_some());
        assert_eq!(batch.done, 1);
        assert_eq!(shown(&state), ["c:443"]);
        on_events(&mut state, id, vec![row_event(0, row("a", Some(1), None))]);
        assert_eq!(shown(&state), ["a:443", "c:443"]);
    }

    #[test]
    fn quando_evento_de_outro_job_deve_ser_ignorado() {
        let (mut state, id) = three();
        let other = JobId(id.0 + 100);
        on_events(
            &mut state,
            other,
            vec![BatchEvent::Finished { cancelled: true }],
        );
        assert!(state.batch.as_ref().unwrap().is_running());
    }

    #[test]
    fn quando_finished_deve_parar_de_rodar_e_liberar_o_job() {
        let (mut state, id) = three();
        on_events(
            &mut state,
            id,
            vec![BatchEvent::Finished { cancelled: false }],
        );
        let batch = state.batch.as_ref().unwrap();
        assert_eq!(batch.phase, BatchPhase::Done);
        assert!(!state.jobs.is_active(id));
    }

    #[test]
    fn quando_s_deve_ordenar_por_dias_crescente_e_depois_inverter() {
        let (mut state, _) = three();
        assert_eq!(shown(&state), ["a.test:443", "b.test:443", "c.test:443"]);
        update(&mut state, key('s'));
        assert_eq!(state.batch.as_ref().unwrap().sort, crate::SortKey::Days);
        // Without a certificate (no days) goes last.
        assert_eq!(shown(&state), ["b.test:443", "a.test:443", "c.test:443"]);
        update(&mut state, key('S'));
        assert!(state.batch.as_ref().unwrap().descending);
        assert_eq!(shown(&state), ["a.test:443", "b.test:443", "c.test:443"]);
    }

    #[test]
    fn quando_s_repetido_deve_percorrer_as_colunas_e_voltar_a_ordem_da_lista() {
        let (mut state, _) = three();
        let mut seen = Vec::new();
        for _ in 0..7 {
            update(&mut state, key('s'));
            seen.push(state.batch.as_ref().unwrap().sort);
        }
        assert_eq!(seen.last(), Some(&crate::SortKey::Input));
        assert_eq!(seen.len(), 7);
        let unique: std::collections::HashSet<String> =
            seen.iter().map(|k| format!("{k:?}")).collect();
        assert_eq!(unique.len(), 7);
    }

    #[test]
    fn quando_ordena_por_cn_deve_ignorar_caixa_e_deixar_sem_cn_por_ultimo() {
        let (mut state, _) = three();
        for _ in 0..4 {
            update(&mut state, key('s'));
        }
        assert_eq!(state.batch.as_ref().unwrap().sort, crate::SortKey::Cn);
        // alpha < Bravo, then the row without CN.
        assert_eq!(shown(&state), ["a.test:443", "b.test:443", "c.test:443"]);
    }

    #[test]
    fn quando_filtro_deve_mostrar_so_linhas_que_casam_e_manter_selecao_valida() {
        let (mut state, _) = three();
        update(&mut state, key('j'));
        update(&mut state, key('j'));
        assert_eq!(state.batch.as_ref().unwrap().selected, 2);
        update(&mut state, key('/'));
        assert!(state.batch.as_ref().unwrap().filter_editing);
        for c in "BRAVO".chars() {
            update(&mut state, key(c));
        }
        assert_eq!(shown(&state), ["b.test:443"]);
        let batch = state.batch.as_ref().unwrap();
        assert_eq!(batch.selected, 0, "the selection must stay inside the view");
        // Keys typed while editing never reach the keymap: `q` does not quit.
        update(&mut state, key('q'));
        assert!(!state.should_quit);
        update(&mut state, special(KeyCode::Enter));
        assert!(!state.batch.as_ref().unwrap().filter_editing);
        assert_eq!(state.batch.as_ref().unwrap().filter, "BRAVOq");
    }

    #[test]
    fn quando_filtro_casa_issuer_ou_alvo_deve_incluir() {
        let (mut state, _) = three();
        update(&mut state, key('/'));
        for c in "test ca".chars() {
            update(&mut state, key(c));
        }
        assert_eq!(shown(&state).len(), 3);
        for _ in 0..7 {
            update(&mut state, special(KeyCode::Backspace));
        }
        for c in "c.test".chars() {
            update(&mut state, key(c));
        }
        assert_eq!(shown(&state), ["c.test:443"]);
    }

    #[test]
    fn quando_esc_digitando_filtro_deve_limpar_e_parar_de_digitar() {
        let (mut state, _) = three();
        update(&mut state, key('/'));
        update(&mut state, key('z'));
        assert_eq!(shown(&state).len(), 0);
        update(&mut state, special(KeyCode::Esc));
        let batch = state.batch.as_ref().unwrap();
        assert!(!batch.filter_editing && batch.filter.is_empty());
        assert_eq!(shown(&state).len(), 3);
        assert_eq!(state.screen, Screen::Batch);
    }

    #[test]
    fn quando_enter_deve_emitir_inspect_do_alvo_da_linha_filtrada() {
        let (mut state, _) = three();
        update(&mut state, key('/'));
        for c in "b.test".chars() {
            update(&mut state, key(c));
        }
        update(&mut state, special(KeyCode::Enter));
        let commands = update(&mut state, special(KeyCode::Enter));
        let inspect = state.inspect.as_ref().unwrap();
        assert_eq!(state.screen, Screen::Inspect);
        assert!(inspect.from_batch);
        assert_eq!(
            commands,
            vec![Command::Inspect {
                id: inspect.job,
                target: Target::Network(target("b.test")),
            }]
        );
    }

    #[test]
    fn quando_esc_na_inspecao_aberta_do_batch_deve_voltar_ao_batch() {
        let (mut state, _) = three();
        update(&mut state, special(KeyCode::Enter));
        let job = state.inspect.as_ref().unwrap().job;
        let commands = update(&mut state, special(KeyCode::Esc));
        assert_eq!(state.screen, Screen::Batch);
        assert_eq!(commands, vec![Command::CancelJob(job)]);
        assert!(state.batch.is_some());
    }

    #[test]
    fn quando_esc_com_batch_rodando_deve_emitir_cancel_job() {
        let (mut state, id) = three();
        let commands = update(&mut state, special(KeyCode::Esc));
        assert_eq!(commands, vec![Command::CancelJob(id)]);
        let batch = state.batch.as_ref().unwrap();
        assert_eq!(batch.phase, BatchPhase::Cancelled);
        assert_eq!(state.screen, Screen::Batch);
        assert!(!state.jobs.is_active(id));
        // The rows already collected stay.
        assert_eq!(shown(&state).len(), 3);
    }

    #[test]
    fn quando_q_com_batch_rodando_deve_cancelar_sem_sair() {
        let (mut state, id) = three();
        let commands = update(&mut state, key('q'));
        assert_eq!(commands, vec![Command::CancelJob(id)]);
        assert!(!state.should_quit);
        update(&mut state, key('q'));
        assert!(state.should_quit);
    }

    #[test]
    fn quando_esc_com_batch_parado_deve_limpar_filtro_e_depois_voltar_a_home() {
        let (mut state, id) = three();
        on_events(
            &mut state,
            id,
            vec![BatchEvent::Finished { cancelled: false }],
        );
        update(&mut state, key('/'));
        update(&mut state, key('a'));
        update(&mut state, special(KeyCode::Enter));
        let commands = update(&mut state, special(KeyCode::Esc));
        assert_eq!(commands, Vec::new());
        assert_eq!(state.screen, Screen::Batch);
        assert_eq!(state.batch.as_ref().unwrap().filter, "");
        update(&mut state, special(KeyCode::Esc));
        assert_eq!(state.screen, Screen::Home);
    }

    #[test]
    fn quando_y_deve_copiar_tsv_da_linha() {
        let (mut state, _) = three();
        update(&mut state, key('j'));
        let commands = update(&mut state, key('y'));
        let [Command::CopyToClipboard(CopyPayload { label, text })] = commands.as_slice() else {
            panic!("{commands:?}");
        };
        assert_eq!(label, "row");
        assert_eq!(text, "b.test:443\terror\t-5\tBravo\tTest CA\t1\t0\t1\t");
    }

    #[test]
    #[allow(non_snake_case)] // Justificativa: o nome do teste cita a tecla `Y` do plano.
    fn quando_Y_deve_copiar_csv_so_das_linhas_filtradas() {
        let (mut state, _) = three();
        update(&mut state, key('/'));
        for c in "alpha".chars() {
            update(&mut state, key(c));
        }
        update(&mut state, special(KeyCode::Enter));
        let commands = update(&mut state, key('Y'));
        let [Command::CopyToClipboard(CopyPayload { label, text })] = commands.as_slice() else {
            panic!("{commands:?}");
        };
        assert_eq!(label, "table");
        assert_eq!(
            text,
            "target,status,days,cn,issuer,errors,warnings,infos,failure\n\
             a.test:443,ok,10,alpha,Test CA,0,0,1,\n"
        );
    }

    #[test]
    #[allow(non_snake_case)] // Justificativa: o nome do teste cita a tecla `Y` do plano.
    fn quando_Y_passa_do_limite_deve_dar_toast_e_nao_copiar() {
        let (mut state, _) = three();
        state.max_clipboard_bytes = 20;
        let commands = update(&mut state, key('Y'));
        assert_eq!(commands, Vec::new());
        let toast = state.toast.as_ref().unwrap();
        assert_eq!(toast.kind, ToastKind::Error);
        assert!(toast.text.contains("too large to copy"), "{}", toast.text);
    }

    #[test]
    fn quando_sem_linhas_y_nao_deve_copiar_nada() {
        let mut state = AppState::new(Instant::now());
        start_batch(&mut state, vec![target("a")]);
        assert_eq!(update(&mut state, key('y')), Vec::new());
        assert_eq!(update(&mut state, key('Y')), Vec::new());
    }

    #[test]
    fn quando_j_e_k_deve_mover_a_selecao_dentro_dos_limites() {
        let (mut state, _) = three();
        update(&mut state, key('k'));
        assert_eq!(state.batch.as_ref().unwrap().selected, 0);
        for _ in 0..9 {
            update(&mut state, key('j'));
        }
        assert_eq!(state.batch.as_ref().unwrap().selected, 2);
    }

    #[test]
    fn quando_chegam_rows_deve_manter_a_linha_selecionada_pelo_alvo() {
        let mut state = AppState::new(Instant::now());
        let commands = start_batch(&mut state, vec![target("a"), target("b"), target("c")]);
        let Some(Command::RunBatch { id, .. }) = commands.into_iter().next() else {
            panic!("no job");
        };
        on_events(&mut state, id, vec![row_event(2, row("c", Some(1), None))]);
        on_events(&mut state, id, vec![row_event(1, row("b", Some(2), None))]);
        // The selection stays on `c`, which moved from position 0 to 1.
        let batch = state.batch.as_ref().unwrap();
        assert_eq!(batch.row_at(batch.selected).unwrap().0, 2);
    }

    #[test]
    fn quando_10000_rows_deve_ordenar_em_menos_de_100ms() {
        let mut state = AppState::new(Instant::now());
        let targets: Vec<NetworkTarget> = (0..10_000).map(|i| target(&format!("h{i}"))).collect();
        let commands = start_batch(&mut state, targets);
        let Some(Command::RunBatch { id, .. }) = commands.into_iter().next() else {
            panic!("no job");
        };
        let events: Vec<BatchEvent> = (0..10_000_usize)
            .map(|i| {
                let cn = format!("\u{4e2d}\u{6587}-{}\u{1b}[31m", (i * 7919) % 10_000);
                row_event(
                    i,
                    row(
                        &format!("h{i}"),
                        Some(i64::try_from(i % 365).unwrap()),
                        Some(&cn),
                    ),
                )
            })
            .collect();
        on_events(&mut state, id, events);
        // Days, status, target, CN: the columns that compare strings are the slow ones.
        for _ in 0..4 {
            let started = Instant::now();
            update(&mut state, key('s'));
            let spent = started.elapsed();
            assert!(
                spent.as_millis() < 100,
                "{:?}: {spent:?}",
                state.batch.as_ref().unwrap().sort
            );
        }
        assert_eq!(state.batch.as_ref().unwrap().view.len(), 10_000);
    }

    #[test]
    fn quando_o_na_batch_deve_ir_para_a_home_digitando_e_cancelar_o_job() {
        let (mut state, id) = three();
        let commands = update(&mut state, key('o'));
        assert_eq!(commands, vec![Command::CancelJob(id)]);
        assert_eq!(state.screen, Screen::Home);
        assert!(state.home.editing);
    }
}
