//! The event loop of the TUI.
//!
//! Draws only when the state changed, at most 30 times a second, and ticks
//! only while a job runs or a toast is on screen, so an idle terminal costs
//! no CPU.

use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use certtui_app::export::FileWriter;
use certtui_app::history::{HistoryNote, HistoryRepository};
use certtui_domain::limits::Limits;
use certtui_domain::target::{NetworkTarget, Target};
use certtui_tui::app_state::{BatchLoader, TargetParser};
use certtui_tui::clipboard::{ClipboardStrategy, EnvView, FallbackSink, build_sinks};
use certtui_tui::toast::{Toast, ToastKind};
use certtui_tui::{
    AppState, Command, Msg, TerminalGuard, ThemeKind, install_panic_hook, install_signal_restore,
    start_batch, start_inspect, update, view,
};
use crossterm::event::{Event, KeyEventKind};
use futures_util::{Stream, StreamExt as _};
use ratatui::Terminal;
use ratatui::backend::{Backend, CrosstermBackend};
use tokio::sync::mpsc;

use crate::command_executor::{CommandExecutor, Inspector};
use crate::runtime;

/// Longest the loop waits between two ticks while something is animating.
pub const TICK_INTERVAL: Duration = Duration::from_millis(250);

/// Shortest time between two frames (30 frames a second).
pub const MIN_FRAME_INTERVAL: Duration = Duration::from_millis(33);

/// Capacity of every channel of the loop.
pub const CHANNEL_CAPACITY: usize = 256;

/// How a TUI session starts.
pub struct TuiOptions {
    /// A target to inspect at once; `None` opens the Home screen.
    pub initial: Option<Target>,
    /// A batch to run at once, instead of `initial`.
    pub initial_batch: Option<Vec<NetworkTarget>>,
    /// Targets a batch inspects at once; `None` keeps the default.
    pub batch_concurrency: Option<usize>,
    /// Colors; `NO_COLOR` is applied by the caller.
    pub theme: ThemeKind,
    /// Which clipboard methods to use.
    pub clipboard: ClipboardStrategy,
    /// Limits of this run (clipboard size and timeout).
    pub limits: Limits,
    /// How text typed on Home becomes a target.
    pub target_parser: TargetParser,
    /// How the path typed for a batch on Home becomes its targets.
    pub batch_loader: BatchLoader,
    /// The keys, with the user's remapping applied.
    pub keymap: certtui_tui::Keymap,
    /// Where the history of targets is kept; `None` keeps none.
    pub history: Option<Arc<dyn HistoryRepository>>,
    /// The wall clock the history stamps targets with.
    pub wall_clock: certtui_tui::app_state::WallClock,
}

/// Runs the TUI until the user quits.
///
/// The terminal is restored on every way out: normal return, error, panic and
/// SIGINT/SIGTERM.
///
/// # Errors
///
/// The clipboard setting cannot be honored, or the terminal failed.
pub fn run(
    options: TuiOptions,
    inspector: Arc<dyn Inspector>,
    writer: Arc<dyn FileWriter>,
) -> anyhow::Result<()> {
    let (osc_tx, osc_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let sinks = build_sinks(
        options.clipboard,
        &EnvView::from_process(),
        ChannelWriter(osc_tx),
    )
    .context("choosing the clipboard method")?;
    let clipboard = Arc::new(FallbackSink::new(sinks));
    runtime::block_on(async move {
        install_signal_restore();
        install_panic_hook();
        let _terminal_guard = TerminalGuard::enter().context("entering the terminal")?;
        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend).context("starting the terminal")?;
        let (columns, rows) = crossterm::terminal::size().context("reading the terminal size")?;
        let mut state = AppState::new(Instant::now());
        state.theme = options.theme;
        state.size = (columns, rows);
        state.target_parser = options.target_parser;
        state.batch_loader = options.batch_loader;
        state.max_clipboard_bytes = options.limits.max_clipboard_bytes;
        state.history_max_entries = options.limits.history_entries;
        state.keymap = options.keymap;
        state.wall_clock = options.wall_clock;
        if let Some(repository) = &options.history {
            load_history(&mut state, repository.as_ref());
        }
        let (msg_tx, msgs) = mpsc::channel(CHANNEL_CAPACITY);
        let mut executor = CommandExecutor::new(
            inspector,
            clipboard,
            options.limits.clipboard_timeout,
            writer,
        );
        if let Some(concurrency) = options.batch_concurrency {
            executor = executor.with_batch_concurrency(concurrency);
        }
        if let Some(repository) = options.history {
            executor = executor.with_history(repository);
        }
        if let Some(targets) = options.initial_batch {
            for command in start_batch(&mut state, targets) {
                executor.run(command, msg_tx.clone());
            }
        } else if let Some(target) = options.initial {
            for command in start_inspect(&mut state, target) {
                executor.run(command, msg_tx.clone());
            }
        } else {
            state.home.editing = true;
        }
        let mut event_loop = EventLoop {
            terminal,
            events: crossterm::event::EventStream::new(),
            osc_out: io::stdout(),
            executor,
            msgs,
            msg_tx,
            osc_rx,
            stats: LoopStats::default(),
        };
        event_loop.run(&mut state).await
    })?
}

/// Fills the Home lists from the saved history. A history that cannot be read
/// starts empty; the user is told, and the app keeps working.
fn load_history(state: &mut AppState, repository: &dyn HistoryRepository) {
    let message = match repository.load() {
        Ok(loaded) => {
            state.history = loaded.history;
            state.sync_history_lists();
            loaded.note.map(
                |HistoryNote::Recovered| "history file was unreadable; kept as history.json.bak",
            )
        }
        Err(_) => Some("could not read the history; starting empty"),
    };
    if let Some(message) = message {
        let toast = Toast::new(message, ToastKind::Error, state.now);
        state.set_toast(toast);
    }
}

/// What the loop did, for the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoopStats {
    /// Ticks delivered to `update`.
    pub ticks: u32,
    /// Frames drawn.
    pub frames: u32,
}

/// A writer that hands every write to the loop as a message.
///
/// The OSC 52 sink writes through it, so the bytes reach the terminal between
/// two frames, never in the middle of one.
#[derive(Debug, Clone)]
pub struct ChannelWriter(pub mpsc::Sender<Vec<u8>>);

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .try_send(buf.to_vec())
            .map_err(|_| io::Error::other("the terminal loop is busy or gone"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The message a terminal event stands for, if any.
#[must_use]
pub fn msg_from_event(event: Event) -> Option<Msg> {
    match event {
        Event::Key(key) if key.kind != KeyEventKind::Release => Some(Msg::Key(key)),
        Event::Resize(columns, rows) => Some(Msg::Resize(columns, rows)),
        Event::Paste(text) => Some(Msg::Paste(text)),
        Event::Key(_) | Event::FocusGained | Event::FocusLost | Event::Mouse(_) => None,
    }
}

/// Whether the loop needs ticks right now.
#[must_use]
pub fn needs_tick(state: &AppState) -> bool {
    state.jobs.any_active() || state.toast.is_some()
}

/// Everything the loop owns.
pub struct EventLoop<B: Backend, E, W: Write> {
    /// Where frames are drawn.
    pub terminal: Terminal<B>,
    /// Keys, pastes and resizes.
    pub events: E,
    /// Where OSC 52 bytes go, between frames.
    pub osc_out: W,
    /// Runs the commands `update` asks for.
    pub executor: CommandExecutor,
    /// Receives the outcome of commands.
    pub msgs: mpsc::Receiver<Msg>,
    /// Lets commands report back.
    pub msg_tx: mpsc::Sender<Msg>,
    /// OSC 52 bytes waiting to be written.
    pub osc_rx: mpsc::Receiver<Vec<u8>>,
    /// Counters for the tests.
    pub stats: LoopStats,
}

impl<B, E, W> EventLoop<B, E, W>
where
    B: Backend,
    B::Error: Send + Sync + 'static,
    E: Stream<Item = io::Result<Event>> + Unpin,
    W: Write,
{
    /// Runs until the state asks to quit or the event stream ends.
    ///
    /// # Errors
    ///
    /// Drawing or writing to the terminal failed, or reading its events did.
    pub async fn run(&mut self, state: &mut AppState) -> anyhow::Result<()> {
        let mut dirty = true;
        let mut last_frame: Option<Instant> = None;
        let mut ticker = tokio::time::interval(TICK_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut ticking = false;
        loop {
            if dirty {
                let wait = last_frame.map_or(Duration::ZERO, |at| {
                    MIN_FRAME_INTERVAL.saturating_sub(at.elapsed())
                });
                if wait.is_zero() {
                    self.terminal.draw(|frame| view(state, frame))?;
                    self.stats.frames += 1;
                    last_frame = Some(Instant::now());
                    dirty = false;
                }
            }
            let tick_wanted = needs_tick(state);
            if tick_wanted && !ticking {
                ticker.reset();
            }
            ticking = tick_wanted;
            let frame_wait = last_frame.map_or(Duration::ZERO, |at| {
                MIN_FRAME_INTERVAL.saturating_sub(at.elapsed())
            });
            let msg = tokio::select! {
                event = self.events.next() => match event {
                    Some(Ok(event)) => msg_from_event(event),
                    Some(Err(error)) => return Err(error.into()),
                    None => return Ok(()),
                },
                Some(msg) = self.msgs.recv() => Some(msg),
                Some(bytes) = self.osc_rx.recv() => {
                    self.osc_out.write_all(&bytes)?;
                    self.osc_out.flush()?;
                    None
                }
                _ = ticker.tick(), if tick_wanted => {
                    self.stats.ticks += 1;
                    Some(Msg::Tick(Instant::now()))
                }
                () = tokio::time::sleep(frame_wait), if dirty => None,
            };
            if let Some(msg) = msg {
                let commands: Vec<Command> = update(state, msg);
                for command in commands {
                    self.executor.run(command, self.msg_tx.clone());
                }
                dirty = true;
            }
            if state.should_quit {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {

    struct StubHistory(
        Result<certtui_app::history::LoadedHistory, certtui_app::history::HistoryError>,
    );

    impl HistoryRepository for StubHistory {
        fn load(
            &self,
        ) -> Result<certtui_app::history::LoadedHistory, certtui_app::history::HistoryError>
        {
            self.0.clone()
        }

        fn save(
            &self,
            _history: &certtui_app::history::History,
        ) -> Result<(), certtui_app::history::HistoryError> {
            Ok(())
        }
    }

    #[test]
    fn quando_historico_carrega_deve_preencher_a_home_sem_toast() {
        let mut history = certtui_app::history::History::default();
        history.toggle_favorite("a.example");
        let repo = StubHistory(Ok(certtui_app::history::LoadedHistory {
            history,
            note: None,
        }));
        let mut state = AppState::new(Instant::now());
        load_history(&mut state, &repo);
        assert_eq!(state.home.favorites, ["a.example"]);
        assert!(state.toast.is_none());
    }

    #[test]
    fn quando_historico_foi_recuperado_deve_avisar_e_comecar_vazio() {
        let repo = StubHistory(Ok(certtui_app::history::LoadedHistory {
            history: certtui_app::history::History::default(),
            note: Some(HistoryNote::Recovered),
        }));
        let mut state = AppState::new(Instant::now());
        load_history(&mut state, &repo);
        let toast = state.toast.unwrap();
        assert!(toast.text.contains("history.json.bak"), "{}", toast.text);
    }

    #[test]
    fn quando_historico_nao_le_deve_avisar_e_seguir_com_o_estado_vazio() {
        let repo = StubHistory(Err(certtui_app::history::HistoryError::Io(
            "denied".to_owned(),
        )));
        let mut state = AppState::new(Instant::now());
        load_history(&mut state, &repo);
        assert_eq!(state.home.recents, Vec::<String>::new());
        assert!(state.toast.unwrap().text.contains("could not read"));
    }
    use std::sync::Arc;

    use certtui_domain::model::InspectionReport;
    use certtui_domain::target::Target;
    use certtui_tui::clipboard::{ClipboardError, ClipboardSink, CopyMethod};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use futures_util::stream;
    use ratatui::backend::TestBackend;
    use tokio_util::sync::CancellationToken;

    use certtui_app::keystore::SecretString;
    use certtui_tui::InspectFailure;

    use super::*;
    use crate::command_executor::Inspector;

    struct NeverInspector;

    #[async_trait::async_trait]
    impl Inspector for NeverInspector {
        async fn inspect(
            &self,
            _target: Target,
            _password: Option<SecretString>,
            cancel: CancellationToken,
        ) -> Result<InspectionReport, InspectFailure> {
            cancel.cancelled().await;
            Err(InspectFailure::Message("cancelled".to_owned()))
        }
    }

    struct NullSink;

    impl ClipboardSink for NullSink {
        fn copy(&self, _text: &str) -> Result<CopyMethod, ClipboardError> {
            Ok(CopyMethod::Native)
        }
    }

    fn event_loop<E>(events: E) -> EventLoop<TestBackend, E, Vec<u8>>
    where
        E: Stream<Item = io::Result<Event>> + Unpin,
    {
        let (msg_tx, msgs) = mpsc::channel(CHANNEL_CAPACITY);
        let (_osc_tx, osc_rx) = mpsc::channel(CHANNEL_CAPACITY);
        EventLoop {
            terminal: Terminal::new(TestBackend::new(80, 24)).unwrap(),
            events,
            osc_out: Vec::new(),
            executor: CommandExecutor::new(
                Arc::new(NeverInspector),
                Arc::new(NullSink),
                Duration::from_secs(1),
                Arc::new(certtui_app::testing::FakeFileWriter::new(Ok(()))),
            ),
            msgs,
            msg_tx,
            osc_rx,
            stats: LoopStats::default(),
        }
    }

    fn key(c: char) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    #[tokio::test(start_paused = true)]
    async fn quando_loop_ocioso_e_sem_jobs_deve_nao_gerar_ticks() {
        let mut state = AppState::new(Instant::now());
        let mut looped = event_loop(stream::pending::<io::Result<Event>>());
        let run = tokio::time::timeout(Duration::from_secs(1), looped.run(&mut state)).await;
        assert!(run.is_err(), "the loop keeps waiting for events");
        assert_eq!(looped.stats.ticks, 0);
        assert_eq!(looped.stats.frames, 1, "only the first frame");
    }

    #[tokio::test(start_paused = true)]
    async fn quando_ha_job_ativo_deve_gerar_ticks_a_cada_250ms() {
        let mut state = AppState::new(Instant::now());
        state.jobs.start();
        let mut looped = event_loop(stream::pending::<io::Result<Event>>());
        let _ = tokio::time::timeout(Duration::from_millis(1100), looped.run(&mut state)).await;
        assert!((3..=5).contains(&looped.stats.ticks), "{:?}", looped.stats);
    }

    #[tokio::test]
    async fn quando_q_na_home_deve_encerrar_o_loop() {
        let mut state = AppState::new(Instant::now());
        let mut looped = event_loop(stream::iter([Ok(key('q'))]));
        looped.run(&mut state).await.unwrap();
        assert!(state.should_quit);
    }

    #[tokio::test]
    async fn quando_stream_acaba_deve_encerrar_sem_erro() {
        let mut state = AppState::new(Instant::now());
        let mut looped = event_loop(stream::iter(Vec::<io::Result<Event>>::new()));
        looped.run(&mut state).await.unwrap();
        assert!(!state.should_quit);
    }

    #[tokio::test]
    async fn quando_stream_da_erro_deve_propagar() {
        let mut state = AppState::new(Instant::now());
        let mut looped = event_loop(stream::iter([Err(io::Error::other("tty gone"))]));
        let error = looped.run(&mut state).await.unwrap_err();
        assert!(error.to_string().contains("tty gone"));
    }

    #[tokio::test(start_paused = true)]
    async fn quando_muitas_teclas_rapidas_deve_respeitar_o_teto_de_30_fps() {
        let mut state = AppState::new(Instant::now());
        // Ten key presses in the same instant, then quit.
        let mut keys: Vec<io::Result<Event>> = (0..10).map(|_| Ok(key('?'))).collect();
        keys.push(Ok(key('?')));
        keys.push(Ok(key('q')));
        let mut looped = event_loop(stream::iter(keys));
        let started = tokio::time::Instant::now();
        looped.run(&mut state).await.unwrap();
        let elapsed = started.elapsed();
        assert!(
            u128::from(looped.stats.frames) * MIN_FRAME_INTERVAL.as_millis()
                <= elapsed.as_millis() + MIN_FRAME_INTERVAL.as_millis(),
            "{:?} in {elapsed:?}",
            looped.stats
        );
    }

    #[tokio::test]
    async fn quando_osc52_chega_deve_escrever_no_terminal_fora_do_frame() {
        let (msg_tx, msgs) = mpsc::channel(CHANNEL_CAPACITY);
        let (osc_tx, osc_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let mut state = AppState::new(Instant::now());
        let mut looped = EventLoop {
            terminal: Terminal::new(TestBackend::new(80, 24)).unwrap(),
            events: stream::pending::<io::Result<Event>>(),
            osc_out: Vec::new(),
            executor: CommandExecutor::new(
                Arc::new(NeverInspector),
                Arc::new(NullSink),
                Duration::from_secs(1),
                Arc::new(certtui_app::testing::FakeFileWriter::new(Ok(()))),
            ),
            msgs,
            msg_tx,
            osc_rx,
            stats: LoopStats::default(),
        };
        osc_tx.send(b"\x1b]52;c;aGk=\x07".to_vec()).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_millis(50), looped.run(&mut state)).await;
        assert_eq!(looped.osc_out, b"\x1b]52;c;aGk=\x07");
    }

    #[test]
    fn quando_evento_e_release_ou_mouse_ou_foco_deve_ser_ignorado() {
        use crossterm::event::{MouseEvent, MouseEventKind};
        let mut release = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert!(msg_from_event(Event::Key(release)).is_none());
        assert!(msg_from_event(Event::FocusGained).is_none());
        assert!(msg_from_event(Event::FocusLost).is_none());
        let mouse = MouseEvent {
            kind: MouseEventKind::Moved,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        };
        assert!(msg_from_event(Event::Mouse(mouse)).is_none());
    }

    #[test]
    fn quando_resize_e_paste_deve_virar_msg() {
        assert!(matches!(
            msg_from_event(Event::Resize(100, 30)),
            Some(Msg::Resize(100, 30))
        ));
        assert!(matches!(
            msg_from_event(Event::Paste("a".to_owned())),
            Some(Msg::Paste(text)) if text == "a"
        ));
    }

    #[tokio::test]
    async fn quando_channel_writer_cheio_deve_dar_erro_em_vez_de_bloquear() {
        let (tx, _rx) = mpsc::channel(1);
        let mut writer = ChannelWriter(tx);
        writer.write_all(b"a").unwrap();
        assert!(writer.write_all(b"b").is_err());
    }
}
