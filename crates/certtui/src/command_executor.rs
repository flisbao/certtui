//! Runs the [`Command`]s of the TUI as tasks and sends back [`Msg`]s.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use certtui_app::batch::{BatchRunner, TargetInspector};
use certtui_app::export::{FileWriter, WriteError, render_export};
use certtui_app::keystore::SecretString;
use certtui_domain::limits::Limits;
use certtui_domain::model::InspectionReport;
use certtui_domain::target::{NetworkTarget, Target};
use certtui_infra::clock::SystemClock;
use certtui_tui::clipboard::{ClipboardSink, copy_with_timeout};
use certtui_tui::{Command, ExportFailure, ExportRequest, InspectFailure, JobId, Msg};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Inspects a target for the TUI: loads or fetches its chain and validates it.
#[async_trait::async_trait]
pub trait Inspector: Send + Sync {
    /// The validated report of `target`, or why there is none.
    ///
    /// `password` opens keystores (`None` uses the one from the command line,
    /// if any). `cancel` is cancelled when the user leaves the screen; the
    /// caller stops waiting then, so an implementation only needs to stop
    /// early to save work.
    async fn inspect(
        &self,
        target: Target,
        password: Option<SecretString>,
        cancel: CancellationToken,
    ) -> Result<InspectionReport, InspectFailure>;
}

/// Executes commands and reports their outcome through a bounded channel.
pub struct CommandExecutor {
    inspector: Arc<dyn Inspector>,
    clipboard: Arc<dyn ClipboardSink>,
    clipboard_timeout: Duration,
    writer: Arc<dyn FileWriter>,
    /// Targets a batch inspects at once.
    batch_concurrency: usize,
    /// Token of every inspect job still running.
    jobs: Arc<Mutex<HashMap<JobId, CancellationToken>>>,
}

impl CommandExecutor {
    /// An executor using `inspector` for inspections, `clipboard` for copies
    /// and `writer` for exports.
    #[must_use]
    pub fn new(
        inspector: Arc<dyn Inspector>,
        clipboard: Arc<dyn ClipboardSink>,
        clipboard_timeout: Duration,
        writer: Arc<dyn FileWriter>,
    ) -> Self {
        Self {
            inspector,
            clipboard,
            clipboard_timeout,
            writer,
            batch_concurrency: Limits::default().batch_concurrency,
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Sets how many targets a batch inspects at once (at least 1, at most
    /// the hard cap).
    #[must_use]
    pub fn with_batch_concurrency(mut self, concurrency: usize) -> Self {
        self.batch_concurrency = concurrency.clamp(1, Limits::HARD_CAPS.batch_concurrency);
        self
    }

    /// Starts `command`; its outcome, if any, arrives on `tx`.
    ///
    /// Must be called from inside a tokio runtime.
    pub fn run(&self, command: Command, tx: mpsc::Sender<Msg>) {
        match command {
            Command::Inspect { id, target } => self.inspect(id, target, None, tx),
            Command::InspectWithPassword {
                id,
                target,
                password,
            } => self.inspect(id, target, Some(password.into_secret()), tx),
            Command::RunBatch { id, targets } => self.batch(id, targets, tx),
            Command::Export(request) => self.export(request, tx),
            Command::CancelJob(id) => self.cancel(id),
            Command::CopyToClipboard(payload) => {
                let clipboard = Arc::clone(&self.clipboard);
                let timeout = self.clipboard_timeout;
                tokio::spawn(async move {
                    let bytes = payload.text.len();
                    let outcome = copy_with_timeout(clipboard, payload.text, timeout).await;
                    let msg = match outcome {
                        Ok(method) => Msg::Copied {
                            label: payload.label,
                            bytes,
                            method,
                        },
                        Err(error) => Msg::CopyFailed {
                            reason: error.to_string(),
                        },
                    };
                    // The loop may be gone already; then nobody needs the answer.
                    let _ = tx.send(msg).await;
                });
            }
        }
    }

    fn export(&self, request: ExportRequest, tx: mpsc::Sender<Msg>) {
        let writer = Arc::clone(&self.writer);
        tokio::spawn(async move {
            // Rendering and writing touch the disk: off the async threads.
            let outcome =
                tokio::task::spawn_blocking(move || write_export(&request, writer.as_ref()))
                    .await
                    .unwrap_or_else(|_| {
                        Err(ExportFailure::Message("the export task failed".to_owned()))
                    });
            let msg = match outcome {
                Ok(path) => Msg::ExportDone { path },
                Err(failure) => Msg::ExportFailed(failure),
            };
            let _ = tx.send(msg).await;
        });
    }

    fn inspect(
        &self,
        id: JobId,
        target: Target,
        password: Option<SecretString>,
        tx: mpsc::Sender<Msg>,
    ) {
        let token = CancellationToken::new();
        lock(&self.jobs).insert(id, token.clone());
        let inspector = Arc::clone(&self.inspector);
        let jobs = Arc::clone(&self.jobs);
        tokio::spawn(async move {
            let outcome = tokio::select! {
                () = token.cancelled() => None,
                result = inspector.inspect(target, password, token.clone()) => Some(result),
            };
            lock(&jobs).remove(&id);
            // A cancelled job leaves no result behind: the screen it fed is gone.
            let msg = match outcome {
                None => return,
                Some(Ok(report)) => Msg::InspectDone {
                    id,
                    result: Ok(Arc::new(report)),
                },
                Some(Err(InspectFailure::PasswordRequired)) => {
                    Msg::PasswordNeeded { id, wrong: false }
                }
                Some(Err(InspectFailure::WrongPassword)) => Msg::PasswordNeeded { id, wrong: true },
                Some(Err(InspectFailure::Message(message))) => Msg::InspectDone {
                    id,
                    result: Err(message),
                },
            };
            let _ = tx.send(msg).await;
        });
    }

    /// Runs a batch as one job: its events reach the loop in groups of up to
    /// [`BATCH_GROUP`], so a large batch does not flood it.
    fn batch(&self, id: JobId, targets: Vec<NetworkTarget>, tx: mpsc::Sender<Msg>) {
        let token = CancellationToken::new();
        lock(&self.jobs).insert(id, token.clone());
        let inspector = InspectorAdapter(Arc::clone(&self.inspector));
        let jobs = Arc::clone(&self.jobs);
        let concurrency = self.batch_concurrency;
        tokio::spawn(async move {
            // The inspector enforces the user's `--timeout`; this limit is
            // only the net under it.
            let limits = Limits {
                target_total_timeout: Limits::HARD_CAPS.target_total_timeout,
                ..Limits::default()
            };
            let clock = SystemClock;
            let runner = BatchRunner::new(&inspector, &clock, &limits);
            let (events_tx, mut events_rx) = mpsc::channel(BATCH_CHANNEL);
            let run = runner.run(targets, concurrency, events_tx, token.clone());
            let forward = async {
                while let Some(first) = events_rx.recv().await {
                    let mut events = vec![first];
                    while events.len() < BATCH_GROUP {
                        let Ok(event) = events_rx.try_recv() else {
                            break;
                        };
                        events.push(event);
                    }
                    // A cancelled batch leaves nothing behind: its screen is gone.
                    if token.is_cancelled() || tx.send(Msg::Batch { id, events }).await.is_err() {
                        break;
                    }
                }
            };
            tokio::join!(run, forward);
            lock(&jobs).remove(&id);
        });
    }

    fn cancel(&self, id: JobId) {
        if let Some(token) = lock(&self.jobs).remove(&id) {
            token.cancel();
        }
    }
}

/// Events per message of a batch job.
const BATCH_GROUP: usize = 64;
/// Capacity of the channel between the batch runner and its forwarder.
const BATCH_CHANNEL: usize = 256;

/// Lets the batch runner use the inspector of the TUI.
struct InspectorAdapter(Arc<dyn Inspector>);

#[async_trait::async_trait]
impl TargetInspector for InspectorAdapter {
    async fn inspect(
        &self,
        target: &NetworkTarget,
        cancel: CancellationToken,
    ) -> Result<InspectionReport, String> {
        self.0
            .inspect(Target::Network(target.clone()), None, cancel)
            .await
            .map_err(|failure| match failure {
                InspectFailure::Message(message) => message,
                InspectFailure::PasswordRequired | InspectFailure::WrongPassword => {
                    "a password is required".to_owned()
                }
            })
    }
}

/// Renders and writes one export; the path shown on success, or why not.
fn write_export(request: &ExportRequest, writer: &dyn FileWriter) -> Result<String, ExportFailure> {
    let bytes = render_export(&request.report, request.format, request.selection)
        .map_err(|error| ExportFailure::Message(error.to_string()))?;
    writer
        .write(&request.path, &bytes, request.overwrite)
        .map(|()| request.path.to_string_lossy().into_owned())
        .map_err(|error| match error {
            WriteError::AlreadyExists => ExportFailure::AlreadyExists,
            other => ExportFailure::Message(other.to_string()),
        })
}

/// Locks `mutex`, ignoring poisoning: the map stays usable after a panic.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use certtui_app::batch::BatchEvent;
    use certtui_app::keystore::ExposeSecret;
    use certtui_app::testing::FakeFileWriter;
    use certtui_domain::target::NetworkTarget;
    use certtui_tui::clipboard::{ClipboardError, CopyMethod};
    use certtui_tui::copy::CopyPayload;

    use super::*;
    use crate::output::testing::network_report;

    fn target() -> Target {
        Target::Network(NetworkTarget {
            host: "example.test".to_owned(),
            port: 443,
            sni: None,
            connect_to: None,
        })
    }

    /// Answers after `delay` with a canned result.
    struct FakeInspector {
        delay: Duration,
        result: Result<InspectionReport, InspectFailure>,
        started: AtomicUsize,
        running: AtomicUsize,
        peak: AtomicUsize,
        passwords: Mutex<Vec<Option<String>>>,
    }

    impl FakeInspector {
        fn new(delay: Duration, result: Result<InspectionReport, InspectFailure>) -> Arc<Self> {
            Arc::new(Self {
                delay,
                result,
                started: AtomicUsize::new(0),
                running: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                passwords: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl Inspector for FakeInspector {
        async fn inspect(
            &self,
            _target: Target,
            password: Option<SecretString>,
            _cancel: CancellationToken,
        ) -> Result<InspectionReport, InspectFailure> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            lock(&self.passwords).push(password.map(|p| p.expose_secret().to_owned()));
            tokio::time::sleep(self.delay).await;
            self.running.fetch_sub(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    struct FakeSink {
        result: Result<CopyMethod, ClipboardError>,
        delay: Duration,
        copies: Mutex<Vec<String>>,
    }

    impl ClipboardSink for FakeSink {
        fn copy(&self, text: &str) -> Result<CopyMethod, ClipboardError> {
            std::thread::sleep(self.delay);
            lock(&self.copies).push(text.to_owned());
            self.result.clone()
        }
    }

    fn sink(result: Result<CopyMethod, ClipboardError>, delay: Duration) -> Arc<FakeSink> {
        Arc::new(FakeSink {
            result,
            delay,
            copies: Mutex::new(Vec::new()),
        })
    }

    fn executor(
        inspector: Arc<FakeInspector>,
        sink: Arc<FakeSink>,
        timeout: Duration,
    ) -> CommandExecutor {
        CommandExecutor::new(
            inspector,
            sink,
            timeout,
            Arc::new(FakeFileWriter::new(Ok(()))),
        )
    }

    #[tokio::test]
    async fn quando_command_inspect_deve_devolver_inspect_done() {
        let report = network_report(&["rsa2048-leaf"]);
        let inspector = FakeInspector::new(Duration::from_millis(1), Ok(report.clone()));
        let exec = executor(
            inspector,
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::Inspect {
                id: JobId(7),
                target: target(),
            },
            tx,
        );
        match rx.recv().await {
            Some(Msg::InspectDone { id, result }) => {
                assert_eq!(id, JobId(7));
                assert_eq!(*result.unwrap(), report);
            }
            other => unreachable!("expected InspectDone, got {other:?}"),
        }
        assert!(lock(&exec.jobs).is_empty(), "the finished job is forgotten");
    }

    /// Every message of a batch job, flattened, until it finishes.
    async fn batch_events(rx: &mut mpsc::Receiver<Msg>, id: JobId) -> Vec<BatchEvent> {
        let mut events = Vec::new();
        while let Some(msg) = rx.recv().await {
            let Msg::Batch {
                id: got,
                events: chunk,
            } = msg
            else {
                unreachable!("expected Batch, got {msg:?}");
            };
            assert_eq!(got, id);
            let finished = chunk
                .iter()
                .any(|event| matches!(event, BatchEvent::Finished { .. }));
            events.extend(chunk);
            if finished {
                break;
            }
        }
        events
    }

    fn network_targets(n: usize) -> Vec<NetworkTarget> {
        (0..n)
            .map(|i| NetworkTarget {
                host: format!("h{i}.test"),
                port: 443,
                sni: None,
                connect_to: None,
            })
            .collect()
    }

    #[tokio::test]
    async fn quando_run_batch_deve_devolver_uma_row_por_alvo_em_lotes_e_finished() {
        let report = network_report(&["rsa2048-leaf"]);
        let inspector = FakeInspector::new(Duration::from_millis(1), Ok(report));
        let exec = executor(
            Arc::clone(&inspector),
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::RunBatch {
                id: JobId(3),
                targets: network_targets(150),
            },
            tx,
        );
        let events = batch_events(&mut rx, JobId(3)).await;
        let rows = events
            .iter()
            .filter(|event| matches!(event, BatchEvent::Row { .. }))
            .count();
        assert_eq!(rows, 150);
        assert_eq!(
            events.last(),
            Some(&BatchEvent::Finished { cancelled: false })
        );
        assert_eq!(inspector.started.load(Ordering::SeqCst), 150);
        assert!(lock(&exec.jobs).is_empty(), "the finished job is forgotten");
    }

    #[tokio::test]
    async fn quando_inspector_falha_no_batch_deve_virar_row_failed_com_a_mensagem() {
        let inspector = FakeInspector::new(
            Duration::ZERO,
            Err(InspectFailure::Message("connection refused".to_owned())),
        );
        let exec = executor(
            inspector,
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::RunBatch {
                id: JobId(1),
                targets: network_targets(1),
            },
            tx,
        );
        let events = batch_events(&mut rx, JobId(1)).await;
        let Some(BatchEvent::Row { row, .. }) = events.first() else {
            unreachable!("{events:?}");
        };
        assert_eq!(row.status, certtui_domain::batch_row::RowStatus::Failed);
        assert_eq!(row.failure.as_deref(), Some("connection refused"));
    }

    #[tokio::test(start_paused = true)]
    async fn quando_batch_tem_concorrencia_configurada_deve_respeitar_o_limite() {
        let inspector = FakeInspector::new(
            Duration::from_millis(10),
            Ok(network_report(&["rsa2048-leaf"])),
        );
        let exec = executor(
            Arc::clone(&inspector),
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        )
        .with_batch_concurrency(3);
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::RunBatch {
                id: JobId(5),
                targets: network_targets(20),
            },
            tx,
        );
        let events = batch_events(&mut rx, JobId(5)).await;
        assert_eq!(events.len(), 20 + 1 + 20, "rows, progress and the end");
        assert_eq!(inspector.peak.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn quando_cancel_job_no_batch_deve_parar_os_alvos_pendentes() {
        let inspector = FakeInspector::new(
            Duration::from_secs(10),
            Ok(network_report(&["rsa2048-leaf"])),
        );
        let exec = executor(
            Arc::clone(&inspector),
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::RunBatch {
                id: JobId(9),
                targets: network_targets(100),
            },
            tx.clone(),
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
        exec.run(Command::CancelJob(JobId(9)), tx);
        tokio::time::sleep(Duration::from_secs(60)).await;
        assert!(
            inspector.started.load(Ordering::SeqCst) <= 32,
            "only the first wave starts"
        );
        assert!(rx.try_recv().is_err(), "a cancelled batch reports nothing");
        assert!(lock(&exec.jobs).is_empty());
    }

    #[tokio::test]
    async fn quando_inspect_falha_deve_devolver_a_mensagem() {
        let inspector = FakeInspector::new(
            Duration::ZERO,
            Err(InspectFailure::Message("connection refused".to_owned())),
        );
        let exec = executor(
            inspector,
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::Inspect {
                id: JobId(1),
                target: target(),
            },
            tx,
        );
        match rx.recv().await {
            Some(Msg::InspectDone { result, .. }) => {
                assert_eq!(result.unwrap_err(), "connection refused");
            }
            other => unreachable!("expected InspectDone, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn quando_cancel_job_deve_cancelar_o_token_e_nao_devolver_msg_de_sucesso() {
        let inspector = FakeInspector::new(
            Duration::from_secs(5),
            Ok(network_report(&["rsa2048-leaf"])),
        );
        let exec = executor(
            inspector.clone(),
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::Inspect {
                id: JobId(3),
                target: target(),
            },
            tx.clone(),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(inspector.started.load(Ordering::SeqCst), 1);
        exec.run(Command::CancelJob(JobId(3)), tx.clone());
        // Past the moment the inspector would have answered.
        tokio::time::sleep(Duration::from_secs(10)).await;
        drop(tx);
        assert!(rx.recv().await.is_none(), "no message after a cancel");
        assert!(lock(&exec.jobs).is_empty());
    }

    #[tokio::test]
    async fn quando_cancel_de_job_desconhecido_deve_ser_ignorado() {
        let inspector =
            FakeInspector::new(Duration::ZERO, Err(InspectFailure::Message("x".to_owned())));
        let exec = executor(
            inspector,
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        );
        let (tx, _rx) = mpsc::channel(8);
        exec.run(Command::CancelJob(JobId(99)), tx);
    }

    #[tokio::test]
    async fn quando_copy_deve_chamar_sink_e_devolver_copied() {
        let fake = sink(Ok(CopyMethod::Osc52), Duration::ZERO);
        let exec = executor(
            FakeInspector::new(Duration::ZERO, Err(InspectFailure::Message("x".to_owned()))),
            fake.clone(),
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::CopyToClipboard(CopyPayload {
                label: "Serial".to_owned(),
                text: "01AB".to_owned(),
            }),
            tx,
        );
        match rx.recv().await {
            Some(Msg::Copied {
                label,
                bytes,
                method,
            }) => {
                assert_eq!(
                    (label.as_str(), bytes, method),
                    ("Serial", 4, CopyMethod::Osc52)
                );
            }
            other => unreachable!("expected Copied, got {other:?}"),
        }
        assert_eq!(*lock(&fake.copies), ["01AB"]);
    }

    #[tokio::test]
    async fn quando_sink_falha_deve_devolver_copy_failed_com_o_motivo() {
        let fake = sink(
            Err(ClipboardError::Unavailable("no display".to_owned())),
            Duration::ZERO,
        );
        let exec = executor(
            FakeInspector::new(Duration::ZERO, Err(InspectFailure::Message("x".to_owned()))),
            fake,
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::CopyToClipboard(CopyPayload {
                label: "x".to_owned(),
                text: "x".to_owned(),
            }),
            tx,
        );
        match rx.recv().await {
            Some(Msg::CopyFailed { reason }) => assert!(reason.contains("no display"), "{reason}"),
            other => unreachable!("expected CopyFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn quando_sink_estoura_timeout_deve_devolver_copy_failed() {
        let fake = sink(Ok(CopyMethod::Native), Duration::from_millis(500));
        let exec = executor(
            FakeInspector::new(Duration::ZERO, Err(InspectFailure::Message("x".to_owned()))),
            fake,
            Duration::from_millis(20),
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(
            Command::CopyToClipboard(CopyPayload {
                label: "x".to_owned(),
                text: "x".to_owned(),
            }),
            tx,
        );
        match rx.recv().await {
            Some(Msg::CopyFailed { reason }) => assert!(reason.contains("timed out"), "{reason}"),
            other => unreachable!("expected CopyFailed, got {other:?}"),
        }
    }

    // --- passwords and exports --------------------------------------------

    #[tokio::test]
    async fn quando_inspect_with_password_deve_passar_a_senha_ao_inspector() {
        let inspector = FakeInspector::new(Duration::ZERO, Ok(network_report(&["rsa2048-leaf"])));
        let exec = executor(
            inspector.clone(),
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
        );
        let (tx, mut rx) = mpsc::channel(8);

        exec.run(
            Command::InspectWithPassword {
                id: JobId(1),
                target: target(),
                password: certtui_tui::Password::new(SecretString::from("changeit".to_owned())),
            },
            tx.clone(),
        );
        assert!(matches!(rx.recv().await, Some(Msg::InspectDone { .. })));
        exec.run(
            Command::Inspect {
                id: JobId(2),
                target: target(),
            },
            tx,
        );
        assert!(matches!(rx.recv().await, Some(Msg::InspectDone { .. })));

        assert_eq!(
            *lock(&inspector.passwords),
            vec![Some("changeit".to_owned()), None]
        );
    }

    #[tokio::test]
    async fn quando_inspector_pede_senha_deve_virar_password_needed_e_nao_inspect_done() {
        for (failure, wrong) in [
            (InspectFailure::PasswordRequired, false),
            (InspectFailure::WrongPassword, true),
        ] {
            let inspector = FakeInspector::new(Duration::ZERO, Err(failure));
            let exec = executor(
                inspector,
                sink(Ok(CopyMethod::Native), Duration::ZERO),
                Duration::from_secs(1),
            );
            let (tx, mut rx) = mpsc::channel(8);

            exec.run(
                Command::Inspect {
                    id: JobId(5),
                    target: target(),
                },
                tx,
            );

            match rx.recv().await {
                Some(Msg::PasswordNeeded { id, wrong: got }) => {
                    assert_eq!(id, JobId(5));
                    assert_eq!(got, wrong);
                }
                other => unreachable!("expected PasswordNeeded, got {other:?}"),
            }
        }
    }

    fn export_request(overwrite: certtui_app::export::Overwrite) -> ExportRequest {
        ExportRequest {
            report: Arc::new(network_report(&["rsa2048-leaf"])),
            format: certtui_app::export::ExportFormat::Pem,
            selection: certtui_app::export::ExportSelection::Index(0),
            path: std::path::PathBuf::from("out.pem"),
            overwrite,
        }
    }

    async fn run_export(writer: Arc<FakeFileWriter>, request: ExportRequest) -> Msg {
        let exec = CommandExecutor::new(
            FakeInspector::new(Duration::ZERO, Err(InspectFailure::Message("x".to_owned()))),
            sink(Ok(CopyMethod::Native), Duration::ZERO),
            Duration::from_secs(1),
            writer,
        );
        let (tx, mut rx) = mpsc::channel(8);
        exec.run(Command::Export(request), tx);
        rx.recv().await.unwrap()
    }

    #[tokio::test]
    async fn quando_export_deve_escrever_o_pem_e_avisar_o_caminho() {
        let fake = Arc::new(FakeFileWriter::new(Ok(())));

        let msg = run_export(
            Arc::clone(&fake),
            export_request(certtui_app::export::Overwrite::Refuse),
        )
        .await;

        assert!(
            matches!(&msg, Msg::ExportDone { path } if path == "out.pem"),
            "{msg:?}"
        );
        let writes = fake.writes();
        assert_eq!(writes.len(), 1);
        assert!(writes[0].1.starts_with(b"-----BEGIN CERTIFICATE-----\n"));
        assert_eq!(writes[0].2, certtui_app::export::Overwrite::Refuse);
    }

    #[tokio::test]
    async fn quando_arquivo_existe_deve_devolver_already_exists() {
        let writer = Arc::new(FakeFileWriter::new(Err(WriteError::AlreadyExists)));
        let msg = run_export(
            writer,
            export_request(certtui_app::export::Overwrite::Refuse),
        )
        .await;
        assert!(
            matches!(msg, Msg::ExportFailed(ExportFailure::AlreadyExists)),
            "{msg:?}"
        );
    }

    #[tokio::test]
    async fn quando_escrita_falha_deve_devolver_a_mensagem() {
        let writer = Arc::new(FakeFileWriter::new(Err(WriteError::ParentMissing)));
        let msg = run_export(
            writer,
            export_request(certtui_app::export::Overwrite::Allow),
        )
        .await;
        assert!(
            matches!(&msg, Msg::ExportFailed(ExportFailure::Message(m)) if m.contains("does not exist")),
            "{msg:?}"
        );
    }

    #[tokio::test]
    async fn quando_der_de_cadeia_deve_falhar_sem_escrever() {
        let writer = Arc::new(FakeFileWriter::new(Ok(())));
        let mut request = export_request(certtui_app::export::Overwrite::Refuse);
        request.format = certtui_app::export::ExportFormat::Der;
        request.selection = certtui_app::export::ExportSelection::Chain;

        let msg = run_export(Arc::clone(&writer), request).await;

        assert!(
            matches!(&msg, Msg::ExportFailed(ExportFailure::Message(m)) if m.contains("DER cannot hold")),
            "{msg:?}"
        );
        assert_eq!(writer.writes(), Vec::new());
    }
}
