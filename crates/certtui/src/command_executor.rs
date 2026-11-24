//! Runs the [`Command`]s of the TUI as tasks and sends back [`Msg`]s.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use certtui_domain::model::InspectionReport;
use certtui_domain::target::Target;
use certtui_tui::clipboard::{ClipboardSink, copy_with_timeout};
use certtui_tui::{Command, JobId, Msg};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Inspects a target for the TUI: loads or fetches its chain and validates it.
#[async_trait::async_trait]
pub trait Inspector: Send + Sync {
    /// The validated report of `target`, or a message fit for the screen.
    ///
    /// `cancel` is cancelled when the user leaves the screen; the caller stops
    /// waiting then, so an implementation only needs to stop early to save work.
    async fn inspect(
        &self,
        target: Target,
        cancel: CancellationToken,
    ) -> Result<InspectionReport, String>;
}

/// Executes commands and reports their outcome through a bounded channel.
pub struct CommandExecutor {
    inspector: Arc<dyn Inspector>,
    clipboard: Arc<dyn ClipboardSink>,
    clipboard_timeout: Duration,
    /// Token of every inspect job still running.
    jobs: Arc<Mutex<HashMap<JobId, CancellationToken>>>,
}

impl CommandExecutor {
    /// An executor using `inspector` for inspections and `clipboard` for copies.
    #[must_use]
    pub fn new(
        inspector: Arc<dyn Inspector>,
        clipboard: Arc<dyn ClipboardSink>,
        clipboard_timeout: Duration,
    ) -> Self {
        Self {
            inspector,
            clipboard,
            clipboard_timeout,
            jobs: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Starts `command`; its outcome, if any, arrives on `tx`.
    ///
    /// Must be called from inside a tokio runtime.
    pub fn run(&self, command: Command, tx: mpsc::Sender<Msg>) {
        match command {
            Command::Inspect { id, target } => self.inspect(id, target, tx),
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

    fn inspect(&self, id: JobId, target: Target, tx: mpsc::Sender<Msg>) {
        let token = CancellationToken::new();
        lock(&self.jobs).insert(id, token.clone());
        let inspector = Arc::clone(&self.inspector);
        let jobs = Arc::clone(&self.jobs);
        tokio::spawn(async move {
            let outcome = tokio::select! {
                () = token.cancelled() => None,
                result = inspector.inspect(target, token.clone()) => Some(result),
            };
            lock(&jobs).remove(&id);
            // A cancelled job leaves no result behind: the screen it fed is gone.
            if let Some(result) = outcome {
                let result = result.map(Arc::new);
                let _ = tx.send(Msg::InspectDone { id, result }).await;
            }
        });
    }

    fn cancel(&self, id: JobId) {
        if let Some(token) = lock(&self.jobs).remove(&id) {
            token.cancel();
        }
    }
}

/// Locks `mutex`, ignoring poisoning: the map stays usable after a panic.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        result: Result<InspectionReport, String>,
        started: AtomicUsize,
    }

    impl FakeInspector {
        fn new(delay: Duration, result: Result<InspectionReport, String>) -> Arc<Self> {
            Arc::new(Self {
                delay,
                result,
                started: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl Inspector for FakeInspector {
        async fn inspect(
            &self,
            _target: Target,
            _cancel: CancellationToken,
        ) -> Result<InspectionReport, String> {
            self.started.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
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
        CommandExecutor::new(inspector, sink, timeout)
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

    #[tokio::test]
    async fn quando_inspect_falha_deve_devolver_a_mensagem() {
        let inspector = FakeInspector::new(Duration::ZERO, Err("connection refused".to_owned()));
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
        let inspector = FakeInspector::new(Duration::ZERO, Err("x".to_owned()));
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
            FakeInspector::new(Duration::ZERO, Err("x".to_owned())),
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
            FakeInspector::new(Duration::ZERO, Err("x".to_owned())),
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
            FakeInspector::new(Duration::ZERO, Err("x".to_owned())),
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
}
