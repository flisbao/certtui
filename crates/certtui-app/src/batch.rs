//! Batch inspection: many targets, bounded concurrency, compact rows
//! (spec section 6.5).
//!
//! Only a [`BatchRow`] outlives each job; the report and chain of a target
//! are dropped as soon as they have been summarized, so memory grows with
//! the number of rows and not with the size of the chains.

use std::sync::Arc;
use std::time::Duration;

use certtui_domain::batch_row::BatchRow;
use certtui_domain::limits::Limits;
use certtui_domain::model::InspectionReport;
use certtui_domain::target::NetworkTarget;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::ports::Clock;

/// Runs the full inspection pipeline for one network target.
#[async_trait::async_trait]
pub trait TargetInspector: Send + Sync {
    /// The validated report of `target`, or a short reason why there is none.
    ///
    /// `cancel` fires when the batch is cancelled; the runner stops waiting
    /// then, so an implementation only needs to stop early to save work.
    async fn inspect(
        &self,
        target: &NetworkTarget,
        cancel: CancellationToken,
    ) -> Result<InspectionReport, String>;
}

/// What a running batch tells its consumer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchEvent {
    /// The result of the target at `index` of the input list.
    Row {
        /// Position of the target in the input list.
        index: usize,
        /// Its compact result.
        row: BatchRow,
    },
    /// How many targets are finished.
    Progress {
        /// Targets finished so far.
        done: usize,
        /// Targets in the batch.
        total: usize,
    },
    /// The batch is over; always the last event.
    Finished {
        /// Whether the batch stopped early because it was cancelled.
        cancelled: bool,
    },
}

/// Runs a list of targets with bounded concurrency.
pub struct BatchRunner {
    inspector: Arc<dyn TargetInspector>,
    clock: Arc<dyn Clock>,
    limits: Limits,
}

impl BatchRunner {
    /// A runner over `inspector`; `limits.target_total_timeout` bounds each
    /// target.
    #[must_use]
    pub fn new(inspector: Arc<dyn TargetInspector>, clock: Arc<dyn Clock>, limits: Limits) -> Self {
        Self {
            inspector,
            clock,
            limits,
        }
    }

    /// Inspects `targets`, at most `concurrency` at a time (clamped to
    /// `1..=256`), and reports through `tx`.
    ///
    /// Each target gets `limits.target_total_timeout`; a target that fails or
    /// times out becomes a [`RowStatus::Failed`](certtui_domain::batch_row::RowStatus)
    /// row and the others go on. `tx` is bounded and awaited, so a slow
    /// consumer slows the jobs down instead of growing a queue. Cancelling
    /// `cancel` (or dropping the receiver) stops new jobs, cuts the running
    /// ones and ends with [`BatchEvent::Finished`].
    pub async fn run(
        &self,
        targets: Vec<NetworkTarget>,
        concurrency: usize,
        tx: mpsc::Sender<BatchEvent>,
        cancel: CancellationToken,
    ) {
        let total = targets.len();
        let concurrency = concurrency.clamp(1, Limits::HARD_CAPS.batch_concurrency);
        let token = cancel.child_token();
        let (row_tx, row_rx) = mpsc::channel(concurrency);
        let dispatch = self.dispatch(targets, concurrency, row_tx, &token);
        let collect = forward(row_rx, &tx, total, &token);
        tokio::join!(dispatch, collect);
        let _ = tx
            .send(BatchEvent::Finished {
                cancelled: cancel.is_cancelled(),
            })
            .await;
    }

    /// Starts one task per target, never more than `concurrency` alive, and
    /// waits for all of them.
    async fn dispatch(
        &self,
        targets: Vec<NetworkTarget>,
        concurrency: usize,
        row_tx: mpsc::Sender<(usize, BatchRow)>,
        token: &CancellationToken,
    ) {
        let permits = Arc::new(Semaphore::new(concurrency));
        let mut jobs = JoinSet::new();
        for (index, target) in targets.into_iter().enumerate() {
            let permit = tokio::select! {
                biased;
                () = token.cancelled() => break,
                permit = Arc::clone(&permits).acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
            };
            let job = Job {
                inspector: Arc::clone(&self.inspector),
                clock: Arc::clone(&self.clock),
                timeout: self.limits.target_total_timeout,
                token: token.clone(),
            };
            let row_tx = row_tx.clone();
            jobs.spawn(async move {
                let _permit = permit;
                if let Some(row) = job.run(&target).await {
                    let _ = row_tx.send((index, row)).await;
                }
            });
        }
        drop(row_tx);
        while jobs.join_next().await.is_some() {}
    }
}

/// What one task needs to inspect one target.
struct Job {
    inspector: Arc<dyn TargetInspector>,
    clock: Arc<dyn Clock>,
    timeout: Duration,
    token: CancellationToken,
}

impl Job {
    /// The row of `target`, or `None` when the batch was cancelled first.
    /// The report is dropped before this returns.
    async fn run(&self, target: &NetworkTarget) -> Option<BatchRow> {
        let label = target_label(target);
        let outcome = tokio::select! {
            biased;
            () = self.token.cancelled() => return None,
            outcome = tokio::time::timeout(
                self.timeout,
                self.inspector.inspect(target, self.token.clone()),
            ) => outcome,
        };
        Some(match outcome {
            Ok(Ok(report)) => BatchRow::from_report(&label, &report, self.clock.now()),
            Ok(Err(reason)) => BatchRow::failed(&label, &reason),
            Err(_) => BatchRow::failed(&label, "timed out"),
        })
    }
}

/// Passes rows from the jobs to the consumer, counting progress. When the
/// consumer is gone it cancels the batch and stops reading, which makes the
/// jobs' own sends fail.
async fn forward(
    mut rows: mpsc::Receiver<(usize, BatchRow)>,
    tx: &mpsc::Sender<BatchEvent>,
    total: usize,
    token: &CancellationToken,
) {
    let mut done = 0_usize;
    while let Some((index, row)) = rows.recv().await {
        done = done.saturating_add(1);
        let sent = tx.send(BatchEvent::Row { index, row }).await.is_ok()
            && tx.send(BatchEvent::Progress { done, total }).await.is_ok();
        if !sent {
            token.cancel();
            return;
        }
    }
}

/// `host:port`, with brackets around an IPv6 literal.
fn target_label(target: &NetworkTarget) -> String {
    if target.host.contains(':') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use certtui_domain::batch_row::RowStatus;
    use certtui_domain::model::{Chain, StapleState, Timings, TrustVerdict};
    use certtui_domain::target::Target;
    use certtui_domain::time::Timestamp;

    use super::*;
    use crate::testing::FixedClock;

    fn target(host: &str) -> NetworkTarget {
        NetworkTarget {
            host: host.to_owned(),
            port: 443,
            sni: None,
            connect_to: None,
        }
    }

    fn targets(n: usize) -> Vec<NetworkTarget> {
        (0..n).map(|i| target(&format!("h{i}.test"))).collect()
    }

    fn empty_report(t: &NetworkTarget) -> InspectionReport {
        InspectionReport {
            target: Target::Network(t.clone()),
            tls: None,
            ocsp_staple: None,
            chain: Chain::new(Vec::new(), &Limits::default()).unwrap(),
            trust: TrustVerdict::NotEvaluated,
            revocation: Vec::new(),
            staple: StapleState::NotApplicable,
            findings: Vec::new(),
            timings: Timings::default(),
            notes: Vec::new(),
        }
    }

    /// Behaviour by host name: `fail.*` errors, `hang.*` never answers,
    /// `slow.*` and the rest take `work` to answer.
    struct FakeInspector {
        work: Duration,
        current: AtomicUsize,
        peak: AtomicUsize,
    }

    impl FakeInspector {
        fn new(work: Duration) -> Arc<Self> {
            Arc::new(Self {
                work,
                current: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            })
        }
    }

    #[async_trait::async_trait]
    impl TargetInspector for FakeInspector {
        async fn inspect(
            &self,
            target: &NetworkTarget,
            _cancel: CancellationToken,
        ) -> Result<InspectionReport, String> {
            let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            let _guard = Decrement(&self.current);
            if target.host.starts_with("hang.") {
                std::future::pending::<()>().await;
            }
            tokio::time::sleep(self.work).await;
            if target.host.starts_with("fail.") {
                return Err("connection refused".to_owned());
            }
            Ok(empty_report(target))
        }
    }

    struct Decrement<'a>(&'a AtomicUsize);
    impl Drop for Decrement<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn runner(inspector: Arc<FakeInspector>) -> BatchRunner {
        let now = Timestamp::from_unix(1_800_000_000).unwrap();
        BatchRunner::new(inspector, Arc::new(FixedClock(now)), Limits::default())
    }

    async fn run_collect(
        runner: &BatchRunner,
        targets: Vec<NetworkTarget>,
        concurrency: usize,
        capacity: usize,
    ) -> Vec<BatchEvent> {
        let (tx, mut rx) = mpsc::channel(capacity);
        let consumer = async {
            let mut events = Vec::new();
            while let Some(event) = rx.recv().await {
                events.push(event);
            }
            events
        };
        let (events, ()) = tokio::join!(
            consumer,
            runner.run(targets, concurrency, tx, CancellationToken::new())
        );
        events
    }

    fn rows(events: &[BatchEvent]) -> BTreeMap<usize, BatchRow> {
        events
            .iter()
            .filter_map(|e| match e {
                BatchEvent::Row { index, row } => Some((*index, row.clone())),
                _ => None,
            })
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn quando_batch_roda_deve_emitir_uma_row_por_alvo_e_finished() {
        let runner = runner(FakeInspector::new(Duration::from_millis(5)));
        let events = run_collect(&runner, targets(7), 3, 256).await;
        let rows = rows(&events);
        assert_eq!(
            rows.keys().copied().collect::<Vec<_>>(),
            (0..7).collect::<Vec<_>>()
        );
        assert_eq!(rows[&2].target, "h2.test:443");
        assert_eq!(rows[&2].status, RowStatus::Ok);
        assert_eq!(
            events.last(),
            Some(&BatchEvent::Finished { cancelled: false })
        );
        let progress: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                BatchEvent::Progress { done, total } => {
                    assert_eq!(*total, 7);
                    Some(*done)
                }
                _ => None,
            })
            .collect();
        assert_eq!(progress, (1..=7).collect::<Vec<_>>());
    }

    #[tokio::test(start_paused = true)]
    async fn quando_concorrencia_e_4_deve_nunca_ter_mais_de_4_jobs_simultaneos() {
        let fake = FakeInspector::new(Duration::from_millis(10));
        let runner = runner(Arc::clone(&fake));
        let events = run_collect(&runner, targets(20), 4, 256).await;
        assert_eq!(rows(&events).len(), 20);
        assert_eq!(fake.peak.load(Ordering::SeqCst), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn quando_concorrencia_e_zero_deve_rodar_um_por_vez() {
        let fake = FakeInspector::new(Duration::from_millis(10));
        let runner = runner(Arc::clone(&fake));
        let events = run_collect(&runner, targets(3), 0, 256).await;
        assert_eq!(rows(&events).len(), 3);
        assert_eq!(fake.peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn quando_alvo_falha_deve_virar_row_failed_e_seguir() {
        let runner = runner(FakeInspector::new(Duration::from_millis(1)));
        let list = vec![target("a.test"), target("fail.test"), target("b.test")];
        let rows = rows(&run_collect(&runner, list, 2, 256).await);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[&1].status, RowStatus::Failed);
        assert_eq!(rows[&1].failure.as_deref(), Some("connection refused"));
        assert_eq!(rows[&0].status, RowStatus::Ok);
        assert_eq!(rows[&2].status, RowStatus::Ok);
    }

    #[tokio::test(start_paused = true)]
    async fn quando_alvo_pendura_deve_falhar_em_target_total_timeout_sem_travar_os_outros() {
        let runner = runner(FakeInspector::new(Duration::from_millis(1)));
        let mut list = vec![target("hang.test")];
        list.extend((0..5).map(|i| target(&format!("ok{i}.test"))));
        let (tx, mut rx) = mpsc::channel(256);
        let started = tokio::time::Instant::now();
        let run = runner.run(list, 2, tx, CancellationToken::new());
        let collect = async {
            let mut done_at = BTreeMap::new();
            let mut hung = None;
            while let Some(event) = rx.recv().await {
                if let BatchEvent::Row { index, row } = event {
                    if index == 0 {
                        hung = Some(row);
                    } else {
                        done_at.insert(index, started.elapsed());
                    }
                }
            }
            (done_at, hung, started.elapsed())
        };
        let ((done_at, hung, total), ()) = tokio::join!(collect, run);
        assert_eq!(done_at.len(), 5);
        assert!(
            done_at.values().all(|t| *t < Duration::from_secs(1)),
            "{done_at:?}"
        );
        let hung = hung.unwrap();
        assert_eq!(hung.status, RowStatus::Failed);
        assert_eq!(hung.failure.as_deref(), Some("timed out"));
        let limit = Limits::default().target_total_timeout;
        assert!(
            total >= limit && total < limit + Duration::from_secs(1),
            "{total:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn quando_cancelado_deve_emitir_finished_cancelled_e_liberar_permissoes() {
        let fake = FakeInspector::new(Duration::from_secs(1));
        let runner = runner(Arc::clone(&fake));
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(256);
        let trigger = cancel.clone();
        let canceller = async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            trigger.cancel();
        };
        let consumer = async {
            let mut events = Vec::new();
            while let Some(event) = rx.recv().await {
                events.push(event);
            }
            events
        };
        let (events, (), ()) =
            tokio::join!(consumer, canceller, runner.run(targets(50), 4, tx, cancel));
        assert_eq!(
            events.last(),
            Some(&BatchEvent::Finished { cancelled: true })
        );
        // 4 jobs finished at 1 s, 4 more were cut at 1.5 s; the rest never started.
        let done = rows(&events).len();
        assert!((4..=8).contains(&done), "{done}");
        assert_eq!(fake.current.load(Ordering::SeqCst), 0, "jobs left running");
    }

    #[tokio::test(start_paused = true)]
    async fn quando_canal_esta_cheio_deve_aplicar_backpressure_sem_perder_rows() {
        let runner = runner(FakeInspector::new(Duration::from_millis(1)));
        let (tx, mut rx) = mpsc::channel(1);
        let run = runner.run(targets(30), 8, tx, CancellationToken::new());
        let slow_consumer = async {
            let mut events = Vec::new();
            while let Some(event) = rx.recv().await {
                tokio::time::sleep(Duration::from_millis(20)).await;
                events.push(event);
            }
            events
        };
        let (events, ()) = tokio::join!(slow_consumer, run);
        assert_eq!(rows(&events).len(), 30);
        assert_eq!(
            events.last(),
            Some(&BatchEvent::Finished { cancelled: false })
        );
    }

    #[tokio::test(start_paused = true)]
    async fn quando_consumidor_some_deve_parar_sem_travar() {
        let runner = runner(FakeInspector::new(Duration::from_millis(1)));
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        runner
            .run(targets(10), 2, tx, CancellationToken::new())
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn quando_lista_vazia_deve_emitir_so_finished() {
        let runner = runner(FakeInspector::new(Duration::from_millis(1)));
        let events = run_collect(&runner, Vec::new(), 4, 8).await;
        assert_eq!(events, vec![BatchEvent::Finished { cancelled: false }]);
    }
}
