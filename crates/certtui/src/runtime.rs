//! The async runtime of the network commands.
//!
//! Local targets (files, directories, standard input) are synchronous and
//! never touch this module, so they pay for no runtime and no worker threads.

use std::future::Future;
use std::num::NonZeroUsize;

use anyhow::Context as _;

/// Most worker threads the runtime starts: a fetch is I/O-bound.
const MAX_WORKERS: usize = 4;

/// Builds a multi-threaded runtime and runs `future` to completion on it.
///
/// # Errors
///
/// The runtime could not be created (for example, the process cannot start
/// threads).
pub fn block_on<F: Future>(future: F) -> anyhow::Result<F::Output> {
    let workers = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers.min(MAX_WORKERS))
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    let output = runtime.block_on(future);
    // DNS may have started a blocking OS resolver call. `Runtime::drop`
    // waits for blocking jobs, which would extend the target deadline past
    // the timeout result already returned by the future.
    runtime.shutdown_background();
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_future_pronta_deve_devolver_o_valor() {
        assert_eq!(block_on(async { 7 }).unwrap(), 7);
    }

    #[test]
    fn quando_future_usa_timer_deve_funcionar_no_runtime_com_enable_all() {
        let slept = block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            true
        });
        assert!(slept.unwrap());
    }

    #[test]
    fn quando_spawn_blocking_ultrapassa_future_deve_retornar_sem_esperar() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_at = std::time::Instant::now();
        let result = block_on(async move {
            let _blocking_job = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                std::thread::sleep(std::time::Duration::from_secs(2));
            });
            started_rx.await.unwrap();
            7
        });
        let elapsed = started_at.elapsed();

        assert_eq!(result.unwrap(), 7);
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "runtime shutdown waited {elapsed:?} for blocking DNS-like work"
        );
    }
}
