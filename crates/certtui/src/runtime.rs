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
    Ok(runtime.block_on(future))
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
}
