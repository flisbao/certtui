//! Cooperative cancellation helper shared by the async use cases.

use std::future::Future;
use std::task::Poll;

use tokio_util::sync::CancellationToken;

/// Runs `fut` until it finishes or `cancel` fires; `None` means cancelled.
///
/// Needs no runtime of its own: it only polls the two futures.
pub(crate) async fn cancellable<T>(
    cancel: &CancellationToken,
    fut: impl Future<Output = T>,
) -> Option<T> {
    let mut fut = std::pin::pin!(fut);
    let mut cancelled = std::pin::pin!(cancel.cancelled());
    std::future::poll_fn(|cx| {
        if let Poll::Ready(value) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(value));
        }
        if cancelled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        Poll::Pending
    })
    .await
}
