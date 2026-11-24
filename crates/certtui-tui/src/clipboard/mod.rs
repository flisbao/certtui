//! Clipboard sinks (OSC 52, native, fallback) and the strategy that picks them.

pub mod fallback;
#[cfg(feature = "native-clipboard")]
pub mod native;
pub mod osc52;
pub mod strategy;

use std::sync::Arc;
use std::time::Duration;

use thiserror::Error;

pub use fallback::FallbackSink;
#[cfg(feature = "native-clipboard")]
pub use native::NativeSink;
pub use osc52::{Osc52Sink, encode_osc52};
pub use strategy::{ClipboardConfigError, ClipboardStrategy, EnvView, build_sinks, plan_methods};

/// How a copy reached the clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMethod {
    /// Escape sequence sent to the terminal; delivery is not confirmed.
    Osc52,
    /// The operating system clipboard.
    Native,
}

/// Why a copy failed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ClipboardError {
    /// No method could take the text.
    #[error("clipboard unavailable: {0}")]
    Unavailable(String),
    /// The clipboard did not answer in time.
    #[error("clipboard timed out")]
    Timeout,
    /// The text is larger than the clipboard accepts.
    #[error("text too large for the clipboard")]
    TooLarge,
    /// Writing to the clipboard failed.
    #[error("clipboard I/O error: {0}")]
    Io(String),
}

/// Somewhere text can be copied to.
pub trait ClipboardSink: Send + Sync {
    /// Puts `text` on the clipboard and says how.
    ///
    /// # Errors
    ///
    /// A [`ClipboardError`] when the text could not be delivered.
    fn copy(&self, text: &str) -> Result<CopyMethod, ClipboardError>;
}

/// Runs `sink` off the async threads and gives up after `timeout`.
///
/// A sink that never returns keeps its blocking thread until it does; only the
/// caller stops waiting.
///
/// # Errors
///
/// The sink's own error, [`ClipboardError::Timeout`] when it takes too long, or
/// [`ClipboardError::Io`] when its thread panicked.
pub async fn copy_with_timeout(
    sink: Arc<dyn ClipboardSink>,
    text: String,
    timeout: Duration,
) -> Result<CopyMethod, ClipboardError> {
    let job = tokio::task::spawn_blocking(move || sink.copy(&text));
    match tokio::time::timeout(timeout, job).await {
        Err(_) => Err(ClipboardError::Timeout),
        Ok(Err(error)) => Err(ClipboardError::Io(format!(
            "clipboard thread failed: {error}"
        ))),
        Ok(Ok(result)) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Slow(Duration);

    impl ClipboardSink for Slow {
        fn copy(&self, _text: &str) -> Result<CopyMethod, ClipboardError> {
            std::thread::sleep(self.0);
            Ok(CopyMethod::Native)
        }
    }

    #[tokio::test]
    async fn quando_sink_demora_demais_deve_dar_timeout() {
        let sink: Arc<dyn ClipboardSink> = Arc::new(Slow(Duration::from_millis(400)));
        let result = copy_with_timeout(sink, "x".to_owned(), Duration::from_millis(20)).await;
        assert_eq!(result, Err(ClipboardError::Timeout));
    }

    #[tokio::test]
    async fn quando_sink_responde_a_tempo_deve_devolver_o_metodo() {
        let sink: Arc<dyn ClipboardSink> = Arc::new(Slow(Duration::from_millis(1)));
        let result = copy_with_timeout(sink, "x".to_owned(), Duration::from_secs(5)).await;
        assert_eq!(result, Ok(CopyMethod::Native));
    }

    struct Panics;

    impl ClipboardSink for Panics {
        fn copy(&self, _text: &str) -> Result<CopyMethod, ClipboardError> {
            panic!("sink bug");
        }
    }

    #[tokio::test]
    async fn quando_sink_entra_em_panico_deve_virar_erro_io() {
        let sink: Arc<dyn ClipboardSink> = Arc::new(Panics);
        let result = copy_with_timeout(sink, "x".to_owned(), Duration::from_secs(5)).await;
        assert!(matches!(result, Err(ClipboardError::Io(_))), "{result:?}");
    }
}
