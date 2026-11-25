//! File-only logging (decision D14): `tracing` events go to a file when one
//! is asked for, and nowhere else. Never to stdout or stderr: either would
//! corrupt the screen of the TUI.

use std::fs::{File, OpenOptions};
use std::path::Path;

use certtui_app::config::LogLevel;
use thiserror::Error;
use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt as _;

/// Only events of this program's own crates are written: the `trace` output
/// of `hyper`, `h2` or `rustls` can hold URLs and headers.
const OWN_TARGET_PREFIX: &str = "certtui";

/// Why logging could not start.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LoggingError {
    /// The log file cannot be opened for appending.
    #[error("cannot open the log file {path}: {reason}")]
    Open {
        /// The path, as given.
        path: String,
        /// What the operating system said, in a word.
        reason: String,
    },
    /// A global subscriber is already installed.
    #[error("logging was already started")]
    AlreadyStarted,
}

/// Keeps the background writer alive; dropping it flushes the file.
#[must_use = "dropping the guard stops the log writer"]
pub struct LogGuard(Option<WorkerGuard>);

impl LogGuard {
    /// A guard that holds nothing: logging is off.
    pub const fn none() -> Self {
        Self(None)
    }
}

impl std::fmt::Debug for LogGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogGuard")
            .field("active", &self.0.is_some())
            .finish()
    }
}

/// The level in force: `RUST_LOG`, when it is a plain level, over the config.
///
/// Only a single level word is understood (`off`, `error`, `warn`, `info`,
/// `debug`, `trace`); directives such as `hyper=trace` are ignored, so a
/// shell that exports `RUST_LOG` for another program cannot enable the
/// dependencies' output here.
#[must_use]
pub fn effective_level(configured: LogLevel, rust_log: Option<&str>) -> LogLevel {
    let from_env = match rust_log
        .map(|value| value.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("off") => Some(LogLevel::Off),
        Some("error") => Some(LogLevel::Error),
        Some("warn") => Some(LogLevel::Warn),
        Some("info") => Some(LogLevel::Info),
        Some("debug") => Some(LogLevel::Debug),
        Some("trace") => Some(LogLevel::Trace),
        _ => None,
    };
    from_env.unwrap_or(configured)
}

/// The most verbose [`Level`] written, or `None` when nothing is.
fn max_level(level: LogLevel) -> Option<Level> {
    match level {
        LogLevel::Off => None,
        LogLevel::Error => Some(Level::ERROR),
        LogLevel::Warn => Some(Level::WARN),
        LogLevel::Info => Some(Level::INFO),
        LogLevel::Debug => Some(Level::DEBUG),
        LogLevel::Trace => Some(Level::TRACE),
    }
}

/// Opens `path` for appending; created with mode 0600 on Unix, since the log
/// may name targets and paths.
fn open_log(path: &Path) -> Result<File, LoggingError> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).map_err(|error| LoggingError::Open {
        path: path.display().to_string(),
        reason: error.kind().to_string(),
    })
}

/// Starts logging to `file` at `level` (overridden by `rust_log`, see
/// [`effective_level`]). Without a `file` nothing is logged and nothing is
/// printed.
///
/// # Errors
///
/// [`LoggingError::Open`] when the file cannot be opened,
/// [`LoggingError::AlreadyStarted`] when a subscriber is already installed.
pub fn init_logging(
    file: Option<&Path>,
    level: LogLevel,
    rust_log: Option<&str>,
) -> Result<LogGuard, LoggingError> {
    let Some(path) = file else {
        return Ok(LogGuard::none());
    };
    let handle = open_log(path)?;
    let max = max_level(effective_level(level, rust_log));
    let (writer, guard) = tracing_appender::non_blocking(handle);
    let layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .with_filter(filter_fn(move |metadata| {
            metadata.target().starts_with(OWN_TARGET_PREFIX)
                && max.is_some_and(|max| *metadata.level() <= max)
        }));
    tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer))
        .map_err(|_| LoggingError::AlreadyStarted)?;
    Ok(LogGuard(Some(guard)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_level_deve_preferir_rust_log_quando_e_um_nivel_simples() {
        assert_eq!(
            effective_level(LogLevel::Error, Some("trace")),
            LogLevel::Trace
        );
        assert_eq!(
            effective_level(LogLevel::Info, Some(" DEBUG ")),
            LogLevel::Debug
        );
        assert_eq!(effective_level(LogLevel::Info, Some("off")), LogLevel::Off);
    }

    #[test]
    fn effective_level_deve_ignorar_diretivas_e_lixo() {
        for value in ["hyper=trace", "certtui=debug,warn", "loud", "", "1"] {
            assert_eq!(
                effective_level(LogLevel::Warn, Some(value)),
                LogLevel::Warn,
                "{value:?}"
            );
        }
        assert_eq!(effective_level(LogLevel::Warn, None), LogLevel::Warn);
    }

    #[test]
    fn max_level_deve_ordenar_do_silencio_ao_trace() {
        assert_eq!(max_level(LogLevel::Off), None);
        assert_eq!(max_level(LogLevel::Error), Some(Level::ERROR));
        assert_eq!(max_level(LogLevel::Trace), Some(Level::TRACE));
        // A more verbose level admits the less verbose ones.
        assert!(Level::WARN <= Level::INFO);
        assert!(Level::TRACE > Level::INFO);
    }

    #[test]
    fn quando_nao_ha_arquivo_deve_devolver_guarda_vazia_sem_tocar_nada() {
        let guard = init_logging(None, LogLevel::Trace, Some("trace")).unwrap();
        assert!(guard.0.is_none());
    }

    #[test]
    fn quando_diretorio_nao_existe_deve_dar_erro_open_com_o_caminho() {
        let path = std::env::temp_dir().join("certtui-no-such-dir-xyz/run.log");
        let error = init_logging(Some(&path), LogLevel::Info, None).unwrap_err();
        match error {
            LoggingError::Open { path, .. } => assert!(path.contains("run.log"), "{path}"),
            other @ LoggingError::AlreadyStarted => panic!("unexpected: {other:?}"),
        }
    }
}
