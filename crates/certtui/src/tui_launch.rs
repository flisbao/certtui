//! Opening the TUI from the command line.

use std::fs::File;
use std::io::{self, IsTerminal as _};
use std::path::PathBuf;
use std::sync::Arc;

use certtui_app::config::{Theme, UiConfig};
use certtui_app::enrich::RevocationOptions;
use certtui_app::error::LoadError;
use certtui_app::history::HistoryRepository;
use certtui_app::keystore::SecretString;
use certtui_app::ports::{Clock as _, LoadedCerts, LocalSource, SourceLoader};
use certtui_app::trust::TrustSource;
use certtui_domain::limits::Limits;
use certtui_domain::lint::Thresholds;
use certtui_domain::target::{NetworkTarget, Target};
use certtui_infra::atomic_write::AtomicFileWriter;
use certtui_infra::chain_verifier::WebpkiChainVerifier;
use certtui_infra::clock::SystemClock;
use certtui_infra::history::FileHistoryRepository;
use certtui_infra::source::FsSourceLoader;
use certtui_infra::tls::RustlsChainFetcher;
use certtui_infra::trust::NativeTrustProvider;
use certtui_tui::ThemeKind;
use certtui_tui::clipboard::ClipboardStrategy;
use tokio::sync::OnceCell;

use crate::network_args::ConnectTo;
use crate::system_inspector::SystemInspector;
use crate::target_parse::parse_target;
use crate::tui_runner::{self, TuiOptions};

/// The command line options an inspection inside the TUI honors.
#[derive(Debug, Clone, Default)]
pub struct InspectorOptions {
    /// `--sni`.
    pub sni: Option<String>,
    /// `--connect-to`.
    pub connect_to: Option<ConnectTo>,
    /// The limits of the run: defaults, config, `--timeout`.
    pub limits: Limits,
    /// Expiry thresholds: defaults, config, `--warn-days`.
    pub thresholds: Thresholds,
    /// Trust sources to validate against.
    pub trust_sources: Vec<TrustSource>,
    /// `--ca-file` paths.
    pub ca_files: Vec<PathBuf>,
    /// `--host-check`.
    pub host_check: Option<String>,
    /// `--aia`, `--revocation` and `--no-revocation`.
    pub revocation: RevocationOptions,
    /// The keystore password given on the command line, if any.
    pub password: Option<SecretString>,
}

/// What the TUI is opened with.
#[derive(Debug, Clone)]
pub struct TuiRequest {
    /// A target to inspect at once; `None` opens the Home screen.
    pub target: Option<Target>,
    /// Standard input, read before the terminal entered raw mode.
    pub stdin: Option<LoadedCerts>,
    /// The targets of a batch to run at once; `target` is `None` then.
    pub batch: Option<Vec<NetworkTarget>>,
    /// `--concurrency` of `certtui batch`; `None` keeps the default.
    pub batch_concurrency: Option<usize>,
    /// The options of the command line.
    pub options: InspectorOptions,
    /// Interface settings of the configuration.
    pub ui: UiConfig,
}

/// Decides whether a terminal is there and opens the TUI on it.
pub trait TuiLauncher {
    /// Whether there is a terminal to draw on and to read keys from.
    fn is_interactive(&self) -> bool;

    /// Runs the TUI until the user quits.
    ///
    /// # Errors
    ///
    /// The terminal failed or the clipboard setting cannot be honored.
    fn launch(&self, request: TuiRequest) -> anyhow::Result<()>;
}

/// The launcher of the real process.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessLauncher;

impl TuiLauncher for ProcessLauncher {
    fn is_interactive(&self) -> bool {
        // The screen goes to stdout; keys come from stdin, or from the
        // terminal device when stdin is a pipe (`cat cert.pem | certtui -`).
        io::stdout().is_terminal() && (io::stdin().is_terminal() || File::open("/dev/tty").is_ok())
    }

    fn launch(&self, request: TuiRequest) -> anyhow::Result<()> {
        // One loader for the targets and for `--ca-file`: a keystore used as a
        // CA file needs the same password, and so does one the dialog opens.
        let files: Arc<FsSourceLoader> =
            Arc::new(FsSourceLoader::new().with_password(request.options.password.clone()));
        let trust_loader: Arc<dyn SourceLoader> = files.clone();
        let loader: Arc<dyn SourceLoader> = Arc::new(StdinPreloaded {
            inner: files,
            stdin: request.stdin,
        });
        let limits = request.options.limits;
        let inspector = SystemInspector {
            loader,
            fetcher: Arc::new(RustlsChainFetcher::new()),
            verifier: Arc::new(WebpkiChainVerifier::new()),
            clock: Arc::new(SystemClock),
            trust_provider: Arc::new(move |ca_files| {
                Box::new(NativeTrustProvider::new(
                    ca_files,
                    Arc::clone(&trust_loader),
                    limits,
                ))
            }),
            enricher: Arc::new(crate::system_inspector::real_enricher()),
            options: request.options,
            anchors: OnceCell::new(),
        };
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
        // The strategy was checked when the configuration was resolved.
        let clipboard = request
            .ui
            .clipboard
            .parse::<ClipboardStrategy>()
            .map_err(|error| anyhow::anyhow!("ui.clipboard: {error}"))?;
        tui_runner::run(
            TuiOptions {
                initial: request.target,
                initial_batch: request.batch,
                batch_concurrency: request.batch_concurrency,
                theme: if no_color {
                    ThemeKind::Mono
                } else {
                    theme_kind(request.ui.theme)
                },
                clipboard,
                limits,
                target_parser: parse_for_tui,
                batch_loader: crate::cli::load_batch_list,
                history: certtui_infra::paths::history_path().map(|path| {
                    Arc::new(FileHistoryRepository::new(path)) as Arc<dyn HistoryRepository>
                }),
                wall_clock: || SystemClock.now(),
            },
            Arc::new(inspector),
            Arc::new(AtomicFileWriter),
        )
    }
}

/// The TUI theme a configuration value names.
fn theme_kind(theme: Theme) -> ThemeKind {
    match theme {
        Theme::Dark => ThemeKind::Dark,
        Theme::Light => ThemeKind::Light,
        Theme::Mono => ThemeKind::Mono,
    }
}

/// Turns what the user typed on Home into a target, looking at the file system.
fn parse_for_tui(text: &str) -> Result<Target, String> {
    parse_target(text, false, false, &|path| path.exists()).map_err(|error| error.to_string())
}

/// A loader that answers for standard input from what was read before the
/// TUI started: the terminal is busy with keys, so nothing may read stdin now.
struct StdinPreloaded {
    inner: Arc<dyn SourceLoader>,
    stdin: Option<LoadedCerts>,
}

impl SourceLoader for StdinPreloaded {
    fn set_password(&self, password: Option<SecretString>) {
        self.inner.set_password(password);
    }

    fn load(&self, src: &LocalSource, limits: &Limits) -> Result<LoadedCerts, LoadError> {
        match src {
            LocalSource::Stdin => self.stdin.clone().ok_or(LoadError::Unsupported(
                "standard input can only be opened as `certtui -`",
            )),
            other => self.inner.load(other, limits),
        }
    }
}

#[cfg(test)]
mod tests {
    use certtui_app::testing::FakeSourceLoader;

    use super::*;

    fn loaded() -> LoadedCerts {
        LoadedCerts {
            certs: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn quando_stdin_foi_lido_antes_deve_devolver_o_mesmo_conteudo() {
        let loader = StdinPreloaded {
            inner: Arc::new(FakeSourceLoader(Err(LoadError::Io("unused".to_owned())))),
            stdin: Some(loaded()),
        };
        assert_eq!(
            loader.load(&LocalSource::Stdin, &Limits::default()),
            Ok(loaded())
        );
    }

    #[test]
    fn quando_stdin_nao_foi_lido_antes_deve_recusar_sem_tocar_no_terminal() {
        let loader = StdinPreloaded {
            inner: Arc::new(FakeSourceLoader(Ok(loaded()))),
            stdin: None,
        };
        assert!(matches!(
            loader.load(&LocalSource::Stdin, &Limits::default()),
            Err(LoadError::Unsupported(_))
        ));
    }

    #[test]
    fn quando_arquivo_deve_delegar_ao_loader_de_verdade() {
        let loader = StdinPreloaded {
            inner: Arc::new(FakeSourceLoader(Ok(loaded()))),
            stdin: None,
        };
        let source = LocalSource::File(PathBuf::from("x.pem"));
        assert_eq!(loader.load(&source, &Limits::default()), Ok(loaded()));
    }

    #[test]
    fn quando_texto_da_home_e_host_deve_virar_alvo_de_rede() {
        assert!(matches!(
            parse_for_tui("example.com:8443"),
            Ok(Target::Network(_))
        ));
        assert_eq!(parse_for_tui("-"), Ok(Target::Stdin));
        assert!(parse_for_tui("ftp://example.com").is_err());
    }
}
