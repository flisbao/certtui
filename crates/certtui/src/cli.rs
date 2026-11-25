//! Command-line definition and the `inspect` command.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use certtui_app::check::FailOn;
use certtui_app::config::{
    CliOverrides, Config, ConfigError, FingerprintFormatConfig, LogLevel, ResolvedConfig,
    RevocationMode, ThresholdsConfig, UiConfig,
};
use certtui_app::enrich::{ReportEnricher, RevocationOptions};
use certtui_app::error::{InspectError, LoadError};
use certtui_app::export::{
    ExportError, ExportFormat, ExportSelection, FileWriter, Overwrite, WriteError, render_export,
};
use certtui_app::inspect::inspect_local;
use certtui_app::inspect_network::inspect_network;
use certtui_app::keystore::SecretString;
use certtui_app::ports::{
    ChainFetcher, ChainVerifier, Clock, LocalSource, SourceLoader, TrustStoreProvider,
};
use certtui_app::proxy::ProxySettings;
use certtui_app::revocation::RevocationScope;
use certtui_app::trust::{TrustAnchors, TrustSource, resolve_sources};
use certtui_app::validate::{ValidationInputs, known_issuers, validate};
use certtui_domain::limits::Limits;
use certtui_domain::lint::Thresholds;
use certtui_domain::model::{FingerprintFormat, InspectionReport, LoadNote};
use certtui_domain::target::{NetworkTarget, Target};
use certtui_infra::env::EnvVars;
use certtui_infra::proxy::{EnvProxy, parse_proxy_url};
use certtui_tui::Keymap;
use certtui_tui::clipboard::ClipboardStrategy;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio_util::sync::CancellationToken;

use crate::exit_code::ExitCode;
use crate::logging::{LogGuard, LoggingError};
use crate::network_args::{ConnectTo, parse_connect_to, parse_sni, parse_timeout};
use crate::output::check::TargetResult;
use crate::output::field::Field;
use crate::output::{self, View};
use crate::password::{PasswordSource, resolve_password};
use crate::runtime;
use crate::target_parse::{local_source, parse_target};
use crate::tui_launch::{InspectorOptions, TuiLauncher, TuiRequest};

mod batch;
pub use batch::{BatchArgs, load_batch_list};

/// Inspect and analyze X.509 certificates.
#[derive(Debug, Parser)]
#[command(name = "certtui", version, about)]
#[allow(clippy::struct_excessive_bools)] // Justificativa: cada flag global do clap é um booleano independente da linha de comando.
pub struct Cli {
    /// What to do. Without a command, the interactive UI opens.
    #[command(subcommand)]
    pub command: Option<Command>,
    /// Configuration file; `$CERTTUI_CONFIG` takes precedence over it. Without
    /// either, `~/.config/certtui/config.json` is read if it exists.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Write a log to this file (appended; nothing is logged without one).
    #[arg(long, global = true, value_name = "PATH")]
    log_file: Option<PathBuf>,
    /// Reach TLS servers, OCSP, CRL and AIA through this HTTP CONNECT proxy,
    /// `http://host:port` (no credentials, no https or socks).
    #[arg(long, global = true, value_name = "URL", conflicts_with = "no_proxy")]
    proxy: Option<String>,
    /// Connect directly: ignore the proxy of the config and of the environment.
    #[arg(long, global = true)]
    no_proxy: bool,
    /// Server name to send in SNI instead of the host (network targets only).
    /// An IP literal sends no SNI.
    #[arg(long, global = true, value_name = "NAME")]
    sni: Option<String>,
    /// Connect to this address instead of resolving the host: `IP`, `IP:PORT`
    /// or `[IPV6]:PORT`; the port defaults to the target's (network targets
    /// only).
    #[arg(long, global = true, value_name = "IP[:PORT]", value_parser = parse_connect_to)]
    connect_to: Option<ConnectTo>,
    /// Overall time limit for the target, in seconds, up to a hard cap of
    /// 120 (network targets only).
    #[arg(long, global = true, value_name = "SECONDS", value_parser = parse_timeout)]
    timeout: Option<std::time::Duration>,
    /// Trust source for validation: `system` (the default), `mozilla` or
    /// `custom`; repeatable.
    #[arg(long, global = true, value_enum, value_name = "SOURCE")]
    trust: Vec<TrustArg>,
    /// CA certificates to trust, in any format `inspect` reads (adds the
    /// `custom` source); repeatable.
    #[arg(long, global = true, value_name = "PATH")]
    ca_file: Vec<PathBuf>,
    /// Trust only the `--ca-file` certificates.
    #[arg(long, global = true)]
    ca_only: bool,
    /// Name the leaf must match; defaults to the host of a network target and
    /// is skipped for files.
    #[arg(long, global = true, value_name = "NAME")]
    host_check: Option<String>,
    /// Download missing intermediate certificates from their AIA URLs (off by
    /// default; marked `AIA_FETCHED` in the report).
    #[arg(long, global = true, conflicts_with = "no_aia")]
    aia: bool,
    /// Do not download missing intermediates, even if the config turns it on.
    #[arg(long, global = true)]
    no_aia: bool,
    /// Which certificates are checked for revocation on network targets: the
    /// `leaf` (the default) or the `leaf` and every intermediate (`full`).
    #[arg(
        long,
        global = true,
        value_enum,
        value_name = "SCOPE",
        conflicts_with = "no_revocation"
    )]
    revocation: Option<RevocationArg>,
    /// Do not check revocation (no OCSP or CRL request is made).
    #[arg(long, global = true)]
    no_revocation: bool,
    /// Read the keystore password (PKCS#12, JKS) from this environment
    /// variable. Never pass a password as an argument.
    #[arg(long, global = true, value_name = "VAR", conflicts_with_all = ["password_file", "password_stdin"])]
    password_env: Option<String>,
    /// Read the keystore password from the first line of this file.
    #[arg(long, global = true, value_name = "PATH", conflicts_with_all = ["password_env", "password_stdin"])]
    password_file: Option<PathBuf>,
    /// Read the keystore password from the first line of standard input
    /// (not with the target `-`, which also reads standard input).
    #[arg(long, global = true, conflicts_with_all = ["password_env", "password_file"])]
    password_stdin: bool,
    /// Let the OCSP, CRL and AIA URLs found in certificates reach loopback,
    /// link-local and cloud metadata addresses (refused by default; private
    /// ranges such as 10.x are always allowed).
    #[arg(long, global = true)]
    allow_internal_urls: bool,
}

/// `--revocation` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RevocationArg {
    /// Only the leaf.
    Leaf,
    /// The leaf and every intermediate.
    Full,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the certificates of a file, directory, standard input or TLS server.
    Inspect(InspectArgs),
    /// Validate the certificates of one or more targets and report findings.
    Check(CheckArgs),
    /// Inspect a list of TLS servers and report one row per target.
    Batch(BatchArgs),
    /// Write the certificates of a target to a file as PEM, DER or JSON.
    Export(ExportArgs),
    /// `certtui <TARGET>`: open the interactive UI on a file, a directory, `-`
    /// for standard input, or a TLS server. Without a terminal it is
    /// inspected like `certtui inspect --text <TARGET>`. Options go before
    /// the target.
    #[command(external_subcommand)]
    External(Vec<String>),
}

/// Trust source (`--trust`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TrustArg {
    /// The operating system store.
    System,
    /// The bundled Mozilla roots.
    Mozilla,
    /// The `--ca-file` certificates.
    Custom,
}

impl From<TrustArg> for TrustSource {
    fn from(arg: TrustArg) -> Self {
        match arg {
            TrustArg::System => TrustSource::System,
            TrustArg::Mozilla => TrustSource::Mozilla,
            TrustArg::Custom => TrustSource::Custom,
        }
    }
}

/// Lowest severity that fails a check (`--fail-on`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum FailOnArg {
    /// Warnings and errors fail.
    Warning,
    /// Only errors fail.
    #[default]
    Error,
}

impl From<FailOnArg> for FailOn {
    fn from(arg: FailOnArg) -> Self {
        match arg {
            FailOnArg::Warning => FailOn::Warning,
            FailOnArg::Error => FailOn::Error,
        }
    }
}

/// Export file format (`--format`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormatArg {
    /// PEM text.
    Pem,
    /// DER, one certificate.
    Der,
    /// The JSON document of `inspect --json`.
    Json,
}

impl From<ExportFormatArg> for ExportFormat {
    fn from(arg: ExportFormatArg) -> Self {
        match arg {
            ExportFormatArg::Pem => ExportFormat::Pem,
            ExportFormatArg::Der => ExportFormat::Der,
            ExportFormatArg::Json => ExportFormat::Json,
        }
    }
}

/// Arguments of `certtui export`.
#[allow(clippy::struct_excessive_bools)]
// Justificativa: the CLI contract is a set of independent boolean flags.
#[derive(Debug, Args)]
pub struct ExportArgs {
    /// What to export from: a file, a keystore, `-` for standard input, or a
    /// TLS server.
    pub target: String,
    /// File format.
    #[arg(long, value_enum)]
    pub format: ExportFormatArg,
    /// Export the certificate at this chain index (default 0).
    #[arg(long, value_name = "N", conflicts_with = "chain")]
    pub index: Option<usize>,
    /// Export every certificate, in the order they were presented (PEM or
    /// JSON; DER holds a single certificate).
    #[arg(long)]
    pub chain: bool,
    /// Where to write the file.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    /// Replace the file if it already exists.
    #[arg(long)]
    pub force: bool,
    /// Treat the target as a file even if it looks like a host name.
    #[arg(long)]
    pub file: bool,
    /// Descend into subdirectories when the target is a directory.
    #[arg(long)]
    pub recursive: bool,
}

/// Arguments of `certtui check`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// What to check: files, directories, `-` for standard input or TLS
    /// servers, as for `inspect`.
    #[arg(required = true)]
    pub targets: Vec<String>,
    /// Lowest severity of a finding that makes the command exit 1 (default
    /// `error`).
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOnArg>,
    /// Warn when a certificate expires within this many days (default 30).
    #[arg(long, value_name = "N")]
    pub warn_days: Option<u32>,
    /// Report an error when a certificate expires within this many days
    /// (default 7).
    #[arg(long, value_name = "N")]
    pub critical_days: Option<u32>,
    /// Machine-readable JSON (`schema_version` 1).
    #[arg(long)]
    pub json: bool,
    /// Treat every target as a file even if it looks like a host name.
    #[arg(long)]
    pub file: bool,
    /// Descend into subdirectories when a target is a directory.
    #[arg(long)]
    pub recursive: bool,
}

/// Fingerprint display format (`--fingerprint-format`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum FingerprintFormatArg {
    /// Upper-case hex pairs separated by colons.
    #[default]
    Colon,
    /// Lower-case hex without separators.
    Hex,
    /// Standard base64.
    Base64,
}

impl From<FingerprintFormatArg> for FingerprintFormat {
    fn from(arg: FingerprintFormatArg) -> Self {
        match arg {
            FingerprintFormatArg::Colon => FingerprintFormat::ColonHexUpper,
            FingerprintFormatArg::Hex => FingerprintFormat::HexLower,
            FingerprintFormatArg::Base64 => FingerprintFormat::Base64,
        }
    }
}

impl From<FingerprintFormatArg> for FingerprintFormatConfig {
    fn from(arg: FingerprintFormatArg) -> Self {
        match arg {
            FingerprintFormatArg::Colon => FingerprintFormatConfig::Colon,
            FingerprintFormatArg::Hex => FingerprintFormatConfig::Hex,
            FingerprintFormatArg::Base64 => FingerprintFormatConfig::Base64,
        }
    }
}

/// The display format a configuration value names.
fn fingerprint_format_of(config: FingerprintFormatConfig) -> FingerprintFormat {
    match config {
        FingerprintFormatConfig::Colon => FingerprintFormat::ColonHexUpper,
        FingerprintFormatConfig::Hex => FingerprintFormat::HexLower,
        FingerprintFormatConfig::Base64 => FingerprintFormat::Base64,
    }
}

/// Arguments of `certtui inspect`.
#[allow(clippy::struct_excessive_bools)]
// Justificativa: the CLI contract is a set of independent boolean flags.
#[derive(Debug, Args)]
pub struct InspectArgs {
    /// What to inspect: a file, a directory, `-` for standard input, or a TLS
    /// server (`host`, `host:port`, `https://host[:port]`, `[v6]:port`).
    pub target: String,
    /// Machine-readable JSON (`schema_version` 1).
    #[arg(long, conflicts_with_all = ["text", "pem", "field"])]
    pub json: bool,
    /// Readable text (the default).
    #[arg(long, conflicts_with_all = ["json", "pem", "field"])]
    pub text: bool,
    /// PEM of the certificates.
    #[arg(long, conflicts_with_all = ["json", "text", "field"])]
    pub pem: bool,
    /// Only the certificate at this chain index (default 0 with `--field`).
    #[arg(long, value_name = "N")]
    pub index: Option<usize>,
    /// Print only the value of one field of the certificate, no decoration.
    #[arg(long, value_name = "FIELD", value_enum)]
    pub field: Option<Field>,
    /// How to display fingerprints (default `colon`).
    #[arg(long, value_enum)]
    pub fingerprint_format: Option<FingerprintFormatArg>,
    /// Treat the target as a file even if it looks like a host name.
    #[arg(long)]
    pub file: bool,
    /// Descend into subdirectories when the target is a directory.
    #[arg(long)]
    pub recursive: bool,
    /// Accepted for compatibility; output never uses colors.
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Clone)]
struct NetworkOptions {
    sni: Option<String>,
    connect_to: Option<ConnectTo>,
    /// `--timeout`, kept to tell that the flag was given.
    timeout: Option<std::time::Duration>,
    /// The limits of the run: defaults, then the config, then `--timeout`.
    limits: Limits,
}

impl NetworkOptions {
    fn network_only_flags(&self) -> Vec<&'static str> {
        [
            ("--sni", self.sni.is_some()),
            ("--connect-to", self.connect_to.is_some()),
            ("--timeout", self.timeout.is_some()),
        ]
        .into_iter()
        .filter_map(|(flag, given)| given.then_some(flag))
        .collect()
    }
}

/// Starts file logging for a run; see [`crate::logging::init_logging`].
pub type LogStarter = dyn Fn(Option<&Path>, LogLevel) -> Result<LogGuard, LoggingError>;

/// What the command needs from the outside world; the composition root
/// supplies the real adapters and tests supply fakes.
#[derive(Clone, Copy)]
pub struct Env<'a> {
    /// Reads local certificates.
    pub loader: &'a dyn SourceLoader,
    /// Fetches the chain of a network target.
    pub fetcher: &'a dyn ChainFetcher,
    /// Decides whether a chain is trusted.
    pub verifier: &'a dyn ChainVerifier,
    /// Source of "now".
    pub clock: &'a dyn Clock,
    /// Builds the trust store provider for the `--ca-file` paths of a run.
    pub trust_provider: &'a dyn Fn(Vec<PathBuf>, Limits) -> Box<dyn TrustStoreProvider>,
    /// Opens the interactive UI.
    pub tui: &'a dyn TuiLauncher,
    /// Writes export files.
    pub writer: &'a dyn FileWriter,
    /// AIA chasing and revocation, between gathering and validating.
    pub enricher: &'a dyn ReportEnricher,
    /// Loads the configuration file; the argument is `--config`.
    pub config: &'a dyn Fn(Option<&Path>) -> Result<Config, ConfigError>,
    /// The environment variables the proxy settings read.
    pub variables: &'a EnvVars,
    /// Starts file logging: the log file, the configured level.
    pub log: &'a LogStarter,
}

/// Trust-related options shared by every command.
#[derive(Clone)]
struct TrustOptions {
    sources: Vec<TrustSource>,
    ca_files: Vec<PathBuf>,
    host_check: Option<String>,
    /// `--aia`, `--revocation` and `--no-revocation`.
    revocation: RevocationOptions,
    /// The keystore password, when one was given.
    password: Option<SecretString>,
    /// Expiry thresholds and the failure policy: config, then flags.
    thresholds: ThresholdsConfig,
    /// How fingerprints are displayed unless `--fingerprint-format` says.
    fingerprint_format: FingerprintFormat,
    /// Interface settings, for the TUI.
    ui: UiConfig,
    /// The proxy of `--proxy`, the config or the environment.
    proxy: Option<ProxySettings>,
    /// The limits of the run, for the trust store (`max_ca_file_certs`, ...).
    limits: Limits,
}

/// Loads the anchors of `options`, reporting warnings on `err`; a failure is
/// a configuration error (exit 2).
fn load_anchors(
    options: &TrustOptions,
    env: &Env<'_>,
    err: &mut dyn Write,
) -> anyhow::Result<Result<TrustAnchors, ExitCode>> {
    let provider = (env.trust_provider)(options.ca_files.clone(), options.limits);
    match provider.anchors(&options.sources) {
        Ok(anchors) => {
            for warning in &anchors.warnings {
                writeln!(err, "certtui: warning: {}", output::single_line(warning))
                    .context("writing the trust warning")?;
            }
            if anchors.is_empty() {
                writeln!(err, "certtui: warning: no trust anchors loaded")
                    .context("writing the trust warning")?;
            }
            Ok(Ok(anchors))
        }
        Err(error) => usage(err, &output::single_line(&error.to_string())).map(Err),
    }
}

/// Everything [`validate`] needs that does not depend on the report.
struct Validation<'a> {
    env: &'a Env<'a>,
    anchors: &'a TrustAnchors,
    thresholds: Thresholds,
    host_check: Option<&'a str>,
    revocation: RevocationOptions,
}

impl Validation<'_> {
    /// The report with AIA and revocation done, its trust verdict and its
    /// findings filled in; see [`validate_for_target`].
    fn apply(&self, report: InspectionReport) -> anyhow::Result<InspectionReport> {
        // Nothing cancels the token yet: Ctrl-C ends the process through the
        // default SIGINT disposition, which is all a one-shot command needs.
        let report = runtime::block_on(self.env.enricher.enrich(
            report,
            &known_issuers(self.anchors),
            self.revocation,
            CancellationToken::new(),
        ))?;
        Ok(validate_for_target(
            report,
            self.env.verifier,
            self.anchors,
            self.env.clock,
            self.thresholds,
            self.host_check,
        ))
    }
}

/// `report` with its trust verdict and findings filled in. A network target
/// is checked against its SNI, or else its host, unless `host_check` names
/// another name.
pub fn validate_for_target(
    report: InspectionReport,
    verifier: &dyn ChainVerifier,
    anchors: &TrustAnchors,
    clock: &dyn Clock,
    thresholds: Thresholds,
    host_check: Option<&str>,
) -> InspectionReport {
    let network_host = match &report.target {
        Target::Network(network) => {
            Some(network.sni.clone().unwrap_or_else(|| network.host.clone()))
        }
        _ => None,
    };
    validate(
        report,
        ValidationInputs {
            verifier,
            anchors,
            clock,
            thresholds,
            hostname: host_check.map(str::to_owned).or(network_host.clone()),
            is_network_target: network_host.is_some(),
        },
    )
}

/// How the certificates are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Text,
    Json,
    Pem,
    Field(Field),
}

impl InspectArgs {
    fn mode(&self) -> Mode {
        match (self.field, self.json, self.pem) {
            (Some(field), _, _) => Mode::Field(field),
            (None, true, _) => Mode::Json,
            (None, false, true) => Mode::Pem,
            (None, false, false) => Mode::Text,
        }
    }
}

/// Parses `args` and runs the command, writing results to `out` and
/// diagnostics to `err`.
///
/// # Errors
///
/// Unexpected failures (such as a failed write to `out`); expected failures
/// are reported on `err` and returned as an [`ExitCode`].
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let message = error.render().to_string();
            let code = if error.use_stderr() {
                write!(err, "{message}")
                    .context("writing the usage message")
                    .map(|()| ExitCode::Usage)
            } else {
                write!(out, "{message}")
                    .context("writing the help message")
                    .map(|()| ExitCode::Ok)
            };
            return code;
        }
    };
    let resolved = match load_settings(&cli, env, err)? {
        Ok(resolved) => resolved,
        Err(code) => return Ok(code),
    };
    let (_log, proxy) = match start_services(&cli, &resolved, env, err)? {
        Ok(started) => started,
        Err(code) => return Ok(code),
    };
    let network_options = match cli.sni.as_deref().map(parse_sni).transpose() {
        Ok(sni) => NetworkOptions {
            sni,
            connect_to: cli.connect_to,
            timeout: cli.timeout,
            limits: resolved.limits,
        },
        Err(message) => return usage(err, &format!("--sni: {message}")),
    };
    let password = match read_password(&cli, err)? {
        Ok(password) => password,
        Err(code) => return Ok(code),
    };
    env.loader.set_password(password.clone());
    let trust_options = TrustOptions {
        sources: resolve_sources(
            &resolved.trust_sources,
            !resolved.ca_files.is_empty(),
            cli.ca_only,
        ),
        ca_files: resolved.ca_files,
        host_check: cli.host_check,
        revocation: RevocationOptions {
            scope: match resolved.revocation {
                RevocationMode::Off => RevocationScope::Off,
                RevocationMode::Full => RevocationScope::Full,
                RevocationMode::Leaf => RevocationScope::Leaf,
            },
            aia: resolved.aia,
            allow_internal_urls: cli.allow_internal_urls,
        },
        password,
        thresholds: resolved.thresholds,
        fingerprint_format: fingerprint_format_of(resolved.ui.fingerprint_format),
        ui: resolved.ui,
        proxy,
        limits: resolved.limits,
    };
    match cli.command {
        Some(Command::Inspect(inspect_args)) => inspect(
            &inspect_args,
            &network_options,
            &trust_options,
            env,
            out,
            err,
        ),
        Some(Command::Check(check_args)) => {
            check(&check_args, &network_options, &trust_options, env, out, err)
        }
        Some(Command::Batch(batch_args)) => {
            batch::run(&batch_args, &network_options, &trust_options, env, out, err)
        }
        Some(Command::Export(export_args)) => {
            export(&export_args, &network_options, &trust_options, env, err)
        }
        Some(Command::External(words)) => match words.as_slice() {
            [target] => open_tui(
                Some(target),
                &network_options,
                &trust_options,
                env,
                out,
                err,
            ),
            _ => usage(
                err,
                "options go before the target: certtui [OPTIONS] <TARGET>",
            ),
        },
        None => open_tui(None, &network_options, &trust_options, env, out, err),
    }
}

/// The keystore password the command line asks for, or the exit code of a
/// usage error.
fn read_password(
    cli: &Cli,
    err: &mut dyn Write,
) -> anyhow::Result<Result<Option<SecretString>, ExitCode>> {
    let password_source = match (
        cli.password_env.clone(),
        cli.password_file.clone(),
        cli.password_stdin,
    ) {
        (Some(name), _, _) => Some(PasswordSource::Env(name)),
        (None, Some(path), _) => Some(PasswordSource::File(path)),
        (None, None, true) => Some(PasswordSource::Stdin),
        (None, None, false) => None,
    };
    if password_source == Some(PasswordSource::Stdin) && reads_stdin_target(cli.command.as_ref()) {
        return usage(
            err,
            "--password-stdin cannot be combined with the target `-`: both read standard input; \
             use --password-env or --password-file for the password",
        )
        .map(Err);
    }
    match resolve_password(
        password_source.as_ref(),
        &mut std::io::stdin().lock(),
        &|name| std::env::var(name).ok(),
    ) {
        Ok(password) => Ok(Ok(password)),
        Err(error) => usage(err, &error.to_string()).map(Err),
    }
}

/// Starts the log and points the network adapters at the proxy, or gives the
/// exit code of a setting that cannot be used. The guard must outlive the run.
fn start_services(
    cli: &Cli,
    resolved: &ResolvedConfig,
    env: &Env<'_>,
    err: &mut dyn Write,
) -> anyhow::Result<Result<(LogGuard, Option<ProxySettings>), ExitCode>> {
    let guard = match (env.log)(resolved.log_file.as_deref(), resolved.log_level) {
        Ok(guard) => guard,
        Err(error) => return usage(err, &output::single_line(&error.to_string())).map(Err),
    };
    log_start(cli, resolved);
    let proxy = match proxy_settings(resolved, env.variables) {
        Ok(proxy) => proxy,
        Err(message) => return usage(err, &message).map(Err),
    };
    env.fetcher.use_proxy(proxy.clone());
    env.enricher.use_proxy(proxy.clone());
    env.enricher.use_limits(resolved.limits);
    Ok(Ok((guard, proxy)))
}

/// What the log says about this run: version, command, and every limit the
/// configuration asked for above its hard cap. Never a password or a path
/// that came from a certificate.
fn log_start(cli: &Cli, resolved: &ResolvedConfig) {
    let command = match &cli.command {
        Some(Command::Inspect(_)) => "inspect",
        Some(Command::Check(_)) => "check",
        Some(Command::Batch(_)) => "batch",
        Some(Command::Export(_)) => "export",
        Some(Command::External(_)) | None => "interactive",
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        command,
        "certtui started"
    );
    for warning in &resolved.limit_warnings {
        tracing::warn!(
            field = warning.field,
            requested = warning.requested,
            applied = warning.applied,
            "limit override above its hard cap; truncated"
        );
    }
    if let Some(variable) = &cli.password_env {
        tracing::debug!(
            variable = variable.as_str(),
            "keystore password read from the environment"
        );
    }
    if cli.password_file.is_some() {
        tracing::debug!("keystore password read from a file");
    }
    tracing::debug!(
        trust_sources = resolved.trust_sources.len(),
        proxy = resolved.proxy.is_some(),
        aia = resolved.aia,
        "settings resolved"
    );
}

/// The configuration file merged with the command line, or the exit code of
/// a configuration that cannot be used.
fn load_settings(
    cli: &Cli,
    env: &Env<'_>,
    err: &mut dyn Write,
) -> anyhow::Result<Result<ResolvedConfig, ExitCode>> {
    let config = match (env.config)(cli.config.as_deref()) {
        Ok(config) => config,
        Err(error) => return config_error(err, &error).map(Err),
    };
    let resolved = match config.resolve(&overrides_from(cli)) {
        Ok(resolved) => resolved,
        Err(error) => return config_error(err, &error).map(Err),
    };
    if let Err(error) = resolved
        .ui
        .clipboard
        .parse::<ClipboardStrategy>()
        .and_then(ClipboardStrategy::check_supported)
    {
        return usage(err, &format!("ui.clipboard: {error}")).map(Err);
    }
    if let Err(error) = Keymap::from_overrides(&resolved.ui.keymap) {
        return usage(err, &format!("ui.keymap: {error}")).map(Err);
    }
    Ok(Ok(resolved))
}

/// The settings the command line gives; they win over the config file.
fn overrides_from(cli: &Cli) -> CliOverrides {
    let (warn_days, critical_days, fail_on) = match &cli.command {
        Some(Command::Check(args)) => (
            args.warn_days,
            args.critical_days,
            args.fail_on.map(FailOn::from),
        ),
        Some(Command::Batch(args)) => (None, None, args.fail_on.map(FailOn::from)),
        _ => (None, None, None),
    };
    let fingerprint_format = match &cli.command {
        Some(Command::Inspect(args)) => args.fingerprint_format.map(Into::into),
        _ => None,
    };
    CliOverrides {
        trust_sources: cli.trust.iter().copied().map(TrustSource::from).collect(),
        ca_files: cli.ca_file.clone(),
        warn_days,
        critical_days,
        fail_on,
        timeout_secs: cli.timeout.map(|timeout| timeout.as_secs()),
        proxy: cli.proxy.clone(),
        no_proxy: cli.no_proxy,
        log_file: cli.log_file.clone(),
        aia: match (cli.aia, cli.no_aia) {
            (true, _) => Some(true),
            (false, true) => Some(false),
            (false, false) => None,
        },
        revocation: match (cli.no_revocation, cli.revocation) {
            (true, _) => Some(RevocationMode::Off),
            (false, Some(RevocationArg::Full)) => Some(RevocationMode::Full),
            (false, Some(RevocationArg::Leaf)) => Some(RevocationMode::Leaf),
            (false, None) => None,
        },
        fingerprint_format,
        ..CliOverrides::default()
    }
}

/// The proxy to use: `--proxy` or `network.proxy` (for every target), else the
/// environment when `network.use_env_proxy` allows it.
fn proxy_settings(
    resolved: &ResolvedConfig,
    vars: &EnvVars,
) -> Result<Option<ProxySettings>, String> {
    match &resolved.proxy {
        Some(url) => Ok(Some(ProxySettings {
            endpoint: parse_proxy_url(url).map_err(|error| error.to_string())?,
            no_proxy: None,
        })),
        None => EnvProxy::from_env(vars, resolved.use_env_proxy)
            .map_err(|error| format!("HTTPS_PROXY: {error}")),
    }
}

/// A configuration that cannot be used is a usage error (exit 2).
fn config_error(err: &mut dyn Write, error: &ConfigError) -> anyhow::Result<ExitCode> {
    usage(err, &output::single_line(&error.to_string()))
}

/// Whether the command names `-` (standard input) as a target.
fn reads_stdin_target(command: Option<&Command>) -> bool {
    match command {
        Some(Command::Inspect(args)) => args.target == "-",
        Some(Command::Check(args)) => args.targets.iter().any(|target| target == "-"),
        Some(Command::Export(args)) => args.target == "-",
        Some(Command::Batch(args)) => args.file == "-",
        Some(Command::External(words)) => words.iter().any(|word| word == "-"),
        None => false,
    }
}

/// `certtui [TARGET]`: the interactive UI, or `inspect --text` when there is
/// no terminal to draw on.
fn open_tui(
    target_arg: Option<&str>,
    network_options: &NetworkOptions,
    trust_options: &TrustOptions,
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let target = match target_arg
        .map(|arg| parse_target(arg, false, false, &|path| path.exists()))
        .transpose()
    {
        Ok(target) => target,
        Err(error) => return usage(err, &error.to_string()),
    };
    if !env.tui.is_interactive() {
        let Some(arg) = target_arg else {
            return usage(
                err,
                "no terminal available; give a target, as in `certtui inspect <TARGET>`",
            );
        };
        let args = InspectArgs {
            target: arg.to_owned(),
            json: false,
            text: true,
            pem: false,
            index: None,
            field: None,
            fingerprint_format: None,
            file: false,
            recursive: false,
            no_color: false,
        };
        return inspect(&args, network_options, trust_options, env, out, err);
    }
    if let Some(local) = target.as_ref().filter(|t| !matches!(t, Target::Network(_))) {
        let flags = network_options.network_only_flags();
        if !flags.is_empty() && local_source(local).is_some() {
            let verb = if flags.len() == 1 { "applies" } else { "apply" };
            return usage(
                err,
                &format!("{} only {verb} to network targets", flags.join(", ")),
            );
        }
    }
    // Standard input is read whole before the terminal enters raw mode: the
    // keys then come from the terminal device, and a pipe never blocks them.
    let stdin = if matches!(target, Some(Target::Stdin)) {
        match env
            .loader
            .load(&LocalSource::Stdin, &network_options.limits)
        {
            Ok(loaded) => Some(loaded),
            Err(error) => return load_failure(err, &error),
        }
    } else {
        None
    };
    let request = TuiRequest {
        target,
        stdin,
        batch: None,
        batch_concurrency: None,
        options: inspector_options(network_options, trust_options),
        ui: trust_options.ui.clone(),
    };
    env.tui.launch(request)?;
    Ok(ExitCode::Ok)
}

/// The command line options an inspection inside the TUI honors.
fn inspector_options(
    network_options: &NetworkOptions,
    trust_options: &TrustOptions,
) -> InspectorOptions {
    InspectorOptions {
        sni: network_options.sni.clone(),
        connect_to: network_options.connect_to,
        limits: network_options.limits,
        thresholds: to_thresholds(&trust_options.thresholds),
        trust_sources: trust_options.sources.clone(),
        ca_files: trust_options.ca_files.clone(),
        host_check: trust_options.host_check.clone(),
        revocation: trust_options.revocation,
        password: trust_options.password.clone(),
        proxy: trust_options.proxy.clone(),
        fingerprint_format: trust_options.fingerprint_format,
    }
}

fn inspect(
    args: &InspectArgs,
    network_options: &NetworkOptions,
    trust_options: &TrustOptions,
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let target = match parse_target(&args.target, args.file, args.recursive, &|path| {
        path.exists()
    }) {
        Ok(target) => target,
        Err(error) => return usage(err, &error.to_string()),
    };
    let anchors = match load_anchors(trust_options, env, err)? {
        Ok(anchors) => anchors,
        Err(code) => return Ok(code),
    };
    let report = match gather(network_options, env, target, err)? {
        Ok(report) => report,
        Err(code) => return Ok(code),
    };
    let report = Validation {
        env,
        anchors: &anchors,
        thresholds: to_thresholds(&trust_options.thresholds),
        host_check: trust_options.host_check.as_deref(),
        revocation: trust_options.revocation,
    }
    .apply(report)?;
    let mode = args.mode();
    let only = match (args.index, mode) {
        (Some(index), _) => Some(index),
        (None, Mode::Field(_)) => Some(0),
        (None, _) => None,
    };
    if let Some(index) = only
        && index >= report.chain.len()
    {
        return usage(
            err,
            &format!(
                "--index {index} is out of range: {} certificate(s) found",
                report.chain.len()
            ),
        );
    }
    let view = View {
        report: &report,
        only,
        fingerprint_format: args
            .fingerprint_format
            .map_or(trust_options.fingerprint_format, Into::into),
    };
    render(mode, &view, out, err)?;
    Ok(ExitCode::Ok)
}

/// `certtui export`: render the certificates and write them atomically.
fn export(
    args: &ExportArgs,
    network_options: &NetworkOptions,
    trust_options: &TrustOptions,
    env: &Env<'_>,
    err: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let target = match parse_target(&args.target, args.file, args.recursive, &|path| {
        path.exists()
    }) {
        Ok(target) => target,
        Err(error) => return usage(err, &error.to_string()),
    };
    let format = ExportFormat::from(args.format);
    let selection = if args.chain {
        ExportSelection::Chain
    } else {
        ExportSelection::Index(args.index.unwrap_or(0))
    };
    // A request that cannot work is refused before touching the target: no
    // network round trip, no password prompt for a file that would not be written.
    if format == ExportFormat::Der && selection == ExportSelection::Chain {
        return usage(err, &ExportError::DerCannotRepresentChain.to_string());
    }
    let report = match gather(network_options, env, target, err)? {
        Ok(report) => report,
        Err(code) => return Ok(code),
    };
    // The JSON is the document `inspect --json` prints, validation included;
    // PEM and DER need only the certificates.
    let report = if format == ExportFormat::Json {
        let anchors = match load_anchors(trust_options, env, err)? {
            Ok(anchors) => anchors,
            Err(code) => return Ok(code),
        };
        Validation {
            env,
            anchors: &anchors,
            thresholds: to_thresholds(&trust_options.thresholds),
            host_check: trust_options.host_check.as_deref(),
            revocation: trust_options.revocation,
        }
        .apply(report)?
    } else {
        report
    };
    let bytes = match render_export(&report, format, selection) {
        Ok(bytes) => bytes,
        Err(error) => return usage(err, &error.to_string()),
    };
    let overwrite = if args.force {
        Overwrite::Allow
    } else {
        Overwrite::Refuse
    };
    let shown = output::single_line(&args.out.to_string_lossy());
    match env.writer.write(&args.out, &bytes, overwrite) {
        Ok(()) => {
            writeln!(err, "certtui: wrote {shown} ({} bytes)", bytes.len())
                .context("writing the confirmation")?;
            Ok(ExitCode::Ok)
        }
        Err(WriteError::AlreadyExists) => usage(
            err,
            &format!("{shown} already exists; use --force to replace it"),
        ),
        Err(error @ (WriteError::IsDirectory | WriteError::ParentMissing)) => {
            usage(err, &format!("{shown}: {error}"))
        }
        Err(WriteError::Io(message)) => {
            writeln!(
                err,
                "certtui: cannot write {shown}: {}",
                output::single_line(&message)
            )
            .context("writing the error")?;
            Ok(ExitCode::Internal)
        }
    }
}

fn check(
    args: &CheckArgs,
    network_options: &NetworkOptions,
    trust_options: &TrustOptions,
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let mut targets = Vec::new();
    for raw in &args.targets {
        match parse_target(raw, args.file, args.recursive, &|path| path.exists()) {
            Ok(target) => targets.push((raw.as_str(), target)),
            Err(error) => return usage(err, &error.to_string()),
        }
    }
    let thresholds = match thresholds(args, &trust_options.thresholds) {
        Ok(thresholds) => thresholds,
        Err(message) => return usage(err, &message),
    };
    let anchors = match load_anchors(trust_options, env, err)? {
        Ok(anchors) => anchors,
        Err(code) => return Ok(code),
    };
    let validation = Validation {
        env,
        anchors: &anchors,
        thresholds,
        host_check: trust_options.host_check.as_deref(),
        revocation: trust_options.revocation,
    };
    let mut checked: Vec<(&str, Result<InspectionReport, String>)> = Vec::new();
    for (raw, target) in targets {
        // The fetch and load failures are written as `certtui: <message>`; they
        // are captured so each can be attributed to its target.
        let mut failure = Vec::new();
        match gather(network_options, env, target, &mut failure)? {
            Ok(report) => checked.push((raw, Ok(validation.apply(report)?))),
            Err(ExitCode::Usage) => {
                err.write_all(&failure).context("writing the usage error")?;
                return Ok(ExitCode::Usage);
            }
            Err(_) => {
                let message = report_failure(err, raw, &failure)?;
                checked.push((raw, Err(message)));
            }
        }
    }
    let results: Vec<TargetResult<'_>> = checked
        .iter()
        .map(|(target, outcome)| TargetResult {
            target,
            outcome: outcome.as_ref().map_err(String::as_str),
        })
        .collect();
    if args.json {
        output::check::write_json(out, &results)
    } else {
        output::check::write_text(out, &results)
    }
    .context("writing the output")?;
    Ok(exit_code_of(
        &results,
        args.fail_on
            .map_or(trust_options.thresholds.fail_on, Into::into),
    ))
}

/// Writes a captured failure on `err`, each line attributed to `target`, and
/// returns the first line without its `certtui: ` prefix.
fn report_failure(err: &mut dyn Write, target: &str, captured: &[u8]) -> anyhow::Result<String> {
    let text = String::from_utf8_lossy(captured);
    let target = output::single_line(target);
    let mut first = None;
    for line in text.lines() {
        let message = line.strip_prefix("certtui: ").unwrap_or(line);
        writeln!(err, "certtui: {target}: {message}").context("writing the failure")?;
        first.get_or_insert_with(|| message.to_owned());
    }
    Ok(first.unwrap_or_else(|| "failed".to_owned()))
}

/// 3 when no target could be checked, 1 when some failed or a finding reaches
/// `fail_on`, 0 otherwise.
fn exit_code_of(results: &[TargetResult<'_>], fail_on: FailOn) -> ExitCode {
    let failed = results
        .iter()
        .filter(|result| result.outcome.is_err())
        .count();
    if failed == results.len() {
        return ExitCode::Input;
    }
    let findings_fail = results
        .iter()
        .filter_map(|result| result.outcome.ok())
        .any(|report| fail_on.fails(&report.findings));
    if failed > 0 || findings_fail {
        ExitCode::Findings
    } else {
        ExitCode::Ok
    }
}

/// The thresholds of a `check`: the config and the flags are already merged
/// in `merged`; only their consistency is checked here.
fn thresholds(args: &CheckArgs, merged: &ThresholdsConfig) -> Result<Thresholds, String> {
    let ThresholdsConfig {
        warn_days,
        critical_days,
        ..
    } = *merged;
    if critical_days > warn_days {
        let from_flags = args.warn_days.is_some() || args.critical_days.is_some();
        return Err(if from_flags {
            format!("--critical-days ({critical_days}) must not exceed --warn-days ({warn_days})")
        } else {
            format!(
                "thresholds.critical_days ({critical_days}) must not exceed \
                 thresholds.warn_days ({warn_days})"
            )
        });
    }
    Ok(to_thresholds(merged))
}

/// The lint thresholds of the configuration.
pub(crate) fn to_thresholds(config: &ThresholdsConfig) -> Thresholds {
    Thresholds {
        warn_days: config.warn_days,
        critical_days: config.critical_days,
        ..Thresholds::default()
    }
}

/// The report of `target`, or the exit code of a failure already reported on
/// `err`.
fn gather(
    network_options: &NetworkOptions,
    env: &Env<'_>,
    target: Target,
    err: &mut dyn Write,
) -> anyhow::Result<Result<InspectionReport, ExitCode>> {
    match target {
        Target::Network(network) => gather_network(network_options, env, network, err),
        local => gather_local(network_options, env, local, err),
    }
}

fn gather_local(
    network_options: &NetworkOptions,
    env: &Env<'_>,
    target: Target,
    err: &mut dyn Write,
) -> anyhow::Result<Result<InspectionReport, ExitCode>> {
    let flags = network_options.network_only_flags();
    if !flags.is_empty() {
        let verb = if flags.len() == 1 { "applies" } else { "apply" };
        let message = format!("{} only {verb} to network targets", flags.join(", "));
        return usage(err, &message).map(Err);
    }
    let source = local_source(&target)
        .ok_or_else(|| anyhow::anyhow!("a network target reached the local loader"))?;
    match inspect_local(env.loader, &source, target, &network_options.limits) {
        Ok(report) => Ok(Ok(report)),
        Err(error) => load_failure(err, &error).map(Err),
    }
}

fn gather_network(
    network_options: &NetworkOptions,
    env: &Env<'_>,
    parsed: NetworkTarget,
    err: &mut dyn Write,
) -> anyhow::Result<Result<InspectionReport, ExitCode>> {
    let limits = network_options.limits;
    let target = NetworkTarget {
        sni: network_options.sni.clone(),
        connect_to: network_options.connect_to.map(|connect_to| {
            std::net::SocketAddr::new(connect_to.ip, connect_to.port.unwrap_or(parsed.port))
        }),
        ..parsed
    };
    // Nothing cancels the token yet: Ctrl-C ends the process through the
    // default SIGINT disposition, which is all a one-shot command needs.
    let cancel = CancellationToken::new();
    let fetched = runtime::block_on(inspect_network(env.fetcher, target, &limits, cancel))?;
    match fetched {
        Ok(report) => Ok(Ok(report)),
        Err(error) => inspect_failure(err, &error).map(Err),
    }
}

fn render(
    mode: Mode,
    view: &View<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<()> {
    match mode {
        Mode::Text => output::text::write(out, view),
        Mode::Json => output::json::write(out, view),
        Mode::Pem => {
            write_notes(err, &view.report.notes)?;
            output::pem::write(out, view)
        }
        Mode::Field(field) => {
            write_notes(err, &view.report.notes)?;
            let record = view.certs().next();
            record.map_or(Ok(()), |(_, record)| {
                output::field::write(out, record, field, view.fingerprint_format)
            })
        }
    }
    .context("writing the output")
}

/// Notes of modes whose stdout is pure data go to stderr.
fn write_notes(err: &mut dyn Write, notes: &[LoadNote]) -> anyhow::Result<()> {
    for note in notes {
        writeln!(err, "certtui: note: {}", output::note_text(note))
            .context("writing diagnostics")?;
    }
    Ok(())
}

fn usage(err: &mut dyn Write, message: &str) -> anyhow::Result<ExitCode> {
    writeln!(err, "certtui: {message}").context("writing the usage error")?;
    Ok(ExitCode::Usage)
}

fn inspect_failure(err: &mut dyn Write, error: &InspectError) -> anyhow::Result<ExitCode> {
    // The messages come from the fetcher, which already keeps them to short
    // printable text; the escaping is a second line of defense.
    writeln!(err, "certtui: {}", output::single_line(&error.to_string()))
        .context("writing the fetch error")?;
    if let InspectError::NoUsableCertificates { notes } = error {
        write_notes(err, notes)?;
    }
    Ok(ExitCode::from(error))
}

fn load_failure(err: &mut dyn Write, error: &LoadError) -> anyhow::Result<ExitCode> {
    writeln!(err, "certtui: {error}").context("writing the load error")?;
    if matches!(error, LoadError::PasswordRequired) {
        writeln!(
            err,
            "certtui: use --password-env, --password-file or --password-stdin"
        )
        .context("writing the load error")?;
    }
    if let LoadError::NoCertificatesFound { notes } = error {
        write_notes(err, notes)?;
    }
    Ok(ExitCode::from(error))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;
    use std::time::Duration;

    use certtui_app::enrich::NoEnricher;
    use certtui_app::error::LoadError;
    use certtui_app::fetch::{FetchError, FetchRequest, FetchedChain, Stage};
    use certtui_app::ports::{ChainVerification, LoadedCerts};
    use certtui_app::testing::{
        FakeChainFetcher, FakeChainVerifier, FakeFileWriter, FakeSourceLoader, FakeTrustProvider,
        FixedClock,
    };
    use certtui_app::trust::TrustAnchor;
    use certtui_domain::model::{CertRevocation, RevocationStatus, StapleState};
    use certtui_domain::model::{Timings, TlsSessionInfo, TrustVerdict};
    use certtui_domain::time::Timestamp;
    use serde_json::Value;

    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    /// Records every request and answers with a canned result.
    struct Recording {
        requests: Mutex<Vec<FetchRequest>>,
        answer: Result<FetchedChain, FetchError>,
    }

    #[async_trait::async_trait]
    impl ChainFetcher for Recording {
        async fn fetch(
            &self,
            req: &FetchRequest,
            _cancel: CancellationToken,
        ) -> Result<FetchedChain, FetchError> {
            self.requests.lock().unwrap().push(req.clone());
            self.answer.clone()
        }
    }

    fn chain(ders: Vec<Vec<u8>>) -> FetchedChain {
        FetchedChain {
            ders,
            ocsp_staple: None,
            session: Some(TlsSessionInfo {
                version: "TLSv1.3".to_owned(),
                cipher_suite: "TLS_AES_256_GCM_SHA384".to_owned(),
                key_exchange_group: None,
                alpn: None,
                peer_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            }),
            note: None,
            timings: Timings {
                handshake: Some(Duration::from_millis(41)),
                ..Timings::default()
            },
        }
    }

    fn leaf_der() -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/rsa2048-leaf.der")).unwrap()
    }

    /// Records what the UI would be opened with.
    struct FakeLauncher {
        interactive: bool,
        requests: Mutex<Vec<TuiRequest>>,
    }

    impl FakeLauncher {
        fn new(interactive: bool) -> Self {
            Self {
                interactive,
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<TuiRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl TuiLauncher for FakeLauncher {
        fn is_interactive(&self) -> bool {
            self.interactive
        }

        fn launch(&self, request: TuiRequest) -> anyhow::Result<()> {
            self.requests.lock().unwrap().push(request);
            Ok(())
        }
    }

    struct Outcome {
        code: ExitCode,
        out: String,
        err: String,
    }

    /// Runs the CLI with fake adapters: the verifier trusts everything, the
    /// clock is fixed and the trust store is empty.
    fn run_in_env(
        loader: &dyn SourceLoader,
        fetcher: &dyn ChainFetcher,
        args: &[&str],
    ) -> (anyhow::Result<ExitCode>, Vec<u8>, Vec<u8>) {
        run_with_launcher(loader, fetcher, &FakeLauncher::new(false), args)
    }

    fn run_with_launcher(
        loader: &dyn SourceLoader,
        fetcher: &dyn ChainFetcher,
        launcher: &dyn TuiLauncher,
        args: &[&str],
    ) -> (anyhow::Result<ExitCode>, Vec<u8>, Vec<u8>) {
        run_full(
            loader,
            fetcher,
            launcher,
            &NoEnricher,
            &FakeFileWriter::new(Ok(())),
            args,
        )
    }

    fn run_full(
        loader: &dyn SourceLoader,
        fetcher: &dyn ChainFetcher,
        launcher: &dyn TuiLauncher,
        enricher: &dyn ReportEnricher,
        writer: &dyn FileWriter,
        args: &[&str],
    ) -> (anyhow::Result<ExitCode>, Vec<u8>, Vec<u8>) {
        let verifier = FakeChainVerifier::new(ChainVerification {
            trust: TrustVerdict::Trusted {
                anchor: "Fake Root".to_owned(),
            },
            hostname_ok: None,
        });
        let clock = FixedClock(Timestamp::from_unix(1_769_904_000).unwrap());
        let provider = |_files: Vec<PathBuf>, limits: Limits| -> Box<dyn TrustStoreProvider> {
            PROVIDER_LIMITS.lock().unwrap().push(limits);
            // One anchor, so the "no trust anchors loaded" warning stays out
            // of the stderr these tests compare.
            Box::new(FakeTrustProvider(Ok(TrustAnchors {
                entries: vec![TrustAnchor {
                    subject_der: Vec::new(),
                    spki_der: Vec::new(),
                    name_constraints_der: None,
                    source: TrustSource::System,
                    label: "Fake Root".to_owned(),
                }],
                warnings: Vec::new(),
            })))
        };
        let env = Env {
            loader,
            fetcher,
            verifier: &verifier,
            clock: &clock,
            trust_provider: &provider,
            tui: launcher,
            writer,
            enricher,
            config: &|_| Ok(Config::default()),
            variables: &EnvVars::default(),
            log: &|_, _| Ok(LogGuard::none()),
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let cli_args = std::iter::once("certtui").chain(args.iter().copied());
        let result = run(cli_args.map(OsString::from), &env, &mut out, &mut err);
        (result, out, err)
    }

    fn run_with(fetcher: &dyn ChainFetcher, args: &[&str]) -> Outcome {
        let loader = FakeSourceLoader(Err(LoadError::Io("no files in unit tests".to_owned())));
        let (code, out, err) = run_in_env(&loader, fetcher, args);
        let code = code.unwrap();
        Outcome {
            code,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    /// Limits every trust provider of the tests was built with.
    static PROVIDER_LIMITS: Mutex<Vec<Limits>> = Mutex::new(Vec::new());

    #[test]
    fn quando_run_comeca_deve_construir_o_trust_provider_com_os_limites_resolvidos() {
        let fake = enricher(Vec::new(), StapleState::Missing);
        let got = run_enriched(
            &fake,
            &["--timeout", "13", "inspect", "example.test", "--json"],
        );
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        assert!(
            PROVIDER_LIMITS
                .lock()
                .unwrap()
                .iter()
                .any(|limits| limits.target_total_timeout == Duration::from_secs(13)),
            "no trust provider saw the resolved limits"
        );
    }

    /// Records the options of every enrichment and fills in a canned
    /// revocation outcome, like the real enricher would for a network target.
    struct FakeEnricher {
        calls: Mutex<Vec<RevocationOptions>>,
        limits_seen: Mutex<Vec<Limits>>,
        revocation: Vec<CertRevocation>,
        staple: StapleState,
    }

    #[async_trait::async_trait]
    impl ReportEnricher for FakeEnricher {
        fn use_limits(&self, limits: Limits) {
            self.limits_seen.lock().unwrap().push(limits);
        }

        async fn enrich(
            &self,
            mut report: InspectionReport,
            _anchors: &[certtui_domain::chain_analysis::KnownIssuer],
            options: RevocationOptions,
            _cancel: CancellationToken,
        ) -> InspectionReport {
            self.calls.lock().unwrap().push(options);
            if options.scope != RevocationScope::Off {
                report.revocation.clone_from(&self.revocation);
                report.staple = self.staple.clone();
            }
            report
        }
    }

    fn enricher(revocation: Vec<CertRevocation>, staple: StapleState) -> FakeEnricher {
        FakeEnricher {
            calls: Mutex::new(Vec::new()),
            limits_seen: Mutex::new(Vec::new()),
            revocation,
            staple,
        }
    }

    fn run_enriched(enricher: &FakeEnricher, args: &[&str]) -> Outcome {
        let loader = FakeSourceLoader(Err(LoadError::Io("no files in unit tests".to_owned())));
        // The leaf of a 3-certificate chain: issued by someone else, so no
        // self-signed error clouds the exit code the revocation tests check.
        let leaf = std::fs::read(format!("{FIXTURES}/chain-3.der")).unwrap();
        let fetcher = FakeChainFetcher(Ok(chain(vec![leaf])));
        let (code, out, err) = run_full(
            &loader,
            &fetcher,
            &FakeLauncher::new(false),
            enricher,
            &FakeFileWriter::new(Ok(())),
            args,
        );
        Outcome {
            code: code.unwrap(),
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    fn entry(status: RevocationStatus) -> CertRevocation {
        CertRevocation {
            cert_index: 0,
            status,
        }
    }

    #[test]
    fn quando_sem_flags_de_revogacao_deve_usar_leaf_sem_aia() {
        let fake = enricher(Vec::new(), StapleState::Missing);
        let got = run_enriched(&fake, &["inspect", "example.test", "--json"]);
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec![RevocationOptions::default()]
        );
    }

    #[test]
    fn quando_run_comeca_deve_entregar_os_limites_resolvidos_ao_enricher() {
        let fake = enricher(Vec::new(), StapleState::Missing);
        let got = run_enriched(
            &fake,
            &["--timeout", "7", "inspect", "example.test", "--json"],
        );
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        let seen = fake.limits_seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].target_total_timeout, Duration::from_secs(7));
        assert_eq!(seen[0].max_crl_bytes, Limits::default().max_crl_bytes);
    }

    #[test]
    fn quando_no_aia_e_no_proxy_deve_virar_override_explicito() {
        let overrides = |args: &[&str]| {
            let cli = Cli::try_parse_from(std::iter::once("certtui").chain(args.iter().copied()))
                .unwrap();
            overrides_from(&cli)
        };
        assert_eq!(overrides(&["--no-aia", "inspect", "x"]).aia, Some(false));
        assert_eq!(overrides(&["--aia", "inspect", "x"]).aia, Some(true));
        assert_eq!(overrides(&["inspect", "x"]).aia, None);
        assert!(overrides(&["--no-proxy", "inspect", "x"]).no_proxy);
        assert!(!overrides(&["inspect", "x"]).no_proxy);
    }

    #[test]
    fn quando_flags_de_revogacao_e_aia_deve_chegar_ao_enricher() {
        let with = |scope, aia, allow_internal_urls| RevocationOptions {
            scope,
            aia,
            allow_internal_urls,
        };
        let cases: [(&[&str], RevocationOptions); 5] = [
            (
                &["--revocation", "full"],
                with(RevocationScope::Full, false, false),
            ),
            (
                &["--revocation", "leaf", "--aia"],
                with(RevocationScope::Leaf, true, false),
            ),
            (
                &["--no-revocation"],
                with(RevocationScope::Off, false, false),
            ),
            (
                &["--aia", "--no-revocation"],
                with(RevocationScope::Off, true, false),
            ),
            (
                &["--allow-internal-urls"],
                with(RevocationScope::Leaf, false, true),
            ),
        ];
        for (flags, want) in cases {
            let fake = enricher(Vec::new(), StapleState::Missing);
            let mut args = vec!["inspect", "example.test", "--json"];
            args.extend_from_slice(flags);
            let got = run_enriched(&fake, &args);
            assert_eq!(got.code, ExitCode::Ok, "{flags:?}: {}", got.err);
            assert_eq!(*fake.calls.lock().unwrap(), vec![want], "{flags:?}");
        }
    }

    #[test]
    fn quando_revocation_e_no_revocation_juntos_deve_dar_erro_de_uso() {
        let fake = enricher(Vec::new(), StapleState::Missing);
        let got = run_enriched(
            &fake,
            &[
                "inspect",
                "example.test",
                "--revocation",
                "full",
                "--no-revocation",
            ],
        );
        assert_eq!(got.code, ExitCode::Usage);
        assert!(fake.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn quando_revocation_tem_valor_invalido_deve_dar_erro_de_uso() {
        let fake = enricher(Vec::new(), StapleState::Missing);
        let got = run_enriched(
            &fake,
            &["inspect", "example.test", "--revocation", "everything"],
        );
        assert_eq!(got.code, ExitCode::Usage);
    }

    #[test]
    fn quando_revocation_full_deve_incluir_os_status_no_json() {
        let fake = enricher(
            vec![
                entry(RevocationStatus::Good),
                CertRevocation {
                    cert_index: 1,
                    status: RevocationStatus::Unknown {
                        why: "ocsp: request timed out".to_owned(),
                    },
                },
            ],
            StapleState::Valid,
        );
        let got = run_enriched(
            &fake,
            &["inspect", "example.test", "--json", "--revocation", "full"],
        );
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        let json: Value = serde_json::from_str(&got.out).unwrap();
        assert_eq!(json["revocation"][0]["status"], "good");
        assert_eq!(json["revocation"][1]["cert_index"], 1);
        assert_eq!(json["revocation"][1]["why"], "ocsp: request timed out");
        assert_eq!(json["ocsp_staple"]["state"], "valid");
    }

    /// Severity of the finding `code` in the `check --json` output, if any.
    fn finding_severity(out: &str, code: &str) -> Option<String> {
        let json: Value = serde_json::from_str(out).unwrap();
        json["results"][0]["findings"]
            .as_array()?
            .iter()
            .find(|finding| finding["code"] == code)
            .and_then(|finding| finding["severity"].as_str().map(str::to_owned))
    }

    #[test]
    fn quando_responder_ocsp_diz_revoked_deve_listar_revoked_como_erro() {
        let revoked = RevocationStatus::Revoked {
            reason: Some("keyCompromise".to_owned()),
            at: None,
        };
        let fake = enricher(vec![entry(revoked)], StapleState::Missing);
        let got = run_enriched(&fake, &["check", "example.test", "--json"]);
        assert_eq!(got.code, ExitCode::Findings, "{}", got.err);
        assert_eq!(
            finding_severity(&got.out, "REVOKED").as_deref(),
            Some("error")
        );
    }

    #[test]
    fn quando_responder_ocsp_cai_deve_listar_revocation_unknown_como_warning() {
        let unknown = RevocationStatus::Unknown {
            why: "ocsp: request timed out".to_owned(),
        };
        let fake = enricher(vec![entry(unknown)], StapleState::Missing);
        let got = run_enriched(&fake, &["check", "example.test", "--json"]);
        assert_eq!(
            finding_severity(&got.out, "REVOCATION_UNKNOWN").as_deref(),
            Some("warning"),
            "{}",
            got.out
        );
        assert!(got.out.contains("request timed out"), "{}", got.out);
        assert_eq!(finding_severity(&got.out, "REVOKED"), None);
    }

    #[test]
    fn quando_flag_no_revocation_deve_nao_ter_findings_de_revogacao() {
        let revoked = RevocationStatus::Revoked {
            reason: None,
            at: None,
        };
        let fake = enricher(vec![entry(revoked)], StapleState::Missing);
        let got = run_enriched(
            &fake,
            &["check", "example.test", "--json", "--no-revocation"],
        );
        assert_eq!(finding_severity(&got.out, "REVOKED"), None, "{}", got.out);
        assert_eq!(finding_severity(&got.out, "REVOCATION_UNKNOWN"), None);
    }

    #[test]
    fn quando_text_de_alvo_com_revogacao_deve_listar_a_secao() {
        let fake = enricher(vec![entry(RevocationStatus::Good)], StapleState::Valid);
        let got = run_enriched(&fake, &["inspect", "example.test", "--text"]);
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        assert!(got.out.contains("Revocation:\n  [0] good"), "{}", got.out);
    }

    fn run_export(writer: &FakeFileWriter, args: &[&str]) -> Outcome {
        let loader = FakeSourceLoader(Err(LoadError::Io("no files in unit tests".to_owned())));
        let fetcher = FakeChainFetcher(Ok(chain(vec![leaf_der()])));
        let (code, out, err) = run_full(
            &loader,
            &fetcher,
            &FakeLauncher::new(false),
            &NoEnricher,
            writer,
            args,
        );
        Outcome {
            code: code.unwrap(),
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
        }
    }

    #[test]
    fn quando_export_deve_entregar_ao_writer_o_pem_e_o_modo_sem_sobrescrever() {
        let fake = FakeFileWriter::new(Ok(()));
        let got = run_export(
            &fake,
            &[
                "export",
                "example.test",
                "--format",
                "pem",
                "--out",
                "out.pem",
            ],
        );
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        let writes = fake.writes();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, PathBuf::from("out.pem"));
        assert!(writes[0].1.starts_with(b"-----BEGIN CERTIFICATE-----\n"));
        assert_eq!(writes[0].2, certtui_app::export::Overwrite::Refuse);
        assert_eq!(got.out, "", "the confirmation goes to stderr");
    }

    #[test]
    fn quando_export_com_force_deve_pedir_allow_ao_writer() {
        let writer = FakeFileWriter::new(Ok(()));
        run_export(
            &writer,
            &[
                "export",
                "example.test",
                "--format",
                "der",
                "--force",
                "--out",
                "o.der",
            ],
        );
        assert_eq!(writer.writes()[0].2, certtui_app::export::Overwrite::Allow);
    }

    #[test]
    fn quando_writer_falha_com_io_deve_sair_4_com_a_mensagem() {
        let writer = FakeFileWriter::new(Err(certtui_app::export::WriteError::Io(
            "no space left on device".to_owned(),
        )));
        let got = run_export(
            &writer,
            &[
                "export",
                "example.test",
                "--format",
                "pem",
                "--out",
                "out.pem",
            ],
        );
        assert_eq!(got.code, ExitCode::Internal);
        assert!(
            got.err
                .contains("cannot write out.pem: no space left on device"),
            "{}",
            got.err
        );
    }

    #[test]
    fn quando_writer_diz_already_exists_deve_sair_2_sugerindo_force() {
        let writer = FakeFileWriter::new(Err(certtui_app::export::WriteError::AlreadyExists));
        let got = run_export(
            &writer,
            &[
                "export",
                "example.test",
                "--format",
                "pem",
                "--out",
                "out.pem",
            ],
        );
        assert_eq!(got.code, ExitCode::Usage);
        assert!(
            got.err.contains("already exists; use --force"),
            "{}",
            got.err
        );
    }

    fn recording(answer: Result<FetchedChain, FetchError>) -> Recording {
        Recording {
            requests: Mutex::new(Vec::new()),
            answer,
        }
    }

    fn only_request(fetcher: &Recording) -> FetchRequest {
        let requests = fetcher.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        requests.first().unwrap().clone()
    }

    #[test]
    fn quando_alvo_de_rede_e_fetcher_fake_deve_renderizar_json_com_tls() {
        let fetcher = FakeChainFetcher(Ok(chain(vec![leaf_der()])));
        let got = run_with(&fetcher, &["inspect", "example.test:8443", "--json"]);
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        assert_eq!(got.err, "");
        let json: Value = serde_json::from_str(&got.out).unwrap();
        assert_eq!(json["target"]["host"], "example.test");
        assert_eq!(json["target"]["port"], 8443);
        assert_eq!(json["tls"]["peer_ip"], "93.184.216.34");
        assert_eq!(json["timings"]["handshake"], 41);
        assert_eq!(json["certificates"][0]["origin"]["kind"], "presented");
    }

    #[test]
    fn quando_flags_de_rede_deve_chegar_ao_fetcher_no_request() {
        let fetcher = recording(Ok(chain(vec![leaf_der()])));
        let got = run_with(
            &fetcher,
            &[
                "inspect",
                "example.test:8443",
                "--sni",
                "Other.Test",
                "--connect-to",
                "10.0.0.7",
                "--timeout",
                "7",
            ],
        );
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        let request = only_request(&fetcher);
        assert_eq!(request.target.host, "example.test");
        assert_eq!(request.target.sni.as_deref(), Some("other.test"));
        assert_eq!(
            request.target.connect_to,
            Some("10.0.0.7:8443".parse().unwrap())
        );
        assert_eq!(request.limits.target_total_timeout, Duration::from_secs(7));
        assert_eq!(request.limits.dns_timeout, Limits::default().dns_timeout);
    }

    #[test]
    fn quando_flags_globais_estao_antes_ou_depois_do_subcomando_deve_aceitar() {
        for args in [
            vec![
                "--sni",
                "Other.Test",
                "--connect-to",
                "10.0.0.7",
                "--timeout",
                "7",
                "inspect",
                "example.test:8443",
            ],
            vec![
                "inspect",
                "example.test:8443",
                "--sni",
                "Other.Test",
                "--connect-to",
                "10.0.0.7",
                "--timeout",
                "7",
            ],
        ] {
            let fetcher = recording(Ok(chain(vec![leaf_der()])));
            let got = run_with(&fetcher, &args);
            assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
            let request = only_request(&fetcher);
            assert_eq!(request.target.sni.as_deref(), Some("other.test"));
            assert_eq!(
                request.target.connect_to,
                Some("10.0.0.7:8443".parse().unwrap())
            );
            assert_eq!(request.limits.target_total_timeout, Duration::from_secs(7));
        }
    }

    #[test]
    fn quando_connect_to_tem_porta_deve_prevalecer_sobre_a_do_alvo() {
        let fetcher = recording(Ok(chain(vec![leaf_der()])));
        let got = run_with(
            &fetcher,
            &["inspect", "example.test:8443", "--connect-to", "[::1]:9"],
        );
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        let request = only_request(&fetcher);
        assert_eq!(request.target.connect_to, Some("[::1]:9".parse().unwrap()));
        assert_eq!(request.target.port, 8443);
    }

    #[test]
    fn quando_timeout_passa_do_teto_deve_ir_ao_fetcher_limitado_ao_hard_cap() {
        let fetcher = recording(Ok(chain(vec![leaf_der()])));
        let got = run_with(
            &fetcher,
            &["inspect", "example.test", "--timeout", "100000"],
        );
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        assert_eq!(
            only_request(&fetcher).limits.target_total_timeout,
            Limits::HARD_CAPS.target_total_timeout
        );
    }

    #[test]
    fn quando_sem_flags_deve_usar_os_limites_padrao_e_nenhum_sni() {
        let fetcher = recording(Ok(chain(vec![leaf_der()])));
        let got = run_with(&fetcher, &["inspect", "example.test"]);
        assert_eq!(got.code, ExitCode::Ok, "{}", got.err);
        let request = only_request(&fetcher);
        assert_eq!(request.limits, Limits::default());
        assert_eq!(request.target.sni, None);
        assert_eq!(request.target.connect_to, None);
        assert_eq!(request.target.port, 443);
    }

    #[test]
    fn quando_fetch_falha_deve_sair_3_com_a_mensagem_no_stderr_e_stdout_vazio() {
        let error = FetchError::Timeout(Stage::Handshake);
        let fetcher = FakeChainFetcher(Err(error.clone()));
        let got = run_with(&fetcher, &["inspect", "example.test", "--json"]);
        assert_eq!(got.code, ExitCode::Input);
        assert_eq!(got.out, "");
        assert_eq!(got.err, format!("certtui: {error}\n"));
    }

    #[test]
    fn quando_cadeia_vem_vazia_deve_sair_3_dizendo_que_nao_ha_certificados() {
        let fetcher = FakeChainFetcher(Ok(chain(Vec::new())));
        let got = run_with(&fetcher, &["inspect", "example.test"]);
        assert_eq!(got.code, ExitCode::Input);
        assert_eq!(got.err, "certtui: the peer presented no certificates\n");
    }

    #[test]
    fn quando_nenhum_der_parseia_deve_sair_3_e_listar_as_notas_no_stderr() {
        let junk = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        let fetcher = FakeChainFetcher(Ok(chain(vec![junk])));
        let got = run_with(&fetcher, &["inspect", "example.test"]);
        assert_eq!(got.code, ExitCode::Input);
        assert_eq!(got.out, "");
        assert!(
            got.err.starts_with("certtui: none of the presented"),
            "{}",
            got.err
        );
        assert!(got.err.contains("certtui: note: "), "{}", got.err);
    }

    #[test]
    fn quando_der_invalido_entre_validos_deve_virar_nota_no_json_e_no_stderr_do_pem() {
        let junk = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        let fetcher = FakeChainFetcher(Ok(chain(vec![leaf_der(), junk])));
        let json = run_with(&fetcher, &["inspect", "example.test", "--json"]);
        let json: Value = serde_json::from_str(&json.out).unwrap();
        assert_eq!(json["notes"][0]["kind"], "unparsable");
        let pem = run_with(&fetcher, &["inspect", "example.test", "--pem"]);
        assert_eq!(pem.code, ExitCode::Ok);
        assert!(pem.out.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.err.contains("certtui: note: "), "{}", pem.err);
    }

    #[test]
    fn quando_flag_de_rede_em_alvo_local_deve_sair_2_sem_tocar_no_loader_nem_no_fetcher() {
        let fetcher = recording(Ok(chain(vec![leaf_der()])));
        for (flags, message) in [
            (
                vec!["--sni", "a.test"],
                "--sni only applies to network targets",
            ),
            (
                vec!["--connect-to", "1.2.3.4", "--timeout", "3"],
                "--connect-to, --timeout only apply to network targets",
            ),
        ] {
            let mut args = vec!["inspect", "-"];
            args.extend(flags);
            let got = run_with(&fetcher, &args);
            assert_eq!(got.code, ExitCode::Usage);
            assert_eq!(got.out, "");
            assert_eq!(got.err, format!("certtui: {message}\n"));
        }
        assert!(fetcher.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn quando_alvo_local_deve_usar_o_loader_e_nunca_o_fetcher() {
        let fetcher = recording(Err(FetchError::Cancelled));
        let loader = FakeSourceLoader(Ok(LoadedCerts {
            certs: Vec::new(),
            notes: Vec::new(),
        }));
        let (code, _out, _err) = run_in_env(&loader, &fetcher, &["inspect", "-"]);
        assert_eq!(code.unwrap(), ExitCode::Input);
        assert!(fetcher.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn quando_alvo_de_rede_e_invalido_deve_sair_2_sem_chamar_o_fetcher() {
        let fetcher = recording(Err(FetchError::Cancelled));
        for target in [
            "http://example.test",
            "example.test:0",
            "https://u:pw@example.test",
        ] {
            let got = run_with(&fetcher, &["inspect", target]);
            assert_eq!(got.code, ExitCode::Usage, "{target}");
            assert!(!got.err.contains("pw"), "{}", got.err);
        }
        assert!(fetcher.requests.lock().unwrap().is_empty());
    }

    #[test]
    fn quando_valor_de_flag_de_rede_e_invalido_deve_sair_2_antes_do_fetch() {
        let fetcher = recording(Err(FetchError::Cancelled));
        for args in [
            ["--sni", "bad name"],
            ["--connect-to", "nope"],
            ["--timeout", "0"],
            ["--timeout", "abc"],
        ] {
            let got = run_with(&fetcher, &["inspect", "example.test", args[0], args[1]]);
            assert_eq!(got.code, ExitCode::Usage, "{args:?}");
            assert_eq!(got.out, "");
        }
        assert!(fetcher.requests.lock().unwrap().is_empty());
    }

    fn run_tui(
        launcher: &FakeLauncher,
        loader: &dyn SourceLoader,
        args: &[&str],
    ) -> (ExitCode, String, String) {
        let fetcher = FakeChainFetcher(Err(FetchError::Cancelled));
        let (code, out, err) = run_with_launcher(loader, &fetcher, launcher, args);
        (
            code.unwrap(),
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn no_files() -> FakeSourceLoader {
        FakeSourceLoader(Err(LoadError::Io("no files in unit tests".to_owned())))
    }

    #[test]
    fn quando_sem_args_e_interativo_deve_abrir_a_tui_na_home() {
        let launcher = FakeLauncher::new(true);
        let (code, out, err) = run_tui(&launcher, &no_files(), &[]);
        assert_eq!((code, out.as_str(), err.as_str()), (ExitCode::Ok, "", ""));
        let requests = launcher.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].target, None);
        assert!(requests[0].stdin.is_none());
    }

    #[test]
    fn quando_sem_args_e_sem_terminal_deve_sair_2_com_orientacao() {
        let launcher = FakeLauncher::new(false);
        let (code, out, err) = run_tui(&launcher, &no_files(), &[]);
        assert_eq!(code, ExitCode::Usage);
        assert_eq!(out, "");
        assert!(err.contains("no terminal available"), "{err}");
        assert!(launcher.requests().is_empty());
    }

    #[test]
    fn quando_alvo_de_rede_e_interativo_deve_abrir_a_tui_ja_inspecionando() {
        let launcher = FakeLauncher::new(true);
        let (code, _, _) = run_tui(
            &launcher,
            &no_files(),
            &["--sni", "alt.test", "example.test:8443"],
        );
        assert_eq!(code, ExitCode::Ok);
        let request = launcher.requests().remove(0);
        assert!(matches!(
            request.target,
            Some(Target::Network(ref network)) if network.host == "example.test" && network.port == 8443
        ));
        assert_eq!(request.options.sni.as_deref(), Some("alt.test"));
    }

    #[test]
    fn quando_hifen_e_interativo_deve_ler_o_stdin_antes_de_abrir_a_tui() {
        let launcher = FakeLauncher::new(true);
        let piped = LoadedCerts {
            certs: Vec::new(),
            notes: Vec::new(),
        };
        let loader = FakeSourceLoader(Ok(piped.clone()));
        let (code, _, _) = run_tui(&launcher, &loader, &["-"]);
        assert_eq!(code, ExitCode::Ok);
        let request = launcher.requests().remove(0);
        assert_eq!(request.target, Some(Target::Stdin));
        assert_eq!(request.stdin, Some(piped));
    }

    #[test]
    fn quando_stdin_falha_deve_sair_com_o_codigo_do_load_e_nao_abrir_a_tui() {
        let launcher = FakeLauncher::new(true);
        let (code, _, err) = run_tui(&launcher, &no_files(), &["-"]);
        assert_eq!(code, ExitCode::Input);
        assert!(err.contains("I/O error"), "{err}");
        assert!(launcher.requests().is_empty());
    }

    #[test]
    fn quando_sem_terminal_e_alvo_deve_cair_no_modo_text_sem_abrir_a_tui() {
        let launcher = FakeLauncher::new(false);
        let loader = FakeSourceLoader(Err(LoadError::Io("denied".to_owned())));
        let (code, _, err) = run_tui(&launcher, &loader, &["some.pem"]);
        // The same failure `certtui inspect some.pem` reports.
        assert_eq!(code, ExitCode::Input);
        assert!(err.contains("denied"), "{err}");
        assert!(launcher.requests().is_empty());
    }

    #[test]
    fn quando_flag_de_rede_com_alvo_local_na_tui_deve_sair_2() {
        let launcher = FakeLauncher::new(true);
        let (code, _, err) = run_tui(&launcher, &no_files(), &["--sni", "x.test", "-"]);
        assert_eq!(code, ExitCode::Usage);
        assert!(
            err.contains("--sni only applies to network targets"),
            "{err}"
        );
        assert!(launcher.requests().is_empty());
    }

    #[test]
    fn quando_alvo_invalido_deve_sair_2_sem_abrir_a_tui() {
        let launcher = FakeLauncher::new(true);
        let (code, _, err) = run_tui(&launcher, &no_files(), &["https://user:pw@example.com"]);
        assert_eq!(code, ExitCode::Usage);
        assert!(!err.contains("pw"), "{err}");
        assert!(launcher.requests().is_empty());
    }

    #[test]
    fn quando_subcomando_inspect_deve_continuar_sem_abrir_a_tui() {
        let launcher = FakeLauncher::new(true);
        let (_, _, _) = run_tui(&launcher, &no_files(), &["inspect", "x.pem"]);
        assert!(launcher.requests().is_empty());
    }

    /// A list file in a scratch directory, removed when dropped.
    struct ListFile(PathBuf);

    impl ListFile {
        fn new(tag: &str, content: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "certtui-batch-unit-{tag}-{}.txt",
                std::process::id()
            ));
            std::fs::write(&path, content).unwrap();
            Self(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for ListFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn quando_batch_com_terminal_e_sem_flag_deve_abrir_a_tui_com_a_lista() {
        let list = ListFile::new("tty", "a.test\nb.test:8443\n# c\na.test\n");
        let launcher = FakeLauncher::new(true);
        let (code, out, err) = run_tui(&launcher, &no_files(), &["batch", list.path()]);
        assert_eq!((code, out.as_str(), err.as_str()), (ExitCode::Ok, "", ""));
        let request = launcher.requests().remove(0);
        assert_eq!(request.target, None);
        let hosts: Vec<(String, u16)> = request
            .batch
            .unwrap()
            .into_iter()
            .map(|t| (t.host, t.port))
            .collect();
        assert_eq!(
            hosts,
            [("a.test".to_owned(), 443), ("b.test".to_owned(), 8443)]
        );
    }

    #[test]
    fn quando_batch_com_terminal_e_concurrency_deve_passar_ao_tui() {
        let list = ListFile::new("tty-conc", "a.test\n");
        let launcher = FakeLauncher::new(true);
        let args = ["batch", list.path(), "--concurrency", "8"];
        let (code, _, _) = run_tui(&launcher, &no_files(), &args);
        assert_eq!(code, ExitCode::Ok);
        assert_eq!(launcher.requests().remove(0).batch_concurrency, Some(8));
        let launcher = FakeLauncher::new(true);
        let args = ["batch", list.path(), "--concurrency", "1000"];
        let (_, _, err) = run_tui(&launcher, &no_files(), &args);
        assert_eq!(launcher.requests().remove(0).batch_concurrency, Some(256));
        assert!(err.contains("--concurrency 1000"), "{err}");
        let launcher = FakeLauncher::new(true);
        let (_, _, _) = run_tui(&launcher, &no_files(), &["batch", list.path()]);
        assert_eq!(launcher.requests().remove(0).batch_concurrency, None);
    }

    #[test]
    fn quando_batch_com_terminal_e_json_deve_continuar_headless() {
        let list = ListFile::new("tty-json", "a.test\n");
        let launcher = FakeLauncher::new(true);
        let (code, out, _) = run_tui(&launcher, &no_files(), &["batch", list.path(), "--json"]);
        assert_eq!(code, ExitCode::Input, "the fake fetcher fails every target");
        assert!(out.contains("\"schema_version\""), "{out}");
        assert!(launcher.requests().is_empty());
    }

    #[test]
    fn quando_batch_sem_terminal_e_sem_flag_deve_cair_em_json() {
        let list = ListFile::new("notty", "a.test\n");
        let launcher = FakeLauncher::new(false);
        let (_, out, _) = run_tui(&launcher, &no_files(), &["batch", list.path()]);
        assert!(out.contains("\"schema_version\""), "{out}");
        assert!(launcher.requests().is_empty());
    }

    #[test]
    fn quando_batch_com_terminal_e_lista_vazia_deve_sair_2_sem_abrir_a_tui() {
        let list = ListFile::new("tty-empty", "# nothing\n");
        let launcher = FakeLauncher::new(true);
        let (code, _, err) = run_tui(&launcher, &no_files(), &["batch", list.path()]);
        assert_eq!(code, ExitCode::Usage);
        assert!(err.contains("no targets"), "{err}");
        assert!(launcher.requests().is_empty());
    }
}
