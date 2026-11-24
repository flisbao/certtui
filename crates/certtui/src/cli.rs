//! Command-line definition and the `inspect` command.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Context as _;
use certtui_app::check::FailOn;
use certtui_app::error::{InspectError, LoadError};
use certtui_app::inspect::inspect_local;
use certtui_app::inspect_network::inspect_network;
use certtui_app::ports::{ChainFetcher, ChainVerifier, Clock, SourceLoader, TrustStoreProvider};
use certtui_app::trust::{TrustAnchors, TrustSource, resolve_sources};
use certtui_app::validate::{ValidationInputs, validate};
use certtui_domain::limits::Limits;
use certtui_domain::lint::Thresholds;
use certtui_domain::model::{FingerprintFormat, InspectionReport, LoadNote};
use certtui_domain::target::{NetworkTarget, Target};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tokio_util::sync::CancellationToken;

use crate::exit_code::ExitCode;
use crate::network_args::{ConnectTo, parse_connect_to, parse_sni, parse_timeout, with_timeout};
use crate::output::check::TargetResult;
use crate::output::field::Field;
use crate::output::{self, View};
use crate::runtime;
use crate::target_parse::{local_source, parse_target};

/// Inspect and analyze X.509 certificates.
#[derive(Debug, Parser)]
#[command(name = "certtui", version, about)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
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
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the certificates of a file, directory, standard input or TLS server.
    Inspect(InspectArgs),
    /// Validate the certificates of one or more targets and report findings.
    Check(CheckArgs),
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

/// Arguments of `certtui check`.
#[derive(Debug, Args)]
pub struct CheckArgs {
    /// What to check: files, directories, `-` for standard input or TLS
    /// servers, as for `inspect`.
    #[arg(required = true)]
    pub targets: Vec<String>,
    /// Lowest severity of a finding that makes the command exit 1.
    #[arg(long, value_enum, default_value_t)]
    pub fail_on: FailOnArg,
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
    /// How to display fingerprints.
    #[arg(long, value_enum, default_value_t)]
    pub fingerprint_format: FingerprintFormatArg,
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
    timeout: Option<std::time::Duration>,
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
    pub trust_provider: &'a dyn Fn(Vec<PathBuf>) -> Box<dyn TrustStoreProvider>,
}

/// Trust-related options shared by every command.
#[derive(Clone)]
struct TrustOptions {
    sources: Vec<TrustSource>,
    ca_files: Vec<PathBuf>,
    host_check: Option<String>,
}

/// Loads the anchors of `options`, reporting warnings on `err`; a failure is
/// a configuration error (exit 2).
fn load_anchors(
    options: &TrustOptions,
    env: &Env<'_>,
    err: &mut dyn Write,
) -> anyhow::Result<Result<TrustAnchors, ExitCode>> {
    let provider = (env.trust_provider)(options.ca_files.clone());
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
}

impl Validation<'_> {
    /// The report with its trust verdict and findings filled in. A network
    /// target is checked against its SNI, or else its host, unless
    /// `--host-check` says otherwise.
    fn apply(&self, report: InspectionReport) -> InspectionReport {
        let network_host = match &report.target {
            Target::Network(network) => {
                Some(network.sni.clone().unwrap_or_else(|| network.host.clone()))
            }
            _ => None,
        };
        validate(
            report,
            ValidationInputs {
                verifier: self.env.verifier,
                anchors: self.anchors,
                clock: self.env.clock,
                thresholds: self.thresholds,
                hostname: self.host_check.map(str::to_owned).or(network_host.clone()),
                is_network_target: network_host.is_some(),
            },
        )
    }
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
    let network_options = match cli.sni.as_deref().map(parse_sni).transpose() {
        Ok(sni) => NetworkOptions {
            sni,
            connect_to: cli.connect_to,
            timeout: cli.timeout,
        },
        Err(message) => return usage(err, &format!("--sni: {message}")),
    };
    let sources: Vec<TrustSource> = cli.trust.iter().copied().map(TrustSource::from).collect();
    let trust_options = TrustOptions {
        sources: resolve_sources(&sources, !cli.ca_file.is_empty(), cli.ca_only),
        ca_files: cli.ca_file,
        host_check: cli.host_check,
    };
    match cli.command {
        Command::Inspect(inspect_args) => inspect(
            &inspect_args,
            &network_options,
            &trust_options,
            env,
            out,
            err,
        ),
        Command::Check(check_args) => {
            check(&check_args, &network_options, &trust_options, env, out, err)
        }
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
        thresholds: Thresholds::default(),
        host_check: trust_options.host_check.as_deref(),
    }
    .apply(report);
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
        fingerprint_format: args.fingerprint_format.into(),
    };
    render(mode, &view, out, err)?;
    Ok(ExitCode::Ok)
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
    let thresholds = match thresholds(args) {
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
    };
    let mut checked: Vec<(&str, Result<InspectionReport, String>)> = Vec::new();
    for (raw, target) in targets {
        // The fetch and load failures are written as `certtui: <message>`; they
        // are captured so each can be attributed to its target.
        let mut failure = Vec::new();
        match gather(network_options, env, target, &mut failure)? {
            Ok(report) => checked.push((raw, Ok(validation.apply(report)))),
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
    Ok(exit_code_of(&results, args.fail_on.into()))
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

fn thresholds(args: &CheckArgs) -> Result<Thresholds, String> {
    let defaults = Thresholds::default();
    let warn_days = args.warn_days.unwrap_or(defaults.warn_days);
    let critical_days = args.critical_days.unwrap_or(defaults.critical_days);
    if critical_days > warn_days {
        return Err(format!(
            "--critical-days ({critical_days}) must not exceed --warn-days ({warn_days})"
        ));
    }
    Ok(Thresholds {
        warn_days,
        critical_days,
        ..defaults
    })
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
    match inspect_local(env.loader, &source, target, &Limits::default()) {
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
    let limits = network_options
        .timeout
        .map_or_else(Limits::default, |timeout| {
            with_timeout(&Limits::default(), timeout)
        });
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

    use certtui_app::error::LoadError;
    use certtui_app::fetch::{FetchError, FetchRequest, FetchedChain, Stage};
    use certtui_app::ports::{ChainVerification, LoadedCerts};
    use certtui_app::testing::{
        FakeChainFetcher, FakeChainVerifier, FakeSourceLoader, FakeTrustProvider, FixedClock,
    };
    use certtui_app::trust::TrustAnchor;
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
        let verifier = FakeChainVerifier::new(ChainVerification {
            trust: TrustVerdict::Trusted {
                anchor: "Fake Root".to_owned(),
            },
            hostname_ok: None,
        });
        let clock = FixedClock(Timestamp::from_unix(1_769_904_000).unwrap());
        let provider = |_files: Vec<PathBuf>| -> Box<dyn TrustStoreProvider> {
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
}
