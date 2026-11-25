//! `certtui batch`: inspect a list of TLS servers and report one compact row
//! per target.

use std::io::{Read as _, Write};

use anyhow::Context as _;
use certtui_app::batch::{BatchEvent, BatchRunner, TargetInspector};
use certtui_app::check::FailOn;
use certtui_app::enrich::{ReportEnricher, RevocationOptions};
use certtui_app::ports::{ChainFetcher, ChainVerifier, Clock};
use certtui_app::trust::TrustAnchors;
use certtui_app::validate::known_issuers;
use certtui_domain::batch_input::{BatchInputError, SkippedLine, parse_batch_input};
use certtui_domain::batch_row::{BatchRow, RowStatus};
use certtui_domain::chain_analysis::KnownIssuer;
use certtui_domain::limits::Limits;
use certtui_domain::lint::Thresholds;
use certtui_domain::model::InspectionReport;
use certtui_domain::target::NetworkTarget;
use clap::Args;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{
    Env, FailOnArg, NetworkOptions, TrustOptions, inspector_options, load_anchors, usage,
    validate_for_target,
};
use crate::exit_code::ExitCode;
use crate::network_args::with_timeout;
use crate::output;
use crate::runtime;
use crate::tui_launch::TuiRequest;

/// Capacity of the channel between the runner and the collector.
const CHANNEL_CAPACITY: usize = 256;

/// Arguments of `certtui batch`.
#[derive(Debug, Args)]
pub struct BatchArgs {
    /// File with one target per line (`#` starts a comment) or a JSON array
    /// of strings; `-` reads standard input.
    pub file: String,
    /// How many targets are inspected at once (default 32, at most 256).
    #[arg(long, value_name = "N")]
    pub concurrency: Option<usize>,
    /// Machine-readable JSON (`schema_version` 1); the default.
    #[arg(long, conflicts_with = "csv")]
    pub json: bool,
    /// CSV, one line per target.
    #[arg(long, conflicts_with = "json")]
    pub csv: bool,
    /// Lowest severity of a finding that makes the command exit 1.
    #[arg(long, value_enum, default_value_t)]
    pub fail_on: FailOnArg,
}

/// Runs `certtui batch`.
pub fn run(
    args: &BatchArgs,
    network_options: &NetworkOptions,
    trust_options: &TrustOptions,
    env: &Env<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let unsupported: Vec<&str> = network_options
        .network_only_flags()
        .into_iter()
        .filter(|flag| *flag != "--timeout")
        .collect();
    if !unsupported.is_empty() {
        let message = format!(
            "{} cannot be used with batch: they would apply to every target",
            unsupported.join(", ")
        );
        return usage(err, &message);
    }
    let limits = network_options
        .timeout
        .map_or_else(Limits::default, |timeout| {
            with_timeout(&Limits::default(), timeout)
        });
    let concurrency = match concurrency(args.concurrency, &limits, err)? {
        Ok(concurrency) => concurrency,
        Err(code) => return Ok(code),
    };
    let bytes = match read_list(&args.file, limits.max_input_file_bytes) {
        Ok(bytes) => bytes,
        Err(error) => {
            writeln!(
                err,
                "certtui: cannot read {}: {}",
                output::single_line(&args.file),
                output::single_line(&error.to_string())
            )
            .context("writing the read error")?;
            return Ok(ExitCode::Input);
        }
    };
    let input = match parse_batch_input(&bytes, &limits) {
        Ok(input) => input,
        Err(error @ (BatchInputError::TooManyTargets { .. } | BatchInputError::TooLarge)) => {
            return usage(err, &error.to_string());
        }
        Err(BatchInputError::InvalidJson(message)) => {
            return usage(
                err,
                &format!("invalid JSON list: {}", output::single_line(&message)),
            );
        }
    };
    if input.targets.is_empty() {
        return usage(err, "no targets in the list");
    }
    if !args.json && !args.csv && env.tui.is_interactive() {
        // The screen takes over: the list is read already, the terminal is
        // free for keys.
        env.tui.launch(TuiRequest {
            target: None,
            stdin: None,
            batch: Some(input.targets),
            options: inspector_options(network_options, trust_options),
        })?;
        return Ok(ExitCode::Ok);
    }
    let anchors = match load_anchors(trust_options, env, err)? {
        Ok(anchors) => anchors,
        Err(code) => return Ok(code),
    };
    let inspector = NetworkInspector {
        fetcher: env.fetcher,
        verifier: env.verifier,
        clock: env.clock,
        enricher: env.enricher,
        anchors: &anchors,
        issuers: known_issuers(&anchors),
        thresholds: Thresholds::default(),
        host_check: trust_options.host_check.as_deref(),
        revocation: trust_options.revocation,
        limits,
    };
    let rows = runtime::block_on(collect(
        &inspector,
        env.clock,
        &limits,
        input.targets,
        concurrency,
    ))?;
    if args.csv {
        for entry in &input.skipped {
            warn_skipped(err, entry)?;
        }
        output::batch::write_csv(out, &rows)
    } else {
        output::batch::write_json(out, &rows, &input.skipped)
    }
    .context("writing the output")?;
    Ok(exit_code_of(&rows, args.fail_on.into()))
}

/// The number of workers: the request or the default, cut to the hard cap
/// with a warning. `Err` holds the exit code of a usage error.
fn concurrency(
    requested: Option<usize>,
    limits: &Limits,
    err: &mut dyn Write,
) -> anyhow::Result<Result<usize, ExitCode>> {
    let cap = Limits::HARD_CAPS.batch_concurrency;
    match requested {
        None => Ok(Ok(limits.batch_concurrency)),
        Some(0) => usage(err, "--concurrency must be at least 1").map(Err),
        Some(n) if n > cap => {
            writeln!(
                err,
                "certtui: warning: --concurrency {n} is above the limit; using {cap}"
            )
            .context("writing the warning")?;
            Ok(Ok(cap))
        }
        Some(n) => Ok(Ok(n)),
    }
}

/// Reads the list, at most `limit + 1` bytes so an oversized list is seen
/// without being held in memory.
fn read_list(path: &str, limit: usize) -> std::io::Result<Vec<u8>> {
    let reader: Box<dyn std::io::Read> = if path == "-" {
        Box::new(std::io::stdin().lock())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    let mut bytes = Vec::new();
    reader
        .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The targets of the list in the file at `path`, for the Home screen: the
/// lines that are not targets are left out, and the reason a list cannot be
/// used is one line fit for a toast.
///
/// # Errors
///
/// The file cannot be read, is too large or malformed, or has too many
/// targets.
pub fn load_batch_list(path: &str) -> Result<Vec<NetworkTarget>, String> {
    let limits = Limits::default();
    let bytes = read_list(path, limits.max_input_file_bytes)
        .map_err(|error| output::single_line(&format!("cannot read the list: {error}")))?;
    parse_batch_input(&bytes, &limits)
        .map(|input| input.targets)
        .map_err(|error| output::single_line(&error.to_string()))
}

fn warn_skipped(err: &mut dyn Write, entry: &SkippedLine) -> anyhow::Result<()> {
    writeln!(
        err,
        "certtui: warning: line {} skipped: {}",
        entry.line, entry.reason
    )
    .context("writing the warning")
}

/// Runs the batch and returns the rows in the order of the list.
async fn collect(
    inspector: &NetworkInspector<'_>,
    clock: &dyn Clock,
    limits: &Limits,
    targets: Vec<NetworkTarget>,
    concurrency: usize,
) -> Vec<BatchRow> {
    let total = targets.len();
    let runner = BatchRunner::new(inspector, clock, limits);
    let (tx, mut rx) = mpsc::channel(CHANNEL_CAPACITY);
    let gather = async {
        let mut rows: Vec<Option<BatchRow>> = vec![None; total];
        while let Some(event) = rx.recv().await {
            if let BatchEvent::Row { index, row } = event
                && let Some(slot) = rows.get_mut(index)
            {
                *slot = Some(row);
            }
        }
        rows
    };
    // Nothing cancels the token: Ctrl-C ends the process through the default
    // SIGINT disposition, which is all a one-shot command needs.
    let (rows, ()) = tokio::join!(
        gather,
        runner.run(targets, concurrency, tx, CancellationToken::new())
    );
    rows.into_iter().flatten().collect()
}

/// 3 when every target failed, 1 when some failed or a row has a finding at
/// or above `fail_on`, 0 otherwise.
fn exit_code_of(rows: &[BatchRow], fail_on: FailOn) -> ExitCode {
    let failed = rows
        .iter()
        .filter(|row| row.status == RowStatus::Failed)
        .count();
    if failed == rows.len() {
        return ExitCode::Input;
    }
    let findings_fail = rows.iter().any(|row| match fail_on {
        FailOn::Warning => row.errors > 0 || row.warnings > 0,
        FailOn::Error => row.errors > 0,
    });
    if failed > 0 || findings_fail {
        ExitCode::Findings
    } else {
        ExitCode::Ok
    }
}

/// The inspect-enrich-validate pipeline of `check`, for one target at a time.
struct NetworkInspector<'a> {
    fetcher: &'a dyn ChainFetcher,
    verifier: &'a dyn ChainVerifier,
    clock: &'a dyn Clock,
    enricher: &'a dyn ReportEnricher,
    anchors: &'a TrustAnchors,
    issuers: Vec<KnownIssuer>,
    thresholds: Thresholds,
    host_check: Option<&'a str>,
    revocation: RevocationOptions,
    limits: Limits,
}

#[async_trait::async_trait]
impl TargetInspector for NetworkInspector<'_> {
    async fn inspect(
        &self,
        target: &NetworkTarget,
        cancel: CancellationToken,
    ) -> Result<InspectionReport, String> {
        let report = certtui_app::inspect_network::inspect_network(
            self.fetcher,
            target.clone(),
            &self.limits,
            cancel.clone(),
        )
        .await
        .map_err(|error| output::single_line(&error.to_string()))?;
        let report = self
            .enricher
            .enrich(report, &self.issuers, self.revocation, cancel)
            .await;
        Ok(validate_for_target(
            report,
            self.verifier,
            self.anchors,
            self.clock,
            self.thresholds,
            self.host_check,
        ))
    }
}
