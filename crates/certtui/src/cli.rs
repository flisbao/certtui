//! Command-line definition and the `inspect` command.

use std::ffi::OsString;
use std::io::Write;

use anyhow::Context as _;
use certtui_app::error::LoadError;
use certtui_app::inspect::inspect_local;
use certtui_app::ports::SourceLoader;
use certtui_domain::limits::Limits;
use certtui_domain::model::{FingerprintFormat, LoadNote};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::exit_code::ExitCode;
use crate::output::field::Field;
use crate::output::{self, View};
use crate::target_parse::{UsageError, local_source, parse_target};

/// Inspect and analyze X.509 certificates.
#[derive(Debug, Parser)]
#[command(name = "certtui", version, about)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show the certificates of a file, directory or standard input.
    Inspect(InspectArgs),
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
    /// Local target: a file, a directory, or `-` for standard input.
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
    loader: &dyn SourceLoader,
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
    match cli.command {
        Command::Inspect(inspect_args) => inspect(&inspect_args, loader, out, err),
    }
}

fn inspect(
    args: &InspectArgs,
    loader: &dyn SourceLoader,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> anyhow::Result<ExitCode> {
    let target = match parse_target(&args.target, args.file, args.recursive, &|path| {
        path.exists()
    }) {
        Ok(target) => target,
        Err(error) => return usage(err, &error.to_string()),
    };
    let Some(source) = local_source(&target) else {
        return usage(err, &UsageError::NetworkTarget.to_string());
    };
    let report = match inspect_local(loader, &source, target, &Limits::default()) {
        Ok(report) => report,
        Err(error) => return load_failure(err, &error),
    };
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

fn load_failure(err: &mut dyn Write, error: &LoadError) -> anyhow::Result<ExitCode> {
    writeln!(err, "certtui: {error}").context("writing the load error")?;
    if let LoadError::NoCertificatesFound { notes } = error {
        write_notes(err, notes)?;
    }
    Ok(ExitCode::from(error))
}
