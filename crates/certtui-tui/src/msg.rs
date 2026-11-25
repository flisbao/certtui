//! Events entering [`crate::update`] and side effects leaving it.

use std::sync::Arc;
use std::time::Instant;

use std::fmt;
use std::path::PathBuf;

use certtui_app::batch::BatchEvent;
use certtui_app::export::{ExportFormat, ExportSelection, Overwrite};
use certtui_app::keystore::{ExposeSecret, SecretString};
use certtui_domain::model::InspectionReport;
use certtui_domain::target::{NetworkTarget, Target};
use crossterm::event::KeyEvent;

use crate::app_state::JobId;
use crate::clipboard::CopyMethod;
use crate::copy::CopyPayload;

/// A keystore password on its way to an inspect job.
///
/// `Debug` never shows it; equality exists only so [`Command`] can be
/// compared in tests.
#[derive(Clone)]
pub struct Password(SecretString);

impl Password {
    /// Wraps a typed password.
    #[must_use]
    pub fn new(secret: SecretString) -> Self {
        Self(secret)
    }

    /// The secret, for the executor that hands it to the loader.
    #[must_use]
    pub fn into_secret(self) -> SecretString {
        self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

impl PartialEq for Password {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for Password {}

/// Why an inspect job produced no report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InspectFailure {
    /// The keystore needs a password and none was given.
    PasswordRequired,
    /// The password given does not open it (or the keystore is damaged).
    WrongPassword,
    /// Anything else, as a message fit for the screen.
    Message(String),
}

/// Why an export did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportFailure {
    /// The file exists and overwriting was not allowed.
    AlreadyExists,
    /// Any other reason, as a message fit for the screen.
    Message(String),
}

/// An export the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRequest {
    /// The report whose certificates are exported.
    pub report: Arc<InspectionReport>,
    /// File format.
    pub format: ExportFormat,
    /// Which certificates.
    pub selection: ExportSelection,
    /// Where to write.
    pub path: PathBuf,
    /// What to do if the file exists.
    pub overwrite: Overwrite,
}

/// Every event that can change the state.
#[derive(Debug, Clone)]
pub enum Msg {
    /// A key press.
    Key(KeyEvent),
    /// Text pasted into the terminal (bracketed paste).
    Paste(String),
    /// The terminal was resized to `(columns, rows)`.
    Resize(u16, u16),
    /// Time moved forward; carries the clock reading.
    Tick(Instant),
    /// An inspect job finished.
    InspectDone {
        /// Job that produced the result.
        id: JobId,
        /// The report, or a user-facing error message.
        result: Result<Arc<InspectionReport>, String>,
    },
    /// Events of a running batch, in the order they happened; rows are
    /// grouped so a large batch does not flood the loop.
    Batch {
        /// Job that produced the events.
        id: JobId,
        /// What happened.
        events: Vec<BatchEvent>,
    },
    /// The job needs a keystore password (`wrong` when one was tried).
    PasswordNeeded {
        /// Job that asked.
        id: JobId,
        /// The password given was rejected.
        wrong: bool,
    },
    /// An export was written.
    ExportDone {
        /// Where, as shown to the user.
        path: String,
    },
    /// An export failed.
    ExportFailed(ExportFailure),
    /// A copy reached the clipboard.
    Copied {
        /// Label of the datum copied.
        label: String,
        /// Size of the text copied.
        bytes: usize,
        /// How it was delivered.
        method: CopyMethod,
    },
    /// A copy failed.
    CopyFailed {
        /// Why, for the toast.
        reason: String,
    },
}

/// A side effect requested by [`crate::update`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Inspect `target` as job `id`.
    Inspect {
        /// Identifier of the job.
        id: JobId,
        /// What to inspect.
        target: Target,
    },
    /// Inspect `target` as job `id`, opening keystores with `password`.
    InspectWithPassword {
        /// Identifier of the job.
        id: JobId,
        /// What to inspect.
        target: Target,
        /// The password the user typed.
        password: Password,
    },
    /// Inspect every target as job `id`, reporting compact rows.
    RunBatch {
        /// Identifier of the job.
        id: JobId,
        /// The targets, in list order.
        targets: Vec<NetworkTarget>,
    },
    /// Write certificates to a file.
    Export(ExportRequest),
    /// Cancel a running job.
    CancelJob(JobId),
    /// Put text on the clipboard.
    CopyToClipboard(CopyPayload),
}
