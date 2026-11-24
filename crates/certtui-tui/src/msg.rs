//! Events entering [`crate::update`] and side effects leaving it.

use std::sync::Arc;
use std::time::Instant;

use certtui_domain::model::InspectionReport;
use certtui_domain::target::Target;
use crossterm::event::KeyEvent;

use crate::app_state::JobId;
use crate::clipboard::CopyMethod;
use crate::copy::CopyPayload;

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
    /// Cancel a running job.
    CancelJob(JobId),
    /// Put text on the clipboard.
    CopyToClipboard(CopyPayload),
}
