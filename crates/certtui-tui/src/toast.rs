//! Transient feedback line.

use std::time::{Duration, Instant};

use certtui_app::present::labels;

use crate::clipboard::CopyMethod;

/// How long a toast stays on screen.
pub const TOAST_TTL: Duration = Duration::from_secs(2);

/// Kind of a toast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    /// Neutral or success message.
    Info,
    /// Something failed.
    Error,
}

/// A message shown briefly at the bottom of the screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    /// Text shown.
    pub text: String,
    /// Kind of message.
    pub kind: ToastKind,
    /// When the toast disappears.
    pub expires_at: Instant,
}

/// Longest reason kept in a failure toast, in characters.
const MAX_REASON_CHARS: usize = 160;

impl Toast {
    /// The toast of a finished copy.
    ///
    /// OSC 52 is never confirmed by the terminal, so it says "Sent", not
    /// "Copied".
    #[must_use]
    pub fn copied(label: &str, bytes: usize, method: CopyMethod, now: Instant) -> Self {
        let label = labels::single_line(label);
        let text = match method {
            CopyMethod::Native => format!("Copied {label} ({bytes} B)"),
            CopyMethod::Osc52 => format!("Sent {label} via OSC 52 ({bytes} B)"),
        };
        Self::new(text, ToastKind::Info, now)
    }

    /// The toast of a copy that failed.
    #[must_use]
    pub fn copy_failed(reason: &str, now: Instant) -> Self {
        let reason: String = labels::single_line(reason)
            .chars()
            .take(MAX_REASON_CHARS)
            .collect();
        Self::new(format!("Copy failed: {reason}"), ToastKind::Error, now)
    }

    /// A toast created at `now` that expires after [`TOAST_TTL`].
    #[must_use]
    pub fn new(text: impl Into<String>, kind: ToastKind, now: Instant) -> Self {
        Self {
            text: text.into(),
            kind,
            expires_at: now + TOAST_TTL,
        }
    }
}
