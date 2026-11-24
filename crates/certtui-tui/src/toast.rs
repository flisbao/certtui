//! Transient feedback line.

use std::time::{Duration, Instant};

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

impl Toast {
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
