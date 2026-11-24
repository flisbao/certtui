//! Transient feedback line.

use std::time::Instant;

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
