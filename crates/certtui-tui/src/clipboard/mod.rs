//! Clipboard sinks (OSC 52, native, fallback).

/// How a copy reached the clipboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyMethod {
    /// Escape sequence sent to the terminal; delivery is not confirmed.
    Osc52,
    /// The operating system clipboard.
    Native,
}
