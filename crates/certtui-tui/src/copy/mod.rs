//! What can be copied and the text that results.

pub mod copyable;
pub mod render_text;

pub use copyable::{Copyable, InspectCopy};

/// Text to put on the clipboard, with the label shown in the toast.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyPayload {
    /// Short name of the datum, for the toast.
    pub label: String,
    /// The exact text to copy.
    pub text: String,
}
