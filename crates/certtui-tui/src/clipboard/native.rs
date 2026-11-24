//! The operating system clipboard, through `arboard`.

use std::sync::Mutex;

use super::{ClipboardError, ClipboardSink, CopyMethod};

/// The system clipboard.
///
/// The handle is created on first use and kept: on X11 and Wayland the
/// program that set the clipboard must stay alive to serve it.
pub struct NativeSink {
    clipboard: Mutex<Option<arboard::Clipboard>>,
}

impl NativeSink {
    /// A sink that has not touched the system clipboard yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            clipboard: Mutex::new(None),
        }
    }
}

impl Default for NativeSink {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for NativeSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeSink").finish_non_exhaustive()
    }
}

impl ClipboardSink for NativeSink {
    fn copy(&self, text: &str) -> Result<CopyMethod, ClipboardError> {
        let mut guard = self
            .clipboard
            .lock()
            .map_err(|_| ClipboardError::Io("clipboard handle poisoned".to_owned()))?;
        if guard.is_none() {
            let clipboard = arboard::Clipboard::new()
                .map_err(|error| ClipboardError::Unavailable(error.to_string()))?;
            *guard = Some(clipboard);
        }
        let Some(clipboard) = guard.as_mut() else {
            return Err(ClipboardError::Unavailable(
                "no clipboard handle".to_owned(),
            ));
        };
        clipboard
            .set_text(text.to_owned())
            .map_err(|error| ClipboardError::Io(error.to_string()))?;
        Ok(CopyMethod::Native)
    }
}
