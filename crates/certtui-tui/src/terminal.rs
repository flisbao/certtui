//! Entering and leaving the terminal safely.

use std::io::{self, Write};

use crossterm::cursor::{Hide, Show};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

/// Smallest terminal the screens are laid out for, as `(columns, rows)`.
pub const MIN_SIZE: (u16, u16) = (80, 24);

/// Raw mode plus the alternate screen, undone on drop.
///
/// The mouse is never captured.
#[derive(Debug)]
pub struct TerminalGuard {
    _private: (),
}

impl TerminalGuard {
    /// Enters raw mode and the alternate screen.
    ///
    /// # Errors
    ///
    /// The terminal could not be configured. Nothing is left changed.
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        if let Err(error) = execute!(io::stdout(), EnterAlternateScreen, Hide) {
            restore_terminal();
            return Err(error);
        }
        Ok(Self { _private: () })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Leaves raw mode and the alternate screen; safe to call more than once.
pub fn restore_terminal() {
    // Nothing can be done if the terminal itself is gone.
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen, Show);
    let _ = stdout.flush();
}

/// Makes a panic restore the terminal before its message is printed.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

/// Restores the terminal and ends the process on SIGINT or SIGTERM.
///
/// Must be called from inside a tokio runtime. A no-op on platforms without
/// Unix signals.
pub fn install_signal_restore() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        const EXIT_SIGINT: i32 = 130;
        const EXIT_SIGTERM: i32 = 143;

        let (Ok(mut interrupt), Ok(mut terminate)) = (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        ) else {
            return;
        };
        tokio::spawn(async move {
            let code = tokio::select! {
                _ = interrupt.recv() => EXIT_SIGINT,
                _ = terminate.recv() => EXIT_SIGTERM,
            };
            restore_terminal();
            std::process::exit(code);
        });
    }
}
