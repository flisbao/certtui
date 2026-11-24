//! Terminal UI layer: screens and widgets over the application layer.
//!
//! The architecture is Elm-style: [`AppState`] holds plain data, [`Msg`] is
//! every event that can change it, and [`update`] is a pure function that
//! returns the [`Command`]s (side effects) the executor must run.

pub mod app_state;
pub mod clipboard;
pub mod copy;
pub mod keymap;
pub mod msg;
pub mod terminal;
pub mod theme;
pub mod toast;
pub mod update;
pub mod view;

pub use app_state::{AppState, HomeState, InspectState, JobId, JobTracker, Modal, Screen};
pub use keymap::{Action, Keymap};
pub use msg::{Command, Msg};
pub use terminal::{MIN_SIZE, TerminalGuard, install_panic_hook, install_signal_restore};
pub use theme::{Theme, ThemeKind};
pub use update::update;
pub use view::view;
