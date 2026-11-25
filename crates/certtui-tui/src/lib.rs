//! Terminal UI layer: screens and widgets over the application layer.
//!
//! The architecture is Elm-style: [`AppState`] holds plain data, [`Msg`] is
//! every event that can change it, and [`update`] is a pure function that
//! returns the [`Command`]s (side effects) the executor must run.

pub mod app_state;
pub mod clipboard;
pub mod copy;
pub mod detail_rows;
pub mod keymap;
pub mod msg;
pub mod terminal;
#[cfg(test)]
mod test_fixtures;
pub mod text;
pub mod theme;
pub mod toast;
pub mod update;
pub mod update_batch;
pub mod update_home;
pub mod update_inspect;
pub mod update_modal;
pub mod view;

pub use app_state::{
    AppState, BatchPhase, BatchState, HomeState, InspectState, JobId, JobTracker, Modal, Pane,
    Phase, Screen, SortKey, Tab,
};
pub use keymap::{Action, HelpEntry, Keymap};
pub use msg::{Command, ExportFailure, ExportRequest, InspectFailure, Msg, Password};
pub use terminal::{MIN_SIZE, TerminalGuard, install_panic_hook, install_signal_restore};
pub use theme::{Theme, ThemeKind};
pub use update::update;
pub use update_batch::start_batch;
pub use update_home::start_inspect;
pub use view::view;
