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
pub mod theme;
pub mod toast;
pub mod update;

pub use app_state::{AppState, HomeState, InspectState, JobId, JobTracker, Modal, Screen};
pub use keymap::{Action, Keymap};
pub use msg::{Command, Msg};
pub use update::update;
