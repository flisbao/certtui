//! Pure renderers of an [`InspectionReport`]: they only write to a
//! `&mut dyn Write` handed in by the caller.

pub mod check;
pub mod field;

pub mod pem;
pub mod text;

use certtui_app::present::labels;
pub use certtui_app::present::{View, json};

pub use labels::{note_text, single_line};

#[cfg(test)]
pub(crate) use certtui_app::present::testing;
