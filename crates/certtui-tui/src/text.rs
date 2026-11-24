//! Text that came from outside, made safe for the screen.

use std::borrow::Cow;

use certtui_domain::sanitize::sanitize_display;

/// `input` without control characters, for drawing.
///
/// Line breaks and tabs are kept by [`sanitize_display`]; views that draw a
/// single line replace them here so a value cannot spill onto other rows.
#[must_use]
pub fn display(input: &str) -> Cow<'_, str> {
    let clean = sanitize_display(input);
    if clean.contains(['\n', '\t']) {
        Cow::Owned(clean.replace(['\n', '\t'], " "))
    } else {
        clean
    }
}
