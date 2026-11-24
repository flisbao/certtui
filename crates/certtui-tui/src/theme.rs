//! Color themes.

/// Which theme is active.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ThemeKind {
    /// Light text on a dark terminal.
    #[default]
    Dark,
    /// Dark text on a light terminal.
    Light,
    /// No colors at all (also what `NO_COLOR` selects).
    Mono,
}
