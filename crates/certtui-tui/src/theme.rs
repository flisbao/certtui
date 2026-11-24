//! Color themes.

use ratatui::style::{Color, Modifier, Style};

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

/// The styles every view draws with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Default text.
    pub base: Style,
    /// Screen and pane titles.
    pub title: Style,
    /// Frames around panes.
    pub border: Style,
    /// The row under the cursor.
    pub selected: Style,
    /// Secondary text.
    pub dim: Style,
    /// Good status.
    pub ok: Style,
    /// Warnings.
    pub warn: Style,
    /// Errors.
    pub error: Style,
}

impl Theme {
    /// The theme for `kind`; `no_color` (the `NO_COLOR` convention) forces
    /// [`ThemeKind::Mono`].
    #[must_use]
    pub fn for_kind(kind: ThemeKind, no_color: bool) -> Self {
        if no_color {
            return Self::mono();
        }
        match kind {
            ThemeKind::Dark => Self::dark(),
            ThemeKind::Light => Self::light(),
            ThemeKind::Mono => Self::mono(),
        }
    }

    fn dark() -> Self {
        Self {
            base: Style::new(),
            title: Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            border: Style::new().fg(Color::DarkGray),
            selected: Style::new().add_modifier(Modifier::REVERSED),
            dim: Style::new().fg(Color::DarkGray),
            ok: Style::new().fg(Color::Green),
            warn: Style::new().fg(Color::Yellow),
            error: Style::new().fg(Color::Red),
        }
    }

    fn light() -> Self {
        Self {
            base: Style::new(),
            title: Style::new().fg(Color::Blue).add_modifier(Modifier::BOLD),
            border: Style::new().fg(Color::Gray),
            selected: Style::new().add_modifier(Modifier::REVERSED),
            dim: Style::new().fg(Color::Gray),
            ok: Style::new().fg(Color::Green),
            warn: Style::new().fg(Color::Magenta),
            error: Style::new().fg(Color::Red),
        }
    }

    fn mono() -> Self {
        Self {
            base: Style::new(),
            title: Style::new().add_modifier(Modifier::BOLD),
            border: Style::new(),
            selected: Style::new().add_modifier(Modifier::REVERSED),
            dim: Style::new().add_modifier(Modifier::DIM),
            ok: Style::new(),
            warn: Style::new().add_modifier(Modifier::BOLD),
            error: Style::new().add_modifier(Modifier::BOLD),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_no_color_deve_escolher_tema_mono() {
        assert_eq!(
            Theme::for_kind(ThemeKind::Dark, true),
            Theme::for_kind(ThemeKind::Mono, false)
        );
        assert_ne!(
            Theme::for_kind(ThemeKind::Dark, false),
            Theme::for_kind(ThemeKind::Mono, false)
        );
    }
}
