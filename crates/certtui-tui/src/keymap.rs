//! Keys and the actions they trigger.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// What a key press asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Leave the program.
    Quit,
    /// Go back or cancel.
    Back,
    /// Open the help dialog.
    Help,
    /// Focus the next pane.
    NextPane,
    /// Focus the previous pane.
    PrevPane,
    /// Show the next tab.
    NextTab,
    /// Show the previous tab.
    PrevTab,
    /// Move up one row.
    Up,
    /// Move down one row.
    Down,
    /// Open or confirm.
    Enter,
    /// Enter a new target.
    NewTarget,
    /// Run the inspection again.
    Refresh,
    /// Cycle the fingerprint format.
    ToggleFingerprintFormat,
    /// Mark the target as favorite.
    Favorite,
    /// Copy the datum under the cursor.
    CopyFocused,
    /// Copy the visible tab.
    CopyView,
    /// Copy the selected certificate as PEM.
    CopyPem,
    /// Copy the whole chain as PEM.
    CopyChainPem,
    /// Copy the report as JSON.
    CopyJson,
    /// Export to a file.
    Export,
    /// Filter rows.
    Filter,
    /// Sort rows.
    Sort,
}

/// Maps key presses to [`Action`]s.
#[derive(Debug, Clone, Default)]
pub struct Keymap;

impl Keymap {
    /// The keys of the design (section 10).
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// The action bound to `key`, if any. Releases and unbound keys give `None`.
    #[must_use]
    pub fn resolve(&self, key: KeyEvent) -> Option<Action> {
        if key.kind == KeyEventKind::Release {
            return None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            // Raw mode turns Ctrl-C into a key, not a signal.
            return (key.code == KeyCode::Char('c')).then_some(Action::Quit);
        }
        if key.modifiers.contains(KeyModifiers::ALT) {
            return None;
        }
        let action = match key.code {
            KeyCode::Char(c) => return char_action(c),
            KeyCode::Up => Action::Up,
            KeyCode::Down => Action::Down,
            KeyCode::Tab => Action::NextPane,
            KeyCode::BackTab => Action::PrevPane,
            KeyCode::Enter => Action::Enter,
            KeyCode::Esc => Action::Back,
            _ => return None,
        };
        Some(action)
    }
}

fn char_action(c: char) -> Option<Action> {
    let action = match c {
        'j' => Action::Down,
        'k' => Action::Up,
        'h' => Action::PrevPane,
        'l' => Action::NextPane,
        '[' => Action::PrevTab,
        ']' => Action::NextTab,
        '/' => Action::Filter,
        'o' => Action::NewTarget,
        'r' => Action::Refresh,
        'e' => Action::Export,
        'x' => Action::ToggleFingerprintFormat,
        'f' => Action::Favorite,
        's' => Action::Sort,
        '?' => Action::Help,
        'q' => Action::Quit,
        'y' => Action::CopyFocused,
        'Y' => Action::CopyView,
        'c' => Action::CopyPem,
        'C' => Action::CopyChainPem,
        'J' => Action::CopyJson,
        _ => return None,
    };
    Some(action)
}
