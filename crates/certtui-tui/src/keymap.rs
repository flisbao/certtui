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

impl Action {
    /// Every action, in the order the help lists them.
    pub const ALL: [Action; 22] = [
        Action::Down,
        Action::Up,
        Action::NextPane,
        Action::PrevPane,
        Action::NextTab,
        Action::PrevTab,
        Action::Enter,
        Action::Back,
        Action::NewTarget,
        Action::Refresh,
        Action::ToggleFingerprintFormat,
        Action::Favorite,
        Action::Filter,
        Action::Sort,
        Action::Export,
        Action::CopyFocused,
        Action::CopyView,
        Action::CopyPem,
        Action::CopyChainPem,
        Action::CopyJson,
        Action::Help,
        Action::Quit,
    ];

    /// What the action does, for the help dialog.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Action::Quit => "quit (on Inspect while loading: cancel)",
            Action::Back => "back, cancel, stop typing",
            Action::Help => "this help",
            Action::NextPane => "next pane",
            Action::PrevPane => "previous pane",
            Action::NextTab => "next tab",
            Action::PrevTab => "previous tab",
            Action::Up => "move up",
            Action::Down => "move down",
            Action::Enter => "open / confirm",
            Action::NewTarget => "enter a new target",
            Action::Refresh => "inspect again (not yet)",
            Action::ToggleFingerprintFormat => "cycle fingerprint format",
            Action::Favorite => "favorite the target (not yet)",
            Action::CopyFocused => "copy the field under the cursor",
            Action::CopyView => "copy the visible tab as text",
            Action::CopyPem => "copy the certificate as PEM",
            Action::CopyChainPem => "copy the whole chain as PEM",
            Action::CopyJson => "copy the report as JSON",
            Action::Export => "export to a file (not yet)",
            Action::Filter => "filter rows (not yet)",
            Action::Sort => "sort rows (not yet)",
        }
    }
}

/// One line of the help: an action and the keys bound to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpEntry {
    /// The action.
    pub action: Action,
    /// Its keys, as shown (`j / ↓`).
    pub keys: String,
}

/// Maps key presses to [`Action`]s.
#[derive(Debug, Clone)]
pub struct Keymap {
    bindings: Vec<(KeyCode, Action)>,
}

impl Default for Keymap {
    fn default() -> Self {
        Self::new()
    }
}

impl Keymap {
    /// The keys of the design (section 10).
    #[must_use]
    pub fn new() -> Self {
        let bindings = vec![
            (KeyCode::Char('j'), Action::Down),
            (KeyCode::Down, Action::Down),
            (KeyCode::Char('k'), Action::Up),
            (KeyCode::Up, Action::Up),
            (KeyCode::Char('h'), Action::PrevPane),
            (KeyCode::BackTab, Action::PrevPane),
            (KeyCode::Char('l'), Action::NextPane),
            (KeyCode::Tab, Action::NextPane),
            (KeyCode::Char('['), Action::PrevTab),
            (KeyCode::Char(']'), Action::NextTab),
            (KeyCode::Char('/'), Action::Filter),
            (KeyCode::Char('o'), Action::NewTarget),
            (KeyCode::Char('r'), Action::Refresh),
            (KeyCode::Char('e'), Action::Export),
            (KeyCode::Char('x'), Action::ToggleFingerprintFormat),
            (KeyCode::Char('f'), Action::Favorite),
            (KeyCode::Char('s'), Action::Sort),
            (KeyCode::Enter, Action::Enter),
            (KeyCode::Esc, Action::Back),
            (KeyCode::Char('?'), Action::Help),
            (KeyCode::Char('q'), Action::Quit),
            (KeyCode::Char('y'), Action::CopyFocused),
            (KeyCode::Char('Y'), Action::CopyView),
            (KeyCode::Char('c'), Action::CopyPem),
            (KeyCode::Char('C'), Action::CopyChainPem),
            (KeyCode::Char('J'), Action::CopyJson),
        ];
        Self { bindings }
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
        self.bindings
            .iter()
            .find(|(code, _)| *code == key.code)
            .map(|(_, action)| *action)
    }

    /// What the help dialog lists: every action with its keys.
    #[must_use]
    pub fn help_entries(&self) -> Vec<HelpEntry> {
        Action::ALL
            .into_iter()
            .map(|action| {
                let keys: Vec<String> = self
                    .bindings
                    .iter()
                    .filter(|(_, bound)| *bound == action)
                    .map(|(code, _)| key_label(*code))
                    .collect();
                HelpEntry {
                    action,
                    keys: keys.join(" / "),
                }
            })
            .collect()
    }
}

fn key_label(code: KeyCode) -> String {
    match code {
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Up => "\u{2191}".to_owned(),
        KeyCode::Down => "\u{2193}".to_owned(),
        KeyCode::Tab => "Tab".to_owned(),
        KeyCode::BackTab => "Shift-Tab".to_owned(),
        KeyCode::Enter => "Enter".to_owned(),
        KeyCode::Esc => "Esc".to_owned(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_all_deve_ter_todas_as_actions_sem_repeticao() {
        let mut seen = std::collections::HashSet::new();
        assert!(Action::ALL.iter().all(|action| seen.insert(*action)));
        assert_eq!(seen.len(), Action::ALL.len());
    }

    #[test]
    fn quando_action_do_keymap_deve_ter_pelo_menos_uma_tecla() {
        for entry in Keymap::new().help_entries() {
            assert!(!entry.keys.is_empty(), "{:?} has no key", entry.action);
        }
    }

    #[test]
    fn quando_tecla_com_alt_ou_ctrl_diferente_de_c_deve_ser_ignorada() {
        let keymap = Keymap::new();
        let alt = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::ALT);
        let ctrl_q = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(keymap.resolve(alt), None);
        assert_eq!(keymap.resolve(ctrl_q), None);
    }
}
