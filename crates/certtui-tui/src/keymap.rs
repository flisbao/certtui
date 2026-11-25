//! Keys and the actions they trigger.

use std::collections::BTreeMap;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use thiserror::Error;

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
    /// Reverse the order of the rows.
    ReverseSort,
    /// Open a batch from a file listing targets.
    OpenBatch,
}

impl Action {
    /// Every action, in the order the help lists them.
    pub const ALL: [Action; 24] = [
        Action::Down,
        Action::Up,
        Action::NextPane,
        Action::PrevPane,
        Action::NextTab,
        Action::PrevTab,
        Action::Enter,
        Action::Back,
        Action::NewTarget,
        Action::OpenBatch,
        Action::Refresh,
        Action::ToggleFingerprintFormat,
        Action::Favorite,
        Action::Filter,
        Action::Sort,
        Action::ReverseSort,
        Action::Export,
        Action::CopyFocused,
        Action::CopyView,
        Action::CopyPem,
        Action::CopyChainPem,
        Action::CopyJson,
        Action::Help,
        Action::Quit,
    ];

    /// The name used in `ui.keymap`, in `snake_case`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Action::Quit => "quit",
            Action::Back => "back",
            Action::Help => "help",
            Action::NextPane => "next_pane",
            Action::PrevPane => "prev_pane",
            Action::NextTab => "next_tab",
            Action::PrevTab => "prev_tab",
            Action::Up => "up",
            Action::Down => "down",
            Action::Enter => "enter",
            Action::NewTarget => "new_target",
            Action::Refresh => "refresh",
            Action::ToggleFingerprintFormat => "toggle_fingerprint_format",
            Action::Favorite => "favorite",
            Action::CopyFocused => "copy_focused",
            Action::CopyView => "copy_view",
            Action::CopyPem => "copy_pem",
            Action::CopyChainPem => "copy_chain_pem",
            Action::CopyJson => "copy_json",
            Action::Export => "export",
            Action::Filter => "filter",
            Action::Sort => "sort",
            Action::ReverseSort => "reverse_sort",
            Action::OpenBatch => "open_batch",
        }
    }

    /// The action called `name` in `ui.keymap`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.name() == name)
    }

    /// Every name, comma separated, for messages.
    fn names() -> String {
        Self::ALL
            .iter()
            .map(|action| action.name())
            .collect::<Vec<_>>()
            .join(", ")
    }

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
            Action::Favorite => "favorite or unfavorite the selected target (Home)",
            Action::CopyFocused => "copy the field under the cursor (Batch: the row as TSV)",
            Action::CopyView => "copy the visible tab as text (Batch: the table as CSV)",
            Action::CopyPem => "copy the certificate as PEM",
            Action::CopyChainPem => "copy the whole chain as PEM",
            Action::CopyJson => "copy the report as JSON",
            Action::Export => "export to a file",
            Action::Filter => "filter rows (Batch)",
            Action::Sort => "sort by the next column (Batch)",
            Action::ReverseSort => "reverse the order (Batch)",
            Action::OpenBatch => "inspect a list of targets from a file (Home)",
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

/// A key a binding names: a key code, with Ctrl when `ctrl` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Key {
    code: KeyCode,
    ctrl: bool,
}

impl Key {
    const fn plain(code: KeyCode) -> Self {
        Self { code, ctrl: false }
    }
}

/// Why a `ui.keymap` entry cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeymapError {
    /// The action name is not one of [`Action::name`].
    #[error("unknown keymap action `{}`; use one of: {}", shorten(.0), Action::names())]
    UnknownAction(String),
    /// The key text is not a key this program understands.
    #[error(
        "unknown key `{}`; use one character, ctrl+<character>, shift+tab, F1 to F12, or \
         enter, tab, space, up, down, left, right, home, end, pageup, pagedown",
        shorten(.0)
    )]
    UnknownKey(String),
    /// `Esc` and `Ctrl-C` always keep their meaning.
    #[error("`{}` is reserved: Esc always goes back and Ctrl-C always quits", shorten(.0))]
    Reserved(String),
    /// Two actions would answer to the same key.
    #[error("key `{key}` would be bound to both `{a}` and `{b}`")]
    Conflict {
        /// The key, as shown in the help.
        key: String,
        /// One of the two actions (the first in alphabetical order).
        a: String,
        /// The other action.
        b: String,
    },
}

/// At most 40 characters of `text`, for messages.
fn shorten(text: &str) -> String {
    text.chars().take(40).collect()
}

/// Maps key presses to [`Action`]s.
#[derive(Debug, Clone)]
pub struct Keymap {
    bindings: Vec<(Key, Action)>,
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
        let defaults = [
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
            (KeyCode::Char('b'), Action::OpenBatch),
            (KeyCode::Char('r'), Action::Refresh),
            (KeyCode::Char('e'), Action::Export),
            (KeyCode::Char('x'), Action::ToggleFingerprintFormat),
            (KeyCode::Char('f'), Action::Favorite),
            (KeyCode::Char('s'), Action::Sort),
            (KeyCode::Char('S'), Action::ReverseSort),
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
        Self {
            bindings: defaults
                .into_iter()
                .map(|(code, action)| (Key::plain(code), action))
                .collect(),
        }
    }

    /// The default keys with `overrides` applied: action name (`quit`,
    /// `copy_focused`, ...) to key (`q`, `ctrl+y`, `F5`, `shift+tab`). An
    /// overridden action loses all its default keys, except `Esc`, which
    /// always goes back.
    ///
    /// # Errors
    ///
    /// [`KeymapError`] for an unknown action or key, a reserved key (`Esc`,
    /// `Ctrl-C`), or a key two actions would share.
    pub fn from_overrides(overrides: &BTreeMap<String, String>) -> Result<Self, KeymapError> {
        let mut keymap = Self::new();
        for (name, key_text) in overrides {
            let action =
                Action::from_name(name).ok_or_else(|| KeymapError::UnknownAction(name.clone()))?;
            let key = parse_key(key_text)?;
            keymap
                .bindings
                .retain(|(bound, existing)| *existing != action || *bound == PINNED_ESC);
            keymap.bindings.push((key, action));
        }
        keymap.check_conflicts()?;
        Ok(keymap)
    }

    /// Fails when one key answers for two actions.
    fn check_conflicts(&self) -> Result<(), KeymapError> {
        for (index, (key, action)) in self.bindings.iter().enumerate() {
            let rest = self.bindings.iter().skip(index + 1);
            if let Some((_, other)) = rest.into_iter().find(|(other_key, _)| other_key == key) {
                let (mut a, mut b) = (action.name(), other.name());
                if b < a {
                    std::mem::swap(&mut a, &mut b);
                }
                return Err(KeymapError::Conflict {
                    key: key_label(*key),
                    a: a.to_owned(),
                    b: b.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// The action bound to `key`, if any. Releases and unbound keys give `None`.
    ///
    /// `Ctrl-C` always quits and `Esc` always goes back, whatever the
    /// bindings say.
    #[must_use]
    pub fn resolve(&self, key: KeyEvent) -> Option<Action> {
        if key.kind == KeyEventKind::Release {
            return None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            // Raw mode turns Ctrl-C into a key, not a signal.
            let KeyCode::Char(c) = key.code else {
                return None;
            };
            let c = c.to_ascii_lowercase();
            if c == 'c' {
                return Some(Action::Quit);
            }
            return self.lookup(Key {
                code: KeyCode::Char(c),
                ctrl: true,
            });
        }
        if key.modifiers.contains(KeyModifiers::ALT) {
            return None;
        }
        self.lookup(Key::plain(key.code))
    }

    fn lookup(&self, key: Key) -> Option<Action> {
        self.bindings
            .iter()
            .find(|(bound, _)| *bound == key)
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
                    .map(|(key, _)| key_label(*key))
                    .collect();
                HelpEntry {
                    action,
                    keys: keys.join(" / "),
                }
            })
            .collect()
    }
}

/// The binding that no override can take away.
const PINNED_ESC: Key = Key::plain(KeyCode::Esc);

/// Reads a key from its `ui.keymap` spelling.
fn parse_key(text: &str) -> Result<Key, KeymapError> {
    let unknown = || KeymapError::UnknownKey(text.to_owned());
    let lower = text.trim().to_ascii_lowercase();
    if matches!(lower.as_str(), "esc" | "escape" | "ctrl+c") {
        return Err(KeymapError::Reserved(text.to_owned()));
    }
    match lower.split_once('+').filter(|_| lower != "+") {
        None => parse_plain(text.trim(), &lower)
            .map(Key::plain)
            .ok_or_else(unknown),
        Some(("ctrl", rest)) => {
            let mut chars = rest.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) if c.is_ascii_graphic() => Ok(Key {
                    code: KeyCode::Char(c),
                    ctrl: true,
                }),
                _ => Err(unknown()),
            }
        }
        Some(("shift", "tab")) => Ok(Key::plain(KeyCode::BackTab)),
        Some(_) => Err(unknown()),
    }
}

/// A key without modifiers: one character, or a name (`lower` is `text` in
/// lower case; a lone character keeps its case).
fn parse_plain(text: &str, lower: &str) -> Option<KeyCode> {
    let mut chars = text.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        return (!c.is_control() && !c.is_whitespace()).then_some(KeyCode::Char(c));
    }
    match lower {
        "enter" => Some(KeyCode::Enter),
        "tab" => Some(KeyCode::Tab),
        "space" => Some(KeyCode::Char(' ')),
        "up" => Some(KeyCode::Up),
        "down" => Some(KeyCode::Down),
        "left" => Some(KeyCode::Left),
        "right" => Some(KeyCode::Right),
        "home" => Some(KeyCode::Home),
        "end" => Some(KeyCode::End),
        "pageup" => Some(KeyCode::PageUp),
        "pagedown" => Some(KeyCode::PageDown),
        other => {
            let number: u8 = other.strip_prefix('f')?.parse().ok()?;
            (1..=12).contains(&number).then_some(KeyCode::F(number))
        }
    }
}

fn key_label(key: Key) -> String {
    let base = match key.code {
        KeyCode::Char(' ') => "Space".to_owned(),
        KeyCode::Char(c) if key.ctrl => c.to_ascii_uppercase().to_string(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Up => "\u{2191}".to_owned(),
        KeyCode::Down => "\u{2193}".to_owned(),
        KeyCode::Left => "\u{2190}".to_owned(),
        KeyCode::Right => "\u{2192}".to_owned(),
        KeyCode::Tab => "Tab".to_owned(),
        KeyCode::BackTab => "Shift-Tab".to_owned(),
        KeyCode::Enter => "Enter".to_owned(),
        KeyCode::Esc => "Esc".to_owned(),
        KeyCode::Home => "Home".to_owned(),
        KeyCode::End => "End".to_owned(),
        KeyCode::PageUp => "PageUp".to_owned(),
        KeyCode::PageDown => "PageDown".to_owned(),
        KeyCode::F(n) => format!("F{n}"),
        other => format!("{other:?}"),
    };
    if key.ctrl {
        format!("Ctrl-{base}")
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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

    fn overrides(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(action, key)| ((*action).to_owned(), (*key).to_owned()))
            .collect()
    }

    fn press(keymap: &Keymap, code: KeyCode) -> Option<Action> {
        keymap.resolve(KeyEvent::new(code, KeyModifiers::NONE))
    }

    #[test]
    fn quando_remapeia_quit_para_x_deve_resolver_x_e_nao_q() {
        // `x` is taken by ToggleFingerprintFormat, so the example uses `z`.
        let keymap = Keymap::from_overrides(&overrides(&[("quit", "z")])).unwrap();
        assert_eq!(press(&keymap, KeyCode::Char('z')), Some(Action::Quit));
        assert_eq!(press(&keymap, KeyCode::Char('q')), None);
    }

    #[test]
    fn quando_remapeia_acao_com_duas_teclas_deve_trocar_todas_pela_nova() {
        let keymap = Keymap::from_overrides(&overrides(&[("down", "n")])).unwrap();
        assert_eq!(press(&keymap, KeyCode::Char('n')), Some(Action::Down));
        assert_eq!(press(&keymap, KeyCode::Char('j')), None);
        assert_eq!(press(&keymap, KeyCode::Down), None);
    }

    #[test]
    fn quando_sem_overrides_deve_ser_igual_ao_keymap_padrao() {
        let keymap = Keymap::from_overrides(&BTreeMap::new()).unwrap();
        assert_eq!(keymap.help_entries(), Keymap::new().help_entries());
    }

    #[test]
    fn quando_acao_desconhecida_deve_dar_unknown_action() {
        let error = Keymap::from_overrides(&overrides(&[("explode", "x")])).unwrap_err();
        assert_eq!(error, KeymapError::UnknownAction("explode".to_owned()));
        assert!(error.to_string().contains("quit"), "{error}");
    }

    #[test]
    fn quando_tecla_invalida_deve_dar_unknown_key() {
        for key in [
            "",
            "ctrl+",
            "hyper+q",
            "F99",
            "qq",
            "ctrl+enter",
            "shift+x",
            "alt+q",
        ] {
            let error = Keymap::from_overrides(&overrides(&[("quit", key)])).unwrap_err();
            assert_eq!(error, KeymapError::UnknownKey(key.to_owned()), "{key:?}");
        }
    }

    #[test]
    fn quando_tecla_e_enorme_o_erro_nao_deve_ecoar_tudo() {
        let long = "x".repeat(500);
        let error = Keymap::from_overrides(&overrides(&[("quit", &long)])).unwrap_err();
        assert!(error.to_string().len() < 200, "{}", error.to_string().len());
    }

    #[test]
    fn quando_remapeia_para_esc_ou_ctrl_c_deve_dar_reserved() {
        for key in ["esc", "Esc", "escape", "ctrl+c", "Ctrl+C"] {
            let error = Keymap::from_overrides(&overrides(&[("quit", key)])).unwrap_err();
            assert_eq!(error, KeymapError::Reserved(key.to_owned()), "{key}");
        }
    }

    #[test]
    fn quando_duas_acoes_na_mesma_tecla_deve_dar_conflict_listando_as_duas() {
        let error =
            Keymap::from_overrides(&overrides(&[("quit", "z"), ("favorite", "z")])).unwrap_err();
        assert_eq!(
            error,
            KeymapError::Conflict {
                key: "z".to_owned(),
                a: "favorite".to_owned(),
                b: "quit".to_owned(),
            }
        );
        let text = error.to_string();
        assert!(text.contains("quit") && text.contains("favorite"), "{text}");
    }

    #[test]
    fn quando_remapeia_para_tecla_de_outra_acao_padrao_deve_dar_conflict() {
        // `f` is Favorite by default.
        let error = Keymap::from_overrides(&overrides(&[("quit", "f")])).unwrap_err();
        assert!(matches!(error, KeymapError::Conflict { .. }), "{error:?}");
    }

    #[test]
    fn quando_troca_teclas_entre_duas_acoes_nao_deve_dar_conflict() {
        let keymap =
            Keymap::from_overrides(&overrides(&[("quit", "f"), ("favorite", "q")])).unwrap();
        assert_eq!(press(&keymap, KeyCode::Char('f')), Some(Action::Quit));
        assert_eq!(press(&keymap, KeyCode::Char('q')), Some(Action::Favorite));
    }

    #[test]
    fn quando_quit_e_remapeado_ctrl_c_deve_continuar_saindo() {
        let keymap = Keymap::from_overrides(&overrides(&[("quit", "z")])).unwrap();
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(keymap.resolve(ctrl_c), Some(Action::Quit));
    }

    #[test]
    fn quando_back_e_remapeado_esc_deve_continuar_voltando() {
        let keymap = Keymap::from_overrides(&overrides(&[("back", "z")])).unwrap();
        assert_eq!(press(&keymap, KeyCode::Esc), Some(Action::Back));
        assert_eq!(press(&keymap, KeyCode::Char('z')), Some(Action::Back));
    }

    #[test]
    fn quando_tecla_tem_ctrl_f_shift_tab_deve_resolver() {
        let keymap = Keymap::from_overrides(&overrides(&[
            ("copy_pem", "ctrl+y"),
            ("refresh", "F5"),
            ("next_pane", "tab"),
            ("prev_pane", "shift+tab"),
            ("enter", "space"),
        ]))
        .unwrap();
        let ctrl_y = KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL);
        assert_eq!(keymap.resolve(ctrl_y), Some(Action::CopyPem));
        // Plain `y` is still CopyFocused: only Ctrl-Y moved.
        assert_eq!(
            press(&keymap, KeyCode::Char('y')),
            Some(Action::CopyFocused)
        );
        assert_eq!(press(&keymap, KeyCode::F(5)), Some(Action::Refresh));
        assert_eq!(press(&keymap, KeyCode::Char(' ')), Some(Action::Enter));
        let back_tab = KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT);
        assert_eq!(keymap.resolve(back_tab), Some(Action::PrevPane));
    }

    #[test]
    fn quando_nome_da_tecla_tem_outra_caixa_deve_aceitar() {
        let keymap = Keymap::from_overrides(&overrides(&[("quit", "F10"), ("help", "ENTER")]));
        // `enter` is Enter's own key: remapping help onto it conflicts.
        assert!(
            matches!(keymap, Err(KeymapError::Conflict { .. })),
            "{keymap:?}"
        );
        let keymap = Keymap::from_overrides(&overrides(&[("quit", "f10")])).unwrap();
        assert_eq!(press(&keymap, KeyCode::F(10)), Some(Action::Quit));
    }

    #[test]
    fn quando_remapeado_a_ajuda_deve_listar_a_tecla_nova() {
        let keymap =
            Keymap::from_overrides(&overrides(&[("quit", "ctrl+x"), ("refresh", "F5")])).unwrap();
        let entries = keymap.help_entries();
        let keys_of = |action| {
            entries
                .iter()
                .find(|entry| entry.action == action)
                .map(|entry| entry.keys.clone())
        };
        assert_eq!(keys_of(Action::Quit), Some("Ctrl-X".to_owned()));
        assert_eq!(keys_of(Action::Refresh), Some("F5".to_owned()));
    }

    #[test]
    fn quando_action_tem_nome_deve_ida_e_volta_para_todas() {
        for action in Action::ALL {
            assert_eq!(Action::from_name(action.name()), Some(action));
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
