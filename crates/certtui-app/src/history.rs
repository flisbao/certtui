//! Recent targets and favorites (spec section 5.3, `HistoryRepository`).

use certtui_domain::target_parse::parse_network_target;
use certtui_domain::time::Timestamp;

/// One recently inspected target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The target as the user last typed it (trimmed).
    pub target: String,
    /// When it was last inspected.
    pub last_used: Timestamp,
    /// How many times it was inspected.
    pub count: u32,
}

/// Recent targets, newest first, and favorites, in the order they were added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    /// Recently inspected targets, newest first.
    pub recents: Vec<HistoryEntry>,
    /// Favorite targets.
    pub favorites: Vec<String>,
}

/// What loading the history found besides the history itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryNote {
    /// The file was unreadable or from a newer version: it was kept as
    /// `history.json.bak` and the history starts empty.
    Recovered,
}

/// A loaded history and what was found on the way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadedHistory {
    /// The history; empty when there was no file or it was recovered.
    pub history: History,
    /// Something worth telling the user.
    pub note: Option<HistoryNote>,
}

/// Why the history could not be read or saved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HistoryError {
    /// The file or its directory could not be read or written.
    #[error("history file: {0}")]
    Io(String),
}

/// Where the history lives.
pub trait HistoryRepository: Send + Sync {
    /// Reads the history. A missing file is an empty history; a corrupted one
    /// is moved aside and replaced by an empty history, with a note.
    ///
    /// # Errors
    ///
    /// [`HistoryError::Io`] when the file exists but cannot be read.
    fn load(&self) -> Result<LoadedHistory, HistoryError>;

    /// Writes the history atomically: a failure leaves the previous file as
    /// it was.
    ///
    /// # Errors
    ///
    /// [`HistoryError::Io`] when the file cannot be written.
    fn save(&self, history: &History) -> Result<(), HistoryError>;
}

/// The key two spellings of the same target share: `A.com`, `a.com:443` and
/// `https://A.COM/x` are one target; anything that is not a network target
/// (a path) is compared as typed.
fn key_of(text: &str) -> String {
    let text = text.trim();
    match parse_network_target(text) {
        Ok(target) => {
            let host = target.host.to_ascii_lowercase();
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host
            };
            if target.port == 443 {
                host
            } else {
                format!("{host}:{}", target.port)
            }
        }
        Err(_) => text.to_owned(),
    }
}

impl History {
    /// Records that `target` was inspected at `now`: it moves to the top (its
    /// count grows when it was there) and the oldest entries beyond
    /// `max_entries` are dropped. Empty targets and `-` are not recorded.
    pub fn record(&mut self, target: &str, now: Timestamp, max_entries: usize) {
        let target = target.trim();
        if target.is_empty() || target == "-" {
            return;
        }
        let key = key_of(target);
        let previous = self
            .recents
            .iter()
            .position(|entry| key_of(&entry.target) == key)
            .map(|index| self.recents.remove(index));
        let count = previous.map_or(1, |entry| entry.count.saturating_add(1));
        self.recents.insert(
            0,
            HistoryEntry {
                target: target.to_owned(),
                last_used: now,
                count,
            },
        );
        self.recents.truncate(max_entries);
    }

    /// Adds `target` to the favorites, or removes it when it is there.
    pub fn toggle_favorite(&mut self, target: &str) {
        let target = target.trim();
        if target.is_empty() || target == "-" {
            return;
        }
        let key = key_of(target);
        match self.favorites.iter().position(|f| key_of(f) == key) {
            Some(index) => {
                self.favorites.remove(index);
            }
            None => self.favorites.push(target.to_owned()),
        }
    }

    /// Whether `target` is a favorite.
    #[must_use]
    pub fn is_favorite(&self, target: &str) -> bool {
        let key = key_of(target);
        self.favorites.iter().any(|f| key_of(f) == key)
    }

    /// Up to `max` known targets that start with `prefix` (ignoring case),
    /// favorites first, each target once.
    #[must_use]
    pub fn suggestions(&self, prefix: &str, max: usize) -> Vec<String> {
        let prefix = prefix.trim().to_lowercase();
        if prefix.is_empty() {
            return Vec::new();
        }
        let mut seen: Vec<String> = Vec::new();
        let mut out: Vec<String> = Vec::new();
        let all = self
            .favorites
            .iter()
            .map(String::as_str)
            .chain(self.recents.iter().map(|entry| entry.target.as_str()));
        for target in all {
            if out.len() >= max {
                break;
            }
            let key = key_of(target);
            if seen.contains(&key) || !target.to_lowercase().starts_with(&prefix) {
                continue;
            }
            seen.push(key);
            out.push(target.to_owned());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use certtui_domain::time::Timestamp;

    use super::*;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix(secs).unwrap()
    }

    fn targets(history: &History) -> Vec<&str> {
        history.recents.iter().map(|e| e.target.as_str()).collect()
    }

    #[test]
    fn quando_registra_alvo_repetido_deve_mover_para_o_topo_e_incrementar_contagem() {
        let mut history = History::default();
        history.record("a.example", at(1), 200);
        history.record("b.example", at(2), 200);
        history.record("a.example", at(3), 200);
        assert_eq!(targets(&history), ["a.example", "b.example"]);
        let top = history.recents.first().unwrap();
        assert_eq!(top.count, 2);
        assert_eq!(top.last_used, at(3));
        assert_eq!(history.recents.get(1).unwrap().count, 1);
    }

    #[test]
    fn quando_passa_de_max_entries_deve_cortar_os_mais_antigos() {
        let mut history = History::default();
        for n in 0..250 {
            history.record(&format!("h{n}.example"), at(n), 200);
        }
        assert_eq!(history.recents.len(), 200);
        assert_eq!(history.recents.first().unwrap().target, "h249.example");
        assert_eq!(history.recents.last().unwrap().target, "h50.example");
    }

    #[test]
    fn quando_max_entries_e_mil_deve_guardar_mil() {
        let mut history = History::default();
        for n in 0..1_100 {
            history.record(&format!("h{n}.example"), at(n), 1_000);
        }
        assert_eq!(history.recents.len(), 1_000);
    }

    #[test]
    fn quando_alvo_normaliza_igual_deve_deduplicar() {
        let mut history = History::default();
        history.record("A.com", at(1), 200);
        history.record("a.com:443", at(2), 200);
        history.record("https://A.COM/path", at(3), 200);
        assert_eq!(history.recents.len(), 1);
        assert_eq!(history.recents.first().unwrap().count, 3);
        // The latest spelling is what is shown and reselected.
        assert_eq!(
            history.recents.first().unwrap().target,
            "https://A.COM/path"
        );
    }

    #[test]
    fn quando_portas_diferem_nao_deve_deduplicar() {
        let mut history = History::default();
        history.record("a.com:8443", at(1), 200);
        history.record("a.com", at(2), 200);
        assert_eq!(history.recents.len(), 2);
    }

    #[test]
    fn quando_alvo_e_vazio_ou_stdin_nao_deve_registrar() {
        let mut history = History::default();
        history.record("   ", at(1), 200);
        history.record("-", at(2), 200);
        assert_eq!(history.recents, []);
    }

    #[test]
    fn quando_caminho_de_arquivo_deve_manter_a_caixa() {
        let mut history = History::default();
        history.record("./Certs/Chain.PEM", at(1), 200);
        history.record("./certs/chain.pem", at(2), 200);
        assert_eq!(history.recents.len(), 2);
    }

    #[test]
    fn quando_toggle_favorite_duas_vezes_deve_voltar_ao_estado_inicial() {
        let mut history = History::default();
        history.record("a.example", at(1), 200);
        let before = history.clone();
        history.toggle_favorite("a.example");
        assert_eq!(history.favorites, ["a.example"]);
        assert!(history.is_favorite("A.EXAMPLE:443"));
        history.toggle_favorite("A.example");
        assert_eq!(history, before);
    }

    #[test]
    fn quando_favorita_alvo_fora_dos_recentes_deve_manter_so_nos_favoritos() {
        let mut history = History::default();
        history.toggle_favorite("x.example");
        assert_eq!(history.recents, []);
        assert_eq!(history.favorites, ["x.example"]);
    }

    #[test]
    fn quando_digita_prefixo_deve_sugerir_favoritos_antes_dos_recentes_sem_repetir() {
        let mut history = History::default();
        history.record("alpha.example", at(1), 200);
        history.record("alps.example", at(2), 200);
        history.record("beta.example", at(3), 200);
        history.toggle_favorite("alps.example");
        assert_eq!(
            history.suggestions("AL", 8),
            ["alps.example", "alpha.example"]
        );
        assert_eq!(history.suggestions("be", 8), ["beta.example"]);
        assert_eq!(history.suggestions("zz", 8), Vec::<String>::new());
        assert_eq!(history.suggestions("", 8), Vec::<String>::new());
    }

    #[test]
    fn quando_ha_mais_sugestoes_que_o_limite_deve_cortar() {
        let mut history = History::default();
        for n in 0..20 {
            history.record(&format!("a{n}.example"), at(n), 200);
        }
        assert_eq!(history.suggestions("a", 5).len(), 5);
    }
}
