//! The history file: [`FileHistoryRepository`].

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use certtui_app::export::Overwrite;
use certtui_app::history::{
    History, HistoryEntry, HistoryError, HistoryNote, HistoryRepository, LoadedHistory,
};
use certtui_domain::limits::Limits;
use certtui_domain::time::Timestamp;
use serde::{Deserialize, Serialize};

use crate::atomic_write::write_atomic;

/// The only `schema_version` of the file this build reads and writes.
const SCHEMA_VERSION: u32 = 1;

/// Largest history file read; a bigger one is treated as corrupted.
const MAX_HISTORY_BYTES: usize = 4 * 1024 * 1024;

/// The history file, a JSON document next to the user's data.
#[derive(Debug, Clone)]
pub struct FileHistoryRepository {
    path: PathBuf,
}

impl FileHistoryRepository {
    /// A repository over the file at `path` (see [`crate::paths::history_path`]).
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The path the corrupted file is moved to: `history.json.bak`.
    fn backup_path(&self) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(ToOwned::to_owned)
            .unwrap_or_default();
        name.push(".bak");
        self.path.with_file_name(name)
    }

    /// Moves the unusable file aside, replacing an older backup, and says so.
    fn recover(&self) -> LoadedHistory {
        let backup = self.backup_path();
        // Windows refuses to rename over an existing file.
        let _ = fs::remove_file(&backup);
        // If even the rename fails the file stays where it is and the next
        // save replaces it: the history is empty either way.
        let _ = fs::rename(&self.path, &backup);
        LoadedHistory {
            history: History::default(),
            note: Some(HistoryNote::Recovered),
        }
    }
}

/// The file format: versioned, one object per recent target.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryFile {
    schema_version: u32,
    recents: Vec<EntryFile>,
    favorites: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryFile {
    target: String,
    /// Seconds since the Unix epoch.
    last_used: i64,
    count: u32,
}

impl From<&History> for HistoryFile {
    fn from(history: &History) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            recents: history
                .recents
                .iter()
                .map(|entry| EntryFile {
                    target: entry.target.clone(),
                    last_used: entry.last_used.unix(),
                    count: entry.count,
                })
                .collect(),
            favorites: history.favorites.clone(),
        }
    }
}

/// The history a file describes, or `None` when it is not one this build can
/// use (wrong version, bad timestamp).
fn history_of(file: HistoryFile) -> Option<History> {
    if file.schema_version != SCHEMA_VERSION {
        return None;
    }
    let cap = Limits::HARD_CAPS.history_entries;
    let recents = file
        .recents
        .into_iter()
        .take(cap)
        .map(|entry| {
            Some(HistoryEntry {
                target: entry.target,
                last_used: Timestamp::from_unix(entry.last_used).ok()?,
                count: entry.count,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(History {
        recents,
        favorites: file.favorites.into_iter().take(cap).collect(),
    })
}

fn read_capped(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(MAX_HISTORY_BYTES).unwrap_or(u64::MAX);
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok((bytes.len() <= MAX_HISTORY_BYTES).then_some(bytes))
}

impl HistoryRepository for FileHistoryRepository {
    fn load(&self) -> Result<LoadedHistory, HistoryError> {
        let bytes = match read_capped(&self.path) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(self.recover()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LoadedHistory::default());
            }
            Err(error) => {
                return Err(HistoryError::Io(format!(
                    "{}: {}",
                    self.path.display(),
                    error.kind()
                )));
            }
        };
        match serde_json::from_slice::<HistoryFile>(&bytes)
            .ok()
            .and_then(history_of)
        {
            Some(history) => Ok(LoadedHistory {
                history,
                note: None,
            }),
            None => Ok(self.recover()),
        }
    }

    fn save(&self, history: &History) -> Result<(), HistoryError> {
        let io = |error: &dyn std::fmt::Display| {
            HistoryError::Io(format!("{}: {error}", self.path.display()))
        };
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|error| io(&error.kind()))?;
        }
        let mut json =
            serde_json::to_vec_pretty(&HistoryFile::from(history)).map_err(|error| io(&error))?;
        json.push(b'\n');
        write_atomic(&self.path, &json, Overwrite::Allow).map_err(|error| io(&error))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use certtui_app::history::{
        History, HistoryEntry, HistoryError, HistoryNote, HistoryRepository, LoadedHistory,
    };
    use certtui_domain::time::Timestamp;

    use super::*;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A scratch directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("certtui-history-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn history(&self) -> PathBuf {
            self.0.join("history.json")
        }

        fn bak(&self) -> PathBuf {
            self.0.join("history.json.bak")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            // A test may leave the directory read-only.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
            }
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample() -> History {
        History {
            recents: vec![
                HistoryEntry {
                    target: "b.example:8443".to_owned(),
                    last_used: Timestamp::from_unix(2_000).unwrap(),
                    count: 3,
                },
                HistoryEntry {
                    target: "a.example".to_owned(),
                    last_used: Timestamp::from_unix(1_000).unwrap(),
                    count: 1,
                },
            ],
            favorites: vec!["a.example".to_owned()],
        }
    }

    #[test]
    fn quando_arquivo_nao_existe_deve_devolver_vazio() {
        let dir = Scratch::new();
        let repo = FileHistoryRepository::new(dir.history());
        assert_eq!(repo.load(), Ok(LoadedHistory::default()));
    }

    #[test]
    fn quando_salva_e_carrega_deve_devolver_o_mesmo_historico() {
        let dir = Scratch::new();
        let repo = FileHistoryRepository::new(dir.history());
        repo.save(&sample()).unwrap();
        let loaded = repo.load().unwrap();
        assert_eq!(loaded.history, sample());
        assert_eq!(loaded.note, None);
    }

    #[test]
    fn quando_diretorio_nao_existe_deve_cria_lo_ao_salvar() {
        let dir = Scratch::new();
        let repo = FileHistoryRepository::new(dir.0.join("nested/deeper/history.json"));
        repo.save(&sample()).unwrap();
        assert_eq!(repo.load().unwrap().history, sample());
    }

    #[test]
    fn quando_json_corrompido_deve_mover_para_bak_e_devolver_vazio() {
        let dir = Scratch::new();
        fs::write(dir.history(), b"{ not json").unwrap();
        let repo = FileHistoryRepository::new(dir.history());
        let loaded = repo.load().unwrap();
        assert_eq!(loaded.history, History::default());
        assert_eq!(loaded.note, Some(HistoryNote::Recovered));
        assert!(!dir.history().exists());
        assert_eq!(fs::read(dir.bak()).unwrap(), b"{ not json");
    }

    #[test]
    fn quando_arquivo_truncado_deve_recuperar_como_corrompido() {
        let dir = Scratch::new();
        let repo = FileHistoryRepository::new(dir.history());
        repo.save(&sample()).unwrap();
        let full = fs::read(dir.history()).unwrap();
        fs::write(dir.history(), &full[..full.len() / 2]).unwrap();
        let loaded = repo.load().unwrap();
        assert_eq!(loaded.history, History::default());
        assert_eq!(loaded.note, Some(HistoryNote::Recovered));
        assert!(dir.bak().exists());
    }

    #[test]
    fn quando_schema_futura_deve_tratar_como_corrompido() {
        let dir = Scratch::new();
        let future = br#"{"schema_version":2,"recents":[],"favorites":[],"novelty":true}"#;
        fs::write(dir.history(), future).unwrap();
        let loaded = FileHistoryRepository::new(dir.history()).load().unwrap();
        assert_eq!(loaded.history, History::default());
        assert_eq!(loaded.note, Some(HistoryNote::Recovered));
        // The newer file is preserved untouched for the newer program.
        assert_eq!(fs::read(dir.bak()).unwrap(), future);
    }

    #[test]
    fn quando_arquivo_nao_e_utf8_ou_esta_vazio_deve_recuperar() {
        for content in [&[0xFFu8, 0xFE, 0x00][..], b"", b"null", b"[]"] {
            let dir = Scratch::new();
            fs::write(dir.history(), content).unwrap();
            let loaded = FileHistoryRepository::new(dir.history()).load().unwrap();
            assert_eq!(loaded.note, Some(HistoryNote::Recovered), "{content:?}");
        }
    }

    #[test]
    fn quando_timestamp_esta_fora_da_faixa_deve_recuperar() {
        let dir = Scratch::new();
        let bad = br#"{"schema_version":1,"recents":[{"target":"a","last_used":99999999999999,"count":1}],"favorites":[]}"#;
        fs::write(dir.history(), bad).unwrap();
        let loaded = FileHistoryRepository::new(dir.history()).load().unwrap();
        assert_eq!(loaded.note, Some(HistoryNote::Recovered));
    }

    #[test]
    fn quando_arquivo_e_enorme_deve_recuperar_sem_ler_tudo() {
        let dir = Scratch::new();
        let file = fs::File::create(dir.history()).unwrap();
        file.set_len(50 * 1024 * 1024).unwrap();
        let loaded = FileHistoryRepository::new(dir.history()).load().unwrap();
        assert_eq!(loaded.note, Some(HistoryNote::Recovered));
    }

    #[test]
    fn quando_ja_existe_bak_antigo_deve_substitui_lo() {
        let dir = Scratch::new();
        fs::write(dir.bak(), b"older").unwrap();
        fs::write(dir.history(), b"garbage").unwrap();
        FileHistoryRepository::new(dir.history()).load().unwrap();
        assert_eq!(fs::read(dir.bak()).unwrap(), b"garbage");
    }

    #[test]
    fn quando_arquivo_tem_mais_de_mil_entradas_deve_cortar_no_teto() {
        let dir = Scratch::new();
        let recents: Vec<String> = (0..1_200)
            .map(|n| format!(r#"{{"target":"h{n}.example","last_used":{n},"count":1}}"#))
            .collect();
        let json = format!(
            r#"{{"schema_version":1,"recents":[{}],"favorites":[]}}"#,
            recents.join(",")
        );
        fs::write(dir.history(), json).unwrap();
        let loaded = FileHistoryRepository::new(dir.history()).load().unwrap();
        assert_eq!(loaded.history.recents.len(), 1_000);
        assert_eq!(loaded.note, None);
    }

    #[cfg(unix)]
    #[test]
    fn quando_save_falha_deve_preservar_arquivo_antigo() {
        use std::os::unix::fs::PermissionsExt;

        let dir = Scratch::new();
        let repo = FileHistoryRepository::new(dir.history());
        repo.save(&sample()).unwrap();
        let before = fs::read(dir.history()).unwrap();
        // A read-only directory stands in for a full disk: the temporary file
        // cannot be created.
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o555)).unwrap();
        if fs::File::create(dir.0.join("probe")).is_ok() {
            // Running as root: permissions do not stop us; nothing to prove.
            return;
        }
        let mut other = sample();
        other.favorites.clear();
        let result = repo.save(&other);
        assert!(matches!(result, Err(HistoryError::Io(_))), "{result:?}");
        assert_eq!(fs::read(dir.history()).unwrap(), before);
        assert_eq!(repo.load().unwrap().history, sample());
    }
}
