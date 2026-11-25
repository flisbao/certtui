//! Reads the configuration file: [`FileConfigRepository`].

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;

use certtui_app::config::{Config, ConfigError, ConfigRepository};

use crate::env::EnvVars;
use crate::paths::{ConfigLocation, config_path};

/// Largest configuration file read (1 MiB); a bigger one is refused without
/// reading it all.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// The UTF-8 byte order mark some editors prepend.
const BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

/// The [`ConfigRepository`] of the real program: a JSON file.
#[derive(Debug, Clone)]
pub struct FileConfigRepository {
    flag_path: Option<PathBuf>,
    env: EnvVars,
    /// Replaces the platform config directory; for tests.
    default_path: Option<PathBuf>,
}

impl FileConfigRepository {
    /// A repository that looks at `$CERTTUI_CONFIG` in `env`, then at
    /// `flag_path` (`--config`), then at the platform config directory.
    #[must_use]
    pub fn new(flag_path: Option<PathBuf>, env: EnvVars) -> Self {
        Self {
            flag_path,
            env,
            default_path: None,
        }
    }

    /// Uses `path` instead of the platform config directory (never explicit).
    #[must_use]
    pub fn with_default_path(mut self, path: PathBuf) -> Self {
        self.default_path = Some(path);
        self
    }

    fn location(&self) -> Option<ConfigLocation> {
        let explicit = config_path(self.flag_path.as_deref(), &self.env)?;
        if explicit.explicit {
            return Some(explicit);
        }
        match &self.default_path {
            Some(path) => Some(ConfigLocation {
                path: path.clone(),
                explicit: false,
            }),
            None => Some(explicit),
        }
    }
}

impl ConfigRepository for FileConfigRepository {
    fn load(&self) -> Result<Config, ConfigError> {
        let Some(location) = self.location() else {
            return Ok(Config::default());
        };
        let file = match File::open(&location.path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound && !location.explicit => {
                return Ok(Config::default());
            }
            Err(error) => {
                return Err(ConfigError::Io(format!(
                    "{}: {}",
                    location.path.display(),
                    error.kind()
                )));
            }
        };
        let mut bytes = Vec::new();
        // One byte past the limit tells "exactly at the limit" from "over it"
        // without ever reading more than the limit allows.
        let limit = u64::try_from(MAX_CONFIG_BYTES).unwrap_or(u64::MAX);
        file.take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| {
                ConfigError::Io(format!("{}: {}", location.path.display(), error.kind()))
            })?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                limit: MAX_CONFIG_BYTES,
            });
        }
        parse_bytes(&bytes)
    }
}

/// Parses the bytes of a configuration file: BOM removed, empty and
/// non-UTF-8 files refused.
fn parse_bytes(bytes: &[u8]) -> Result<Config, ConfigError> {
    let bytes = bytes.strip_prefix(BOM).unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| ConfigError::InvalidValue {
        field: "<root>".to_owned(),
        message: "file is not valid UTF-8".to_owned(),
    })?;
    if text.trim().is_empty() {
        return Err(ConfigError::InvalidValue {
            field: "<root>".to_owned(),
            message: "empty file".to_owned(),
        });
    }
    Config::from_json(text)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use certtui_app::config::{Config, ConfigError, ConfigRepository};

    use super::*;
    use crate::env::EnvVars;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A scratch directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("certtui-config-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn repo_with_default(default: &Path) -> FileConfigRepository {
        FileConfigRepository::new(None, EnvVars::default()).with_default_path(default.to_owned())
    }

    #[test]
    fn quando_arquivo_nao_existe_deve_devolver_default() {
        let dir = Scratch::new();
        let repo = repo_with_default(&dir.0.join("absent.json"));
        assert_eq!(repo.load(), Ok(Config::default()));
    }

    #[test]
    fn quando_arquivo_explicito_nao_existe_deve_dar_erro_citando_o_caminho() {
        let dir = Scratch::new();
        let missing = dir.0.join("typo.json");
        let repo = FileConfigRepository::new(Some(missing.clone()), EnvVars::default());
        match repo.load() {
            Err(ConfigError::Io(message)) => {
                assert!(message.contains("typo.json"), "{message}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quando_arquivo_valido_deve_carregar() {
        let dir = Scratch::new();
        let path = dir.file("c.json", br#"{"ui":{"theme":"light"}}"#);
        let config = repo_with_default(&path).load().unwrap();
        assert_eq!(config.ui.theme, certtui_app::config::Theme::Light);
    }

    #[test]
    fn quando_env_certtui_config_e_flag_conflitam_deve_vencer_o_env() {
        let dir = Scratch::new();
        let from_env = dir.file("env.json", br#"{"ui":{"theme":"mono"}}"#);
        let from_flag = dir.file("flag.json", br#"{"ui":{"theme":"light"}}"#);
        let env = EnvVars::from_pairs([("CERTTUI_CONFIG", from_env.to_str().unwrap())]);
        let repo = FileConfigRepository::new(Some(from_flag), env);
        assert_eq!(
            repo.load().unwrap().ui.theme,
            certtui_app::config::Theme::Mono
        );
    }

    #[test]
    fn quando_env_certtui_config_esta_vazia_deve_ser_ignorada() {
        let dir = Scratch::new();
        let from_flag = dir.file("flag.json", br#"{"ui":{"theme":"light"}}"#);
        let env = EnvVars::from_pairs([("CERTTUI_CONFIG", "")]);
        let repo = FileConfigRepository::new(Some(from_flag), env);
        assert_eq!(
            repo.load().unwrap().ui.theme,
            certtui_app::config::Theme::Light
        );
    }

    #[test]
    fn quando_tem_bom_deve_carregar() {
        let dir = Scratch::new();
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(br#"{"ui":{"mouse":true}}"#);
        let path = dir.file("bom.json", &bytes);
        assert!(repo_with_default(&path).load().unwrap().ui.mouse);
    }

    #[test]
    fn quando_tem_comentario_deve_dar_syntax_com_linha() {
        let dir = Scratch::new();
        let path = dir.file("c.json", b"{\n  // no comments\n  \"ui\": {}\n}");
        match repo_with_default(&path).load() {
            Err(ConfigError::Syntax { line, .. }) => assert_eq!(line, 2),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quando_tem_virgula_sobrando_deve_dar_syntax_com_linha_e_coluna() {
        let dir = Scratch::new();
        let path = dir.file("c.json", b"{\n  \"ui\": {},\n}");
        match repo_with_default(&path).load() {
            Err(ConfigError::Syntax { line, column, .. }) => {
                assert_eq!(line, 3);
                assert!(column >= 1);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quando_campo_desconhecido_deve_citar_campo_e_linha() {
        let dir = Scratch::new();
        let path = dir.file("c.json", b"{\n  \"ui\": {\n    \"colour\": 1\n  }\n}");
        match repo_with_default(&path).load() {
            Err(ConfigError::UnknownField { field, line }) => {
                assert_eq!(field, "ui.colour");
                assert_eq!(line, 3);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quando_tipo_errado_deve_citar_o_campo() {
        let dir = Scratch::new();
        let path = dir.file("c.json", br#"{"batch":{"concurrency":"many"}}"#);
        match repo_with_default(&path).load() {
            Err(ConfigError::InvalidValue { field, .. }) => {
                assert_eq!(field, "batch.concurrency");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quando_arquivo_vazio_deve_dar_empty_file() {
        let dir = Scratch::new();
        for content in [&b""[..], b"  \n\t", b"\xEF\xBB\xBF"] {
            let path = dir.file("empty.json", content);
            match repo_with_default(&path).load() {
                Err(ConfigError::InvalidValue { field, message }) => {
                    assert_eq!(field, "<root>");
                    assert_eq!(message, "empty file");
                }
                other => panic!("unexpected: {other:?}"),
            }
        }
    }

    #[test]
    fn quando_arquivo_nao_e_utf8_deve_dar_invalid_value() {
        let dir = Scratch::new();
        let path = dir.file("bin.json", &[0xFF, 0xFE, b'{', b'}']);
        match repo_with_default(&path).load() {
            Err(ConfigError::InvalidValue { field, message }) => {
                assert_eq!(field, "<root>");
                assert!(message.contains("UTF-8"), "{message}");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quando_arquivo_passa_de_1mib_deve_dar_too_large_sem_ler_tudo() {
        let dir = Scratch::new();
        let path = dir.0.join("huge.json");
        let file = fs::File::create(&path).unwrap();
        // Sparse 50 MiB: reading it all would be visible in the time and the
        // memory of the test; the repository must stop at the limit + 1.
        file.set_len(50 * 1024 * 1024).unwrap();
        assert_eq!(
            repo_with_default(&path).load(),
            Err(ConfigError::TooLarge {
                limit: MAX_CONFIG_BYTES
            })
        );
    }

    #[test]
    fn quando_arquivo_tem_exatamente_1mib_deve_ser_aceito() {
        let dir = Scratch::new();
        let mut bytes = b"{}".to_vec();
        bytes.resize(MAX_CONFIG_BYTES, b' ');
        let path = dir.file("edge.json", &bytes);
        assert_eq!(repo_with_default(&path).load(), Ok(Config::default()));
    }

    #[test]
    fn quando_caminho_e_diretorio_deve_dar_io() {
        let dir = Scratch::new();
        match repo_with_default(&dir.0).load() {
            Err(ConfigError::Io(_)) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }
}
