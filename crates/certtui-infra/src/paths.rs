//! Where the configuration and the history live.

use std::path::{Path, PathBuf};

use etcetera::{AppStrategy, AppStrategyArgs, choose_app_strategy};

use crate::env::EnvVars;

const APP_NAME: &str = "certtui";
/// Name of the configuration file inside the config directory.
const CONFIG_FILE: &str = "config.json";
/// Name of the history file inside the data directory.
const HISTORY_FILE: &str = "history.json";

/// A configuration file location and how it was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLocation {
    /// The file.
    pub path: PathBuf,
    /// `true` when the user named it (`$CERTTUI_CONFIG` or `--config`): a
    /// missing file is then an error instead of "use the defaults".
    pub explicit: bool,
}

fn strategy() -> Option<impl AppStrategy> {
    choose_app_strategy(AppStrategyArgs {
        top_level_domain: String::new(),
        author: String::new(),
        app_name: APP_NAME.to_owned(),
    })
    .ok()
}

/// The configuration file: `$CERTTUI_CONFIG`, then `--config` (`flag`), then
/// the platform config directory (`~/.config/certtui/config.json` on Linux).
/// `None` when no home directory can be determined.
#[must_use]
pub fn config_path(flag: Option<&Path>, env: &EnvVars) -> Option<ConfigLocation> {
    if let Some(value) = env.get("CERTTUI_CONFIG") {
        return Some(ConfigLocation {
            path: PathBuf::from(value),
            explicit: true,
        });
    }
    if let Some(path) = flag {
        return Some(ConfigLocation {
            path: path.to_owned(),
            explicit: true,
        });
    }
    Some(ConfigLocation {
        path: strategy()?.in_config_dir(CONFIG_FILE),
        explicit: false,
    })
}

/// The data directory (`~/.local/share/certtui` on Linux).
#[must_use]
pub fn data_dir() -> Option<PathBuf> {
    strategy().map(|strategy| strategy.data_dir())
}

/// The history file inside [`data_dir`].
#[must_use]
pub fn history_path() -> Option<PathBuf> {
    data_dir().map(|dir| dir.join(HISTORY_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_env_e_flag_existem_deve_vencer_o_env() {
        let env = EnvVars::from_pairs([("CERTTUI_CONFIG", "/env.json")]);
        let location = config_path(Some(Path::new("/flag.json")), &env).unwrap();
        assert_eq!(location.path, PathBuf::from("/env.json"));
        assert!(location.explicit);
    }

    #[test]
    fn quando_so_a_flag_existe_deve_usar_a_flag() {
        let location = config_path(Some(Path::new("/flag.json")), &EnvVars::default()).unwrap();
        assert_eq!(location.path, PathBuf::from("/flag.json"));
        assert!(location.explicit);
    }

    #[test]
    fn quando_nada_e_dado_deve_usar_o_diretorio_da_plataforma_como_implicito() {
        if let Some(location) = config_path(None, &EnvVars::default()) {
            assert!(!location.explicit);
            assert!(location.path.ends_with("certtui/config.json"));
        }
    }

    #[test]
    fn historico_deve_ficar_no_diretorio_de_dados() {
        if let Some(path) = history_path() {
            assert!(path.ends_with("certtui/history.json"));
        }
    }
}
