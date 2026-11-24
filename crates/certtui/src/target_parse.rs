//! Parsing of the `<alvo>` argument into a local [`Target`] (spec section 6.4).

use std::fmt;
use std::path::{Path, PathBuf};

use certtui_app::ports::LocalSource;
use certtui_domain::target::Target;

/// Extensions that mark an argument as a file even when it does not exist,
/// so `certtui inspect missing.pem` reports a missing file instead of
/// looking like a host name.
const FILE_EXTENSIONS: &[&str] = &[
    "pem", "crt", "cer", "cert", "der", "p7b", "p7c", "p12", "pfx", "jks", "txt", "json", "yaml",
    "yml", "log", "csr", "key", "bundle",
];

/// The `<alvo>` argument cannot be used as a local target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// The argument looks like a host name or URL; network inspection is not
    /// available yet.
    NetworkTarget,
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::NetworkTarget => f.write_str("network targets arrive in a later release"),
        }
    }
}

impl std::error::Error for UsageError {}

/// Resolves `arg` to a stdin, file or directory target.
///
/// Precedence: `-` is stdin; `force_file` or an existing path is a file or
/// directory; anything else that looks like a host name, `host:port` or URL
/// is a network target, which is rejected for now.
///
/// # Errors
///
/// [`UsageError::NetworkTarget`] when `arg` is not `-`, does not exist, is not
/// forced to be a file and looks like a network address.
pub fn parse_local_target(
    arg: &str,
    force_file: bool,
    recursive: bool,
) -> Result<Target, UsageError> {
    if arg == "-" {
        return Ok(Target::Stdin);
    }
    let path = PathBuf::from(arg);
    if force_file {
        return Ok(Target::File(path));
    }
    if let Ok(metadata) = std::fs::metadata(&path) {
        return Ok(if metadata.is_dir() {
            Target::Directory { path, recursive }
        } else {
            Target::File(path)
        });
    }
    if looks_like_network(arg) {
        return Err(UsageError::NetworkTarget);
    }
    Ok(Target::File(path))
}

/// The loader source for a local `target`; `None` for network targets.
#[must_use]
pub fn local_source(target: &Target) -> Option<LocalSource> {
    match target {
        Target::Stdin => Some(LocalSource::Stdin),
        Target::File(path) => Some(LocalSource::File(path.clone())),
        Target::Directory { path, recursive } => Some(LocalSource::Directory {
            path: path.clone(),
            recursive: *recursive,
        }),
        Target::Network(_) => None,
    }
}

fn looks_like_network(arg: &str) -> bool {
    if arg.contains("://") || arg.starts_with('[') {
        return true;
    }
    let (host, port) = match arg.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (arg, None),
    };
    if port.is_some_and(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    !host.is_empty()
        && host.bytes().all(is_host_byte)
        && !host.starts_with(['.', '-'])
        && !has_file_extension(host)
}

fn is_host_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
}

fn has_file_extension(host: &str) -> bool {
    Path::new(host)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            FILE_EXTENSIONS
                .iter()
                .any(|known| known.eq_ignore_ascii_case(ext))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    #[test]
    fn quando_hifen_deve_ser_stdin() {
        assert_eq!(parse_local_target("-", false, false), Ok(Target::Stdin));
    }

    #[test]
    fn quando_caminho_existente_deve_ser_file() {
        let path = format!("{FIXTURES}/chain-3.pem");
        assert_eq!(
            parse_local_target(&path, false, false),
            Ok(Target::File(PathBuf::from(&path)))
        );
    }

    #[test]
    fn quando_diretorio_existente_deve_ser_directory_com_recursive() {
        let target = parse_local_target(FIXTURES, false, true).unwrap();
        assert_eq!(
            target,
            Target::Directory {
                path: PathBuf::from(FIXTURES),
                recursive: true
            }
        );
    }

    #[test]
    fn quando_force_file_deve_ser_file_mesmo_com_nome_de_dominio() {
        assert_eq!(
            parse_local_target("example.com", true, false),
            Ok(Target::File(PathBuf::from("example.com")))
        );
    }

    #[test]
    fn quando_parece_rede_e_nao_existe_deve_dar_erro_de_uso() {
        for arg in [
            "example.com",
            "example.com:8443",
            "localhost",
            "10.0.0.1:443",
            "https://example.com/path",
            "[::1]:443",
            "[2001:db8::1]",
        ] {
            assert_eq!(
                parse_local_target(arg, false, false),
                Err(UsageError::NetworkTarget),
                "{arg}"
            );
        }
    }

    #[test]
    fn quando_nao_parece_rede_e_nao_existe_deve_ser_file() {
        for arg in [
            "/no/such/file",
            "./missing",
            "dir/file.pem",
            "missing.pem",
            "MISSING.CRT",
            "has space.txt",
            "host:port",
            "host:",
        ] {
            assert_eq!(
                parse_local_target(arg, false, false),
                Ok(Target::File(PathBuf::from(arg))),
                "{arg}"
            );
        }
    }

    #[test]
    fn quando_erro_de_rede_deve_ter_a_mensagem_da_especificacao() {
        assert_eq!(
            UsageError::NetworkTarget.to_string(),
            "network targets arrive in a later release"
        );
    }

    #[test]
    fn quando_local_source_deve_espelhar_o_alvo() {
        assert_eq!(local_source(&Target::Stdin), Some(LocalSource::Stdin));
        assert_eq!(
            local_source(&Target::File(PathBuf::from("a"))),
            Some(LocalSource::File(PathBuf::from("a")))
        );
        assert_eq!(
            local_source(&Target::Directory {
                path: PathBuf::from("d"),
                recursive: true
            }),
            Some(LocalSource::Directory {
                path: PathBuf::from("d"),
                recursive: true
            })
        );
    }
}
