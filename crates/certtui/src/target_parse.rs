//! Parsing of the `<alvo>` argument into a [`Target`] (spec section 6.4).

use std::fmt;
use std::path::{Path, PathBuf};

use certtui_app::ports::LocalSource;
use certtui_domain::target::{Target, TargetError};
use certtui_domain::target_parse::parse_network_target;

/// Extensions that mark an argument as a file even when it does not exist,
/// so `certtui inspect missing.pem` reports a missing file instead of
/// looking like a host name.
const FILE_EXTENSIONS: &[&str] = &[
    "pem", "crt", "cer", "cert", "der", "p7b", "p7c", "p12", "pfx", "jks", "txt", "json", "yaml",
    "yml", "log", "csr", "key", "bundle",
];

/// The `<alvo>` argument cannot be used as a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageError {
    /// The argument looks like a network target but is malformed. The inner
    /// error never carries the offending text, so credentials in the
    /// argument cannot leak through `Display` or `Debug`.
    Target(TargetError),
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageError::Target(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for UsageError {}

/// Resolves `arg` to a stdin, file, directory or network target.
///
/// Precedence (spec 6.4): `-` is stdin; `force_file` or a path for which
/// `path_exists` is true is a file, or a directory when it is one on disk;
/// anything that looks like a host name, `host:port` or URL is parsed as a
/// network target; everything else is a (possibly missing) file, so that
/// `missing.pem` ends in a read error rather than a DNS name.
///
/// # Errors
///
/// [`UsageError::Target`] when `arg` looks like a network target but is
/// malformed (unsupported scheme, bad port, empty, invalid host or
/// credentials).
pub fn parse_target(
    arg: &str,
    force_file: bool,
    recursive: bool,
    path_exists: &dyn Fn(&Path) -> bool,
) -> Result<Target, UsageError> {
    if arg == "-" {
        return Ok(Target::Stdin);
    }
    let path = PathBuf::from(arg);
    if force_file {
        return Ok(Target::File(path));
    }
    if path_exists(&path) {
        // Only the existence check is injected; telling a directory apart
        // needs the real file system.
        return Ok(if path.is_dir() {
            Target::Directory { path, recursive }
        } else {
            Target::File(path)
        });
    }
    if looks_like_network(arg) {
        return parse_network_target(arg)
            .map(Target::Network)
            .map_err(UsageError::Target);
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

/// Whether a non-existing `arg` should be parsed as a network target rather
/// than treated as a missing file.
fn looks_like_network(arg: &str) -> bool {
    let arg = arg.trim();
    if arg.is_empty() || arg.contains("://") || arg.starts_with('[') {
        return true;
    }
    let (host, port) = match arg.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (arg, None),
    };
    // A port that is not a number still reads as a mistyped target
    // (`host:port`); anything else after the colon (`C:\dir`) is a path.
    if port.is_some_and(|p| !p.chars().all(|c| c.is_ascii_alphanumeric())) {
        return false;
    }
    !host.is_empty()
        && host.chars().all(is_host_char)
        && !host.starts_with(['.', '-'])
        && !has_file_extension(host)
}

fn is_host_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_')
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
    use certtui_domain::target::NetworkTarget;

    use super::*;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn missing(_: &Path) -> bool {
        false
    }

    fn real(path: &Path) -> bool {
        path.exists()
    }

    #[test]
    fn quando_hifen_deve_ser_stdin() {
        assert_eq!(parse_target("-", false, false, &missing), Ok(Target::Stdin));
    }

    #[test]
    fn quando_caminho_existente_deve_ser_file() {
        let path = format!("{FIXTURES}/chain-3.pem");
        assert_eq!(
            parse_target(&path, false, false, &real),
            Ok(Target::File(PathBuf::from(&path)))
        );
    }

    #[test]
    fn quando_diretorio_existente_deve_ser_directory_com_recursive() {
        let target = parse_target(FIXTURES, false, true, &real).unwrap();
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
            parse_target("example.com", true, false, &real),
            Ok(Target::File(PathBuf::from("example.com")))
        );
    }

    fn network(host: &str, port: u16) -> Target {
        Target::Network(NetworkTarget {
            host: host.to_owned(),
            port,
            sni: None,
            connect_to: None,
        })
    }

    #[test]
    fn quando_parece_rede_e_nao_existe_deve_ser_network() {
        for (arg, host, port) in [
            ("example.com", "example.com", 443),
            ("example.com:8443", "example.com", 8443),
            ("localhost", "localhost", 443),
            ("10.0.0.1:443", "10.0.0.1", 443),
            ("https://example.com/path", "example.com", 443),
            ("[::1]:443", "::1", 443),
            ("[2001:db8::1]", "2001:db8::1", 443),
            ("bücher.de", "xn--bcher-kva.de", 443),
        ] {
            assert_eq!(
                parse_target(arg, false, false, &missing),
                Ok(network(host, port)),
                "{arg}"
            );
        }
    }

    #[test]
    fn quando_caminho_existe_deve_virar_file_antes_de_rede() {
        let only_example = |path: &Path| path == Path::new("example.com");
        assert_eq!(
            parse_target("example.com", false, false, &only_example),
            Ok(Target::File(PathBuf::from("example.com")))
        );
        assert_eq!(
            parse_target("example.com", false, false, &missing),
            Ok(network("example.com", 443))
        );
    }

    #[test]
    fn quando_alvo_de_rede_invalido_deve_dar_erro_especifico() {
        for (arg, expected) in [
            (
                "http://example.com",
                TargetError::UnsupportedScheme("http".to_owned()),
            ),
            (
                "ftp://example.com",
                TargetError::UnsupportedScheme("ftp".to_owned()),
            ),
            ("example.com:0", TargetError::InvalidPort),
            ("example.com:65536", TargetError::InvalidPort),
            ("example.com:abc", TargetError::InvalidPort),
            ("example.com:", TargetError::InvalidPort),
            ("host:port", TargetError::InvalidPort),
            ("host:", TargetError::InvalidPort),
            ("", TargetError::Empty),
            ("  ", TargetError::Empty),
            ("https://", TargetError::Empty),
            ("a_b.com", TargetError::InvalidHost),
            ("https://a b.com", TargetError::InvalidHost),
            (
                "https://user:pw@example.com",
                TargetError::CredentialsNotAllowed,
            ),
        ] {
            assert_eq!(
                parse_target(arg, false, false, &missing),
                Err(UsageError::Target(expected)),
                "{arg:?}"
            );
        }
    }

    #[test]
    fn quando_credenciais_no_alvo_nao_deve_vazar_na_mensagem_nem_no_debug() {
        let error =
            parse_target("https://user:pw@example.com", false, false, &missing).unwrap_err();
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains("pw"), "{text}");
            assert!(!text.contains("user"), "{text}");
        }
    }

    #[test]
    fn quando_erro_de_alvo_deve_mostrar_a_mensagem_do_dominio() {
        assert_eq!(
            UsageError::Target(TargetError::InvalidPort).to_string(),
            TargetError::InvalidPort.to_string()
        );
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
            "C:\\dir\\file",
        ] {
            assert_eq!(
                parse_target(arg, false, false, &missing),
                Ok(Target::File(PathBuf::from(arg))),
                "{arg}"
            );
        }
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
