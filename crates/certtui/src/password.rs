//! Where a keystore password comes from on the command line.
//!
//! Never from an argument: a command line is visible to every user of the
//! machine (`ps`) and lands in the shell history. The password comes from an
//! environment variable, a file or standard input, is held as a
//! [`SecretString`] and is never printed.

use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;

use certtui_app::keystore::SecretString;

/// Longest password accepted, in bytes.
const MAX_PASSWORD_BYTES: usize = 1024;

/// `--password-env`, `--password-file` or `--password-stdin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSource {
    /// The value of this environment variable.
    Env(String),
    /// The first line of this file.
    File(PathBuf),
    /// The first line of standard input.
    Stdin,
}

/// A password option that cannot be honored. The messages never carry the
/// password, only where it was supposed to come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn usage(message: &str) -> UsageError {
    UsageError(message.to_owned())
}

/// The password `source` names, or `None` when there is no source.
///
/// A file or standard input supplies its first line without the line ending
/// (`\n` or `\r\n`), at most 1 KiB. `env` looks an environment variable up
/// (the caller passes `std::env::var`'s answer; tests pass a fake).
///
/// # Errors
///
/// [`UsageError`] when the variable is unset, the file cannot be read, the
/// text is not UTF-8 or it is longer than 1 KiB.
pub fn resolve_password(
    source: Option<&PasswordSource>,
    stdin: &mut dyn Read,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<SecretString>, UsageError> {
    let Some(source) = source else {
        return Ok(None);
    };
    let text = match source {
        PasswordSource::Env(name) => {
            let value = env(name).ok_or_else(|| {
                UsageError(format!(
                    "--password-env: the environment variable {} is not set",
                    crate::output::single_line(name)
                ))
            })?;
            if value.len() > MAX_PASSWORD_BYTES {
                return Err(usage("--password-env: the password is longer than 1 KiB"));
            }
            value
        }
        PasswordSource::File(path) => {
            let file = File::open(path).map_err(|error| {
                UsageError(format!(
                    "--password-file: cannot open the file ({})",
                    error.kind()
                ))
            })?;
            first_line(file, "--password-file")?
        }
        PasswordSource::Stdin => first_line(stdin, "--password-stdin")?,
    };
    Ok(Some(SecretString::from(text)))
}

/// The first line of `reader`, without `\n` / `\r\n`, within the size limit.
fn first_line(reader: impl Read, option: &str) -> Result<String, UsageError> {
    // The limit plus room for `\r\n`, so a password of exactly 1 KiB fits.
    let limit = u64::try_from(MAX_PASSWORD_BYTES + 2).unwrap_or(u64::MAX);
    let mut line = Vec::new();
    BufReader::new(reader.take(limit))
        .read_until(b'\n', &mut line)
        .map_err(|error| {
            UsageError(format!(
                "{option}: cannot read the password ({})",
                error.kind()
            ))
        })?;
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.len() > MAX_PASSWORD_BYTES {
        return Err(UsageError(format!(
            "{option}: the password is longer than 1 KiB"
        )));
    }
    String::from_utf8(line)
        .map_err(|_| UsageError(format!("{option}: the password is not valid UTF-8")))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use certtui_app::keystore::ExposeSecret;

    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    fn resolve(
        source: Option<&PasswordSource>,
        stdin: &[u8],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<String>, UsageError> {
        let mut input = Cursor::new(stdin.to_vec());
        resolve_password(source, &mut input, env)
            .map(|password| password.map(|secret| secret.expose_secret().to_owned()))
    }

    #[test]
    fn quando_sem_fonte_deve_dar_none() {
        assert_eq!(resolve(None, b"ignored", &no_env), Ok(None));
    }

    #[test]
    fn quando_env_existe_deve_devolver_o_valor() {
        let env = |name: &str| (name == "PW").then(|| "changeit".to_owned());
        let got = resolve(Some(&PasswordSource::Env("PW".to_owned())), b"", &env);
        assert_eq!(got, Ok(Some("changeit".to_owned())));
    }

    #[test]
    fn quando_env_nao_existe_deve_dar_erro_de_uso_com_o_nome_da_variavel() {
        let got = resolve(Some(&PasswordSource::Env("NOPE".to_owned())), b"", &no_env);
        assert_eq!(
            got,
            Err(UsageError(
                "--password-env: the environment variable NOPE is not set".to_owned()
            ))
        );
    }

    #[test]
    fn quando_stdin_tem_varias_linhas_deve_usar_so_a_primeira_sem_o_fim_de_linha() {
        for (input, want) in [
            (&b"changeit\n"[..], "changeit"),
            (b"changeit\r\n", "changeit"),
            (b"changeit", "changeit"),
            (b"changeit\nsecond line\n", "changeit"),
            (b"with space \n", "with space "),
            (b"\n", ""),
            (b"", ""),
        ] {
            let got = resolve(Some(&PasswordSource::Stdin), input, &no_env);
            assert_eq!(got, Ok(Some(want.to_owned())), "{input:?}");
        }
    }

    #[test]
    fn quando_arquivo_tem_crlf_deve_tirar_o_fim_de_linha() {
        let dir = std::env::temp_dir().join(format!("certtui-password-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pw.txt");
        std::fs::write(&path, b"changeit\r\nmore\r\n").unwrap();

        let got = resolve(Some(&PasswordSource::File(path.clone())), b"", &no_env);

        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got, Ok(Some("changeit".to_owned())));
    }

    #[test]
    fn quando_arquivo_nao_abre_deve_dar_erro_de_uso_sem_o_caminho_do_conteudo() {
        let source = PasswordSource::File(PathBuf::from("/definitely/not/here/pw.txt"));
        let got = resolve(Some(&source), b"", &no_env).unwrap_err();
        assert!(
            got.0.starts_with("--password-file: cannot open the file"),
            "{got}"
        );
    }

    #[test]
    fn quando_senha_passa_de_1_kib_deve_dar_erro() {
        let mut long = vec![b'x'; 1025];
        long.push(b'\n');
        assert!(resolve(Some(&PasswordSource::Stdin), &long, &no_env).is_err());
        let mut exact = vec![b'x'; 1024];
        exact.extend_from_slice(b"\r\n");
        let got = resolve(Some(&PasswordSource::Stdin), &exact, &no_env)
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), 1024);
    }

    #[test]
    fn quando_senha_nao_e_utf8_deve_dar_erro_sem_ecoar() {
        let got = resolve(Some(&PasswordSource::Stdin), &[0xFF, 0xFE, b'\n'], &no_env).unwrap_err();
        assert_eq!(got.0, "--password-stdin: the password is not valid UTF-8");
    }
}
