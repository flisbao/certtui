//! Atomic file writes for exports: never a partial file, never a destroyed
//! original, never an overwrite nobody agreed to. Only `std`.
//!
//! The bytes go to a temporary file in the **same directory** (so the final
//! step is a same-filesystem rename), are flushed to disk, and only then reach
//! the destination: by `hard_link` when overwriting is refused (it fails if the
//! destination appeared meanwhile, so a race cannot clobber it) and by `rename`
//! when allowed. Any failure removes the temporary file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use certtui_app::export::{FileWriter, Overwrite, WriteError};

/// The [`FileWriter`] of the real program: [`write_atomic`].
#[derive(Debug, Clone, Copy, Default)]
pub struct AtomicFileWriter;

impl FileWriter for AtomicFileWriter {
    fn write(&self, path: &Path, bytes: &[u8], overwrite: Overwrite) -> Result<(), WriteError> {
        write_atomic(path, bytes, overwrite)
    }
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Writes `bytes` to `path`.
///
/// # Errors
///
/// [`WriteError::AlreadyExists`] when `path` exists (a symlink included, not
/// followed) and `overwrite` is [`Overwrite::Refuse`]; [`WriteError::IsDirectory`];
/// [`WriteError::ParentMissing`]; [`WriteError::Io`] for anything else. In every
/// case the destination is exactly as it was and no temporary file remains.
pub fn write_atomic(path: &Path, bytes: &[u8], overwrite: Overwrite) -> Result<(), WriteError> {
    write_with(path, overwrite, |file| file.write_all(bytes))
}

/// [`write_atomic`] with the writing step supplied by the caller, so tests can
/// make it fail halfway.
///
/// # Errors
///
/// As [`write_atomic`]; an `Err` from `produce` becomes [`WriteError::Io`].
pub fn write_with(
    path: &Path,
    overwrite: Overwrite,
    produce: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> Result<(), WriteError> {
    check_destination(path, overwrite)?;
    let parent = parent_of(path);
    if !parent.is_dir() {
        return Err(WriteError::ParentMissing);
    }
    let temp = Temp::new(path, &parent)?;
    {
        let mut file = temp.open()?;
        produce(&mut file).map_err(|error| io_error(&error))?;
        file.flush().map_err(|error| io_error(&error))?;
        file.sync_all().map_err(|error| io_error(&error))?;
    }
    publish(&temp, path, overwrite)?;
    // Best effort: persist the directory entry too.
    if let Ok(dir) = File::open(&parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn io_error(error: &io::Error) -> WriteError {
    WriteError::Io(error.to_string())
}

/// The directory that holds `path` (`.` for a bare file name).
fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Looks at the destination without following a symlink.
fn check_destination(path: &Path, overwrite: Overwrite) -> Result<(), WriteError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Err(WriteError::IsDirectory),
        Ok(_) if overwrite == Overwrite::Refuse => Err(WriteError::AlreadyExists),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(&error)),
    }
}

/// Moves the finished temporary file onto the destination.
fn publish(temp: &Temp, path: &Path, overwrite: Overwrite) -> Result<(), WriteError> {
    match overwrite {
        Overwrite::Allow => fs::rename(&temp.path, path).map_err(|error| io_error(&error)),
        Overwrite::Refuse => match fs::hard_link(&temp.path, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(WriteError::AlreadyExists)
            }
            // No hard links here (some filesystems): check again and rename.
            Err(_) => {
                check_destination(path, Overwrite::Refuse)?;
                fs::rename(&temp.path, path).map_err(|error| io_error(&error))
            }
        },
    }
}

/// The temporary file; removed on drop whatever happens.
struct Temp {
    path: PathBuf,
}

impl Temp {
    fn new(destination: &Path, parent: &Path) -> Result<Self, WriteError> {
        let name = destination
            .file_name()
            .ok_or_else(|| WriteError::Io("the destination has no file name".to_owned()))?
            .to_string_lossy();
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("{name}.tmp-{}-{unique}", std::process::id()));
        Ok(Self { path })
    }

    fn open(&self) -> Result<File, WriteError> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)
            .map_err(|error| io_error(&error))
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        // After a successful `rename` the name is gone and this is a no-op;
        // after a `hard_link` it removes the extra name.
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory removed on drop (no `tempfile` crate).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "certtui-atomic-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        /// Names in the directory, to spot a leftover temporary file.
        fn names(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn quando_destino_nao_existe_deve_criar_com_conteudo_exato() {
        let dir = Scratch::new();
        let target = dir.path("out.pem");

        write_atomic(&target, b"hello\n", Overwrite::Refuse).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"hello\n");
        assert_eq!(dir.names(), ["out.pem"], "no temporary file left");
    }

    #[test]
    fn quando_destino_existe_sem_force_deve_dar_already_exists_e_preservar_original() {
        let dir = Scratch::new();
        let target = dir.path("out.pem");
        fs::write(&target, b"original").unwrap();

        let got = write_atomic(&target, b"new", Overwrite::Refuse);

        assert_eq!(got, Err(WriteError::AlreadyExists));
        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert_eq!(dir.names(), ["out.pem"]);
    }

    #[test]
    fn quando_force_deve_substituir_atomicamente() {
        let dir = Scratch::new();
        let target = dir.path("out.pem");
        fs::write(&target, b"original").unwrap();

        write_atomic(&target, b"replacement", Overwrite::Allow).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"replacement");
        assert_eq!(dir.names(), ["out.pem"]);
    }

    #[test]
    fn quando_destino_e_diretorio_deve_dar_is_directory() {
        let dir = Scratch::new();
        let target = dir.path("sub");
        fs::create_dir(&target).unwrap();

        for overwrite in [Overwrite::Refuse, Overwrite::Allow] {
            assert_eq!(
                write_atomic(&target, b"x", overwrite),
                Err(WriteError::IsDirectory)
            );
        }
        assert_eq!(dir.names(), ["sub"]);
    }

    #[test]
    fn quando_pai_nao_existe_deve_dar_parent_missing() {
        let dir = Scratch::new();
        let target = dir.path("missing").join("out.pem");

        let got = write_atomic(&target, b"x", Overwrite::Refuse);

        assert_eq!(got, Err(WriteError::ParentMissing));
        assert_eq!(dir.names(), Vec::<String>::new());
    }

    #[test]
    fn quando_falha_no_meio_deve_remover_temporario_e_preservar_original() {
        let dir = Scratch::new();
        let target = dir.path("out.pem");
        fs::write(&target, b"original").unwrap();

        for overwrite in [Overwrite::Allow, Overwrite::Refuse] {
            let got = write_with(&target, overwrite, |file| {
                file.write_all(b"partial data")?;
                Err(io::Error::other("no space left on device"))
            });
            assert!(matches!(
                got,
                Err(WriteError::Io(_) | WriteError::AlreadyExists)
            ));
        }

        assert_eq!(fs::read(&target).unwrap(), b"original");
        assert_eq!(dir.names(), ["out.pem"], "the temporary file was removed");
    }

    #[test]
    fn quando_falha_no_meio_e_destino_novo_deve_nao_criar_nada() {
        let dir = Scratch::new();
        let target = dir.path("new.pem");

        let got = write_with(&target, Overwrite::Refuse, |file| {
            file.write_all(b"partial")?;
            Err(io::Error::other("disk full"))
        });

        assert_eq!(got, Err(WriteError::Io("disk full".to_owned())));
        assert_eq!(dir.names(), Vec::<String>::new());
    }

    #[test]
    fn quando_destino_e_symlink_e_sem_force_deve_recusar_sem_tocar_no_alvo() {
        let dir = Scratch::new();
        let real = dir.path("real.pem");
        fs::write(&real, b"real content").unwrap();
        let link = dir.path("link.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let got = write_atomic(&link, b"new", Overwrite::Refuse);

        assert_eq!(got, Err(WriteError::AlreadyExists));
        assert_eq!(fs::read(&real).unwrap(), b"real content");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn quando_destino_e_symlink_e_force_deve_substituir_o_link_e_nao_o_alvo() {
        let dir = Scratch::new();
        let real = dir.path("real.pem");
        fs::write(&real, b"real content").unwrap();
        let link = dir.path("link.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        write_atomic(&link, b"new", Overwrite::Allow).unwrap();

        assert_eq!(
            fs::read(&real).unwrap(),
            b"real content",
            "the target is intact"
        );
        let metadata = fs::symlink_metadata(&link).unwrap();
        assert!(
            metadata.file_type().is_file(),
            "the link itself was replaced"
        );
        assert_eq!(fs::read(&link).unwrap(), b"new");
    }

    #[test]
    fn quando_symlink_pendurado_e_sem_force_deve_recusar() {
        let dir = Scratch::new();
        let link = dir.path("dangling.pem");
        std::os::unix::fs::symlink(dir.path("nowhere"), &link).unwrap();

        let got = write_atomic(&link, b"x", Overwrite::Refuse);

        assert_eq!(got, Err(WriteError::AlreadyExists));
        assert_eq!(dir.names(), ["dangling.pem"]);
    }

    #[test]
    fn quando_sem_permissao_no_diretorio_deve_dar_erro_sem_deixar_lixo() {
        let dir = Scratch::new();
        let target = dir.path("out.pem");
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o500)).unwrap();

        let got = write_atomic(&target, b"x", Overwrite::Refuse);

        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        // As root the directory is writable anyway; either way nothing is left
        // behind but, at most, the finished file.
        match got {
            Err(WriteError::Io(_)) => assert_eq!(dir.names(), Vec::<String>::new()),
            Ok(()) => assert_eq!(dir.names(), ["out.pem"]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn quando_nome_e_relativo_sem_diretorio_deve_usar_o_diretorio_atual() {
        assert_eq!(parent_of(Path::new("out.pem")), PathBuf::from("."));
        assert_eq!(parent_of(Path::new("a/out.pem")), PathBuf::from("a"));
        assert_eq!(parent_of(Path::new("/out.pem")), PathBuf::from("/"));
    }
}
