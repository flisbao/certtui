//! Explicit-stack directory traversal without following symbolic links.

use std::fs::{self, File};
use std::path::{Path, PathBuf};

use certtui_app::error::LoadError;
use certtui_app::ports::LoadedCerts;
use certtui_domain::limits::Limits;
use certtui_domain::model::LoadNote;

use super::fs::{OriginKind, load_reader, normalize_notes};

pub(super) fn load_directory(
    path: &Path,
    recursive: bool,
    limits: &Limits,
) -> Result<LoadedCerts, LoadError> {
    let root_metadata =
        fs::symlink_metadata(path).map_err(|error| LoadError::Io(error.to_string()))?;
    if root_metadata.file_type().is_symlink() {
        return Err(LoadError::NoCertificatesFound {
            notes: vec![LoadNote::Unparsable { offset: None }],
        });
    }
    if !root_metadata.is_dir() {
        return Err(LoadError::Io(
            "directory source is not a directory".to_owned(),
        ));
    }

    let mut scan = DirectoryScan::new(path);
    scan.walk(recursive, limits);
    scan.finish(limits)
}

struct DirectoryScan {
    stack: Vec<(PathBuf, usize)>,
    certs: Vec<certtui_app::ports::RawCert>,
    notes: Vec<LoadNote>,
    private_key_count: usize,
    directory_truncated: bool,
    cert_truncated: bool,
    entries: usize,
}

impl DirectoryScan {
    fn new(path: &Path) -> Self {
        Self {
            stack: vec![(path.to_path_buf(), 0)],
            certs: Vec::new(),
            notes: Vec::new(),
            private_key_count: 0,
            directory_truncated: false,
            cert_truncated: false,
            entries: 0,
        }
    }

    fn walk(&mut self, recursive: bool, limits: &Limits) {
        while let Some((directory, depth)) = self.stack.pop() {
            let Ok(read_dir) = fs::read_dir(&directory) else {
                self.record_unparsable(limits);
                continue;
            };
            for entry in read_dir {
                if self.entries >= limits.max_dir_entries {
                    self.directory_truncated = true;
                    return;
                }
                self.entries = self.entries.saturating_add(1);
                let Ok(entry) = entry else {
                    self.record_unparsable(limits);
                    continue;
                };
                self.visit_entry(entry.path(), depth, recursive, limits);
                if self.cert_truncated {
                    return;
                }
            }
        }
    }

    fn visit_entry(&mut self, path: PathBuf, depth: usize, recursive: bool, limits: &Limits) {
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            self.record_unparsable(limits);
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        if metadata.is_dir() {
            if recursive && depth < limits.max_dir_depth {
                self.stack.push((path, depth.saturating_add(1)));
            }
            return;
        }
        if metadata.is_file() {
            self.load_file(path, limits);
        }
    }

    fn load_file(&mut self, path: PathBuf, limits: &Limits) {
        let remaining = limits.max_certs_per_source.saturating_sub(self.certs.len());
        let mut file_limits = *limits;
        file_limits.max_certs_per_source = remaining.saturating_add(1);
        let file_result = File::open(&path)
            .map_err(|_| LoadError::Io("unable to open directory entry".to_owned()))
            .and_then(|file| load_reader(file, OriginKind::File(path), &file_limits));
        match file_result {
            Ok(mut loaded) => {
                let has_extra = loaded.certs.len() > remaining
                    || loaded
                        .notes
                        .iter()
                        .any(|note| matches!(note, LoadNote::TruncatedAtCertLimit { .. }));
                if has_extra {
                    loaded.certs.truncate(remaining);
                    self.cert_truncated = true;
                }
                self.certs.extend(loaded.certs);
                merge_directory_notes(
                    &mut self.notes,
                    &mut self.private_key_count,
                    &loaded.notes,
                    limits.max_scan_diagnostics,
                );
            }
            Err(LoadError::NoCertificatesFound { notes }) => merge_directory_notes(
                &mut self.notes,
                &mut self.private_key_count,
                &notes,
                limits.max_scan_diagnostics,
            ),
            Err(_) => self.record_unparsable(limits),
        }
    }

    fn record_unparsable(&mut self, limits: &Limits) {
        self.notes.push(LoadNote::Unparsable { offset: None });
        self.notes = normalize_notes(std::mem::take(&mut self.notes), limits.max_scan_diagnostics);
    }

    fn finish(mut self, limits: &Limits) -> Result<LoadedCerts, LoadError> {
        if self.private_key_count > 0 {
            self.notes.push(LoadNote::PrivateKeyBlocksIgnored {
                count: self.private_key_count,
            });
        }
        if self.cert_truncated {
            self.notes.push(LoadNote::TruncatedAtCertLimit {
                limit: limits.max_certs_per_source,
            });
        }
        if self.directory_truncated {
            self.notes.push(LoadNote::DirectoryTruncated {
                limit: limits.max_dir_entries,
            });
        }
        if self.certs.is_empty() && self.notes.is_empty() {
            self.notes.push(LoadNote::Unparsable { offset: None });
        }
        let notes = normalize_notes(self.notes, limits.max_scan_diagnostics);
        if self.certs.is_empty() {
            Err(LoadError::NoCertificatesFound { notes })
        } else {
            Ok(LoadedCerts {
                certs: self.certs,
                notes,
            })
        }
    }
}

fn merge_directory_notes(
    target: &mut Vec<LoadNote>,
    private_key_count: &mut usize,
    incoming: &[LoadNote],
    diagnostic_limit: usize,
) {
    for note in incoming {
        match note {
            LoadNote::PrivateKeyBlocksIgnored { count } => {
                *private_key_count = private_key_count.saturating_add(*count);
            }
            LoadNote::DiagnosticsTruncated { .. } => {
                target.push(LoadNote::DiagnosticsTruncated {
                    limit: diagnostic_limit,
                });
            }
            LoadNote::DirectoryTruncated { .. } | LoadNote::TruncatedAtCertLimit { .. } => {}
            LoadNote::Rejected { .. } | LoadNote::Unparsable { .. } => target.push(note.clone()),
        }
    }
    *target = normalize_notes(std::mem::take(target), diagnostic_limit);
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use certtui_app::error::LoadError;
    use certtui_app::ports::{LocalSource, SourceLoader};
    use certtui_domain::limits::Limits;

    use super::super::fs::FsSourceLoader;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    fn malformed_pem() -> Vec<u8> {
        b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n".to_vec()
    }

    #[test]
    fn quando_diretorio_tem_symlink_deve_ignorar_inclusive_alvo() {
        let temp = TestDirectory::new();
        let target = temp.path().join("target.pem");
        let link = temp.path().join("link.pem");
        fs::write(&target, fixture("rsa2048-leaf.pem")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&target, &link).unwrap();
        let result = FsSourceLoader::new()
            .load(
                &LocalSource::Directory {
                    path: temp.path().to_path_buf(),
                    recursive: false,
                },
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(result.certs.len(), 1);
        assert!(matches!(
            result.certs.first().map(|cert| &cert.origin),
            Some(certtui_domain::model::CertOrigin::File { path, .. }) if path == &target
        ));
    }

    #[test]
    fn quando_a_origem_diretorio_e_symlink_deve_ignorar_alvo() {
        let temp = TestDirectory::new();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("cert.pem"), fixture("rsa2048-leaf.pem")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&target, &link).unwrap();
        assert!(matches!(
            FsSourceLoader::new().load(
                &LocalSource::Directory {
                    path: link,
                    recursive: false,
                },
                &Limits::default(),
            ),
            Err(LoadError::NoCertificatesFound { .. })
        ));
    }

    #[test]
    fn quando_diretorio_nao_recursivo_deve_ignorar_subdiretorios() {
        let temp = TestDirectory::new();
        let nested = temp.path().join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("cert.pem"), fixture("rsa2048-leaf.pem")).unwrap();
        assert!(matches!(
            FsSourceLoader::new().load(
                &LocalSource::Directory {
                    path: temp.path().to_path_buf(),
                    recursive: false,
                },
                &Limits::default(),
            ),
            Err(LoadError::NoCertificatesFound { notes })
                if matches!(notes.as_slice(), [certtui_domain::model::LoadNote::Unparsable { .. }])
        ));
    }

    #[test]
    fn quando_recursivo_deve_parar_na_profundidade_3() {
        let temp = TestDirectory::new();
        let mut dir = temp.path().to_path_buf();
        for depth in 1..=4 {
            dir.push(format!("d{depth}"));
            fs::create_dir(&dir).unwrap();
            fs::write(
                dir.join(format!("cert-{depth}.pem")),
                fixture("rsa2048-leaf.pem"),
            )
            .unwrap();
        }
        let result = FsSourceLoader::new()
            .load(
                &LocalSource::Directory {
                    path: temp.path().to_path_buf(),
                    recursive: true,
                },
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(result.certs.len(), 3);
    }

    #[test]
    fn quando_diretorio_tem_mais_entradas_que_o_limite_deve_truncar_e_anotar() {
        let temp = TestDirectory::new();
        fs::write(temp.path().join("a.pem"), fixture("rsa2048-leaf.pem")).unwrap();
        fs::write(temp.path().join("b.pem"), fixture("rsa2048-leaf.pem")).unwrap();
        let limits = Limits {
            max_dir_entries: 1,
            ..Limits::default()
        };
        let result = FsSourceLoader::new()
            .load(
                &LocalSource::Directory {
                    path: temp.path().to_path_buf(),
                    recursive: false,
                },
                &limits,
            )
            .unwrap();
        assert!(result.certs.len() <= 1);
        assert!(
            result
                .notes
                .contains(&certtui_domain::model::LoadNote::DirectoryTruncated { limit: 1 })
        );
    }

    #[test]
    fn quando_um_arquivo_do_diretorio_e_invalido_deve_seguir_com_os_outros() {
        let temp = TestDirectory::new();
        fs::write(temp.path().join("bad.pem"), b"nada").unwrap();
        fs::write(temp.path().join("good.pem"), fixture("rsa2048-leaf.pem")).unwrap();
        let result = FsSourceLoader::new()
            .load(
                &LocalSource::Directory {
                    path: temp.path().to_path_buf(),
                    recursive: false,
                },
                &Limits::default(),
            )
            .unwrap();
        assert_eq!(result.certs.len(), 1);
        assert_ne!(result.notes, []);
    }

    #[test]
    fn quando_diretorio_excede_limite_cumulativo_de_certs_deve_truncar() {
        let temp = TestDirectory::new();
        for name in ["a.pem", "b.pem"] {
            fs::write(temp.path().join(name), fixture("messy/bundle-mixed.txt")).unwrap();
        }
        let limits = Limits {
            max_certs_per_source: 4,
            ..Limits::default()
        };
        let result = FsSourceLoader::new()
            .load(
                &LocalSource::Directory {
                    path: temp.path().to_path_buf(),
                    recursive: false,
                },
                &limits,
            )
            .unwrap();
        assert_eq!(result.certs.len(), 4);
        assert!(
            result
                .notes
                .contains(&certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: 4 })
        );
    }

    #[test]
    fn quando_diagnosticos_de_varios_arquivos_excedem_orcamento_deve_limitar() {
        let temp = TestDirectory::new();
        for name in ["a.pem", "b.pem", "c.pem"] {
            fs::write(temp.path().join(name), malformed_pem()).unwrap();
        }
        let limits = Limits {
            max_scan_diagnostics: 1,
            ..Limits::default()
        };
        assert!(matches!(
            FsSourceLoader::new().load(
                &LocalSource::Directory {
                    path: temp.path().to_path_buf(),
                    recursive: false,
                },
                &limits
            ),
            Err(LoadError::NoCertificatesFound { notes })
                if notes.iter().filter(|note| matches!(note, certtui_domain::model::LoadNote::DiagnosticsTruncated { .. })).count() == 1
                    && notes.iter().filter(|note| matches!(note, certtui_domain::model::LoadNote::Unparsable { .. } | certtui_domain::model::LoadNote::Rejected { .. })).count() <= 1
        ));
    }

    #[test]
    fn quando_diagnosticos_de_diretorio_atingem_limite_exato_deve_preservar_sem_marcador() {
        let temp = TestDirectory::new();
        fs::write(temp.path().join("bad.pem"), malformed_pem()).unwrap();
        let limits = Limits {
            max_scan_diagnostics: 1,
            ..Limits::default()
        };
        assert!(matches!(
            FsSourceLoader::new().load(
                &LocalSource::Directory {
                    path: temp.path().to_path_buf(),
                    recursive: false,
                },
                &limits
            ),
            Err(LoadError::NoCertificatesFound { notes })
                if notes.iter().filter(|note| matches!(note, certtui_domain::model::LoadNote::Rejected { .. } | certtui_domain::model::LoadNote::Unparsable { .. })).count() == 1
                    && !notes.iter().any(|note| matches!(note, certtui_domain::model::LoadNote::DiagnosticsTruncated { .. }))
        ));
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let counter = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("certtui-test-{}-{counter}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
