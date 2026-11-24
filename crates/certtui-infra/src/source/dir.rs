//! Explicit-stack directory traversal without following symbolic links.

use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

use certtui_app::error::LoadError;
use certtui_app::ports::{LoadedCerts, RawCert};
use certtui_domain::limits::Limits;
use certtui_domain::model::{DiagnosticNoteCollector, LoadNote};

use super::fs::{OriginKind, load_reader, normalize_notes};

/// Loads a directory under its traversal and certificate limits.
///
/// # Errors
///
/// Returns a source error when the effective root cannot be inspected or is
/// not a directory, and `NoCertificatesFound` when no usable certificate was
/// extracted.
pub(super) fn load_directory(
    path: &Path,
    options: DirectoryOptions,
    limits: &Limits,
) -> Result<LoadedCerts, LoadError> {
    let effective_path = effective_directory_path(path);
    let root_metadata =
        fs::symlink_metadata(&effective_path).map_err(|error| LoadError::Io(error.to_string()))?;
    if root_metadata.file_type().is_symlink() {
        return Err(LoadError::NoCertificatesFound {
            notes: normalize_notes(
                vec![LoadNote::Unparsable { offset: None }],
                limits.max_scan_diagnostics,
            ),
        });
    }
    if !root_metadata.is_dir() {
        return Err(LoadError::Io(
            "directory source is not a directory".to_owned(),
        ));
    }

    let mut scan = DirectoryScan::new(&effective_path, limits.max_scan_diagnostics);
    scan.walk(options, limits);
    scan.finish(limits)
}

/// Traversal policy for a directory source.
#[derive(Debug, Clone, Copy)]
pub(super) struct DirectoryOptions {
    /// Whether child directories may be visited.
    pub(super) recursive: bool,
}

fn effective_directory_path(path: &Path) -> PathBuf {
    let mut effective = PathBuf::new();
    for component in path.components() {
        if component != Component::CurDir {
            effective.push(component.as_os_str());
        }
    }
    if effective.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        effective
    }
}

#[derive(Debug)]
struct PendingDirectory {
    path: PathBuf,
    depth: usize,
}

struct DirectoryScan {
    stack: Vec<PendingDirectory>,
    certs: Vec<RawCert>,
    notes: DiagnosticNoteCollector,
    directory_truncated: bool,
    cert_overflow: bool,
    cert_truncation_noted: bool,
    entries: usize,
}

impl DirectoryScan {
    fn new(path: &Path, note_limit: usize) -> Self {
        Self {
            stack: vec![PendingDirectory {
                path: path.to_path_buf(),
                depth: 0,
            }],
            certs: Vec::new(),
            notes: DiagnosticNoteCollector::new(note_limit),
            directory_truncated: false,
            cert_overflow: false,
            cert_truncation_noted: false,
            entries: 0,
        }
    }

    fn walk(&mut self, options: DirectoryOptions, limits: &Limits) {
        while let Some(directory) = self.stack.pop() {
            let Ok(read_dir) = fs::read_dir(&directory.path) else {
                self.notes.push(LoadNote::Unparsable { offset: None });
                continue;
            };
            for entry in read_dir {
                if self.entries >= limits.max_dir_entries {
                    self.directory_truncated = true;
                    return;
                }
                self.entries = self.entries.saturating_add(1);
                let Ok(entry) = entry else {
                    self.notes.push(LoadNote::Unparsable { offset: None });
                    continue;
                };
                self.visit_entry(
                    PendingDirectory {
                        path: entry.path(),
                        depth: directory.depth,
                    },
                    options,
                    limits,
                );
                if self.cert_overflow {
                    return;
                }
            }
        }
    }

    fn visit_entry(&mut self, entry: PendingDirectory, options: DirectoryOptions, limits: &Limits) {
        let Ok(metadata) = fs::symlink_metadata(&entry.path) else {
            self.notes.push(LoadNote::Unparsable { offset: None });
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        if metadata.is_dir() {
            if options.recursive && entry.depth < limits.max_dir_depth {
                self.stack.push(PendingDirectory {
                    path: entry.path,
                    depth: entry.depth.saturating_add(1),
                });
            }
            return;
        }
        if metadata.is_file() {
            self.load_file(entry.path, limits);
        }
    }

    fn load_file(&mut self, path: PathBuf, limits: &Limits) {
        let remaining = limits.max_certs_per_source.saturating_sub(self.certs.len());
        let mut file_limits = *limits;
        file_limits.max_certs_per_source = remaining.saturating_add(1);
        let result = File::open(&path)
            .map_err(|_| LoadError::Io("unable to open directory entry".to_owned()))
            .and_then(|file| load_reader(file, OriginKind::File(path), &file_limits));
        self.process_child_result(result, limits);
    }

    fn process_child_result(&mut self, result: Result<LoadedCerts, LoadError>, limits: &Limits) {
        match result {
            Ok(mut loaded) => {
                let remaining = limits.max_certs_per_source.saturating_sub(self.certs.len());
                if loaded.certs.len() > remaining {
                    loaded.certs.truncate(remaining);
                    self.cert_overflow = true;
                    self.push_certificate_truncation(limits.max_certs_per_source);
                }
                self.certs.extend(loaded.certs);
                self.merge_child_notes(loaded.notes, limits.max_certs_per_source);
            }
            Err(LoadError::NoCertificatesFound { notes }) => {
                self.merge_child_notes(notes, limits.max_certs_per_source);
            }
            Err(_) => self.notes.push(LoadNote::Unparsable { offset: None }),
        }
    }

    fn merge_child_notes(&mut self, incoming: Vec<LoadNote>, certificate_limit: usize) {
        for note in incoming {
            match note {
                LoadNote::TruncatedAtCertLimit { .. } if !self.cert_truncation_noted => {
                    self.cert_truncation_noted = true;
                    self.notes.push(LoadNote::TruncatedAtCertLimit {
                        limit: certificate_limit,
                    });
                }
                LoadNote::TruncatedAtCertLimit { .. } => {}
                other => self.notes.push(other),
            }
        }
    }

    fn push_certificate_truncation(&mut self, limit: usize) {
        if !self.cert_truncation_noted {
            self.cert_truncation_noted = true;
            self.notes.push(LoadNote::TruncatedAtCertLimit { limit });
        }
    }

    fn finish(mut self, limits: &Limits) -> Result<LoadedCerts, LoadError> {
        if self.cert_overflow && !self.cert_truncation_noted {
            self.push_certificate_truncation(limits.max_certs_per_source);
        }
        if self.directory_truncated {
            self.notes.push(LoadNote::DirectoryTruncated {
                limit: limits.max_dir_entries,
            });
        }
        if self.certs.is_empty() && self.notes.is_empty() {
            self.notes.push(LoadNote::Unparsable { offset: None });
        }
        let (notes, _, _) = self.notes.finish();
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use certtui_app::error::LoadError;
    use certtui_app::ports::{LoadedCerts, LocalSource, RawCert, SourceLoader};
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
    fn quando_filho_com_truncamento_e_depois_cert_valido_deve_continuar_varredura() {
        let limits = Limits {
            max_certs_per_source: 1,
            ..Limits::default()
        };
        let mut scan =
            super::DirectoryScan::new(std::path::Path::new("root"), limits.max_scan_diagnostics);
        scan.process_child_result(
            Ok(LoadedCerts {
                certs: Vec::new(),
                notes: vec![certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: 1 }],
            }),
            &limits,
        );
        scan.process_child_result(
            Ok(LoadedCerts {
                certs: vec![RawCert {
                    der: vec![0x30],
                    origin: certtui_domain::model::CertOrigin::File {
                        path: PathBuf::from("later.pem"),
                        index: 0,
                    },
                }],
                notes: Vec::new(),
            }),
            &limits,
        );
        let result = scan.finish(&limits).unwrap();
        assert_eq!(result.certs.len(), 1);
        assert!(
            result
                .notes
                .contains(&certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: 1 })
        );
    }

    #[test]
    fn quando_filho_tem_truncamento_deve_preservar_ordem_da_nota() {
        let limits = Limits::default();
        let mut scan =
            super::DirectoryScan::new(std::path::Path::new("root"), limits.max_scan_diagnostics);
        scan.process_child_result(
            Ok(LoadedCerts {
                certs: Vec::new(),
                notes: vec![certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: 1 }],
            }),
            &limits,
        );
        scan.process_child_result(
            Err(LoadError::NoCertificatesFound {
                notes: vec![certtui_domain::model::LoadNote::Unparsable { offset: None }],
            }),
            &limits,
        );
        let result = scan.finish(&limits).unwrap_err();
        let LoadError::NoCertificatesFound { notes } = result else {
            panic!("expected no certificates")
        };
        assert!(matches!(
            notes.as_slice(),
            [
                certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: 500 },
                certtui_domain::model::LoadNote::Unparsable { offset: None }
            ]
        ));
    }

    #[test]
    fn quando_filho_sem_cert_com_truncamento_e_depois_cert_valido_deve_continuar() {
        let limits = Limits {
            max_certs_per_source: 1,
            ..Limits::default()
        };
        let mut scan =
            super::DirectoryScan::new(std::path::Path::new("root"), limits.max_scan_diagnostics);
        scan.process_child_result(
            Err(LoadError::NoCertificatesFound {
                notes: vec![certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: 1 }],
            }),
            &limits,
        );
        scan.process_child_result(
            Ok(LoadedCerts {
                certs: vec![RawCert {
                    der: vec![0x30],
                    origin: certtui_domain::model::CertOrigin::File {
                        path: PathBuf::from("later.pem"),
                        index: 0,
                    },
                }],
                notes: Vec::new(),
            }),
            &limits,
        );
        let result = scan.finish(&limits).unwrap();
        assert_eq!(result.certs.len(), 1);
        assert!(
            result
                .notes
                .contains(&certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: 1 })
        );
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
        for path in [
            link.clone(),
            PathBuf::from(format!("{}/", link.display())),
            link.join("."),
        ] {
            assert!(matches!(
                FsSourceLoader::new().load(
                    &LocalSource::Directory {
                        path,
                        recursive: false,
                    },
                    &Limits::default(),
                ),
                Err(LoadError::NoCertificatesFound { .. })
            ));
        }
        let limits = Limits {
            max_scan_diagnostics: 0,
            ..Limits::default()
        };
        assert!(matches!(
            FsSourceLoader::new().load(
                &LocalSource::Directory {
                    path: link,
                    recursive: false,
                },
                &limits,
            ),
            Err(LoadError::NoCertificatesFound { notes })
                if notes == vec![certtui_domain::model::LoadNote::DiagnosticsTruncated { limit: 0 }]
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
    fn quando_diretorio_tem_quantidade_exata_de_entradas_deve_terminar_sem_truncar() {
        let temp = TestDirectory::new();
        fs::write(temp.path().join("only.pem"), fixture("rsa2048-leaf.pem")).unwrap();
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
        assert_eq!(result.certs.len(), 1);
        assert!(!result.notes.iter().any(|note| matches!(
            note,
            certtui_domain::model::LoadNote::DirectoryTruncated { .. }
        )));
    }

    #[test]
    fn quando_diretorio_agrega_rejected_unparsable_e_metadata_em_ordem_de_fonte() {
        let temp = TestDirectory::new();
        fs::write(
            temp.path().join("bad-base64.pem"),
            b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(temp.path().join("garbage.pem"), b"nada").unwrap();
        fs::write(temp.path().join("valid.pem"), fixture("rsa2048-leaf.pem")).unwrap();
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
        assert!(
            result
                .notes
                .iter()
                .any(|note| matches!(note, certtui_domain::model::LoadNote::Rejected { .. }))
        );
        assert!(
            result
                .notes
                .iter()
                .any(|note| matches!(note, certtui_domain::model::LoadNote::Unparsable { .. }))
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
