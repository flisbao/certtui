//! Explicit-stack directory traversal without following symbolic links.
//!
//! Entries of each directory are visited in byte-wise file-name order, so the
//! output order does not depend on the filesystem's `read_dir` order: the
//! files of a directory first, then its subdirectories in the same order.

use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

use certtui_app::error::LoadError;
use certtui_app::ports::{LoadedCerts, RawCert};
use certtui_domain::limits::Limits;
use certtui_domain::model::{DiagnosticNoteCollector, LoadNote};
use certtui_domain::sanitize::sanitize_display;

use super::fs::{OriginKind, load_reader};

/// Loads a directory under its traversal and certificate limits.
///
/// # Errors
///
/// Returns a source error when the effective root cannot be inspected, is a
/// symbolic link (never followed) or is not a directory, and
/// `NoCertificatesFound` when no usable certificate was extracted.
pub(super) fn load_directory(
    path: &Path,
    options: DirectoryOptions,
    limits: &Limits,
) -> Result<LoadedCerts, LoadError> {
    let effective_path = effective_directory_path(path);
    let root_metadata =
        fs::symlink_metadata(&effective_path).map_err(|error| LoadError::Io(error.to_string()))?;
    if root_metadata.file_type().is_symlink() {
        return Err(LoadError::Unsupported(
            "symlinked directories are not followed",
        ));
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
    root: PathBuf,
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
            root: path.to_path_buf(),
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

    /// Sanitized path of `path` relative to the scanned root, for notes.
    /// `None` for the root itself.
    fn relative(&self, path: &Path) -> Option<String> {
        let relative = path.strip_prefix(&self.root).unwrap_or(path);
        if relative.as_os_str().is_empty() {
            return None;
        }
        Some(sanitize_display(&relative.to_string_lossy()).into_owned())
    }

    fn walk(&mut self, options: DirectoryOptions, limits: &Limits) {
        while let Some(directory) = self.stack.pop() {
            let Ok(read_dir) = fs::read_dir(&directory.path) else {
                let path = self.relative(&directory.path);
                self.notes.push(LoadNote::Unreadable { path });
                continue;
            };
            let (names, truncated) = self.collect_names(read_dir, &directory, limits);
            let mut subdirectories = Vec::new();
            for name in names {
                self.visit_entry(
                    PendingDirectory {
                        path: directory.path.join(name),
                        depth: directory.depth,
                    },
                    options,
                    limits,
                    &mut subdirectories,
                );
                if self.cert_overflow {
                    return;
                }
            }
            if truncated {
                self.directory_truncated = true;
                return;
            }
            // The stack pops last-in first-out: push in reverse so that the
            // subdirectories are visited in name order.
            self.stack.extend(subdirectories.into_iter().rev());
        }
    }

    /// Reads at most the remaining entry budget of names from `read_dir`,
    /// sorted byte-wise. The flag is set when more entries exist than the
    /// budget allows.
    fn collect_names(
        &mut self,
        read_dir: fs::ReadDir,
        directory: &PendingDirectory,
        limits: &Limits,
    ) -> (Vec<OsString>, bool) {
        let mut names = Vec::new();
        let mut truncated = false;
        for entry in read_dir {
            if self.entries >= limits.max_dir_entries {
                truncated = true;
                break;
            }
            self.entries = self.entries.saturating_add(1);
            if let Ok(entry) = entry {
                names.push(entry.file_name());
            } else {
                let path = self.relative(&directory.path);
                self.notes.push(LoadNote::Unreadable { path });
            }
        }
        names.sort_unstable();
        (names, truncated)
    }

    fn visit_entry(
        &mut self,
        entry: PendingDirectory,
        options: DirectoryOptions,
        limits: &Limits,
        subdirectories: &mut Vec<PendingDirectory>,
    ) {
        let Ok(metadata) = fs::symlink_metadata(&entry.path) else {
            let path = self.relative(&entry.path);
            self.notes.push(LoadNote::Unreadable { path });
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        if metadata.is_dir() {
            if options.recursive && entry.depth < limits.max_dir_depth {
                subdirectories.push(PendingDirectory {
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
        let relative = self.relative(&path).unwrap_or_default();
        let result = File::open(&path)
            .map_err(|error| LoadError::Io(error.to_string()))
            .and_then(|file| load_reader(file, OriginKind::File(path), &file_limits));
        self.process_child_result(result, &relative, limits);
    }

    /// Merges the outcome of loading one file; `relative` is its sanitized
    /// path, attached to the per-file notes that name one.
    fn process_child_result(
        &mut self,
        result: Result<LoadedCerts, LoadError>,
        relative: &str,
        limits: &Limits,
    ) {
        match result {
            Ok(mut loaded) => {
                let remaining = limits.max_certs_per_source.saturating_sub(self.certs.len());
                if loaded.certs.len() > remaining {
                    loaded.certs.truncate(remaining);
                    self.cert_overflow = true;
                    self.push_certificate_truncation(limits.max_certs_per_source);
                }
                self.certs.extend(loaded.certs);
                self.merge_child_notes(loaded.notes, relative, limits.max_certs_per_source);
            }
            Err(LoadError::NoCertificatesFound { notes }) => {
                self.merge_child_notes(notes, relative, limits.max_certs_per_source);
            }
            Err(error) => self.notes.push(child_failure_note(&error, relative)),
        }
    }

    fn merge_child_notes(
        &mut self,
        incoming: Vec<LoadNote>,
        relative: &str,
        certificate_limit: usize,
    ) {
        for note in incoming {
            match note {
                LoadNote::TruncatedAtCertLimit { .. } if !self.cert_truncation_noted => {
                    self.cert_truncation_noted = true;
                    self.notes.push(LoadNote::TruncatedAtCertLimit {
                        limit: certificate_limit,
                    });
                }
                LoadNote::TruncatedAtCertLimit { .. } => {}
                other => self.notes.push(other.with_path_if_unset(relative)),
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
            self.notes.push(LoadNote::NoCandidates { path: None });
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

/// The diagnostic for a file whose load failed with `error`.
fn child_failure_note(error: &LoadError, relative: &str) -> LoadNote {
    let path = Some(relative.to_owned());
    match error {
        LoadError::Io(_) => LoadNote::Unreadable { path },
        // A keystore met while scanning a directory has no password to open it.
        LoadError::Unsupported(_) | LoadError::PasswordRequired => {
            LoadNote::UnsupportedFormat { path }
        }
        LoadError::TooLarge { limit } => LoadNote::FileTooLarge {
            path,
            limit: *limit,
        },
        // `NoCertificatesFound` is handled by the caller and a single file
        // never yields `TooManyCerts`; both are reported as malformed input.
        LoadError::Malformed(_)
        | LoadError::Keystore(_)
        | LoadError::NoCertificatesFound { .. }
        | LoadError::TooManyCerts { .. } => LoadNote::MalformedInput { path },
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
            "x.pem",
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
            "x.pem",
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
            "x.pem",
            &limits,
        );
        scan.process_child_result(
            Err(LoadError::NoCertificatesFound {
                notes: vec![certtui_domain::model::LoadNote::Unparsable { offset: None }],
            }),
            "x.pem",
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
            "x.pem",
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
            "x.pem",
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
            assert_eq!(
                FsSourceLoader::new().load(
                    &LocalSource::Directory {
                        path,
                        recursive: false,
                    },
                    &Limits::default(),
                ),
                Err(LoadError::Unsupported(
                    "symlinked directories are not followed"
                ))
            );
        }
        let limits = Limits {
            max_scan_diagnostics: 0,
            ..Limits::default()
        };
        assert_eq!(
            FsSourceLoader::new().load(
                &LocalSource::Directory {
                    path: link,
                    recursive: false,
                },
                &limits,
            ),
            Err(LoadError::Unsupported(
                "symlinked directories are not followed"
            ))
        );
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
                if notes == vec![certtui_domain::model::LoadNote::NoCandidates { path: None }]
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
                .contains(&certtui_domain::model::LoadNote::NoCandidates {
                    path: Some("garbage.pem".to_owned())
                })
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

    fn load_dir(
        path: &std::path::Path,
        recursive: bool,
        limits: &Limits,
    ) -> Result<LoadedCerts, LoadError> {
        FsSourceLoader::new().load(
            &LocalSource::Directory {
                path: path.to_path_buf(),
                recursive,
            },
            limits,
        )
    }

    fn file_names(loaded: &LoadedCerts) -> Vec<String> {
        loaded
            .certs
            .iter()
            .map(|cert| match &cert.origin {
                certtui_domain::model::CertOrigin::File { path, .. } => path
                    .strip_prefix(std::env::temp_dir())
                    .unwrap()
                    .components()
                    .skip(1)
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/"),
                other => panic!("unexpected origin {other:?}"),
            })
            .collect()
    }

    #[test]
    fn quando_arquivos_criados_fora_de_ordem_deve_listar_em_ordem_de_nome() {
        let temp = TestDirectory::new();
        for (name, cert) in [
            ("c.pem", "ec-p256-leaf.pem"),
            ("a.pem", "rsa2048-leaf.pem"),
            ("b.pem", "expired.pem"),
        ] {
            fs::write(temp.path().join(name), fixture(cert)).unwrap();
        }
        let loaded = load_dir(temp.path(), false, &Limits::default()).unwrap();
        let names = file_names(&loaded);
        assert_eq!(names, ["a.pem", "b.pem", "c.pem"]);
    }

    #[test]
    fn quando_recursivo_deve_visitar_arquivos_e_depois_subdiretorios_em_ordem_de_nome() {
        let temp = TestDirectory::new();
        for dir in ["z", "m"] {
            fs::create_dir(temp.path().join(dir)).unwrap();
        }
        fs::write(temp.path().join("z/1.pem"), fixture("ec-p256-leaf.pem")).unwrap();
        fs::write(temp.path().join("m/2.pem"), fixture("expired.pem")).unwrap();
        fs::write(temp.path().join("m/1.pem"), fixture("san-multi.pem")).unwrap();
        fs::write(temp.path().join("top.pem"), fixture("rsa2048-leaf.pem")).unwrap();
        let loaded = load_dir(temp.path(), true, &Limits::default()).unwrap();
        let names = file_names(&loaded);
        assert_eq!(names, ["top.pem", "m/1.pem", "m/2.pem", "z/1.pem"]);
    }

    #[cfg(unix)]
    #[test]
    fn quando_arquivo_nao_e_legivel_deve_anotar_unreadable_com_o_caminho() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestDirectory::new();
        let locked = temp.path().join("locked.pem");
        fs::write(&locked, fixture("rsa2048-leaf.pem")).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&locked).is_ok() {
            return; // running with privileges that ignore permissions
        }
        fs::write(temp.path().join("ok.pem"), fixture("expired.pem")).unwrap();
        let loaded = load_dir(temp.path(), false, &Limits::default()).unwrap();
        assert_eq!(loaded.certs.len(), 1);
        assert_eq!(
            loaded.notes,
            vec![certtui_domain::model::LoadNote::Unreadable {
                path: Some("locked.pem".to_owned())
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn quando_subdiretorio_nao_e_legivel_deve_anotar_unreadable_com_o_caminho() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TestDirectory::new();
        let locked = temp.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        let readable = fs::read_dir(&locked).is_ok();
        fs::write(temp.path().join("ok.pem"), fixture("expired.pem")).unwrap();
        let loaded = load_dir(temp.path(), true, &Limits::default());
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
        if readable {
            return; // running with privileges that ignore permissions
        }
        assert_eq!(
            loaded.unwrap().notes,
            vec![certtui_domain::model::LoadNote::Unreadable {
                path: Some("locked".to_owned())
            }]
        );
    }

    #[test]
    fn quando_arquivo_e_keystore_jks_deve_anotar_formato_nao_suportado_com_o_caminho() {
        let temp = TestDirectory::new();
        fs::write(
            temp.path().join("store.jks"),
            [0xFE, 0xED, 0xFE, 0xED, 0, 2],
        )
        .unwrap();
        fs::write(temp.path().join("ok.pem"), fixture("expired.pem")).unwrap();
        let loaded = load_dir(temp.path(), false, &Limits::default()).unwrap();
        assert_eq!(
            loaded.notes,
            vec![certtui_domain::model::LoadNote::UnsupportedFormat {
                path: Some("store.jks".to_owned())
            }]
        );
    }

    #[test]
    fn quando_arquivo_passa_do_limite_de_entrada_deve_anotar_file_too_large_com_o_caminho() {
        let temp = TestDirectory::new();
        fs::write(temp.path().join("big.txt"), vec![b'x'; 64]).unwrap();
        fs::write(temp.path().join("ok.pem"), fixture("expired.pem")).unwrap();
        let limits = Limits {
            max_input_file_bytes: 32,
            ..Limits::default()
        };
        // `ok.pem` is also above 32 bytes: only the notes matter here.
        let Err(LoadError::NoCertificatesFound { notes }) = load_dir(temp.path(), false, &limits)
        else {
            panic!("expected no certificates");
        };
        assert_eq!(
            notes,
            vec![
                certtui_domain::model::LoadNote::FileTooLarge {
                    path: Some("big.txt".to_owned()),
                    limit: 32
                },
                certtui_domain::model::LoadNote::FileTooLarge {
                    path: Some("ok.pem".to_owned()),
                    limit: 32
                },
            ]
        );
    }

    #[test]
    fn quando_arquivo_sem_candidatos_em_subdiretorio_deve_nomear_o_caminho_relativo() {
        let temp = TestDirectory::new();
        fs::create_dir(temp.path().join("sub")).unwrap();
        fs::write(temp.path().join("sub/prose.txt"), "only prose here\n").unwrap();
        fs::write(temp.path().join("ok.pem"), fixture("expired.pem")).unwrap();
        let loaded = load_dir(temp.path(), true, &Limits::default()).unwrap();
        assert_eq!(
            loaded.notes,
            vec![certtui_domain::model::LoadNote::NoCandidates {
                path: Some("sub/prose.txt".to_owned())
            }]
        );
    }

    #[test]
    fn quando_p7b_do_diretorio_e_malformado_deve_anotar_malformed_input_com_o_caminho() {
        let temp = TestDirectory::new();
        fs::write(temp.path().join("bad.p7b"), &fixture("chain-3.p7b")[..32]).unwrap();
        fs::write(temp.path().join("ok.pem"), fixture("expired.pem")).unwrap();
        let loaded = load_dir(temp.path(), false, &Limits::default()).unwrap();
        assert_eq!(
            loaded.notes,
            vec![certtui_domain::model::LoadNote::MalformedInput {
                path: Some("bad.p7b".to_owned())
            }]
        );
    }

    #[test]
    fn quando_nome_do_arquivo_tem_caractere_de_controle_deve_sanitizar_o_caminho() {
        let temp = TestDirectory::new();
        fs::write(temp.path().join("pro\u{1b}[31mse.txt"), "only prose\n").unwrap();
        fs::write(temp.path().join("ok.pem"), fixture("expired.pem")).unwrap();
        let loaded = load_dir(temp.path(), false, &Limits::default()).unwrap();
        assert_eq!(
            loaded.notes,
            vec![certtui_domain::model::LoadNote::NoCandidates {
                path: Some("pro[31mse.txt".to_owned())
            }]
        );
    }

    #[test]
    fn quando_notas_por_arquivo_excedem_o_orcamento_deve_limitar_com_marcador() {
        let temp = TestDirectory::new();
        for name in ["a.txt", "b.txt", "c.txt"] {
            fs::write(temp.path().join(name), "only prose\n").unwrap();
        }
        let limits = Limits {
            max_scan_diagnostics: 2,
            ..Limits::default()
        };
        let Err(LoadError::NoCertificatesFound { notes }) = load_dir(temp.path(), false, &limits)
        else {
            panic!("expected no certificates");
        };
        assert_eq!(
            notes,
            vec![
                certtui_domain::model::LoadNote::NoCandidates {
                    path: Some("a.txt".to_owned())
                },
                certtui_domain::model::LoadNote::NoCandidates {
                    path: Some("b.txt".to_owned())
                },
                certtui_domain::model::LoadNote::DiagnosticsTruncated { limit: 2 },
            ]
        );
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
