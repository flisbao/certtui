use std::fs::File;
use std::io::{Read, stdin};
use std::path::PathBuf;

use certtui_app::error::LoadError;
use certtui_app::ports::{LoadedCerts, LocalSource, RawCert, SourceLoader};
use certtui_domain::extract::{CandidateKind, scan_text};
use certtui_domain::limits::Limits;
use certtui_domain::model::{CertOrigin, LoadNote, parse_der_cert, retain_diagnostic_notes};

use super::bounded::read_limited;
use super::format::{DetectedFormat, detect_format};
use super::text::utf16_to_utf8_bytes;

/// Origin used while loading a local byte stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OriginKind {
    /// A file path, retained as origin metadata.
    File(PathBuf),
    /// Standard input.
    Stdin,
}

/// Loads certificates from files and standard input based on their contents.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsSourceLoader;

impl FsSourceLoader {
    /// Creates a filesystem source loader.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SourceLoader for FsSourceLoader {
    fn load(&self, src: &LocalSource, limits: &Limits) -> Result<LoadedCerts, LoadError> {
        match src {
            LocalSource::File(path) => {
                let file = File::open(path).map_err(|error| LoadError::Io(error.to_string()))?;
                load_reader(file, OriginKind::File(path.clone()), limits)
            }
            LocalSource::Stdin => load_reader(stdin().lock(), OriginKind::Stdin, limits),
            // Directory traversal is introduced in Task 16. This interim
            // outcome prevents the current loader from implying support.
            LocalSource::Directory { .. } => Err(LoadError::Unsupported(
                "directory sources arrive in a later release",
            )),
        }
    }
}

/// Reads one stream under its source-specific byte limit, then extracts its
/// certificate candidates.
// Justificativa: o contrato do helper no brief do Task 15 exige origem por valor.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn load_reader<R: Read>(
    reader: R,
    origin: OriginKind,
    limits: &Limits,
) -> Result<LoadedCerts, LoadError> {
    let limit = match &origin {
        OriginKind::File(_) => limits.max_input_file_bytes,
        OriginKind::Stdin => limits.max_stdin_bytes,
    };
    let bytes = read_limited(reader, limit)?;
    match detect_format(&bytes) {
        DetectedFormat::Jks => Err(LoadError::Unsupported(
            "JKS keystores arrive in a later release",
        )),
        DetectedFormat::BinaryDer => load_binary_der(&bytes, &origin, limits),
        DetectedFormat::Utf16Text => {
            let decoded = utf16_to_utf8_bytes(&bytes);
            load_text(&decoded, &origin, limits)
        }
        DetectedFormat::Text => {
            let text = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
            load_text(text, &origin, limits)
        }
    }
}

fn load_binary_der(
    bytes: &[u8],
    origin: &OriginKind,
    limits: &Limits,
) -> Result<LoadedCerts, LoadError> {
    if parse_der_cert(bytes, limits).is_err() {
        return Err(LoadError::Unsupported(
            "PKCS#12 keystores arrive in a later release",
        ));
    }
    Ok(LoadedCerts {
        certs: vec![RawCert {
            der: bytes.to_vec(),
            origin: cert_origin(origin, 0),
        }],
        notes: Vec::new(),
    })
}

fn load_text(bytes: &[u8], origin: &OriginKind, limits: &Limits) -> Result<LoadedCerts, LoadError> {
    let outcome = scan_text(bytes, limits);
    let mut notes = Vec::from(&outcome);
    let mut certs = Vec::new();
    for candidate in outcome.candidates {
        if candidate.kind == CandidateKind::Pkcs7 {
            notes.push(LoadNote::Unparsable {
                offset: Some(candidate.offset),
            });
            continue;
        }
        if parse_der_cert(&candidate.der, limits).is_err() {
            notes.push(LoadNote::Unparsable {
                offset: Some(candidate.offset),
            });
            continue;
        }
        let index = certs.len();
        certs.push(RawCert {
            der: candidate.der,
            origin: cert_origin(origin, index),
        });
    }
    if certs.is_empty() && notes.is_empty() {
        notes.push(LoadNote::Unparsable { offset: None });
    }
    let notes = normalize_notes(notes, limits.max_scan_diagnostics);
    if certs.is_empty() {
        return Err(LoadError::NoCertificatesFound { notes });
    }
    Ok(LoadedCerts { certs, notes })
}

fn normalize_notes(notes: Vec<LoadNote>, limit: usize) -> Vec<LoadNote> {
    let (mut notes, _, dropped) = retain_diagnostic_notes(notes, limit);
    if dropped
        && !notes
            .iter()
            .any(|note| matches!(note, LoadNote::DiagnosticsTruncated { .. }))
    {
        notes.push(LoadNote::DiagnosticsTruncated { limit });
    }
    notes
}

fn cert_origin(origin: &OriginKind, index: usize) -> CertOrigin {
    match origin {
        OriginKind::File(path) => CertOrigin::File {
            path: path.clone(),
            index,
        },
        OriginKind::Stdin => CertOrigin::Stdin { index },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use certtui_app::error::LoadError;
    use certtui_app::ports::{LocalSource, SourceLoader};
    use certtui_domain::limits::Limits;

    use super::super::format::{DetectedFormat, detect_format};
    use super::{FsSourceLoader, OriginKind, load_reader};
    use crate::source::text::utf16_to_utf8_bytes;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    fn load_bytes(
        bytes: &[u8],
        origin: OriginKind,
        limits: &Limits,
    ) -> Result<certtui_app::ports::LoadedCerts, LoadError> {
        load_reader(bytes, origin, limits)
    }

    #[test]
    fn quando_pem_simples_deve_achar_um_cert() {
        let result = load_bytes(
            &fixture("rsa2048-leaf.pem"),
            OriginKind::Stdin,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(result.certs.len(), 1);
    }

    #[test]
    fn quando_der_binario_deve_achar_um_cert() {
        let result = load_bytes(
            &fixture("rsa2048-leaf.der"),
            OriginKind::Stdin,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(result.certs.len(), 1);
    }

    #[test]
    fn quando_utf16le_com_bom_deve_achar_certs() {
        let result = load_bytes(
            &fixture("messy/utf16le-bom.txt"),
            OriginKind::Stdin,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(result.certs.len(), 3);
    }

    #[test]
    fn quando_utf8_com_bom_deve_achar_certs() {
        let result = load_bytes(
            &fixture("messy/utf8-bom.txt"),
            OriginKind::Stdin,
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(result.certs.len(), 3);
    }

    #[test]
    fn quando_extensao_mente_deve_detectar_por_conteudo() {
        let pem = fixture("rsa2048-leaf.pem");
        let der = fixture("rsa2048-leaf.der");
        let pem_path = temp_path(".der");
        let der_path = temp_path(".pem");
        fs::write(&pem_path, pem).unwrap();
        fs::write(&der_path, der).unwrap();
        let loader = FsSourceLoader::new();
        let pem_loaded = loader
            .load(&LocalSource::File(pem_path.clone()), &Limits::default())
            .unwrap();
        let der_loaded = loader
            .load(&LocalSource::File(der_path.clone()), &Limits::default())
            .unwrap();
        fs::remove_file(pem_path).unwrap();
        fs::remove_file(der_path).unwrap();
        assert_eq!(pem_loaded.certs.len(), 1);
        assert_eq!(der_loaded.certs.len(), 1);
    }

    fn temp_path(extension: &str) -> PathBuf {
        std::env::temp_dir().join(format!("certtui-task15-{}-{extension}", std::process::id()))
    }

    #[test]
    fn quando_arquivo_passa_de_max_input_file_bytes_deve_dar_too_large() {
        let limits = Limits {
            max_input_file_bytes: 4,
            ..Limits::default()
        };
        assert_eq!(
            load_bytes(b"12345", OriginKind::File(PathBuf::from("x")), &limits),
            Err(LoadError::TooLarge { limit: 4 })
        );
    }

    #[test]
    fn quando_stdin_passa_de_max_stdin_bytes_deve_dar_too_large() {
        let limits = Limits {
            max_stdin_bytes: 4,
            ..Limits::default()
        };
        assert_eq!(
            load_bytes(b"12345", OriginKind::Stdin, &limits),
            Err(LoadError::TooLarge { limit: 4 })
        );
    }

    #[test]
    fn quando_magic_jks_deve_dar_unsupported_claro() {
        assert_eq!(
            load_bytes(
                &[0xFE, 0xED, 0xFE, 0xED],
                OriginKind::Stdin,
                &Limits::default()
            ),
            Err(LoadError::Unsupported(
                "JKS keystores arrive in a later release"
            ))
        );
    }

    #[test]
    fn quando_der_nao_x509_deve_informar_pkcs12_ainda_nao_suportado() {
        assert_eq!(
            load_bytes(
                &fixture("chain-3.p7b"),
                OriginKind::Stdin,
                &Limits::default()
            ),
            Err(LoadError::Unsupported(
                "PKCS#12 keystores arrive in a later release"
            ))
        );
    }

    #[test]
    fn quando_diretorio_e_recebido_antes_do_task16_deve_ser_unsupported() {
        let result = FsSourceLoader::new().load(
            &LocalSource::Directory {
                path: PathBuf::from("certs"),
                recursive: false,
            },
            &Limits::default(),
        );
        assert_eq!(
            result,
            Err(LoadError::Unsupported(
                "directory sources arrive in a later release"
            ))
        );
    }

    #[test]
    fn quando_texto_sem_cert_deve_dar_no_certificates_found_com_notes() {
        let result = load_bytes(
            &fixture("messy/no-certs.txt"),
            OriginKind::Stdin,
            &Limits::default(),
        );
        assert!(
            matches!(result, Err(LoadError::NoCertificatesFound { notes }) if !notes.is_empty())
        );
    }

    #[test]
    fn quando_entrada_vazia_deve_anotar_formato_nao_parseavel() {
        assert_eq!(
            load_bytes(b"", OriginKind::Stdin, &Limits::default()),
            Err(LoadError::NoCertificatesFound {
                notes: vec![certtui_domain::model::LoadNote::Unparsable { offset: None }],
            })
        );
    }

    #[test]
    fn quando_texto_tem_chave_privada_deve_anotar_que_foi_ignorada() {
        let result = load_bytes(
            &fixture("messy/with-private-key.txt"),
            OriginKind::Stdin,
            &Limits::default(),
        )
        .unwrap();
        assert!(
            result
                .notes
                .contains(&certtui_domain::model::LoadNote::PrivateKeyBlocksIgnored { count: 1 })
        );
        let notes = format!("{:?}", result.notes);
        assert!(!notes.contains("PRIVATE KEY"));
    }

    #[test]
    fn quando_pem_termina_sem_end_deve_preservar_nota_de_scan_no_loader() {
        let result = load_bytes(
            &fixture("messy/truncated.txt"),
            OriginKind::Stdin,
            &Limits::default(),
        )
        .unwrap();
        assert!(result.notes.iter().any(|note| matches!(
            note,
            certtui_domain::model::LoadNote::Rejected {
                reason: certtui_domain::model::RejectReason::UnterminatedPem,
                ..
            }
        )));
    }

    #[test]
    fn quando_origem_e_arquivo_deve_indexar_certificados_na_ordem_de_saida() {
        let result = load_bytes(
            &fixture("messy/bundle-mixed.txt"),
            OriginKind::File(PathBuf::from("bundle.txt")),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(result.certs.len(), 3);
        for (index, cert) in result.certs.iter().enumerate() {
            assert_eq!(
                cert.origin,
                certtui_domain::model::CertOrigin::File {
                    path: PathBuf::from("bundle.txt"),
                    index
                }
            );
        }
    }

    #[test]
    fn quando_messy_corpus_e_carregado_deve_respeitar_contagens_esperadas() {
        let expected = fs::read_to_string(format!("{FIXTURES}/messy/expected.tsv")).unwrap();
        for line in expected.lines() {
            let mut columns = line.split('\t');
            let name = columns.next().unwrap();
            let count: usize = columns.next().unwrap().parse().unwrap();
            let bytes = fixture(&format!("messy/{name}"));
            let loaded = load_bytes(&bytes, OriginKind::Stdin, &Limits::default());
            let actual = loaded.map_or(0, |result| result.certs.len());
            assert_eq!(actual, count, "{name}");
        }
    }

    #[test]
    fn quando_utf16_contem_prefixo_nao_ascii_deve_preservar_certificado_posterior() {
        let prefix = "日".repeat(2_000);
        let pem = fixture("rsa2048-leaf.pem");
        let utf8 = format!("{prefix}\n{}", String::from_utf8(pem.clone()).unwrap());
        let mut text = prefix
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        text.extend("\n".encode_utf16().flat_map(u16::to_le_bytes));
        text.extend(pem.iter().flat_map(|byte| u16::from(*byte).to_le_bytes()));
        let mut input = vec![0xFF, 0xFE];
        input.extend(text);
        assert!(utf8.len() > input.len());
        let max_output = input.len().saturating_sub(2).div_ceil(2).saturating_mul(3);
        let decoded = utf16_to_utf8_bytes(&input);
        assert!(decoded.len() <= max_output);
        assert_eq!(decoded, utf8.as_bytes());
        let loaded = load_bytes(&input, OriginKind::Stdin, &Limits::default()).unwrap();
        assert_eq!(loaded.certs.len(), 1);
    }

    fn malformed_pem() -> Vec<u8> {
        b"-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n".to_vec()
    }

    fn non_der_pem() -> &'static [u8] {
        b"-----BEGIN CERTIFICATE-----\n%%%\n-----END CERTIFICATE-----\n"
    }

    #[test]
    fn quando_notes_do_loader_sucesso_passam_do_limite_deve_limitar_com_marcador() {
        let limits = Limits {
            max_scan_diagnostics: 1,
            ..Limits::default()
        };
        let mut input = non_der_pem().to_vec();
        input.extend(malformed_pem());
        input.extend(malformed_pem());
        input.extend(fixture("rsa2048-leaf.pem"));
        let result = load_bytes(&input, OriginKind::Stdin, &limits).unwrap();
        assert_eq!(result.certs.len(), 1);
        assert_eq!(
            result.notes,
            vec![
                certtui_domain::model::LoadNote::Rejected {
                    offset: 0,
                    reason: certtui_domain::model::RejectReason::NotDerSequence,
                },
                certtui_domain::model::LoadNote::DiagnosticsTruncated { limit: 1 },
            ]
        );
    }

    #[test]
    fn quando_notes_do_loader_sem_certificados_passam_do_limite_deve_limitar_com_marcador() {
        let limits = Limits {
            max_scan_diagnostics: 1,
            ..Limits::default()
        };
        let mut input = non_der_pem().to_vec();
        input.extend(malformed_pem());
        input.extend(malformed_pem());
        assert_eq!(
            load_bytes(&input, OriginKind::Stdin, &limits),
            Err(LoadError::NoCertificatesFound {
                notes: vec![
                    certtui_domain::model::LoadNote::Rejected {
                        offset: 0,
                        reason: certtui_domain::model::RejectReason::NotDerSequence,
                    },
                    certtui_domain::model::LoadNote::DiagnosticsTruncated { limit: 1 },
                ],
            })
        );
    }

    #[test]
    fn quando_limite_de_notes_e_zero_deve_preservar_metadados_e_um_marcador() {
        let limits = Limits {
            max_scan_diagnostics: 0,
            ..Limits::default()
        };
        let mut input = malformed_pem();
        input.extend(b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n");
        assert_eq!(
            load_bytes(&input, OriginKind::Stdin, &limits),
            Err(LoadError::NoCertificatesFound {
                notes: vec![
                    certtui_domain::model::LoadNote::PrivateKeyBlocksIgnored { count: 1 },
                    certtui_domain::model::LoadNote::DiagnosticsTruncated { limit: 0 },
                ],
            })
        );
    }

    #[test]
    fn quando_utf16_tem_surrogate_invalido_deve_decodificar_com_replacement_char() {
        assert_eq!(
            String::from_utf8(utf16_to_utf8_bytes(&[0x00, 0xD8])).unwrap(),
            "�"
        );
    }

    #[test]
    fn quando_utf16be_com_bom_deve_achar_certificados() {
        let pem = fixture("rsa2048-leaf.pem");
        let mut bytes = vec![0xFE, 0xFF];
        bytes.extend(
            pem.into_iter()
                .flat_map(|byte| u16::from(byte).to_be_bytes()),
        );
        assert_eq!(
            load_bytes(&bytes, OriginKind::Stdin, &Limits::default())
                .unwrap()
                .certs
                .len(),
            1
        );
    }

    #[test]
    fn quando_formatos_tem_assinaturas_conhecidas_deve_detectar_na_ordem() {
        assert_eq!(
            detect_format(&[0xFE, 0xED, 0xFE, 0xED]),
            DetectedFormat::Jks
        );
        assert_eq!(
            detect_format(&[0xFF, 0xFE, 0x30]),
            DetectedFormat::Utf16Text
        );
        assert_eq!(detect_format(&[0x30, 0x00]), DetectedFormat::BinaryDer);
        assert_eq!(detect_format(b"text"), DetectedFormat::Text);
    }
}
