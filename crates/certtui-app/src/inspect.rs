//! The `inspect_local` use case: files, stdin and directories.

use certtui_domain::limits::Limits;
use certtui_domain::model::{
    CertificateRecord, Chain, InspectionReport, LoadNote, Timings, TrustVerdict,
    retain_diagnostic_notes,
};
use certtui_domain::target::Target;

use crate::error::LoadError;
use crate::ports::{LocalSource, RawCert, SourceLoader};

/// Loads the certificates of `src` and assembles an [`InspectionReport`].
///
/// Raw certificates that fail X.509 parsing become [`LoadNote::Unparsable`]
/// (without any bytes); the loader's own notes come first. Trust is not
/// evaluated for local sources.
///
/// # Errors
///
/// - Any [`LoadError`] from the loader.
/// - [`LoadError::NoCertificatesFound`] (with the retained notes, capped at
///   `limits.max_scan_diagnostics`) when nothing parses.
/// - [`LoadError::TooManyCerts`] when more than `limits.max_certs_per_source`
///   certificates parse. For local sources that cap governs, not
///   `max_chain_len`, which belongs to the presented/AIA chain of a TLS
///   target (spec section 9).
pub fn inspect_local(
    loader: &dyn SourceLoader,
    src: &LocalSource,
    target: Target,
    limits: &Limits,
) -> Result<InspectionReport, LoadError> {
    let found = loader.load(src, limits)?;
    let (loader_notes, diagnostic_slots, loader_dropped) =
        retain_diagnostic_notes(found.notes, limits.max_scan_diagnostics);
    let (records, unparsable, app_dropped) = parse_all(found.certs, limits, diagnostic_slots)?;
    let notes = combine_notes(
        loader_notes,
        unparsable,
        loader_dropped || app_dropped,
        limits,
    );
    if records.is_empty() {
        return Err(LoadError::NoCertificatesFound { notes });
    }
    // A local source is a bundle, not a presented chain: its cap is
    // `max_certs_per_source` (already enforced by `parse_all`), so the chain
    // is built against that cap instead of `max_chain_len`.
    let chain_limits = Limits {
        max_chain_len: limits.max_certs_per_source,
        ..*limits
    };
    let chain = Chain::new(records, &chain_limits).map_err(|error| map_chain_error(&error))?;
    Ok(build_report(target, chain, notes))
}

fn map_chain_error(error: &certtui_domain::error::ChainError) -> LoadError {
    match error {
        certtui_domain::error::ChainError::TooLong { len, max } => LoadError::TooManyCerts {
            len: *len,
            max: *max,
        },
    }
}

fn build_report(target: Target, chain: Chain, notes: Vec<LoadNote>) -> InspectionReport {
    InspectionReport {
        target,
        tls: None,
        ocsp_staple: None,
        chain,
        trust: TrustVerdict::NotEvaluated,
        revocation: Vec::new(),
        findings: Vec::new(),
        timings: Timings::default(),
        notes,
    }
}

/// Parses candidates, retaining only the chain and diagnostic budgets.
fn parse_all(
    raws: Vec<RawCert>,
    limits: &Limits,
    diagnostic_slots: usize,
) -> Result<(Vec<CertificateRecord>, Vec<LoadNote>, bool), LoadError> {
    let mut records = Vec::new();
    let mut notes = Vec::new();
    let mut dropped = false;
    for raw in raws {
        match CertificateRecord::from_der(&raw.der, raw.origin, limits) {
            Ok(_record) if records.len() >= limits.max_certs_per_source => {
                return Err(LoadError::TooManyCerts {
                    len: limits.max_certs_per_source.saturating_add(1),
                    max: limits.max_certs_per_source,
                });
            }
            Ok(record) => records.push(record),
            Err(_) if notes.len() < diagnostic_slots => {
                notes.push(LoadNote::Unparsable { offset: None });
            }
            Err(_) => dropped = true,
        }
    }
    Ok((records, notes, dropped))
}

fn combine_notes(
    mut loader_notes: Vec<LoadNote>,
    unparsable: Vec<LoadNote>,
    dropped: bool,
    limits: &Limits,
) -> Vec<LoadNote> {
    loader_notes.extend(unparsable);
    if dropped
        && !loader_notes
            .iter()
            .any(|note| matches!(note, LoadNote::DiagnosticsTruncated { .. }))
    {
        loader_notes.push(LoadNote::DiagnosticsTruncated {
            limit: limits.max_scan_diagnostics,
        });
    }
    loader_notes
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use certtui_domain::model::{CertOrigin, RejectReason};

    use super::*;
    use crate::testing::FakeSourceLoader;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn raw(name: &str, index: usize) -> RawCert {
        RawCert {
            der: std::fs::read(format!("{FIXTURES}/{name}")).unwrap(),
            origin: CertOrigin::File {
                path: PathBuf::from(name),
                index,
            },
        }
    }

    fn garbage(index: usize) -> RawCert {
        RawCert {
            der: vec![
                0x30, 0x0A, 0x02, 0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03,
            ],
            origin: CertOrigin::File {
                path: PathBuf::from("key.pem"),
                index,
            },
        }
    }

    fn run(
        certs: Vec<RawCert>,
        notes: Vec<LoadNote>,
        limits: &Limits,
    ) -> Result<InspectionReport, LoadError> {
        let loader = FakeSourceLoader(Ok(crate::ports::LoadedCerts { certs, notes }));
        let src = LocalSource::File(PathBuf::from("bundle.pem"));
        inspect_local(
            &loader,
            &src,
            Target::File(PathBuf::from("bundle.pem")),
            limits,
        )
    }

    #[test]
    fn quando_loader_devolve_certs_validos_deve_montar_chain_em_ordem() {
        let certs = vec![raw("rsa2048-leaf.der", 0), raw("expired.der", 1)];
        let report = run(certs, Vec::new(), &Limits::default()).unwrap();
        assert_eq!(report.chain.len(), 2);
        let r0 = report.chain.get(0).unwrap();
        let r1 = report.chain.get(1).unwrap();
        assert_eq!(r0.der.as_ref(), raw("rsa2048-leaf.der", 0).der.as_slice());
        assert_eq!(r1.der.as_ref(), raw("expired.der", 1).der.as_slice());
        assert_eq!(report.target, Target::File(PathBuf::from("bundle.pem")));
        assert!(report.tls.is_none());
        assert_eq!(report.trust, TrustVerdict::NotEvaluated);
        assert_eq!(report.revocation, Vec::new());
        assert_eq!(report.findings, Vec::new());
        assert_eq!(report.timings, Timings::default());
        assert_eq!(report.notes, Vec::new());
    }

    #[test]
    fn quando_um_der_e_invalido_deve_virar_nota_unparsable_e_seguir() {
        let certs = vec![
            raw("rsa2048-leaf.der", 0),
            garbage(1),
            raw("expired.der", 2),
        ];
        let report = run(certs, Vec::new(), &Limits::default()).unwrap();
        assert_eq!(report.chain.len(), 2);
        assert_eq!(report.notes, vec![LoadNote::Unparsable { offset: None }]);
    }

    #[test]
    fn quando_nenhum_der_e_valido_deve_dar_no_certificates_found_com_notes() {
        let loader_note = LoadNote::PrivateKeyBlocksIgnored { count: 1 };
        let err = run(
            vec![garbage(0), garbage(1)],
            vec![loader_note.clone()],
            &Limits::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            LoadError::NoCertificatesFound {
                notes: vec![
                    loader_note,
                    LoadNote::Unparsable { offset: None },
                    LoadNote::Unparsable { offset: None },
                ]
            }
        );
        assert_eq!(err.to_string(), "no certificates found");
    }

    #[test]
    fn quando_notes_do_loader_deve_ir_para_o_relatorio_antes_das_unparsable() {
        let notes = vec![
            LoadNote::Rejected {
                offset: 7,
                reason: RejectReason::InvalidBase64,
            },
            LoadNote::DiagnosticsTruncated { limit: 3 },
        ];
        let certs = vec![garbage(0), raw("rsa2048-leaf.der", 1)];
        let report = run(certs, notes.clone(), &Limits::default()).unwrap();
        let mut expected = notes;
        expected.push(LoadNote::Unparsable { offset: None });
        assert_eq!(report.notes, expected);
    }

    #[test]
    fn quando_certs_passam_de_max_certs_per_source_deve_dar_erro_tipado() {
        let limits = Limits::default();
        let certs: Vec<_> = (0..=limits.max_certs_per_source)
            .map(|i| raw("rsa2048-leaf.der", i))
            .collect();
        let err = run(certs, Vec::new(), &limits).unwrap_err();
        assert_eq!(
            err,
            LoadError::TooManyCerts {
                len: limits.max_certs_per_source + 1,
                max: limits.max_certs_per_source
            }
        );
    }

    #[test]
    fn quando_varios_validos_passam_do_teto_deve_contar_so_validos_ate_o_primeiro_excesso() {
        let limits = Limits {
            max_certs_per_source: 2,
            ..Limits::default()
        };
        let certs = vec![
            raw("rsa2048-leaf.der", 0),
            garbage(1),
            raw("expired.der", 2),
            raw("rsa2048-leaf.der", 3),
            raw("expired.der", 4),
        ];

        let err = run(certs, Vec::new(), &limits).unwrap_err();

        assert_eq!(err, LoadError::TooManyCerts { len: 3, max: 2 });
    }

    #[test]
    fn quando_mais_de_max_chain_len_certs_locais_deve_aceitar_ate_max_certs_per_source() {
        let limits = Limits::default();
        let count = limits.max_chain_len + 2;
        assert!(count <= limits.max_certs_per_source);
        let certs: Vec<_> = (0..count).map(|i| raw("rsa2048-leaf.der", i)).collect();

        let report = run(certs, Vec::new(), &limits).unwrap();

        assert_eq!(report.chain.len(), count);
    }

    #[test]
    fn quando_max_chain_len_e_pequeno_nao_deve_limitar_fonte_local() {
        let limits = Limits {
            max_chain_len: 1,
            ..Limits::default()
        };
        let certs = vec![raw("rsa2048-leaf.der", 0), raw("expired.der", 1)];

        let report = run(certs, Vec::new(), &limits).unwrap();

        assert_eq!(report.chain.len(), 2);
    }

    #[test]
    fn quando_certs_no_limite_exato_de_max_certs_per_source_deve_aceitar() {
        let limits = Limits {
            max_certs_per_source: 3,
            ..Limits::default()
        };
        let certs: Vec<_> = (0..3).map(|i| raw("rsa2048-leaf.der", i)).collect();

        let report = run(certs, Vec::new(), &limits).unwrap();

        assert_eq!(report.chain.len(), 3);
    }

    #[test]
    fn quando_loader_truncou_em_max_certs_per_source_deve_manter_a_nota_de_truncamento() {
        let limits = Limits {
            max_certs_per_source: 2,
            ..Limits::default()
        };
        let note = LoadNote::TruncatedAtCertLimit { limit: 2 };
        let certs = vec![raw("rsa2048-leaf.der", 0), raw("expired.der", 1)];

        let report = run(certs, vec![note.clone()], &limits).unwrap();

        assert_eq!(report.chain.len(), 2);
        assert_eq!(report.notes, vec![note]);
    }

    #[test]
    fn quando_diagnosticos_do_loader_e_parse_excedem_teto_em_sucesso_deve_truncar_combinado() {
        let limits = Limits {
            max_scan_diagnostics: 1,
            ..Limits::default()
        };
        let loader_rejection = LoadNote::Rejected {
            offset: 4,
            reason: RejectReason::InvalidBase64,
        };
        let metadata = LoadNote::PrivateKeyBlocksIgnored { count: 2 };

        let report = run(
            vec![garbage(0), raw("rsa2048-leaf.der", 1), garbage(2)],
            vec![loader_rejection.clone(), metadata.clone()],
            &limits,
        )
        .unwrap();

        assert_eq!(
            report.notes,
            vec![
                loader_rejection,
                metadata,
                LoadNote::DiagnosticsTruncated { limit: 1 },
            ]
        );
    }

    #[test]
    fn quando_diagnosticos_excedem_teto_sem_certificados_deve_truncar_combinado() {
        let limits = Limits {
            max_scan_diagnostics: 2,
            ..Limits::default()
        };
        let rejection = LoadNote::Rejected {
            offset: 4,
            reason: RejectReason::InvalidBase64,
        };
        let err = run(
            vec![garbage(0), garbage(1)],
            vec![rejection.clone()],
            &limits,
        )
        .unwrap_err();

        assert_eq!(
            err,
            LoadError::NoCertificatesFound {
                notes: vec![
                    rejection,
                    LoadNote::Unparsable { offset: None },
                    LoadNote::DiagnosticsTruncated { limit: 2 },
                ]
            }
        );
    }

    #[test]
    fn quando_orcamento_de_diagnosticos_e_zero_deve_preservar_metadados_e_marcar_truncamento() {
        let limits = Limits {
            max_scan_diagnostics: 0,
            ..Limits::default()
        };
        let metadata = LoadNote::PrivateKeyBlocksIgnored { count: 1 };
        let report = run(
            vec![garbage(0), raw("rsa2048-leaf.der", 1)],
            vec![metadata.clone()],
            &limits,
        )
        .unwrap();

        assert_eq!(
            report.notes,
            vec![metadata, LoadNote::DiagnosticsTruncated { limit: 0 }]
        );
    }

    #[test]
    fn quando_loader_ja_truncou_diagnosticos_deve_manter_um_so_marcador() {
        let limits = Limits {
            max_scan_diagnostics: 1,
            ..Limits::default()
        };
        let marker = LoadNote::DiagnosticsTruncated { limit: 1 };
        let report = run(
            vec![garbage(0), raw("rsa2048-leaf.der", 1)],
            vec![marker.clone(), marker.clone()],
            &limits,
        )
        .unwrap();

        assert_eq!(
            report.notes,
            vec![marker, LoadNote::Unparsable { offset: None }]
        );
    }

    #[test]
    fn quando_loader_retorna_vazio_deve_dar_no_certificates_found() {
        let err = run(Vec::new(), Vec::new(), &Limits::default()).unwrap_err();
        assert_eq!(err, LoadError::NoCertificatesFound { notes: Vec::new() });
    }

    #[test]
    fn quando_loader_falha_deve_propagar_o_erro() {
        let loader = FakeSourceLoader(Err(LoadError::TooLarge { limit: 5 }));
        let src = LocalSource::Stdin;
        let err = inspect_local(&loader, &src, Target::Stdin, &Limits::default()).unwrap_err();
        assert_eq!(err, LoadError::TooLarge { limit: 5 });
    }

    #[test]
    fn quando_bloco_de_chave_privada_nao_parseia_deve_sobrar_so_a_nota() {
        let key = garbage(1);
        let needles = ["222, 173, 190, 239", "DEAD", "dead", "de ad", "3, 1, 2"];
        let certs = vec![raw("rsa2048-leaf.der", 0), key];
        let report = run(certs, Vec::new(), &Limits::default()).unwrap();
        assert_eq!(report.notes, vec![LoadNote::Unparsable { offset: None }]);
        let dumped = format!("{report:?} {:?}", report.notes);
        for n in needles {
            assert!(!dumped.contains(n), "leaked {n}");
        }
        let err = run(vec![garbage(0)], Vec::new(), &Limits::default()).unwrap_err();
        let dumped = format!("{err:?} {err}");
        for n in needles {
            assert!(!dumped.contains(n), "leaked {n}");
        }
    }

    #[test]
    fn quando_loaded_certs_vai_para_debug_nao_deve_despejar_bytes() {
        let loaded = crate::ports::LoadedCerts {
            certs: vec![garbage(0)],
            notes: Vec::new(),
        };
        let dumped = format!("{loaded:?} {:?}", loaded.certs);
        assert!(dumped.contains("der_len: 12"));
        assert!(!dumped.contains("222, 173, 190, 239"));
        assert!(!dumped.contains("der: ["));
    }
}
