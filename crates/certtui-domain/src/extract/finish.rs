//! Final pass of a scan: structural check of unarmored candidates, ordering,
//! deduplication and caps, plus the conversion of the outcome into notes.

use std::collections::HashSet;

use crate::limits::Limits;
use crate::model::{Digest, Fingerprints, LoadNote, parse_der_cert};

use super::{Candidate, CandidateKind, Detections, RejectReason, ScanDiagnostic, ScanOutcome};

/// How many candidates the detectors may collect for a final cap of
/// `max_certs_per_source`: the cap itself plus an equal number of slots for
/// candidates that [`finish`] will drop (structural failures and duplicates).
pub(super) fn detection_cap(limits: &Limits) -> usize {
    limits
        .max_certs_per_source
        .saturating_add(limits.max_certs_per_source)
}

/// Turns what the detectors collected into the final [`ScanOutcome`].
///
/// 1. Candidates are sorted by offset (stable).
/// 2. Certificates that did not come from an armored PEM block (bare Base64,
///    hex, nested) must parse as an X.509 certificate with
///    [`parse_der_cert`]; the ones that do not are dropped, their bytes are
///    not kept, and a [`RejectReason::NotDerSequence`] diagnostic with only
///    their offset is recorded. This keeps unarmored private keys and CSRs
///    (which share the `SEQUENCE` header of a certificate) from leaving the
///    scanner as certificates. PEM-labelled certificates and PKCS#7 blobs are
///    not checked here.
/// 3. Duplicates (same SHA-256 of the DER) are removed, keeping the first.
/// 4. At most `limits.max_certs_per_source` candidates are kept; if a further
///    distinct one exists, `truncated` is set.
/// 5. Diagnostics are sorted by offset and cut at
///    `limits.max_scan_diagnostics`.
///
/// Parsing is bounded: each candidate is parsed at most once (cost linear in
/// its size, and candidates do not overlap), the pass stops as soon as the
/// cap is exceeded, and after `max_certs_per_source` structural failures it
/// stops parsing (setting `truncated`): later candidates that would need a
/// parse are dropped unparsed (a real bare Base64 / hex / nested certificate
/// after that many failures is lost), while PEM certificates and PKCS#7
/// candidates, which need no parse, are still kept. So a flood of garbage
/// cannot cause unbounded work.
pub(super) fn finish(raw: Detections, limits: &Limits) -> ScanOutcome {
    let Detections {
        candidates,
        mut diagnostics,
        private_key_blocks_ignored,
        mut truncated,
        mut diagnostics_truncated,
        pem_candidates,
        ..
    } = raw;
    let cap = limits.max_certs_per_source;
    let mut checked: Vec<(bool, Candidate)> = candidates
        .into_iter()
        .enumerate()
        .map(|(i, c)| {
            (
                i >= pem_candidates && c.kind == CandidateKind::Certificate,
                c,
            )
        })
        .collect();
    checked.sort_by_key(|(_, c)| c.offset);

    let mut kept: Vec<Candidate> = Vec::new();
    let mut seen: HashSet<Digest<32>> = HashSet::new();
    let mut failures = 0_usize;
    for (needs_check, candidate) in checked {
        if needs_check {
            if failures >= cap {
                // Failure bound reached: candidates that would need a parse
                // are dropped unparsed, the ones that need none (PEM
                // certificates, PKCS#7) are still processed below.
                truncated = true;
                continue;
            }
            if parse_der_cert(&candidate.der, limits).is_err() {
                failures += 1;
                diagnostics.push(ScanDiagnostic {
                    offset: candidate.offset,
                    reason: RejectReason::NotDerSequence,
                });
                continue;
            }
        }
        if !seen.insert(Fingerprints::compute(&candidate.der).sha256) {
            continue;
        }
        if kept.len() >= cap {
            truncated = true;
            break;
        }
        kept.push(candidate);
    }

    diagnostics.sort_by_key(|d| d.offset);
    if diagnostics.len() > limits.max_scan_diagnostics {
        diagnostics.truncate(limits.max_scan_diagnostics);
        diagnostics_truncated = true;
    }
    ScanOutcome {
        candidates: kept,
        diagnostics,
        private_key_blocks_ignored,
        truncated,
        diagnostics_truncated,
        cert_limit: cap,
        diagnostics_limit: limits.max_scan_diagnostics,
    }
}

impl From<&ScanOutcome> for Vec<LoadNote> {
    /// One [`LoadNote::Rejected`] per diagnostic, then the private key count
    /// (when positive), then the truncation notes. Carries no content.
    fn from(outcome: &ScanOutcome) -> Self {
        let mut notes: Vec<LoadNote> = outcome
            .diagnostics
            .iter()
            .map(|d| LoadNote::Rejected {
                offset: d.offset,
                reason: d.reason,
            })
            .collect();
        if outcome.private_key_blocks_ignored > 0 {
            notes.push(LoadNote::PrivateKeyBlocksIgnored {
                count: outcome.private_key_blocks_ignored,
            });
        }
        if outcome.truncated {
            notes.push(LoadNote::TruncatedAtCertLimit {
                limit: outcome.cert_limit,
            });
        }
        if outcome.diagnostics_truncated {
            notes.push(LoadNote::DiagnosticsTruncated {
                limit: outcome.diagnostics_limit,
            });
        }
        notes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Candidates the detectors would call armored PEM: never parsed.
    fn pem_candidate(offset: usize, byte: u8) -> Candidate {
        Candidate {
            offset,
            kind: CandidateKind::Certificate,
            der: vec![0x30, 0x03, byte, byte, byte],
        }
    }

    fn detections(limits: &Limits, candidates: Vec<Candidate>) -> Detections {
        let mut det = Detections::new(limits);
        det.pem_candidates = candidates.len();
        det.candidates = candidates;
        det
    }

    fn offsets(out: &ScanOutcome) -> Vec<usize> {
        out.candidates.iter().map(|c| c.offset).collect()
    }

    #[test]
    fn quando_candidatos_chegam_fora_de_ordem_deve_ordenar_por_offset_de_forma_estavel() {
        let limits = Limits::default();
        let mut c = vec![
            pem_candidate(30, 1),
            pem_candidate(10, 2),
            pem_candidate(10, 3),
            pem_candidate(20, 4),
        ];
        c[1].der.push(0xaa);
        let out = finish(detections(&limits, c), &limits);
        assert_eq!(offsets(&out), vec![10, 10, 20, 30]);
        // Equal offsets keep their detection order.
        assert_eq!(out.candidates[0].der.last(), Some(&0xaa));
    }

    #[test]
    fn quando_der_se_repete_deve_manter_so_a_primeira_ocorrencia_no_texto() {
        let limits = Limits::default();
        let c = vec![
            pem_candidate(50, 7),
            pem_candidate(10, 7),
            pem_candidate(30, 8),
        ];
        let out = finish(detections(&limits, c), &limits);
        assert_eq!(offsets(&out), vec![10, 30]);
        assert!(!out.truncated);
    }

    #[test]
    fn quando_passa_do_limite_deve_cortar_e_marcar_truncado_so_se_perdeu_distinto() {
        let limits = Limits {
            max_certs_per_source: 2,
            ..Limits::default()
        };
        let three = vec![
            pem_candidate(1, 1),
            pem_candidate(2, 2),
            pem_candidate(3, 3),
        ];
        let out = finish(detections(&limits, three), &limits);
        assert_eq!(offsets(&out), vec![1, 2]);
        assert!(out.truncated);
        assert_eq!(out.cert_limit, 2);
        // The third is a repeat of the first: nothing lost.
        let repeat = vec![
            pem_candidate(1, 1),
            pem_candidate(2, 2),
            pem_candidate(3, 1),
        ];
        let out = finish(detections(&limits, repeat), &limits);
        assert_eq!(offsets(&out), vec![1, 2]);
        assert!(!out.truncated);
    }

    #[test]
    fn quando_detector_ja_marcou_truncado_deve_preservar_a_marca() {
        let limits = Limits::default();
        let mut det = detections(&limits, vec![pem_candidate(1, 1)]);
        det.truncated = true;
        det.diagnostics_truncated = true;
        det.private_key_blocks_ignored = 2;
        let out = finish(det, &limits);
        assert!(out.truncated && out.diagnostics_truncated);
        assert_eq!(out.private_key_blocks_ignored, 2);
    }

    #[test]
    fn quando_candidato_nao_pem_nao_e_certificado_deve_cair_com_so_o_offset() {
        let limits = Limits::default();
        let mut det = Detections::new(&limits);
        det.pem_candidates = 1;
        det.candidates = vec![
            pem_candidate(5, 1),
            Candidate {
                offset: 9,
                kind: CandidateKind::Certificate,
                der: vec![0x30, 0x03, 2, 2, 2],
            },
        ];
        let out = finish(det, &limits);
        assert_eq!(offsets(&out), vec![5]);
        assert_eq!(
            out.diagnostics,
            vec![ScanDiagnostic {
                offset: 9,
                reason: RejectReason::NotDerSequence
            }]
        );
    }

    #[test]
    fn quando_candidato_nao_pem_e_pkcs7_nao_deve_ser_checado() {
        let limits = Limits::default();
        let mut det = Detections::new(&limits);
        det.candidates = vec![Candidate {
            offset: 0,
            kind: CandidateKind::Pkcs7,
            der: vec![0x30, 0x03, 2, 2, 2],
        }];
        let out = finish(det, &limits);
        assert_eq!(out.candidates.len(), 1);
        assert_eq!(out.diagnostics.len(), 0);
    }

    #[test]
    fn quando_diagnosticos_chegam_fora_de_ordem_deve_ordenar_e_cortar() {
        let limits = Limits {
            max_scan_diagnostics: 2,
            ..Limits::default()
        };
        let mut det = Detections::new(&limits);
        det.pem_candidates = 0;
        for at in [9, 3] {
            det.diagnostics.push(ScanDiagnostic {
                offset: at,
                reason: RejectReason::InvalidBase64,
            });
        }
        det.candidates = vec![Candidate {
            offset: 1,
            kind: CandidateKind::Certificate,
            der: vec![0x30, 0x03, 2, 2, 2],
        }];
        let out = finish(det, &limits);
        let at: Vec<usize> = out.diagnostics.iter().map(|d| d.offset).collect();
        assert_eq!(at, vec![1, 3]);
        assert!(out.diagnostics_truncated);
        assert_eq!(out.diagnostics_limit, 2);
    }

    #[test]
    fn quando_ha_falhas_demais_deve_parar_de_parsear_e_marcar_truncado() {
        let limits = Limits {
            max_certs_per_source: 3,
            ..Limits::default()
        };
        let mut det = Detections::new(&limits);
        det.candidates = (0..6)
            .map(|i| Candidate {
                offset: i,
                kind: CandidateKind::Certificate,
                der: vec![0x30, 0x03, 2, 2, 2],
            })
            .collect();
        let out = finish(det, &limits);
        assert_eq!(out.candidates.len(), 0);
        assert_eq!(out.diagnostics.len(), 3, "so as 3 falhas permitidas");
        assert!(out.truncated);
    }

    #[test]
    fn quando_outcome_tem_tudo_deve_virar_notas_na_ordem() {
        let out = ScanOutcome {
            candidates: vec![],
            diagnostics: vec![ScanDiagnostic {
                offset: 4,
                reason: RejectReason::UnterminatedPem,
            }],
            private_key_blocks_ignored: 2,
            truncated: true,
            diagnostics_truncated: true,
            cert_limit: 7,
            diagnostics_limit: 9,
        };
        assert_eq!(
            Vec::<LoadNote>::from(&out),
            vec![
                LoadNote::Rejected {
                    offset: 4,
                    reason: RejectReason::UnterminatedPem
                },
                LoadNote::PrivateKeyBlocksIgnored { count: 2 },
                LoadNote::TruncatedAtCertLimit { limit: 7 },
                LoadNote::DiagnosticsTruncated { limit: 9 },
            ]
        );
    }
}
