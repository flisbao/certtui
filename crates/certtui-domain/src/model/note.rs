//! Diagnostics produced while reading and extracting certificates.
//!
//! None of these types carries file content: only offsets, counts and
//! limits, so they are safe to print and serialize.

use serde::Serialize;

/// Why a candidate certificate block was rejected. Never carries content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    /// A PEM `BEGIN` line without a matching `END`.
    UnterminatedPem,
    /// The `BEGIN` and `END` labels differ.
    LabelMismatch,
    /// The PEM body is not valid Base64.
    InvalidBase64,
    /// The decoded bytes are not a DER `SEQUENCE`.
    NotDerSequence,
    /// The DER length header disagrees with the actual size.
    LengthMismatch,
    /// The block exceeds the size limit.
    TooLarge,
    /// The PEM label is not a certificate label.
    UnsupportedLabel,
    /// The DER nests deeper than the allowed depth.
    NestingTooDeep,
}

/// A diagnostic about reading or extracting certificates from one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LoadNote {
    /// The peer sent a rejection alert after requesting a client certificate.
    HandshakeFailedAfterClientCertRequest {
        /// IP address of the connected peer.
        peer_ip: std::net::IpAddr,
    },
    /// A candidate block at `offset` was rejected.
    Rejected {
        /// Byte offset of the block in the input.
        offset: usize,
        /// Why it was rejected.
        reason: RejectReason,
    },
    /// Private key blocks were found and skipped without being read.
    PrivateKeyBlocksIgnored {
        /// Number of blocks skipped.
        count: usize,
    },
    /// The input could not be parsed as any supported format.
    Unparsable {
        /// Offset of the failure, when known.
        offset: Option<usize>,
    },
    /// Extraction stopped at the per-source certificate limit. `limit` is the
    /// configured cap, not necessarily the number of certificates kept: the
    /// scanner's internal bounds (twice the cap for what detectors collect,
    /// the cap again for structural failures) can also trigger this note.
    TruncatedAtCertLimit {
        /// The limit that was hit.
        limit: usize,
    },
    /// Some scan diagnostics were dropped at the diagnostics limit.
    DiagnosticsTruncated {
        /// The limit that was hit.
        limit: usize,
    },
    /// A directory scan stopped at the entry limit.
    DirectoryTruncated {
        /// The limit that was hit.
        limit: usize,
    },
    /// A file or directory could not be read (open, permission or I/O error).
    ///
    /// `path` is the sanitized path relative to the scanned directory, when
    /// the note originates from a directory source.
    Unreadable {
        /// Sanitized path of the entry, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// The input is in a format that is not supported yet (for example JKS or
    /// PKCS#12 keystores).
    UnsupportedFormat {
        /// Sanitized path of the entry, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// The input held no certificate candidate at all (empty, or only prose).
    NoCandidates {
        /// Sanitized path of the entry, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// The input is larger than the allowed byte limit.
    FileTooLarge {
        /// Sanitized path of the entry, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        /// The limit that was hit, in bytes.
        limit: usize,
    },
    /// The input is structurally invalid (for example a broken PKCS#7 envelope).
    MalformedInput {
        /// Sanitized path of the entry, when known.
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// A JKS keystore was read without a password, so its integrity check
    /// (a SHA-1 over the content keyed by the password) was skipped.
    KeystoreIntegrityUnverified,
}

impl LoadNote {
    /// Whether this is an individual diagnostic, which counts against the
    /// per-source diagnostic budget (as opposed to metadata and markers).
    #[must_use]
    pub fn is_individual_diagnostic(&self) -> bool {
        matches!(
            self,
            LoadNote::HandshakeFailedAfterClientCertRequest { .. }
                | LoadNote::Rejected { .. }
                | LoadNote::Unparsable { .. }
                | LoadNote::Unreadable { .. }
                | LoadNote::UnsupportedFormat { .. }
                | LoadNote::NoCandidates { .. }
                | LoadNote::FileTooLarge { .. }
                | LoadNote::MalformedInput { .. }
        )
    }

    /// Fills the `path` of a path-carrying note that has none yet; every
    /// other note is returned unchanged. `path` must already be sanitized.
    #[must_use]
    pub fn with_path_if_unset(self, path: &str) -> LoadNote {
        match self {
            LoadNote::Unreadable { path: None } => LoadNote::Unreadable {
                path: Some(path.to_owned()),
            },
            LoadNote::UnsupportedFormat { path: None } => LoadNote::UnsupportedFormat {
                path: Some(path.to_owned()),
            },
            LoadNote::NoCandidates { path: None } => LoadNote::NoCandidates {
                path: Some(path.to_owned()),
            },
            LoadNote::FileTooLarge { path: None, limit } => LoadNote::FileTooLarge {
                path: Some(path.to_owned()),
                limit,
            },
            LoadNote::MalformedInput { path: None } => LoadNote::MalformedInput {
                path: Some(path.to_owned()),
            },
            other => other,
        }
    }
}

/// Incrementally retains loader notes within a shared diagnostic budget.
///
/// Individual diagnostics (see [`LoadNote::is_individual_diagnostic`]) are
/// kept only until the configured limit. Non-diagnostic metadata is retained
/// in insertion order. Dropped diagnostics produce one marker when finalized.
#[derive(Debug)]
pub struct DiagnosticNoteCollector {
    notes: Vec<LoadNote>,
    limit: usize,
    diagnostic_count: usize,
    dropped: bool,
    has_marker: bool,
}

impl DiagnosticNoteCollector {
    /// Creates an empty collector with room for at most `limit` diagnostics.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            notes: Vec::new(),
            limit,
            diagnostic_count: 0,
            dropped: false,
            has_marker: false,
        }
    }

    /// Adds one note, discarding individual diagnostics after the budget.
    pub fn push(&mut self, note: LoadNote) {
        if note.is_individual_diagnostic() {
            if self.diagnostic_count < self.limit {
                self.diagnostic_count += 1;
                self.notes.push(note);
            } else {
                self.dropped = true;
            }
        } else if matches!(note, LoadNote::DiagnosticsTruncated { .. }) {
            if self.has_marker {
                self.dropped = true;
            } else {
                self.has_marker = true;
                self.dropped = true;
                self.notes.push(note);
            }
        } else {
            self.notes.push(note);
        }
    }

    /// Whether no notes have been retained so far.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Finalizes notes and appends one marker when diagnostics were dropped.
    #[must_use]
    pub fn finish(mut self) -> (Vec<LoadNote>, usize, bool) {
        if self.dropped && !self.has_marker {
            self.notes
                .push(LoadNote::DiagnosticsTruncated { limit: self.limit });
        }
        (
            self.notes,
            self.limit.saturating_sub(self.diagnostic_count),
            self.dropped,
        )
    }
}

/// Retains loader diagnostics within the shared per-source diagnostic budget.
///
/// Non-diagnostic metadata is always kept, and only one existing
/// [`LoadNote::DiagnosticsTruncated`] marker is retained. The returned tuple
/// contains the notes, remaining individual-diagnostic slots, and whether
/// any diagnostic or duplicate marker was dropped.
#[must_use]
pub fn retain_diagnostic_notes(notes: Vec<LoadNote>, max: usize) -> (Vec<LoadNote>, usize, bool) {
    let had_marker = notes
        .iter()
        .any(|note| matches!(note, LoadNote::DiagnosticsTruncated { .. }));
    let mut collector = DiagnosticNoteCollector::new(max);
    for note in notes {
        collector.push(note);
    }
    let (mut notes, remaining, dropped) = collector.finish();
    if dropped && !had_marker && matches!(notes.last(), Some(LoadNote::DiagnosticsTruncated { .. }))
    {
        notes.pop();
    }
    (notes, remaining, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_load_note_serializa_deve_marcar_o_tipo_sem_conteudo() {
        let n = LoadNote::Rejected {
            offset: 12,
            reason: RejectReason::InvalidBase64,
        };
        assert_eq!(
            serde_json::to_string(&n).unwrap(),
            r#"{"kind":"rejected","offset":12,"reason":"invalid_base64"}"#
        );
    }

    #[test]
    fn quando_variantes_multi_palavra_serializam_deve_ser_snake_case() {
        assert_eq!(
            serde_json::to_string(&RejectReason::NestingTooDeep).unwrap(),
            "\"nesting_too_deep\""
        );
        assert_eq!(
            serde_json::to_string(&LoadNote::PrivateKeyBlocksIgnored { count: 2 }).unwrap(),
            r#"{"kind":"private_key_blocks_ignored","count":2}"#
        );
        assert_eq!(
            serde_json::to_string(&LoadNote::DiagnosticsTruncated { limit: 100 }).unwrap(),
            r#"{"kind":"diagnostics_truncated","limit":100}"#
        );
    }

    #[test]
    fn quando_notas_excedem_orcamento_deve_preservar_metadados_e_slots() {
        let metadata = LoadNote::PrivateKeyBlocksIgnored { count: 2 };
        let notes = vec![
            metadata.clone(),
            LoadNote::Rejected {
                offset: 1,
                reason: RejectReason::InvalidBase64,
            },
            LoadNote::Unparsable { offset: Some(2) },
        ];
        let (kept, remaining, dropped) = retain_diagnostic_notes(notes, 1);
        assert_eq!(
            kept,
            vec![
                metadata,
                LoadNote::Rejected {
                    offset: 1,
                    reason: RejectReason::InvalidBase64,
                },
            ]
        );
        assert_eq!(remaining, 0);
        assert!(dropped);
    }

    #[test]
    fn quando_coletor_atinge_orcamento_deve_limitar_memoria_e_marcar_no_final() {
        let mut collector = DiagnosticNoteCollector::new(1);
        collector.push(LoadNote::Rejected {
            offset: 1,
            reason: RejectReason::InvalidBase64,
        });
        collector.push(LoadNote::Unparsable { offset: Some(2) });
        collector.push(LoadNote::PrivateKeyBlocksIgnored { count: 3 });
        let (notes, remaining, dropped) = collector.finish();
        assert_eq!(remaining, 0);
        assert!(dropped);
        assert_eq!(
            notes,
            vec![
                LoadNote::Rejected {
                    offset: 1,
                    reason: RejectReason::InvalidBase64,
                },
                LoadNote::PrivateKeyBlocksIgnored { count: 3 },
                LoadNote::DiagnosticsTruncated { limit: 1 },
            ]
        );
    }

    #[test]
    fn quando_notas_novas_serializam_deve_omitir_path_ausente_e_manter_o_tipo() {
        assert_eq!(
            serde_json::to_string(&LoadNote::Unreadable { path: None }).unwrap(),
            r#"{"kind":"unreadable"}"#
        );
        assert_eq!(
            serde_json::to_string(&LoadNote::Unreadable {
                path: Some("a/b.pem".to_owned())
            })
            .unwrap(),
            r#"{"kind":"unreadable","path":"a/b.pem"}"#
        );
        assert_eq!(
            serde_json::to_string(&LoadNote::UnsupportedFormat { path: None }).unwrap(),
            r#"{"kind":"unsupported_format"}"#
        );
        assert_eq!(
            serde_json::to_string(&LoadNote::NoCandidates { path: None }).unwrap(),
            r#"{"kind":"no_candidates"}"#
        );
        assert_eq!(
            serde_json::to_string(&LoadNote::FileTooLarge {
                path: Some("big.bin".to_owned()),
                limit: 9
            })
            .unwrap(),
            r#"{"kind":"file_too_large","path":"big.bin","limit":9}"#
        );
        assert_eq!(
            serde_json::to_string(&LoadNote::MalformedInput { path: None }).unwrap(),
            r#"{"kind":"malformed_input"}"#
        );
    }

    #[test]
    fn quando_notas_novas_excedem_orcamento_deve_contar_como_diagnostico() {
        let mut collector = DiagnosticNoteCollector::new(1);
        collector.push(LoadNote::Unreadable { path: None });
        collector.push(LoadNote::UnsupportedFormat { path: None });
        collector.push(LoadNote::NoCandidates { path: None });
        let (notes, remaining, dropped) = collector.finish();
        assert_eq!(remaining, 0);
        assert!(dropped);
        assert_eq!(
            notes,
            vec![
                LoadNote::Unreadable { path: None },
                LoadNote::DiagnosticsTruncated { limit: 1 },
            ]
        );
    }

    #[test]
    fn quando_nota_com_caminho_sem_valor_deve_receber_o_caminho_so_uma_vez() {
        let note = LoadNote::Unreadable { path: None }.with_path_if_unset("x.pem");
        assert_eq!(
            note,
            LoadNote::Unreadable {
                path: Some("x.pem".to_owned())
            }
        );
        assert_eq!(note.clone().with_path_if_unset("y.pem"), note);
        let other = LoadNote::Unparsable { offset: None };
        assert_eq!(other.clone().with_path_if_unset("x.pem"), other);
    }
}
