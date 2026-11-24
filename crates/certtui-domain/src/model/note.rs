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
}

/// Retains loader diagnostics within the shared per-source diagnostic budget.
///
/// Non-diagnostic metadata is always kept, and only one existing
/// [`LoadNote::DiagnosticsTruncated`] marker is retained. The returned tuple
/// contains the notes, remaining individual-diagnostic slots, and whether
/// any diagnostic or duplicate marker was dropped.
#[must_use]
pub fn retain_diagnostic_notes(notes: Vec<LoadNote>, max: usize) -> (Vec<LoadNote>, usize, bool) {
    let mut kept = Vec::new();
    let mut count = 0;
    let mut dropped = false;
    let mut has_marker = false;
    for note in notes {
        match note {
            LoadNote::Rejected { .. } | LoadNote::Unparsable { .. } if count < max => {
                count += 1;
                kept.push(note);
            }
            LoadNote::DiagnosticsTruncated { .. } if !has_marker => {
                has_marker = true;
                dropped = true;
                kept.push(note);
            }
            LoadNote::Rejected { .. }
            | LoadNote::Unparsable { .. }
            | LoadNote::DiagnosticsTruncated { .. } => dropped = true,
            _ => kept.push(note),
        }
    }
    (kept, max.saturating_sub(count), dropped)
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
}
