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
    /// Extraction stopped at the per-source certificate limit.
    TruncatedAtCertLimit {
        /// The limit that was hit.
        limit: usize,
    },
    /// A directory scan stopped at the entry limit.
    DirectoryTruncated {
        /// The limit that was hit.
        limit: usize,
    },
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
    }
}
