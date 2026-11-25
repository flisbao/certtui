//! Trust source types, anchors and resolution.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Source of trusted root certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TrustSource {
    /// System root store provided by the OS.
    System,
    /// Mozilla root CA store.
    Mozilla,
    /// Custom CA certificate files provided by the user.
    Custom,
}

/// A single trusted root anchor.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// DER-encoded Subject Name.
    pub subject_der: Vec<u8>,
    /// DER-encoded `SubjectPublicKeyInfo`.
    pub spki_der: Vec<u8>,
    /// Optional DER-encoded `NameConstraints` extension bytes.
    pub name_constraints_der: Option<Vec<u8>>,
    /// Which trust store provided this anchor.
    pub source: TrustSource,
    /// Human-readable label or subject name for display and findings.
    pub label: String,
}

impl std::fmt::Debug for TrustAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustAnchor")
            .field("subject_der_len", &self.subject_der.len())
            .field("spki_der_len", &self.spki_der.len())
            .field("has_name_constraints", &self.name_constraints_der.is_some())
            .field("source", &self.source)
            .field("label", &self.label)
            .finish()
    }
}

/// Collection of loaded trust anchors and non-fatal warnings encountered during loading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustAnchors {
    /// Loaded root anchors.
    pub entries: Vec<TrustAnchor>,
    /// Non-fatal warnings encountered while loading anchors.
    pub warnings: Vec<String>,
}

impl TrustAnchors {
    /// Returns true if no trust anchors are loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of loaded anchors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if at least one anchor originates from a public source (`System` or `Mozilla`).
    #[must_use]
    pub fn has_public_source(&self) -> bool {
        self.entries
            .iter()
            .any(|a| matches!(a.source, TrustSource::System | TrustSource::Mozilla))
    }
}

/// Errors encountered while loading trust anchors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// A custom CA file could not be read or decoded.
    #[error("failed to read custom CA file '{path}': {cause}")]
    CustomFile {
        /// Path to the custom CA file.
        path: PathBuf,
        /// Reason for the failure.
        cause: String,
    },
}

/// Resolves the effective trust sources based on CLI flags.
///
/// Rules:
/// - If `ca_only` is true, returns exactly `[TrustSource::Custom]`.
/// - If `trust` is empty, defaults to `[TrustSource::System]`.
/// - If `has_ca_file` is true and `Custom` is not yet present, `TrustSource::Custom` is appended.
/// - Order is stable and duplicates are removed.
#[must_use]
pub fn resolve_sources(
    trust: &[TrustSource],
    has_ca_file: bool,
    ca_only: bool,
) -> Vec<TrustSource> {
    if ca_only {
        return vec![TrustSource::Custom];
    }
    let mut resolved = Vec::new();
    if trust.is_empty() {
        resolved.push(TrustSource::System);
    } else {
        for &s in trust {
            if !resolved.contains(&s) {
                resolved.push(s);
            }
        }
    }
    if has_ca_file && !resolved.contains(&TrustSource::Custom) {
        resolved.push(TrustSource::Custom);
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_ca_only_deve_resolver_so_custom() {
        let sources = resolve_sources(&[TrustSource::System, TrustSource::Mozilla], true, true);
        assert_eq!(sources, vec![TrustSource::Custom]);
    }

    #[test]
    fn quando_ca_file_sem_trust_deve_resolver_system_mais_custom() {
        let sources = resolve_sources(&[], true, false);
        assert_eq!(sources, vec![TrustSource::System, TrustSource::Custom]);
    }

    #[test]
    fn quando_trust_repetido_deve_deduplicar() {
        let sources = resolve_sources(
            &[
                TrustSource::Mozilla,
                TrustSource::System,
                TrustSource::Mozilla,
            ],
            false,
            false,
        );
        assert_eq!(sources, vec![TrustSource::Mozilla, TrustSource::System]);
    }

    #[test]
    fn quando_anchors_so_custom_deve_nao_ter_fonte_publica() {
        let anchors = TrustAnchors {
            entries: vec![TrustAnchor {
                subject_der: vec![1, 2, 3],
                spki_der: vec![4, 5, 6],
                name_constraints_der: None,
                source: TrustSource::Custom,
                label: "Custom CA".to_owned(),
            }],
            warnings: vec![],
        };
        assert!(!anchors.has_public_source());

        let public_anchors = TrustAnchors {
            entries: vec![TrustAnchor {
                subject_der: vec![1, 2, 3],
                spki_der: vec![4, 5, 6],
                name_constraints_der: None,
                source: TrustSource::Mozilla,
                label: "Mozilla CA".to_owned(),
            }],
            warnings: vec![],
        };
        assert!(public_anchors.has_public_source());
    }
}
