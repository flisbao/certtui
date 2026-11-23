//! Findings: what the lints report about a certificate chain.

use serde::Serialize;

/// How serious a finding is. Ordered `Info < Warning < Error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational.
    Info,
    /// Worth fixing.
    Warning,
    /// A real problem.
    Error,
}

/// The area a finding belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    /// Trust and validity.
    Trust,
    /// How the chain is presented by the server.
    Presentation,
    /// Certificate quality and hygiene.
    Quality,
    /// Revocation status.
    Revocation,
}

/// Stable identifier of a finding (spec section 7); serialized in
/// `SCREAMING_SNAKE_CASE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingCode {
    /// Chain validation failed against the chosen anchors.
    TrustUntrusted,
    /// The target name does not match the SANs.
    HostnameMismatch,
    /// A certificate is past its `not_after`.
    Expired,
    /// A certificate is before its `not_before`.
    NotYetValid,
    /// Expires within the critical threshold.
    ExpiresSoonCritical,
    /// Expires within the warning threshold.
    ExpiresSoon,
    /// An issuer is neither in the chain nor in the anchors.
    ChainIncomplete,
    /// The chain is not sent leaf to root.
    ChainOrderWrong,
    /// The same fingerprint appears more than once.
    ChainDuplicateCert,
    /// The server sent the self-signed root.
    ChainRootSent,
    /// A certificate does not belong to the path.
    ChainExtraCert,
    /// The leaf is self-signed.
    SelfSignedLeaf,
    /// MD5 or SHA-1 signature on a non-anchor.
    WeakSignature,
    /// RSA below 2048 bits or EC below 256 bits.
    WeakKey,
    /// The leaf has no SAN.
    MissingSan,
    /// EKU present without `serverAuth` on a network leaf.
    LeafMissingServerAuth,
    /// An intermediate without `CA:true`, or a violated `pathLen`.
    BasicConstraintsViolation,
    /// Public leaf valid for more than 398 days.
    ValidityTooLong,
    /// OCSP or CRL reports the certificate revoked.
    Revoked,
    /// Revocation status could not be determined.
    RevocationUnknown,
    /// The stapled OCSP response has an invalid signature or dates.
    OcspStapleInvalid,
    /// The server did not staple an OCSP response.
    OcspStapleMissing,
    /// A publicly trusted leaf carries no embedded SCT.
    NoEmbeddedSct,
    /// An intermediate was fetched through AIA.
    AiaFetched,
    /// A JKS keystore was read without a password.
    KeystoreIntegrityUnverified,
}

impl FindingCode {
    /// The stable `SCREAMING_SNAKE_CASE` identifier, identical to the serde
    /// form. The `match` is exhaustive: adding a variant fails to compile
    /// until it is listed here.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            FindingCode::TrustUntrusted => "TRUST_UNTRUSTED",
            FindingCode::HostnameMismatch => "HOSTNAME_MISMATCH",
            FindingCode::Expired => "EXPIRED",
            FindingCode::NotYetValid => "NOT_YET_VALID",
            FindingCode::ExpiresSoonCritical => "EXPIRES_SOON_CRITICAL",
            FindingCode::ExpiresSoon => "EXPIRES_SOON",
            FindingCode::ChainIncomplete => "CHAIN_INCOMPLETE",
            FindingCode::ChainOrderWrong => "CHAIN_ORDER_WRONG",
            FindingCode::ChainDuplicateCert => "CHAIN_DUPLICATE_CERT",
            FindingCode::ChainRootSent => "CHAIN_ROOT_SENT",
            FindingCode::ChainExtraCert => "CHAIN_EXTRA_CERT",
            FindingCode::SelfSignedLeaf => "SELF_SIGNED_LEAF",
            FindingCode::WeakSignature => "WEAK_SIGNATURE",
            FindingCode::WeakKey => "WEAK_KEY",
            FindingCode::MissingSan => "MISSING_SAN",
            FindingCode::LeafMissingServerAuth => "LEAF_MISSING_SERVER_AUTH",
            FindingCode::BasicConstraintsViolation => "BASIC_CONSTRAINTS_VIOLATION",
            FindingCode::ValidityTooLong => "VALIDITY_TOO_LONG",
            FindingCode::Revoked => "REVOKED",
            FindingCode::RevocationUnknown => "REVOCATION_UNKNOWN",
            FindingCode::OcspStapleInvalid => "OCSP_STAPLE_INVALID",
            FindingCode::OcspStapleMissing => "OCSP_STAPLE_MISSING",
            FindingCode::NoEmbeddedSct => "NO_EMBEDDED_SCT",
            FindingCode::AiaFetched => "AIA_FETCHED",
            FindingCode::KeystoreIntegrityUnverified => "KEYSTORE_INTEGRITY_UNVERIFIED",
        }
    }

    /// Every code, in the order of the spec section 7 table.
    pub const ALL: [FindingCode; 25] = [
        FindingCode::TrustUntrusted,
        FindingCode::HostnameMismatch,
        FindingCode::Expired,
        FindingCode::NotYetValid,
        FindingCode::ExpiresSoonCritical,
        FindingCode::ExpiresSoon,
        FindingCode::ChainIncomplete,
        FindingCode::ChainOrderWrong,
        FindingCode::ChainDuplicateCert,
        FindingCode::ChainRootSent,
        FindingCode::ChainExtraCert,
        FindingCode::SelfSignedLeaf,
        FindingCode::WeakSignature,
        FindingCode::WeakKey,
        FindingCode::MissingSan,
        FindingCode::LeafMissingServerAuth,
        FindingCode::BasicConstraintsViolation,
        FindingCode::ValidityTooLong,
        FindingCode::Revoked,
        FindingCode::RevocationUnknown,
        FindingCode::OcspStapleInvalid,
        FindingCode::OcspStapleMissing,
        FindingCode::NoEmbeddedSct,
        FindingCode::AiaFetched,
        FindingCode::KeystoreIntegrityUnverified,
    ];
}

/// One result reported by a lint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Stable identifier of the rule.
    pub code: FindingCode,
    /// How serious it is.
    pub severity: Severity,
    /// The area it belongs to.
    pub category: FindingCategory,
    /// Index of the affected certificate in the chain, if any.
    pub cert_index: Option<usize>,
    /// English description, without sensitive data.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_severity_comparada_deve_ordenar_info_warning_error() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        let mut v = vec![Severity::Error, Severity::Info, Severity::Warning];
        v.sort();
        assert_eq!(v, [Severity::Info, Severity::Warning, Severity::Error]);
    }

    #[test]
    fn quando_finding_code_serializa_deve_ser_screaming_snake() {
        let table = [
            (FindingCode::TrustUntrusted, "TRUST_UNTRUSTED"),
            (FindingCode::HostnameMismatch, "HOSTNAME_MISMATCH"),
            (FindingCode::Expired, "EXPIRED"),
            (FindingCode::NotYetValid, "NOT_YET_VALID"),
            (FindingCode::ExpiresSoonCritical, "EXPIRES_SOON_CRITICAL"),
            (FindingCode::ExpiresSoon, "EXPIRES_SOON"),
            (FindingCode::ChainIncomplete, "CHAIN_INCOMPLETE"),
            (FindingCode::ChainOrderWrong, "CHAIN_ORDER_WRONG"),
            (FindingCode::ChainDuplicateCert, "CHAIN_DUPLICATE_CERT"),
            (FindingCode::ChainRootSent, "CHAIN_ROOT_SENT"),
            (FindingCode::ChainExtraCert, "CHAIN_EXTRA_CERT"),
            (FindingCode::SelfSignedLeaf, "SELF_SIGNED_LEAF"),
            (FindingCode::WeakSignature, "WEAK_SIGNATURE"),
            (FindingCode::WeakKey, "WEAK_KEY"),
            (FindingCode::MissingSan, "MISSING_SAN"),
            (
                FindingCode::LeafMissingServerAuth,
                "LEAF_MISSING_SERVER_AUTH",
            ),
            (
                FindingCode::BasicConstraintsViolation,
                "BASIC_CONSTRAINTS_VIOLATION",
            ),
            (FindingCode::ValidityTooLong, "VALIDITY_TOO_LONG"),
            (FindingCode::Revoked, "REVOKED"),
            (FindingCode::RevocationUnknown, "REVOCATION_UNKNOWN"),
            (FindingCode::OcspStapleInvalid, "OCSP_STAPLE_INVALID"),
            (FindingCode::OcspStapleMissing, "OCSP_STAPLE_MISSING"),
            (FindingCode::NoEmbeddedSct, "NO_EMBEDDED_SCT"),
            (FindingCode::AiaFetched, "AIA_FETCHED"),
            (
                FindingCode::KeystoreIntegrityUnverified,
                "KEYSTORE_INTEGRITY_UNVERIFIED",
            ),
        ];
        assert_eq!(table.len(), FindingCode::ALL.len());
        for (code, expected) in table {
            assert_eq!(code.as_str(), expected);
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{expected}\"")
            );
            assert!(
                FindingCode::ALL.contains(&code),
                "{expected} missing from ALL"
            );
        }
    }

    #[test]
    fn quando_severity_e_categoria_serializam_deve_ser_lowercase() {
        assert_eq!(
            serde_json::to_string(&Severity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&FindingCategory::Presentation).unwrap(),
            "\"presentation\""
        );
    }

    #[test]
    fn quando_finding_serializa_deve_usar_campos_estaveis() {
        let f = Finding {
            code: FindingCode::ExpiresSoon,
            severity: Severity::Warning,
            category: FindingCategory::Quality,
            cert_index: Some(0),
            message: "expires in 3 days".to_owned(),
        };
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"code":"EXPIRES_SOON","severity":"warning","category":"quality","cert_index":0,"message":"expires in 3 days"}"#
        );
    }
}
