//! Extension-derived types of a certificate summary (spec section 5.2).
//!
//! String payloads (DNS names, URLs, e-mail addresses) are raw certificate
//! text: pass them through `sanitize` before displaying them.

use std::net::IpAddr;

use super::fingerprint::join_hex;
use crate::time::Timestamp;

/// A Subject Alternative Name entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectAltName {
    /// `dNSName`.
    Dns(String),
    /// `iPAddress`.
    Ip(IpAddr),
    /// `rfc822Name`.
    Email(String),
    /// `uniformResourceIdentifier`.
    Uri(String),
    /// Any other general-name type (or a malformed entry).
    Other {
        /// Which kind of general name it was, e.g. `"directoryName"`.
        kind: String,
    },
}

/// The Basic Constraints extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicConstraints {
    /// Whether the subject is a CA.
    pub ca: bool,
    /// Maximum number of intermediate CAs below this one, when constrained.
    pub path_len: Option<u32>,
}

/// The Key Usage extension: one flag per bit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
// Justificativa: one bool per RFC 5280 KeyUsage bit is the clearest model.
pub struct KeyUsage {
    /// `digitalSignature`.
    pub digital_signature: bool,
    /// `nonRepudiation` (a.k.a. `contentCommitment`).
    pub non_repudiation: bool,
    /// `keyEncipherment`.
    pub key_encipherment: bool,
    /// `dataEncipherment`.
    pub data_encipherment: bool,
    /// `keyAgreement`.
    pub key_agreement: bool,
    /// `keyCertSign`.
    pub key_cert_sign: bool,
    /// `cRLSign`.
    pub crl_sign: bool,
    /// `encipherOnly`.
    pub encipher_only: bool,
    /// `decipherOnly`.
    pub decipher_only: bool,
}

/// An Extended Key Usage purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedKeyUsage {
    /// `serverAuth`.
    ServerAuth,
    /// `clientAuth`.
    ClientAuth,
    /// `codeSigning`.
    CodeSigning,
    /// `emailProtection`.
    EmailProtection,
    /// `timeStamping`.
    TimeStamping,
    /// `OCSPSigning`.
    OcspSigning,
    /// `anyExtendedKeyUsage`.
    Any,
    /// Any other purpose, as a dotted OID.
    Other(String),
}

/// A subject/authority key identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(pub Vec<u8>);

impl KeyId {
    /// Upper-case hex without separators (same style as the serial number).
    #[must_use]
    pub fn to_hex(&self) -> String {
        join_hex(&self.0, "", true)
    }
}

/// The Authority Information Access extension.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityInfoAccess {
    /// OCSP responder URLs.
    pub ocsp: Vec<String>,
    /// "CA Issuers" URLs.
    pub ca_issuers: Vec<String>,
}

/// A Signed Certificate Timestamp embedded in the certificate (RFC 6962).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctEntry {
    /// SCT version as a human number: `1` for the RFC 6962 "v1" (wire
    /// value 0), mirroring `CertificateSummary::version`.
    pub version: u8,
    /// Log identifier (SHA-256 of the log's public key).
    pub log_id: [u8; 32],
    /// When the log issued the SCT (millisecond precision is dropped).
    pub timestamp: Timestamp,
}

/// A one-line description of any extension present in the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionSummary {
    /// Dotted OID.
    pub oid: String,
    /// Whether the extension is marked critical.
    pub critical: bool,
    /// Human-readable name; the dotted OID when unknown.
    pub name: String,
}

/// Known extension OIDs and their display names.
const EXTENSION_NAMES: &[(&str, &str)] = &[
    ("2.5.29.14", "Subject Key Identifier"),
    ("2.5.29.15", "Key Usage"),
    ("2.5.29.17", "Subject Alternative Name"),
    ("2.5.29.18", "Issuer Alternative Name"),
    ("2.5.29.19", "Basic Constraints"),
    ("2.5.29.30", "Name Constraints"),
    ("2.5.29.31", "CRL Distribution Points"),
    ("2.5.29.32", "Certificate Policies"),
    ("2.5.29.33", "Policy Mappings"),
    ("2.5.29.35", "Authority Key Identifier"),
    ("2.5.29.36", "Policy Constraints"),
    ("2.5.29.37", "Extended Key Usage"),
    ("2.5.29.46", "Freshest CRL"),
    ("2.5.29.54", "Inhibit Any Policy"),
    ("1.3.6.1.5.5.7.1.1", "Authority Information Access"),
    ("1.3.6.1.5.5.7.1.11", "Subject Information Access"),
    ("1.3.6.1.5.5.7.1.24", "TLS Feature"),
    ("1.3.6.1.4.1.11129.2.4.2", "Signed Certificate Timestamps"),
    ("1.3.6.1.4.1.11129.2.4.3", "CT Precertificate Poison"),
    ("2.16.840.1.113730.1.1", "Netscape Certificate Type"),
    ("2.16.840.1.113730.1.13", "Netscape Comment"),
];

/// Display name of an extension: the table entry for known OIDs, else the
/// dotted OID itself.
#[must_use]
pub fn extension_name(oid: &str) -> String {
    EXTENSION_NAMES
        .iter()
        .find(|(known, _)| *known == oid)
        .map_or_else(|| oid.to_owned(), |(_, name)| (*name).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_oid_conhecido_deve_dar_nome_legivel() {
        assert_eq!(extension_name("2.5.29.17"), "Subject Alternative Name");
        assert_eq!(
            extension_name("1.3.6.1.4.1.11129.2.4.2"),
            "Signed Certificate Timestamps"
        );
    }

    #[test]
    fn quando_oid_desconhecido_deve_dar_o_proprio_oid() {
        assert_eq!(
            extension_name("1.3.6.1.4.1.44363.44"),
            "1.3.6.1.4.1.44363.44"
        );
    }

    #[test]
    fn quando_key_id_deve_dar_hex_maiusculo_sem_separador() {
        assert_eq!(KeyId(vec![0x0A, 0xFF, 0x00]).to_hex(), "0AFF00");
        assert_eq!(KeyId(Vec::new()).to_hex(), "");
    }
}
