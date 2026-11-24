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

/// Whether `host` is covered by `sans`: a DNS name (wildcard only as the whole
/// first label, standing for exactly one label), or, for an IP literal, an IP
/// entry. There is no fallback to the subject common name.
#[must_use]
pub fn san_matches(sans: &[SubjectAltName], host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return sans
            .iter()
            .any(|san| matches!(san, SubjectAltName::Ip(candidate) if *candidate == ip));
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    sans.iter().any(|san| match san {
        SubjectAltName::Dns(pattern) => {
            dns_matches(pattern.strip_suffix('.').unwrap_or(pattern), host)
        }
        _ => false,
    })
}

/// DNS comparison: case-insensitive; a `*.` prefix stands for exactly one
/// non-empty label, and the rest of the pattern must itself be a name with at
/// least two labels and no further `*`.
fn dns_matches(pattern: &str, host: &str) -> bool {
    if pattern.contains('*') {
        let Some(suffix) = pattern.strip_prefix("*.") else {
            return false;
        };
        if suffix.contains('*') || !suffix.contains('.') {
            return false;
        }
        let Some((label, rest)) = host.split_once('.') else {
            return false;
        };
        return !label.is_empty() && rest.eq_ignore_ascii_case(suffix);
    }
    pattern.eq_ignore_ascii_case(host)
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
    /// SCT version as a human-readable number: the wire value plus one, so
    /// `1` for the RFC 6962 "v1" (wire value 0, the only version RFC 6962
    /// defines), mirroring `CertificateSummary::version`.
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
    /// `true` when the extension's content could not be decoded (malformed
    /// for its type). The certificate is still accepted and the matching
    /// summary field stays empty, so UIs should flag the row rather than
    /// show the extension as absent or normal.
    pub decode_error: bool,
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

#[cfg(test)]
mod san_tests {
    use super::*;

    fn dns(name: &str) -> Vec<SubjectAltName> {
        vec![SubjectAltName::Dns(name.to_owned())]
    }

    #[test]
    fn quando_wildcard_cobre_um_rotulo_deve_casar_so_esse() {
        let sans = dns("*.example.com");
        assert!(san_matches(&sans, "a.example.com"));
        assert!(!san_matches(&sans, "example.com"));
        assert!(!san_matches(&sans, "a.b.example.com"));
    }

    #[test]
    fn quando_wildcard_fora_do_primeiro_rotulo_deve_nao_casar() {
        assert!(!san_matches(&dns("a.*.com"), "a.b.com"));
        assert!(!san_matches(&dns("a.*.com"), "a.*.com"));
        assert!(!san_matches(&dns("f*.example.com"), "foo.example.com"));
        assert!(!san_matches(&dns("*.*.example.com"), "a.b.example.com"));
    }

    #[test]
    fn quando_wildcard_cobre_so_um_sufixo_de_um_rotulo_deve_nao_casar() {
        assert!(!san_matches(&dns("*.com"), "example.com"));
    }

    #[test]
    fn quando_caixa_difere_deve_casar() {
        assert!(san_matches(&dns("EXAMPLE.com"), "example.com"));
        assert!(san_matches(&dns("example.com"), "EXAMPLE.COM"));
        assert!(san_matches(&dns("*.Example.COM"), "A.example.com"));
    }

    #[test]
    fn quando_ponto_final_deve_ignorar() {
        assert!(san_matches(&dns("example.com"), "example.com."));
        assert!(san_matches(&dns("example.com."), "example.com"));
    }

    #[test]
    fn quando_nome_exato_diferente_deve_nao_casar() {
        assert!(!san_matches(&dns("example.com"), "example.org"));
        assert!(!san_matches(&dns("example.com"), "www.example.com"));
    }

    #[test]
    fn quando_host_e_ip_deve_casar_so_com_san_ip() {
        let ip = vec![SubjectAltName::Ip("192.0.2.1".parse().unwrap())];
        assert!(san_matches(&ip, "192.0.2.1"));
        assert!(!san_matches(&ip, "192.0.2.2"));
        assert!(!san_matches(&dns("192.0.2.1"), "192.0.2.1"));
        let v6 = vec![SubjectAltName::Ip("2001:db8::1".parse().unwrap())];
        assert!(san_matches(&v6, "2001:db8::1"));
        assert!(san_matches(&v6, "[2001:db8::1]"));
    }

    #[test]
    fn quando_san_ip_e_host_dns_deve_nao_casar() {
        let ip = vec![SubjectAltName::Ip("192.0.2.1".parse().unwrap())];
        assert!(!san_matches(&ip, "example.com"));
    }

    #[test]
    fn quando_so_tem_outros_tipos_de_san_deve_nao_casar() {
        let sans = vec![
            SubjectAltName::Email("example.com".to_owned()),
            SubjectAltName::Uri("example.com".to_owned()),
        ];
        assert!(!san_matches(&sans, "example.com"));
        assert!(!san_matches(&[], "example.com"));
    }
}
