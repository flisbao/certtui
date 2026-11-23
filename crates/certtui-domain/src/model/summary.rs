//! [`CertificateSummary`]: the parsed, display-oriented view of a
//! certificate (spec section 5.2).
//!
//! The extension-related fields exist from the start but stay empty until
//! the extension parser fills them.

use std::net::IpAddr;

use super::key::{PublicKeyInfo, SignatureAlgorithm};
use super::name::{DistinguishedName, SerialNumber};
use crate::time::Timestamp;

/// A Subject Alternative Name entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectAltName {
    /// `dNSName`.
    Dns(String),
    /// `rfc822Name`.
    Email(String),
    /// `uniformResourceIdentifier`.
    Uri(String),
    /// `iPAddress`.
    Ip(IpAddr),
    /// Any other general-name type, rendered as text.
    Other(String),
}

/// The Basic Constraints extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicConstraints {
    /// Whether the subject is a CA.
    pub ca: bool,
    /// Maximum number of intermediate CAs below this one, when constrained.
    pub path_len: Option<u32>,
}

/// One bit of the Key Usage extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUsageFlag {
    /// `digitalSignature`.
    DigitalSignature,
    /// `nonRepudiation` (a.k.a. `contentCommitment`).
    NonRepudiation,
    /// `keyEncipherment`.
    KeyEncipherment,
    /// `dataEncipherment`.
    DataEncipherment,
    /// `keyAgreement`.
    KeyAgreement,
    /// `keyCertSign`.
    KeyCertSign,
    /// `cRLSign`.
    CrlSign,
    /// `encipherOnly`.
    EncipherOnly,
    /// `decipherOnly`.
    DecipherOnly,
}

/// The Key Usage extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUsage {
    /// The bits that are set.
    pub flags: Vec<KeyUsageFlag>,
}

/// An Extended Key Usage purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendedKeyUsage {
    /// `anyExtendedKeyUsage`.
    Any,
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
    /// Any other purpose, as a dotted OID.
    Other(String),
}

/// A subject/authority key identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyId(pub Vec<u8>);

/// The Authority Information Access extension.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityInfoAccess {
    /// OCSP responder URLs.
    pub ocsp_urls: Vec<String>,
    /// "CA Issuers" URLs.
    pub ca_issuers_urls: Vec<String>,
}

/// A Signed Certificate Timestamp embedded in the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctEntry {
    /// Log identifier (SHA-256 of the log's public key).
    pub log_id: Vec<u8>,
    /// When the log issued the SCT.
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

/// The parsed fields of one certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSummary {
    /// X.509 version as a human number (`3` for v3).
    pub version: u8,
    /// Serial number.
    pub serial: SerialNumber,
    /// Subject name.
    pub subject: DistinguishedName,
    /// Issuer name.
    pub issuer: DistinguishedName,
    /// Start of validity (UTC).
    pub not_before: Timestamp,
    /// End of validity (UTC).
    pub not_after: Timestamp,
    /// Subject public key: algorithm, size in bits, curve.
    pub public_key: PublicKeyInfo,
    /// Signature algorithm.
    pub signature_algorithm: SignatureAlgorithm,
    /// Subject Alternative Names.
    pub subject_alt_names: Vec<SubjectAltName>,
    /// Basic Constraints, when present.
    pub basic_constraints: Option<BasicConstraints>,
    /// Key Usage, when present.
    pub key_usage: Option<KeyUsage>,
    /// Extended Key Usage purposes.
    pub extended_key_usage: Vec<ExtendedKeyUsage>,
    /// Subject Key Identifier, when present.
    pub subject_key_id: Option<KeyId>,
    /// Authority Key Identifier, when present.
    pub authority_key_id: Option<KeyId>,
    /// Authority Information Access URLs.
    pub aia: AuthorityInfoAccess,
    /// CRL distribution point URLs.
    pub crl_distribution_points: Vec<String>,
    /// Embedded SCTs.
    pub embedded_scts: Vec<SctEntry>,
    /// Every extension present, in certificate order.
    pub extensions: Vec<ExtensionSummary>,
}
