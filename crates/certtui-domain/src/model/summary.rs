//! [`CertificateSummary`]: the parsed, display-oriented view of a
//! certificate (spec section 5.2).
//!
//! The extension-related types live in [`super::extensions`].

use super::extensions::{
    AuthorityInfoAccess, BasicConstraints, ExtendedKeyUsage, ExtensionSummary, KeyId, KeyUsage,
    SctEntry, SubjectAltName,
};
use super::key::{PublicKeyInfo, SignatureAlgorithm};
use super::name::{DistinguishedName, SerialNumber};
use crate::time::Timestamp;

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
