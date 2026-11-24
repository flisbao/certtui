//! DER certificate parsing into a [`CertificateSummary`] (spec D1, section 9).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use x509_parser::asn1_rs::{FromDer, Tag};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::SignedCertificateTimestamp;
use x509_parser::extensions::{
    self as x509_ext, DistributionPointName, GeneralName, ParsedExtension, X509Extension,
};
use x509_parser::oid_registry::{
    OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS, OID_PKIX_ACCESS_DESCRIPTOR_OCSP,
};
use x509_parser::parse_x509_certificate;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::{AttributeTypeAndValue, SubjectPublicKeyInfo, X509Name};

use crate::error::ParseError;
use crate::limits::Limits;
use crate::time::Timestamp;

use super::extensions::{
    AuthorityInfoAccess, BasicConstraints, ExtendedKeyUsage, ExtensionSummary, KeyId, KeyUsage,
    SctEntry, SubjectAltName, extension_name,
};
use super::fingerprint::join_hex;
use super::key::{PublicKeyAlgorithm, PublicKeyInfo, SignatureAlgorithm};
use super::name::{DistinguishedName, SerialNumber};
use super::summary::CertificateSummary;

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";
const OID_CURVE_P256: &str = "1.2.840.10045.3.1.7";
const OID_CURVE_P384: &str = "1.3.132.0.34";
const OID_CURVE_P521: &str = "1.3.132.0.35";

/// Most embedded SCTs kept per certificate. Real certificates carry two or
/// three; the cap only bounds hostile input.
const MAX_SCT_ENTRIES: usize = 64;

/// Parses one DER certificate and extracts its core fields.
///
/// The size check against `limits.max_cert_der_bytes` runs before any
/// parsing.
///
/// An extension whose content fails to decode (bad SAN, bad SCT list, ...)
/// does not reject the certificate: its summary field stays empty and its
/// entry in `extensions` has `decode_error == true` (with `critical`
/// preserved), so the problem is shown rather than hidden. A repeated
/// extension, by contrast, is a hard error (see below).
///
/// # Errors
///
/// [`ParseError::TooLarge`] when `der` exceeds the limit,
/// [`ParseError::Malformed`] when it is not a well-formed certificate or
/// repeats an extension (RFC 5280 section 4.2 forbids it; `x509-parser`
/// only reports that when an extension is looked up, not while parsing), and
/// [`ParseError::TrailingData`] when bytes follow the certificate.
pub fn parse_der_cert(der: &[u8], limits: &Limits) -> Result<CertificateSummary, ParseError> {
    if der.len() > limits.max_cert_der_bytes {
        return Err(ParseError::TooLarge {
            len: der.len(),
            max: limits.max_cert_der_bytes,
        });
    }
    let (rest, cert) =
        parse_x509_certificate(der).map_err(|e| ParseError::Malformed(e.to_string()))?;
    if !rest.is_empty() {
        return Err(ParseError::TrailingData { extra: rest.len() });
    }
    summarize(&cert)
}

/// Parses a DER-encoded `Name` (e.g. a trust anchor subject) for display.
///
/// Returns `None` when `der` is not a well-formed name or has trailing bytes.
#[must_use]
pub fn parse_name_der(der: &[u8]) -> Option<DistinguishedName> {
    let (rest, name) = X509Name::from_der(der).ok()?;
    rest.is_empty().then(|| distinguished_name(&name))
}

/// Builds the summary from an already-parsed certificate.
fn summarize(cert: &X509Certificate<'_>) -> Result<CertificateSummary, ParseError> {
    let validity = cert.validity();
    let ext = read_extensions(cert)?;
    Ok(CertificateSummary {
        // X.509 encodes v1 as 0, v2 as 1, v3 as 2.
        version: u8::try_from(cert.version().0.saturating_add(1)).unwrap_or(u8::MAX),
        serial: SerialNumber::from_bytes(cert.raw_serial()),
        subject: distinguished_name(cert.subject()),
        issuer: distinguished_name(cert.issuer()),
        not_before: Timestamp::from_unix_saturating(validity.not_before.timestamp()),
        not_after: Timestamp::from_unix_saturating(validity.not_after.timestamp()),
        public_key: public_key_info(cert.public_key()),
        signature_algorithm: SignatureAlgorithm::from_oid(
            &cert.signature_algorithm.algorithm.to_id_string(),
        ),
        subject_alt_names: ext.subject_alt_names,
        basic_constraints: ext.basic_constraints,
        key_usage: ext.key_usage,
        extended_key_usage: ext.extended_key_usage,
        subject_key_id: ext.subject_key_id,
        authority_key_id: ext.authority_key_id,
        aia: ext.aia,
        crl_distribution_points: ext.crl_distribution_points,
        embedded_scts: ext.embedded_scts,
        extensions: ext.extensions,
    })
}

/// The extension-derived part of a [`CertificateSummary`].
#[derive(Default)]
struct ExtensionFields {
    subject_alt_names: Vec<SubjectAltName>,
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    extended_key_usage: Vec<ExtendedKeyUsage>,
    subject_key_id: Option<KeyId>,
    authority_key_id: Option<KeyId>,
    aia: AuthorityInfoAccess,
    crl_distribution_points: Vec<String>,
    embedded_scts: Vec<SctEntry>,
    extensions: Vec<ExtensionSummary>,
}

impl ExtensionFields {
    /// Records what one decoded extension contributes to the summary.
    /// Unrecognized or undecodable extensions contribute nothing; undecodable
    /// ones are flagged separately by [`extension_summary`].
    fn absorb(&mut self, parsed: &ParsedExtension<'_>) {
        match parsed {
            ParsedExtension::SubjectAlternativeName(san) => {
                self.subject_alt_names = subject_alt_names(san);
            }
            ParsedExtension::BasicConstraints(bc) => {
                self.basic_constraints = Some(basic_constraints(bc));
            }
            ParsedExtension::KeyUsage(ku) => self.key_usage = Some(key_usage(*ku)),
            ParsedExtension::ExtendedKeyUsage(eku) => {
                self.extended_key_usage = extended_key_usage(eku);
            }
            ParsedExtension::SubjectKeyIdentifier(id) => self.subject_key_id = Some(key_id(id)),
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                self.authority_key_id = aki.key_identifier.as_ref().map(key_id);
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                self.aia = authority_info_access(aia);
            }
            ParsedExtension::CRLDistributionPoints(points) => {
                self.crl_distribution_points = crl_distribution_urls(points);
            }
            ParsedExtension::SCT(scts) => self.embedded_scts = sct_entries(scts),
            _ => {}
        }
    }
}

/// Walks the extensions in certificate order, rejecting repeated OIDs.
fn read_extensions(cert: &X509Certificate<'_>) -> Result<ExtensionFields, ParseError> {
    let mut fields = ExtensionFields::default();
    let mut seen = HashSet::new();
    for ext in cert.extensions() {
        let oid = ext.oid.to_id_string();
        if !seen.insert(oid.clone()) {
            return Err(ParseError::Malformed(format!("duplicate extension {oid}")));
        }
        let parsed = ext.parsed_extension();
        fields.absorb(parsed);
        fields.extensions.push(extension_summary(ext, oid, parsed));
    }
    Ok(fields)
}

/// One-line description of an extension: OID, criticality, display name and
/// whether its content failed to decode.
fn extension_summary(
    ext: &X509Extension<'_>,
    oid: String,
    parsed: &ParsedExtension<'_>,
) -> ExtensionSummary {
    ExtensionSummary {
        name: extension_name(&oid),
        oid,
        critical: ext.critical,
        decode_error: parsed.error().is_some(),
    }
}

/// The SAN entries, in certificate order.
fn subject_alt_names(san: &x509_ext::SubjectAlternativeName<'_>) -> Vec<SubjectAltName> {
    san.general_names.iter().map(subject_alt_name).collect()
}

/// Maps one general name to its [`SubjectAltName`].
fn subject_alt_name(name: &GeneralName<'_>) -> SubjectAltName {
    let other = |kind: &str| SubjectAltName::Other {
        kind: kind.to_owned(),
    };
    match name {
        GeneralName::DNSName(dns) => SubjectAltName::Dns((*dns).to_owned()),
        GeneralName::RFC822Name(email) => SubjectAltName::Email((*email).to_owned()),
        GeneralName::URI(uri) => SubjectAltName::Uri((*uri).to_owned()),
        GeneralName::IPAddress(bytes) => ip_address(bytes)
            .map_or_else(|| other("iPAddress (invalid length)"), SubjectAltName::Ip),
        GeneralName::OtherName(..) => other("otherName"),
        GeneralName::X400Address(_) => other("x400Address"),
        GeneralName::DirectoryName(_) => other("directoryName"),
        GeneralName::EDIPartyName(_) => other("ediPartyName"),
        GeneralName::RegisteredID(_) => other("registeredID"),
        GeneralName::Invalid(..) => other("invalid"),
    }
}

/// An IPv4 (4 bytes) or IPv6 (16 bytes) address; `None` for other lengths.
fn ip_address(bytes: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(bytes) {
        Some(IpAddr::V4(Ipv4Addr::from(v4)))
    } else if let Ok(v6) = <[u8; 16]>::try_from(bytes) {
        Some(IpAddr::V6(Ipv6Addr::from(v6)))
    } else {
        None
    }
}

/// Basic Constraints.
fn basic_constraints(bc: &x509_ext::BasicConstraints) -> BasicConstraints {
    BasicConstraints {
        ca: bc.ca,
        path_len: bc.path_len_constraint,
    }
}

/// Key Usage bits.
fn key_usage(ku: x509_ext::KeyUsage) -> KeyUsage {
    KeyUsage {
        digital_signature: ku.digital_signature(),
        non_repudiation: ku.non_repudiation(),
        key_encipherment: ku.key_encipherment(),
        data_encipherment: ku.data_encipherment(),
        key_agreement: ku.key_agreement(),
        key_cert_sign: ku.key_cert_sign(),
        crl_sign: ku.crl_sign(),
        encipher_only: ku.encipher_only(),
        decipher_only: ku.decipher_only(),
    }
}

/// Extended Key Usage purposes: the well-known ones in a fixed order, then
/// any others as dotted OIDs (the original order across both groups is not
/// preserved by the parser).
fn extended_key_usage(eku: &x509_ext::ExtendedKeyUsage<'_>) -> Vec<ExtendedKeyUsage> {
    let known = [
        (eku.any, ExtendedKeyUsage::Any),
        (eku.server_auth, ExtendedKeyUsage::ServerAuth),
        (eku.client_auth, ExtendedKeyUsage::ClientAuth),
        (eku.code_signing, ExtendedKeyUsage::CodeSigning),
        (eku.email_protection, ExtendedKeyUsage::EmailProtection),
        (eku.time_stamping, ExtendedKeyUsage::TimeStamping),
        (eku.ocsp_signing, ExtendedKeyUsage::OcspSigning),
    ];
    known
        .into_iter()
        .filter_map(|(present, purpose)| present.then_some(purpose))
        .chain(
            eku.other
                .iter()
                .map(|oid| ExtendedKeyUsage::Other(oid.to_id_string())),
        )
        .collect()
}

/// A subject or authority key identifier.
fn key_id(id: &x509_ext::KeyIdentifier<'_>) -> KeyId {
    KeyId(id.0.to_vec())
}

/// OCSP and CA Issuers URLs from the Authority Information Access
/// extension; other access methods and non-URI locations are ignored.
fn authority_info_access(aia: &x509_ext::AuthorityInfoAccess<'_>) -> AuthorityInfoAccess {
    let mut out = AuthorityInfoAccess::default();
    for desc in aia.iter() {
        let GeneralName::URI(url) = &desc.access_location else {
            continue;
        };
        if desc.access_method == OID_PKIX_ACCESS_DESCRIPTOR_OCSP {
            out.ocsp.push((*url).to_owned());
        } else if desc.access_method == OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS {
            out.ca_issuers.push((*url).to_owned());
        }
    }
    out
}

/// The URI entries of every distribution point's `fullName`.
fn crl_distribution_urls(points: &x509_ext::CRLDistributionPoints<'_>) -> Vec<String> {
    points
        .iter()
        .filter_map(|point| match &point.distribution_point {
            Some(DistributionPointName::FullName(names)) => Some(names),
            _ => None,
        })
        .flatten()
        .filter_map(|name| match name {
            GeneralName::URI(url) => Some((*url).to_owned()),
            _ => None,
        })
        .collect()
}

/// The embedded SCTs (at most [`MAX_SCT_ENTRIES`]). `x509-parser` decodes
/// the TLS-encoded list with bounds-checked readers; a list that does not
/// decode never reaches this function.
fn sct_entries(scts: &[SignedCertificateTimestamp<'_>]) -> Vec<SctEntry> {
    scts.iter().take(MAX_SCT_ENTRIES).map(sct_entry).collect()
}

/// One SCT. The wire timestamp is milliseconds since the Unix epoch.
fn sct_entry(sct: &SignedCertificateTimestamp<'_>) -> SctEntry {
    let seconds = i64::try_from(sct.timestamp / 1000).unwrap_or(i64::MAX);
    SctEntry {
        // The wire value is 0 for v1.
        version: sct.version.0.saturating_add(1),
        log_id: *sct.id.key_id,
        timestamp: Timestamp::from_unix_saturating(seconds),
    }
}

/// Short attribute names from RFC 4514 section 3; others use the dotted OID.
fn attribute_label(oid: &str) -> &str {
    match oid {
        "2.5.4.3" => "CN",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        other => other,
    }
}

/// Escapes an attribute value per RFC 4514 section 2.4; control characters
/// become `\XX` hex pairs.
fn escape_rfc4514(value: &str) -> String {
    let last = value.chars().count().saturating_sub(1);
    let mut out = String::new();
    for (i, c) in value.chars().enumerate() {
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '#' | ' ' if i == 0 => {
                out.push('\\');
                out.push(c);
            }
            ' ' if i == last => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {
                let mut buf = [0_u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    out.push('\\');
                    out.push_str(&join_hex(&[b], "", true));
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Decodes the text of a string-typed attribute value, or `None` when the
/// type is not a supported string type or the bytes are invalid for it.
///
/// Supported: `NumericString`, `PrintableString`, `UTF8String`, `IA5String`;
/// `TeletexString` (T61) and `VisibleString` read as Latin-1; `BMPString` as
/// UTF-16BE; `UniversalString` as UTF-32BE.
fn decode_attribute_text(attr: &AttributeTypeAndValue<'_>) -> Option<String> {
    let value = attr.attr_value();
    if value.header.is_constructed() {
        return None;
    }
    match value.tag() {
        Tag::NumericString | Tag::PrintableString | Tag::Utf8String | Tag::Ia5String => {
            attr.as_str().ok().map(str::to_owned)
        }
        Tag::TeletexString | Tag::VisibleString => {
            Some(value.data.iter().map(|b| char::from(*b)).collect())
        }
        Tag::BmpString => {
            let (pairs, rest) = value.data.as_chunks::<2>();
            if !rest.is_empty() {
                return None;
            }
            char::decode_utf16(pairs.iter().map(|c| u16::from_be_bytes(*c)))
                .collect::<Result<String, _>>()
                .ok()
        }
        Tag::UniversalString => {
            let (quads, rest) = value.data.as_chunks::<4>();
            if !rest.is_empty() {
                return None;
            }
            quads
                .iter()
                .map(|c| char::from_u32(u32::from_be_bytes(*c)))
                .collect()
        }
        _ => None,
    }
}

/// The full BER/DER encoding (tag, length, content) of an attribute value,
/// as RFC 4514 section 2.4 requires for values without a string form.
fn full_encoding(attr: &AttributeTypeAndValue<'_>) -> Vec<u8> {
    let value = attr.attr_value();
    let mut out = Vec::new();
    let class = u8::try_from(value.header.class() as u32).unwrap_or(0);
    let constructed = u8::from(value.header.is_constructed());
    let lead = (class << 6) | (constructed << 5);
    let tag = value.tag().0;
    if tag < 31 {
        out.push(lead | u8::try_from(tag).unwrap_or(0));
    } else {
        out.push(lead | 0x1F);
        // High tag number form: base-128 digits, most significant first.
        let mut digits = Vec::new();
        let mut rest = tag;
        loop {
            digits.push(u8::try_from(rest & 0x7F).unwrap_or(0));
            rest >>= 7;
            if rest == 0 {
                break;
            }
        }
        for (i, d) in digits.iter().rev().enumerate() {
            let more = i + 1 < digits.len();
            out.push(if more { d | 0x80 } else { *d });
        }
    }
    let len = value.data.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        let significant = bytes.get(start..).unwrap_or_default();
        out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0));
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(value.data);
    out
}

/// RFC 4514 value of one attribute: escaped text when the type decodes to a
/// string, otherwise `#` plus the hex of the full BER encoding.
fn attribute_value_rfc4514(attr: &AttributeTypeAndValue<'_>) -> String {
    decode_attribute_text(attr).map_or_else(
        || format!("#{}", join_hex(&full_encoding(attr), "", false)),
        |text| escape_rfc4514(&text),
    )
}

/// Renders a DN in RFC 4514 order (last RDN first, multi-valued RDNs joined
/// with `+`) and extracts the common name.
///
/// With several `commonName` attributes, `common_name` is the **most
/// specific** one: the last in the certificate's encoding, which is also the
/// first `CN=` in the RFC 4514 text (same attribute a reader sees first, and
/// the one RFC 2818 legacy hostname matching prefers). If that attribute has
/// no decodable text, `common_name` is `None` rather than another CN.
fn distinguished_name(name: &X509Name<'_>) -> DistinguishedName {
    let mut rdns: Vec<String> = name
        .iter_rdn()
        .map(|rdn| {
            rdn.iter()
                .map(|attr| {
                    let oid = attr.attr_type().to_id_string();
                    format!(
                        "{}={}",
                        attribute_label(&oid),
                        attribute_value_rfc4514(attr)
                    )
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.reverse();
    let common_name = name
        .iter_common_name()
        .last()
        .and_then(decode_attribute_text);
    DistinguishedName {
        rfc4514: rdns.join(","),
        common_name,
    }
}

/// Bit length of a big-endian unsigned integer (leading zero bytes ignored).
fn bit_length(bytes: &[u8]) -> u32 {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    match bytes.get(start) {
        Some(first) => {
            let remaining =
                u32::try_from(bytes.len().saturating_sub(start + 1)).unwrap_or(u32::MAX);
            remaining
                .saturating_mul(8)
                .saturating_add(8 - first.leading_zeros())
        }
        None => 0,
    }
}

/// Algorithm, size and curve of a `SubjectPublicKeyInfo`.
fn public_key_info(spki: &SubjectPublicKeyInfo<'_>) -> PublicKeyInfo {
    let oid = spki.algorithm.algorithm.to_id_string();
    let fallback_bits =
        u32::try_from(spki.subject_public_key.data.len().saturating_mul(8)).unwrap_or(u32::MAX);
    match oid.as_str() {
        OID_RSA_ENCRYPTION => {
            let bits = match spki.parsed() {
                Ok(PublicKey::RSA(rsa)) => bit_length(rsa.modulus),
                _ => 0,
            };
            PublicKeyInfo {
                algorithm: PublicKeyAlgorithm::Rsa,
                bits,
                curve: None,
            }
        }
        OID_EC_PUBLIC_KEY => {
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|o| o.to_id_string());
            let (algorithm, bits, curve) = match curve_oid.as_deref() {
                Some(OID_CURVE_P256) => (PublicKeyAlgorithm::EcP256, 256, "prime256v1".to_owned()),
                Some(OID_CURVE_P384) => (PublicKeyAlgorithm::EcP384, 384, "secp384r1".to_owned()),
                Some(OID_CURVE_P521) => (PublicKeyAlgorithm::EcP521, 521, "secp521r1".to_owned()),
                Some(other) => (
                    PublicKeyAlgorithm::Other(other.to_owned()),
                    spki.parsed()
                        .map_or(0, |k| u32::try_from(k.key_size()).unwrap_or(0)),
                    other.to_owned(),
                ),
                None => (PublicKeyAlgorithm::Other(oid.clone()), 0, String::new()),
            };
            PublicKeyInfo {
                algorithm,
                bits,
                curve: (!curve.is_empty()).then_some(curve),
            }
        }
        OID_ED25519 => PublicKeyInfo {
            algorithm: PublicKeyAlgorithm::Ed25519,
            bits: 256,
            curve: None,
        },
        OID_ED448 => PublicKeyInfo {
            algorithm: PublicKeyAlgorithm::Ed448,
            bits: 456,
            curve: None,
        },
        _ => PublicKeyInfo {
            algorithm: PublicKeyAlgorithm::Other(oid),
            bits: fallback_bits,
            curve: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AuthorityInfoAccess, BasicConstraints, ExtendedKeyUsage, HashAlgorithm, PublicKeyAlgorithm,
        SubjectAltName,
    };
    use crate::time::Timestamp;
    use x509_parser::prelude::FromDer;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FIXTURES}/{name}.der")).unwrap()
    }

    #[test]
    fn quando_rsa2048_leaf_deve_extrair_campos_basicos() {
        let s = parse_der_cert(&fixture("rsa2048-leaf"), &Limits::default()).unwrap();
        assert_eq!(s.version, 3);
        assert_eq!(s.public_key.algorithm, PublicKeyAlgorithm::Rsa);
        assert_eq!(s.public_key.bits, 2048);
        assert_eq!(s.public_key.curve, None);
        assert_eq!(s.signature_algorithm.name, "sha256WithRSAEncryption");
        assert_eq!(s.signature_algorithm.hash, HashAlgorithm::Sha256);
        assert_eq!(s.signature_algorithm.oid, "1.2.840.113549.1.1.11");
        assert_eq!(
            s.subject.rfc4514,
            "CN=rsa2048.example.test,O=CertTui Test,C=BR"
        );
        assert_eq!(
            s.subject.common_name.as_deref(),
            Some("rsa2048.example.test")
        );
        assert_eq!(s.issuer, s.subject);
        assert_eq!(
            s.serial.to_hex(),
            "737165299F2A97F62F082F339CADEB39BD78B1CE"
        );
    }

    #[test]
    fn quando_ec_p256_deve_informar_curva() {
        let s = parse_der_cert(&fixture("ec-p256-leaf"), &Limits::default()).unwrap();
        assert_eq!(s.public_key.algorithm, PublicKeyAlgorithm::EcP256);
        assert_eq!(s.public_key.curve.as_deref(), Some("prime256v1"));
        assert_eq!(s.public_key.bits, 256);
        assert_eq!(s.signature_algorithm.hash, HashAlgorithm::Sha256);
    }

    #[test]
    fn quando_validade_deve_virar_timestamp_utc() {
        let s = parse_der_cert(&fixture("rsa2048-leaf"), &Limits::default()).unwrap();
        // notBefore=Nov 23 21:05:35 2026 GMT, notAfter=Nov 20 21:05:35 2036 GMT
        assert_eq!(s.not_before, Timestamp::from_unix(1_795_467_935).unwrap());
        assert_eq!(s.not_after, Timestamp::from_unix(2_110_827_935).unwrap());
        assert_eq!(s.not_before.to_string(), "2026-11-23T21:05:35Z");
    }

    #[test]
    fn quando_der_acima_do_limite_deve_dar_too_large() {
        let der = fixture("rsa2048-leaf");
        let limits = Limits {
            max_cert_der_bytes: 100,
            ..Limits::default()
        };
        assert_eq!(
            parse_der_cert(&der, &limits),
            Err(ParseError::TooLarge {
                len: der.len(),
                max: 100
            })
        );
    }

    #[test]
    fn quando_der_truncado_deve_dar_malformed() {
        let der = fixture("rsa2048-leaf");
        let truncated = &der[..der.len() - 10];
        assert!(matches!(
            parse_der_cert(truncated, &Limits::default()),
            Err(ParseError::Malformed(_))
        ));
    }

    #[test]
    fn quando_entrada_vazia_ou_lixo_deve_dar_malformed() {
        assert!(matches!(
            parse_der_cert(&[], &Limits::default()),
            Err(ParseError::Malformed(_))
        ));
        assert!(matches!(
            parse_der_cert(b"not a certificate", &Limits::default()),
            Err(ParseError::Malformed(_))
        ));
    }

    #[test]
    fn quando_sobra_byte_depois_do_cert_deve_dar_trailing_data() {
        let mut der = fixture("rsa2048-leaf");
        der.push(0x00);
        assert_eq!(
            parse_der_cert(&der, &Limits::default()),
            Err(ParseError::TrailingData { extra: 1 })
        );
    }

    #[test]
    fn quando_der_no_limite_exato_deve_parsear() {
        let der = fixture("rsa2048-leaf");
        let limits = Limits {
            max_cert_der_bytes: der.len(),
            ..Limits::default()
        };
        assert!(parse_der_cert(&der, &limits).is_ok());
    }

    #[test]
    fn quando_cert_publico_deve_bater_com_openssl() {
        let s = parse_der_cert(&fixture("public-leaf-with-sct"), &Limits::default()).unwrap();
        assert_eq!(s.subject.rfc4514, "CN=example.com");
        assert_eq!(
            s.issuer.rfc4514,
            "CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US"
        );
        // The DER carries 0x01 first, so no leading zero byte is stripped here.
        assert_eq!(s.serial.to_hex(), "01EEE6AABB521D5E14FC315FD9985690");
    }

    #[test]
    fn quando_valor_de_dn_tem_especiais_deve_escapar_rfc4514() {
        assert_eq!(escape_rfc4514("a,b+c"), "a\\,b\\+c");
        assert_eq!(escape_rfc4514("#x"), "\\#x");
        assert_eq!(escape_rfc4514(" x "), "\\ x\\ ");
        assert_eq!(escape_rfc4514("a#b"), "a#b");
        assert_eq!(escape_rfc4514("a\nb"), "a\\0Ab");
        assert_eq!(escape_rfc4514(""), "");
    }

    #[test]
    fn quando_modulo_tem_zero_a_esquerda_deve_contar_bits_reais() {
        assert_eq!(bit_length(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(bit_length(&[0x01, 0x00]), 9);
        assert_eq!(bit_length(&[0x00]), 0);
        assert_eq!(bit_length(&[]), 0);
    }

    #[test]
    fn quando_todas_as_fixtures_der_deve_parsear() {
        for name in [
            "rsa2048-leaf",
            "ec-p256-leaf",
            "san-multi",
            "expired",
            "public-leaf-with-sct",
            "chain-3",
        ] {
            let result = parse_der_cert(&fixture(name), &Limits::default());
            assert!(result.is_ok(), "{name}: {result:?}");
        }
    }

    fn summary(name: &str) -> CertificateSummary {
        parse_der_cert(&fixture(name), &Limits::default()).unwrap()
    }

    /// DER of the intermediate CA (second certificate) of `chain-3.pem`.
    fn chain_intermediate() -> Vec<u8> {
        let pem = std::fs::read(format!("{FIXTURES}/chain-3.pem")).unwrap();
        let second = x509_parser::pem::Pem::iter_from_buffer(&pem)
            .nth(1)
            .unwrap()
            .unwrap();
        second.contents
    }

    #[test]
    fn quando_san_multi_deve_listar_dns_ip_email_uri() {
        let s = summary("san-multi");
        assert_eq!(
            s.subject_alt_names,
            vec![
                SubjectAltName::Dns("san-multi.example.test".to_owned()),
                SubjectAltName::Dns("*.example.test".to_owned()),
                SubjectAltName::Ip("192.0.2.10".parse().unwrap()),
                SubjectAltName::Ip("2001:db8::10".parse().unwrap()),
                SubjectAltName::Email("admin@example.test".to_owned()),
                SubjectAltName::Uri("https://example.test/path".to_owned()),
            ]
        );
    }

    #[test]
    fn quando_cert_sem_san_deve_dar_lista_vazia() {
        // The chain-3 intermediate CA carries no SAN extension.
        let s = parse_der_cert(&chain_intermediate(), &Limits::default()).unwrap();
        assert_eq!(s.subject_alt_names, Vec::new());
    }

    #[test]
    fn quando_intermediario_deve_ter_ca_true_e_path_len() {
        let s = parse_der_cert(&chain_intermediate(), &Limits::default()).unwrap();
        assert_eq!(
            s.basic_constraints,
            Some(BasicConstraints {
                ca: true,
                path_len: Some(0)
            })
        );
        let ku = s.key_usage.unwrap();
        assert!(ku.key_cert_sign && ku.crl_sign);
        assert!(!ku.digital_signature);
    }

    #[test]
    fn quando_leaf_tem_ca_false_deve_dar_basic_constraints_sem_path_len() {
        let s = summary("chain-3");
        assert_eq!(
            s.basic_constraints,
            Some(BasicConstraints {
                ca: false,
                path_len: None
            })
        );
    }

    #[test]
    fn quando_eku_tem_server_auth_deve_listar() {
        assert_eq!(
            summary("rsa2048-leaf").extended_key_usage,
            vec![ExtendedKeyUsage::ServerAuth]
        );
        assert_eq!(
            summary("ec-p256-leaf").extended_key_usage,
            vec![ExtendedKeyUsage::ServerAuth, ExtendedKeyUsage::ClientAuth]
        );
        assert_eq!(summary("expired").extended_key_usage, Vec::new());
    }

    #[test]
    fn quando_key_usage_presente_deve_marcar_so_os_bits_setados() {
        let ku = summary("rsa2048-leaf").key_usage.unwrap();
        assert!(ku.digital_signature && ku.key_encipherment);
        assert!(!ku.non_repudiation && !ku.data_encipherment && !ku.key_agreement);
        assert!(!ku.key_cert_sign && !ku.crl_sign && !ku.encipher_only && !ku.decipher_only);
        assert_eq!(summary("expired").key_usage, None);
    }

    #[test]
    fn quando_cert_tem_key_ids_deve_expor_ski_e_aki() {
        let s = summary("rsa2048-leaf");
        assert_eq!(
            s.subject_key_id.unwrap().to_hex(),
            "43CA132B8B8B0E385ED2AF58319439A34031446D"
        );
        assert_eq!(
            s.authority_key_id.unwrap().to_hex(),
            "43CA132B8B8B0E385ED2AF58319439A34031446D"
        );
        let public = summary("public-leaf-with-sct");
        assert_eq!(public.subject_key_id, None);
        assert_eq!(
            public.authority_key_id.unwrap().to_hex(),
            "8303FDE7F6F54A4D1541F4ED2216D3320A3ECA66"
        );
    }

    #[test]
    fn quando_aia_deve_separar_ocsp_de_ca_issuers() {
        let s = summary("public-leaf-with-sct");
        assert_eq!(s.aia.ocsp, vec!["http://o.cf-i.ssl.com".to_owned()]);
        assert_eq!(
            s.aia.ca_issuers,
            vec!["http://i.cf-i.ssl.com/Cloudflare-TLS-I-E3.cer".to_owned()]
        );
        assert_eq!(summary("rsa2048-leaf").aia, AuthorityInfoAccess::default());
    }

    #[test]
    fn quando_cert_tem_crl_dp_deve_listar_urls() {
        assert_eq!(
            summary("public-leaf-with-sct").crl_distribution_points,
            vec!["http://c.cf-i.ssl.com/ae801ed1c55bb579d79208b0d772acfb8cc3a208.crl".to_owned()]
        );
        assert_eq!(
            summary("rsa2048-leaf").crl_distribution_points,
            Vec::<String>::new()
        );
    }

    #[test]
    fn quando_cert_publico_tem_sct_deve_listar_log_id_e_timestamp() {
        let s = summary("public-leaf-with-sct");
        assert_eq!(s.embedded_scts.len(), 2);
        let first = s.embedded_scts.first().unwrap();
        assert_eq!(first.version, 1);
        assert_eq!(
            join_hex(&first.log_id, "", true),
            "944E4387FAECC1EF81F3192426A8186501C7D35F3802013F72677D55372E19D8"
        );
        // Sep 26 22:59:12.866 2026 GMT (milliseconds are dropped).
        assert_eq!(first.timestamp.unix(), 1_790_463_552);
        let second = s.embedded_scts.get(1).unwrap();
        assert_eq!(
            join_hex(&second.log_id, "", true),
            "CB38F715897C84A1445F5BC1DDFBC96EF29A59CD470A690585B0CB14C31458E7"
        );
        assert_eq!(second.timestamp.unix(), 1_790_463_552);
        assert_eq!(summary("rsa2048-leaf").embedded_scts, Vec::new());
    }

    #[test]
    fn quando_extensao_desconhecida_deve_listar_oid_como_nome() {
        let s = summary("public-leaf-with-sct");
        let unknown = s
            .extensions
            .iter()
            .find(|e| e.oid == "1.3.6.1.4.1.44363.44")
            .unwrap();
        assert_eq!(unknown.name, "1.3.6.1.4.1.44363.44");
        assert!(!unknown.critical);
    }

    #[test]
    fn quando_extensoes_conhecidas_deve_listar_na_ordem_do_cert_com_critical() {
        let s = summary("rsa2048-leaf");
        let rows: Vec<(&str, bool, &str)> = s
            .extensions
            .iter()
            .map(|e| (e.oid.as_str(), e.critical, e.name.as_str()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("2.5.29.14", false, "Subject Key Identifier"),
                ("2.5.29.35", false, "Authority Key Identifier"),
                ("2.5.29.19", true, "Basic Constraints"),
                ("2.5.29.17", false, "Subject Alternative Name"),
                ("2.5.29.15", true, "Key Usage"),
                ("2.5.29.37", false, "Extended Key Usage"),
            ]
        );
    }

    /// Splits one DER TLV into (tag, content, rest). Test helper: short and
    /// 0x81/0x82 long length forms only.
    fn split_tlv(data: &[u8]) -> (u8, &[u8], &[u8]) {
        let (len, header) = match data[1] {
            n if n < 0x80 => (usize::from(n), 2),
            0x81 => (usize::from(data[2]), 3),
            0x82 => (usize::from(data[2]) << 8 | usize::from(data[3]), 4),
            other => panic!("unsupported length form {other:#x}"),
        };
        (data[0], &data[header..header + len], &data[header + len..])
    }

    /// Re-encodes the `chain-3` leaf with its extensions (each one a whole
    /// DER TLV) rewritten by `rewrite`; the signature is left untouched.
    fn der_with_extensions(rewrite: impl FnOnce(Vec<Vec<u8>>) -> Vec<Vec<u8>>) -> Vec<u8> {
        let der = fixture("chain-3");
        let (_, cert, _) = split_tlv(&der);
        let (_, tbs, after_tbs) = split_tlv(cert);
        // TBS fields are back to back; the [3] extensions wrapper is last.
        let mut raw_fields = Vec::new();
        let mut rest = tbs;
        while !rest.is_empty() {
            let (_, _, next) = split_tlv(rest);
            raw_fields.push(&rest[..rest.len() - next.len()]);
            rest = next;
        }
        let wrapper = raw_fields.pop().unwrap();
        let (_, wrapper_content, _) = split_tlv(wrapper);
        let (_, mut ext_list, _) = split_tlv(wrapper_content);
        let mut exts = Vec::new();
        while !ext_list.is_empty() {
            let (_, _, next) = split_tlv(ext_list);
            exts.push(ext_list[..ext_list.len() - next.len()].to_vec());
            ext_list = next;
        }
        let new_list = tlv(0x30, &rewrite(exts).concat());
        let mut new_tbs = raw_fields.concat();
        new_tbs.extend(tlv(0xA3, &new_list));
        let mut new_cert = tlv(0x30, &new_tbs);
        new_cert.extend_from_slice(after_tbs);
        tlv(0x30, &new_cert)
    }

    /// The chain-3 leaf with every extension repeated (each OID twice).
    fn der_with_duplicate_extension() -> Vec<u8> {
        der_with_extensions(|exts| [exts.clone(), exts].concat())
    }

    /// Replaces the content of the extension with OID `oid_der` (the OID
    /// TLV bytes) by an OCTET STRING holding a BOOLEAN, which is never a
    /// valid SAN or Basic Constraints SEQUENCE. The OID and `critical` flag
    /// are kept.
    fn corrupt_extension(ext: &[u8], oid_der: &[u8]) -> Vec<u8> {
        let (_, content, _) = split_tlv(ext);
        if !content.starts_with(oid_der) {
            return ext.to_vec();
        }
        let (_, _, rest) = split_tlv(content);
        let (tag, _, after_flag) = split_tlv(rest);
        let head = if tag == 0x01 {
            &content[..content.len() - after_flag.len()]
        } else {
            &content[..content.len() - rest.len()]
        };
        tlv(0x30, &[head, &tlv(0x04, &[0x01, 0x01, 0xFF])].concat())
    }

    fn der_with_corrupt_san_and_basic_constraints() -> Vec<u8> {
        der_with_extensions(|exts| {
            exts.iter()
                .map(|e| corrupt_extension(e, &[0x06, 0x03, 0x55, 0x1D, 0x11]))
                .map(|e| corrupt_extension(&e, &[0x06, 0x03, 0x55, 0x1D, 0x13]))
                .collect()
        })
    }

    #[test]
    fn quando_extensao_nao_decodifica_deve_aceitar_o_cert_e_marcar_decode_error() {
        let der = der_with_corrupt_san_and_basic_constraints();
        let s = parse_der_cert(&der, &Limits::default()).unwrap();
        assert_eq!(s.subject_alt_names, Vec::new());
        assert_eq!(s.basic_constraints, None);
        let find = |oid: &str| s.extensions.iter().find(|e| e.oid == oid).unwrap();
        let san = find("2.5.29.17");
        assert!(san.decode_error && !san.critical, "{san:?}");
        let bc = find("2.5.29.19");
        assert!(bc.decode_error && bc.critical, "{bc:?}");
        // Untouched extensions still decode.
        assert!(!find("2.5.29.15").decode_error);
        assert!(s.key_usage.is_some());
    }

    #[test]
    fn quando_cert_saudavel_nenhuma_extensao_deve_ter_decode_error() {
        for name in [
            "rsa2048-leaf",
            "ec-p256-leaf",
            "san-multi",
            "expired",
            "public-leaf-with-sct",
            "chain-3",
        ] {
            let s = summary(name);
            assert!(!s.extensions.is_empty(), "{name}");
            assert!(s.extensions.iter().all(|e| !e.decode_error), "{name}");
        }
    }

    #[test]
    fn quando_extensao_duplicada_deve_dar_malformed() {
        let der = der_with_duplicate_extension();
        let result = parse_der_cert(&der, &Limits::default());
        assert!(
            matches!(&result, Err(ParseError::Malformed(m)) if m.contains("duplicate")),
            "{result:?}"
        );
    }

    #[test]
    fn quando_ip_do_san_tem_tamanho_invalido_deve_virar_other() {
        assert_eq!(
            ip_address(&[10, 0, 0, 1]),
            Some("10.0.0.1".parse().unwrap())
        );
        assert_eq!(ip_address(&[0; 16]), Some("::".parse().unwrap()));
        assert_eq!(ip_address(&[1, 2, 3]), None);
        assert_eq!(
            subject_alt_name(&GeneralName::IPAddress(&[1, 2, 3])),
            SubjectAltName::Other {
                kind: "iPAddress (invalid length)".to_owned()
            }
        );
    }

    #[test]
    fn quando_general_name_e_de_outro_tipo_deve_dar_other_com_o_tipo() {
        assert_eq!(
            subject_alt_name(&GeneralName::Invalid(Tag::Sequence, &[])),
            SubjectAltName::Other {
                kind: "invalid".to_owned()
            }
        );
    }

    fn sct(timestamp: u64, version: u8) -> SignedCertificateTimestamp<'static> {
        use x509_parser::extensions::{CtExtensions, CtLogID, CtVersion, DigitallySigned};
        SignedCertificateTimestamp {
            version: CtVersion(version),
            id: CtLogID { key_id: &[7; 32] },
            timestamp,
            extensions: CtExtensions(&[]),
            signature: DigitallySigned {
                hash_alg_id: 4,
                sign_alg_id: 3,
                data: &[],
            },
        }
    }

    #[test]
    fn quando_sct_tem_timestamp_em_ms_deve_converter_para_segundos() {
        let entry = sct_entry(&sct(1_790_463_552_866, 0));
        assert_eq!(entry.version, 1);
        assert_eq!(entry.log_id, [7; 32]);
        assert_eq!(entry.timestamp.unix(), 1_790_463_552);
    }

    #[test]
    fn quando_sct_tem_timestamp_absurdo_deve_saturar() {
        assert_eq!(sct_entry(&sct(u64::MAX, 0)).timestamp, Timestamp::MAX);
        assert_eq!(sct_entry(&sct(0, 255)).version, 255);
    }

    #[test]
    fn quando_ha_scts_demais_deve_limitar_ao_maximo() {
        let many: Vec<_> = (0..MAX_SCT_ENTRIES + 5).map(|_| sct(0, 0)).collect();
        assert_eq!(sct_entries(&many).len(), MAX_SCT_ENTRIES);
    }

    /// DER TLV with a definite length (up to 65535 bytes).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        match content.len() {
            n if n < 0x80 => out.push(u8::try_from(n).unwrap()),
            n if n < 0x100 => out.extend([0x81, u8::try_from(n).unwrap()]),
            n => out.extend([
                0x82,
                u8::try_from(n >> 8).unwrap(),
                u8::try_from(n & 0xFF).unwrap(),
            ]),
        }
        out.extend_from_slice(content);
        out
    }

    const OID_CN: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];
    const OID_O: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x0A];

    /// One single-attribute RDN: SET { SEQUENCE { oid, value } }.
    fn rdn(oid: &[u8], value_tag: u8, value: &[u8]) -> Vec<u8> {
        let mut seq = oid.to_vec();
        seq.extend(tlv(value_tag, value));
        tlv(0x31, &tlv(0x30, &seq))
    }

    fn dn_from(rdns: &[Vec<u8>]) -> DistinguishedName {
        let der = tlv(0x30, &rdns.concat());
        let (rest, name) = X509Name::from_der(&der).unwrap();
        assert_eq!(rest, &[] as &[u8]);
        distinguished_name(&name)
    }

    fn utf16be(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    #[test]
    fn quando_cn_e_teletex_deve_ler_como_latin1() {
        let dn = dn_from(&[rdn(&OID_CN, 0x14, b"Caf\xE9, Ltda")]);
        assert_eq!(dn.rfc4514, "CN=Café\\, Ltda");
        assert_eq!(dn.common_name.as_deref(), Some("Café, Ltda"));
    }

    #[test]
    fn quando_cn_e_bmpstring_deve_decodificar_utf16be() {
        let dn = dn_from(&[rdn(&OID_CN, 0x1E, &utf16be("Ação 😀"))]);
        assert_eq!(dn.rfc4514, "CN=Ação 😀");
        assert_eq!(dn.common_name.as_deref(), Some("Ação 😀"));
    }

    #[test]
    fn quando_cn_e_universalstring_deve_decodificar_utf32be() {
        let bytes: Vec<u8> = "日本a"
            .chars()
            .flat_map(|c| u32::from(c).to_be_bytes())
            .collect();
        let dn = dn_from(&[rdn(&OID_CN, 0x1C, &bytes)]);
        assert_eq!(dn.rfc4514, "CN=日本a");
        assert_eq!(dn.common_name.as_deref(), Some("日本a"));
    }

    #[test]
    fn quando_tag_de_string_desconhecida_deve_usar_hex_do_ber_completo() {
        // GeneralString (0x1B) is not decoded: RFC 4514 wants '#' + full BER.
        let dn = dn_from(&[rdn(&OID_CN, 0x1B, b"ab")]);
        assert_eq!(dn.rfc4514, "CN=#1b026162");
        assert_eq!(dn.common_name, None);
    }

    #[test]
    fn quando_bmpstring_invalida_deve_usar_hex_do_ber_completo() {
        // Odd length and a lone high surrogate are both invalid UTF-16BE.
        let odd = dn_from(&[rdn(&OID_CN, 0x1E, &[0x00, 0x41, 0x00])]);
        assert_eq!(odd.rfc4514, "CN=#1e03004100");
        let lone = dn_from(&[rdn(&OID_CN, 0x1E, &[0xD8, 0x3D])]);
        assert_eq!(lone.rfc4514, "CN=#1e02d83d");
        assert_eq!(lone.common_name, None);
    }

    #[test]
    fn quando_valor_desconhecido_e_longo_deve_codificar_tamanho_longo() {
        let dn = dn_from(&[rdn(&OID_CN, 0x1B, &[0x61; 200])]);
        assert!(dn.rfc4514.starts_with("CN=#1b81c8"), "{}", dn.rfc4514);
        assert_eq!(dn.rfc4514.len(), "CN=#1b81c8".len() + 400);
    }

    #[test]
    fn quando_ha_varios_cn_deve_usar_o_mais_especifico_como_common_name() {
        // Encoding order: CN=geral, O=Org, CN=especifico.
        let dn = dn_from(&[
            rdn(&OID_CN, 0x0C, b"geral"),
            rdn(&OID_O, 0x0C, b"Org"),
            rdn(&OID_CN, 0x0C, b"especifico"),
        ]);
        assert_eq!(dn.rfc4514, "CN=especifico,O=Org,CN=geral");
        assert_eq!(dn.common_name.as_deref(), Some("especifico"));
    }

    #[test]
    fn quando_cn_mais_especifico_nao_decodifica_nao_deve_cair_em_outro_cn() {
        let dn = dn_from(&[rdn(&OID_CN, 0x0C, b"geral"), rdn(&OID_CN, 0x1B, b"x")]);
        assert_eq!(dn.common_name, None);
    }

    /// `SubjectPublicKeyInfo` with the given algorithm OID TLVs and key bytes.
    fn spki(algorithm: &[&[u8]], key: &[u8]) -> Vec<u8> {
        let mut bits = vec![0x00];
        bits.extend_from_slice(key);
        let mut seq = tlv(0x30, &algorithm.concat());
        seq.extend(tlv(0x03, &bits));
        tlv(0x30, &seq)
    }

    fn key_info(der: &[u8]) -> PublicKeyInfo {
        let (rest, info) = SubjectPublicKeyInfo::from_der(der).unwrap();
        assert_eq!(rest, &[] as &[u8]);
        public_key_info(&info)
    }

    const OID_EC: [u8; 9] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];

    fn ec_point(coord_len: usize) -> Vec<u8> {
        let mut key = vec![0x04];
        key.extend(vec![0x11; coord_len * 2]);
        key
    }

    #[test]
    fn quando_chave_ec_p384_ou_p521_deve_informar_algoritmo_bits_e_curva() {
        let p384 = key_info(&spki(
            &[&OID_EC, &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]],
            &ec_point(48),
        ));
        assert_eq!(p384.algorithm, PublicKeyAlgorithm::EcP384);
        assert_eq!((p384.bits, p384.curve.as_deref()), (384, Some("secp384r1")));
        let p521 = key_info(&spki(
            &[&OID_EC, &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]],
            &ec_point(66),
        ));
        assert_eq!(p521.algorithm, PublicKeyAlgorithm::EcP521);
        assert_eq!((p521.bits, p521.curve.as_deref()), (521, Some("secp521r1")));
    }

    #[test]
    fn quando_curva_ec_desconhecida_deve_dar_other_com_oid() {
        // secp256k1, 1.3.132.0.10
        let info = key_info(&spki(
            &[&OID_EC, &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A]],
            &ec_point(32),
        ));
        assert_eq!(
            info.algorithm,
            PublicKeyAlgorithm::Other("1.3.132.0.10".to_owned())
        );
        assert_eq!(
            (info.bits, info.curve.as_deref()),
            (256, Some("1.3.132.0.10"))
        );
    }

    #[test]
    fn quando_chave_ed25519_ou_ed448_deve_informar_algoritmo_e_bits() {
        let ed25519 = key_info(&spki(&[&[0x06, 0x03, 0x2B, 0x65, 0x70]], &[0x22; 32]));
        assert_eq!(ed25519.algorithm, PublicKeyAlgorithm::Ed25519);
        assert_eq!((ed25519.bits, ed25519.curve), (256, None));
        let ed448 = key_info(&spki(&[&[0x06, 0x03, 0x2B, 0x65, 0x71]], &[0x22; 57]));
        assert_eq!(ed448.algorithm, PublicKeyAlgorithm::Ed448);
        assert_eq!((ed448.bits, ed448.curve), (456, None));
    }

    #[test]
    fn quando_algoritmo_de_chave_desconhecido_deve_dar_other_com_bits_do_bitstring() {
        let info = key_info(&spki(&[&[0x06, 0x03, 0x2A, 0x03, 0x04]], &[0x33; 10]));
        assert_eq!(
            info.algorithm,
            PublicKeyAlgorithm::Other("1.2.3.4".to_owned())
        );
        assert_eq!((info.bits, info.curve), (80, None));
    }
}
