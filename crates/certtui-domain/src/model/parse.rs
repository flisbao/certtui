//! DER certificate parsing into a [`CertificateSummary`] (spec D1, section 9).

use x509_parser::certificate::X509Certificate;
use x509_parser::parse_x509_certificate;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::{SubjectPublicKeyInfo, X509Name};

use crate::error::ParseError;
use crate::limits::Limits;
use crate::time::Timestamp;

use super::fingerprint::join_hex;
use super::key::{PublicKeyAlgorithm, PublicKeyInfo, SignatureAlgorithm};
use super::name::{DistinguishedName, SerialNumber};
use super::summary::{AuthorityInfoAccess, CertificateSummary};

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";
const OID_CURVE_P256: &str = "1.2.840.10045.3.1.7";
const OID_CURVE_P384: &str = "1.3.132.0.34";
const OID_CURVE_P521: &str = "1.3.132.0.35";

/// Parses one DER certificate and extracts its core fields.
///
/// The size check against `limits.max_cert_der_bytes` runs before any
/// parsing. Extension-derived fields of the summary are left empty.
///
/// # Errors
///
/// [`ParseError::TooLarge`] when `der` exceeds the limit,
/// [`ParseError::Malformed`] when it is not a well-formed certificate, and
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
    Ok(summarize(&cert))
}

/// Builds the summary from an already-parsed certificate.
fn summarize(cert: &X509Certificate<'_>) -> CertificateSummary {
    let validity = cert.validity();
    CertificateSummary {
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
        subject_alt_names: Vec::new(),
        basic_constraints: None,
        key_usage: None,
        extended_key_usage: Vec::new(),
        subject_key_id: None,
        authority_key_id: None,
        aia: AuthorityInfoAccess::default(),
        crl_distribution_points: Vec::new(),
        embedded_scts: Vec::new(),
        extensions: Vec::new(),
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

/// Renders a DN in RFC 4514 order (last RDN first, multi-valued RDNs joined
/// with `+`) and extracts the first common name.
fn distinguished_name(name: &X509Name<'_>) -> DistinguishedName {
    let mut rdns: Vec<String> = name
        .iter_rdn()
        .map(|rdn| {
            rdn.iter()
                .map(|attr| {
                    let oid = attr.attr_type().to_id_string();
                    // Non-UTF-8-compatible string types fall back to the hex of
                    // the content.
                    let value = attr.as_str().map_or_else(
                        |_| format!("#{}", join_hex(attr.attr_value().data, "", false)),
                        escape_rfc4514,
                    );
                    format!("{}={value}", attribute_label(&oid))
                })
                .collect::<Vec<_>>()
                .join("+")
        })
        .collect();
    rdns.reverse();
    let common_name = name
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(str::to_owned);
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
    use crate::model::{HashAlgorithm, PublicKeyAlgorithm};
    use crate::time::Timestamp;

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
}
