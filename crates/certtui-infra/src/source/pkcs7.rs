//! Bounded extraction of X.509 certificates from CMS / PKCS#7 `SignedData`.

use std::collections::HashSet;

use certtui_app::error::LoadError;
use certtui_domain::limits::Limits;
use certtui_domain::model::{Digest, Fingerprints, parse_der_cert};
use cms::content_info::CmsVersion;
use der::asn1::ObjectIdentifier;
use der::{Decode, Header, Reader, SliceReader, Tag, TagNumber};

/// Extraction output used by the source loader to report partial results.
#[derive(Debug, Default)]
pub(crate) struct Pkcs7Extraction {
    /// Original certificate DER encodings kept within the configured limits.
    pub(crate) certs: Vec<Vec<u8>>,
    /// Whether another unique usable certificate was present beyond the cap.
    pub(crate) truncated: bool,
    /// Number of X.509 certificate choices exceeding the per-certificate cap.
    pub(crate) oversized: usize,
    /// Number of certificate choices that are not parsable X.509 certificates.
    pub(crate) unparsable: usize,
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: Tag,
    encoded: &'a [u8],
    value: &'a [u8],
}

struct DerCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

struct CertificateCollector<'a> {
    limits: &'a Limits,
    already_seen: &'a HashSet<Digest<32>>,
    seen: HashSet<Digest<32>>,
    output: Pkcs7Extraction,
}

impl CertificateCollector<'_> {
    fn collect(&mut self, encoded: &[u8]) -> Result<(), LoadError> {
        let mut choices = DerCursor::new(encoded);
        while let Some(choice) = choices.next()? {
            if choice.tag != Tag::Sequence {
                if choice.tag.is_context_specific() {
                    continue;
                }
                return Err(malformed("invalid PKCS#7/CMS certificate choice"));
            }
            if choice.encoded.len() > self.limits.max_cert_der_bytes {
                self.output.oversized = self.output.oversized.saturating_add(1);
                continue;
            }
            if parse_der_cert(choice.encoded, self.limits).is_err() {
                self.output.unparsable = self.output.unparsable.saturating_add(1);
                continue;
            }
            let fingerprint = Fingerprints::compute(choice.encoded).sha256;
            if self.already_seen.contains(&fingerprint) || !self.seen.insert(fingerprint) {
                continue;
            }
            if self.output.certs.len() >= self.limits.max_certs_per_source {
                self.output.truncated = true;
                break;
            }
            self.output.certs.push(choice.encoded.to_vec());
        }
        Ok(())
    }
}

impl<'a> DerCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn next(&mut self) -> Result<Option<Tlv<'a>>, LoadError> {
        let Some(remaining) = self.input.get(self.offset..) else {
            return Err(malformed("incomplete PKCS#7/CMS structure"));
        };
        if remaining.is_empty() {
            return Ok(None);
        }
        let mut reader =
            SliceReader::new(remaining).map_err(|_| malformed("invalid PKCS#7/CMS structure"))?;
        let header =
            Header::decode(&mut reader).map_err(|_| malformed("invalid PKCS#7/CMS length"))?;
        let value = reader
            .read_slice(header.length)
            .map_err(|_| malformed("incomplete PKCS#7/CMS value"))?;
        let encoded_len = usize::try_from(reader.position())
            .map_err(|_| malformed("invalid PKCS#7/CMS length"))?;
        let Some(encoded) = remaining.get(..encoded_len) else {
            return Err(malformed("incomplete PKCS#7/CMS value"));
        };
        self.offset = self
            .offset
            .checked_add(encoded_len)
            .ok_or_else(|| malformed("invalid PKCS#7/CMS length"))?;
        Ok(Some(Tlv {
            tag: header.tag,
            encoded,
            value,
        }))
    }

    fn peek_tag(&self) -> Result<Option<Tag>, LoadError> {
        let Some(remaining) = self.input.get(self.offset..) else {
            return Err(malformed("incomplete PKCS#7/CMS structure"));
        };
        if remaining.is_empty() {
            return Ok(None);
        }
        let mut reader =
            SliceReader::new(remaining).map_err(|_| malformed("invalid PKCS#7/CMS structure"))?;
        Ok(Some(
            Header::decode(&mut reader)
                .map_err(|_| malformed("invalid PKCS#7/CMS length"))?
                .tag,
        ))
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.input.len()
    }
}

/// Extracts only X.509 certificates from CMS `SignedData`.
///
/// # Errors
///
/// Returns a sanitized malformed error when the input is not a valid CMS
/// `ContentInfo` / `SignedData` envelope.
#[cfg(test)]
pub(crate) fn extract_pkcs7_certs(der: &[u8], limits: &Limits) -> Result<Vec<Vec<u8>>, LoadError> {
    Ok(extract_pkcs7_certs_with_metadata(der, limits)?.certs)
}

/// Extracts certificates and bounded truncation metadata for loader callers.
pub(crate) fn extract_pkcs7_certs_with_metadata(
    der: &[u8],
    limits: &Limits,
) -> Result<Pkcs7Extraction, LoadError> {
    extract_pkcs7_certs_excluding(der, limits, &HashSet::new())
}

/// Extracts certificates while accounting for DER values already kept.
pub(crate) fn extract_pkcs7_certs_excluding(
    der: &[u8],
    limits: &Limits,
    already_seen: &HashSet<Digest<32>>,
) -> Result<Pkcs7Extraction, LoadError> {
    let content_info = one_tlv(der)?;
    require_tag(content_info, Tag::Sequence)?;
    let mut content_fields = DerCursor::new(content_info.value);
    let oid = required_tlv(&mut content_fields)?;
    require_tag(oid, Tag::ObjectIdentifier)?;
    ObjectIdentifier::from_der(oid.encoded)
        .map_err(|_| malformed("invalid PKCS#7/CMS content type"))?;
    let content = required_tlv(&mut content_fields)?;
    require_context_tag(content, 0, true)?;
    require_finished(&content_fields)?;
    if oid.value != SIGNED_DATA_OID_VALUE {
        return Ok(Pkcs7Extraction::default());
    }

    let signed_data = one_tlv(content.value)?;
    require_tag(signed_data, Tag::Sequence)?;
    extract_signed_data(signed_data.value, limits, already_seen)
}

fn extract_signed_data(
    encoded: &[u8],
    limits: &Limits,
    already_seen: &HashSet<Digest<32>>,
) -> Result<Pkcs7Extraction, LoadError> {
    let mut fields = DerCursor::new(encoded);
    let version = required_tlv(&mut fields)?;
    require_tag(version, Tag::Integer)?;
    CmsVersion::from_der(version.encoded).map_err(|_| malformed("invalid PKCS#7/CMS version"))?;

    let algorithms = required_tlv(&mut fields)?;
    require_tag(algorithms, Tag::Set)?;
    validate_children(algorithms.value)?;

    let encapsulated = required_tlv(&mut fields)?;
    require_tag(encapsulated, Tag::Sequence)?;
    validate_encapsulated_content(encapsulated.value)?;

    let mut collector = CertificateCollector {
        limits,
        already_seen,
        seen: HashSet::new(),
        output: Pkcs7Extraction::default(),
    };
    if fields.peek_tag()? == Some(context_tag(0, true)) {
        let certificates = required_tlv(&mut fields)?;
        collector.collect(certificates.value)?;
    }
    if fields.peek_tag()? == Some(context_tag(1, true)) {
        let crls = required_tlv(&mut fields)?;
        validate_children(crls.value)?;
    }
    let signer_infos = required_tlv(&mut fields)?;
    require_tag(signer_infos, Tag::Set)?;
    validate_children(signer_infos.value)?;
    require_finished(&fields)?;
    Ok(collector.output)
}

fn validate_encapsulated_content(encoded: &[u8]) -> Result<(), LoadError> {
    let mut fields = DerCursor::new(encoded);
    let content_type = required_tlv(&mut fields)?;
    require_tag(content_type, Tag::ObjectIdentifier)?;
    ObjectIdentifier::from_der(content_type.encoded)
        .map_err(|_| malformed("invalid PKCS#7/CMS content type"))?;
    if let Some(tag) = fields.peek_tag()? {
        if tag != context_tag(0, true) {
            return Err(malformed("invalid PKCS#7/CMS encapsulated content"));
        }
        let content = required_tlv(&mut fields)?;
        let octets = one_tlv(content.value)?;
        require_tag(octets, Tag::OctetString)?;
    }
    require_finished(&fields)
}

fn validate_children(encoded: &[u8]) -> Result<(), LoadError> {
    let mut children = DerCursor::new(encoded);
    while children.next()?.is_some() {}
    Ok(())
}

fn one_tlv(encoded: &[u8]) -> Result<Tlv<'_>, LoadError> {
    let mut cursor = DerCursor::new(encoded);
    let tlv = required_tlv(&mut cursor)?;
    require_finished(&cursor)?;
    Ok(tlv)
}

fn required_tlv<'a>(cursor: &mut DerCursor<'a>) -> Result<Tlv<'a>, LoadError> {
    cursor
        .next()?
        .ok_or_else(|| malformed("incomplete PKCS#7/CMS structure"))
}

fn require_tag(tlv: Tlv<'_>, expected: Tag) -> Result<(), LoadError> {
    if tlv.tag == expected {
        Ok(())
    } else {
        Err(malformed("invalid PKCS#7/CMS structure"))
    }
}

fn require_context_tag(tlv: Tlv<'_>, number: u8, constructed: bool) -> Result<(), LoadError> {
    let expected = context_tag(number, constructed);
    if tlv.tag == expected {
        Ok(())
    } else {
        Err(malformed("invalid PKCS#7/CMS content"))
    }
}

const fn context_tag(number: u8, constructed: bool) -> Tag {
    let number = match number {
        0 => TagNumber::N0,
        _ => TagNumber::N1,
    };
    Tag::ContextSpecific {
        constructed,
        number,
    }
}

fn require_finished(cursor: &DerCursor<'_>) -> Result<(), LoadError> {
    if cursor.is_finished() {
        Ok(())
    } else {
        Err(malformed("trailing PKCS#7/CMS data"))
    }
}

fn malformed(message: &'static str) -> LoadError {
    LoadError::Malformed(message.to_owned())
}

/// The bytes after the header of a top-level DER `SEQUENCE`, when `der`
/// starts with one. The declared length is not validated.
fn sequence_content(der: &[u8]) -> Option<&[u8]> {
    if der.first() != Some(&0x30) {
        return None;
    }
    let length_byte = der.get(1).copied()?;
    let header_len = if length_byte & 0x80 == 0 {
        2
    } else {
        2_usize.saturating_add(usize::from(length_byte & 0x7F))
    };
    der.get(header_len..)
}

/// Whether the DER has a top-level CMS `ContentInfo` shape
/// (`SEQUENCE { OBJECT IDENTIFIER, ... }`).
///
/// Used only to distinguish malformed CMS from other binary inputs, without
/// formatting or retaining input bytes.
pub(crate) fn has_cms_content_info_prefix(der: &[u8]) -> bool {
    sequence_content(der).is_some_and(|content| content.first() == Some(&0x06))
}

/// Whether the DER has a PKCS#12 `PFX` shape (`SEQUENCE { INTEGER 3, ... }`).
pub(crate) fn has_pkcs12_pfx_prefix(der: &[u8]) -> bool {
    sequence_content(der).is_some_and(|content| content.starts_with(&[0x02, 0x01, 0x03]))
}

/// Whether the DER looks like an X.509 certificate (`SEQUENCE { SEQUENCE,
/// ... }`), even if it is truncated or otherwise malformed.
pub(crate) fn has_certificate_like_prefix(der: &[u8]) -> bool {
    sequence_content(der).is_some_and(|content| content.first() == Some(&0x30))
}

const SIGNED_DATA_OID_VALUE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

#[cfg(test)]
mod tests {
    use std::fs;

    use certtui_app::error::LoadError;

    use super::{
        extract_pkcs7_certs, extract_pkcs7_certs_with_metadata, has_certificate_like_prefix,
        has_cms_content_info_prefix, has_pkcs12_pfx_prefix,
    };
    use certtui_domain::limits::Limits;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(format!("{FIXTURES}/{name}")).unwrap()
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if value.len() < 128 {
            encoded.push(u8::try_from(value.len()).unwrap());
            encoded.extend_from_slice(value);
            return encoded;
        }
        if let Ok(medium_len) = u16::try_from(value.len()) {
            encoded.push(0x82);
            encoded.extend(medium_len.to_be_bytes());
        } else {
            encoded.push(0x84);
            encoded.extend(u32::try_from(value.len()).unwrap().to_be_bytes());
        }
        encoded.extend_from_slice(value);
        encoded
    }

    fn signed_data(certificates: &[u8], digest_algorithms: &[u8]) -> Vec<u8> {
        const DATA_OID: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
        ];
        const SIGNED_DATA_OID: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
        ];
        let mut fields = vec![0x02, 0x01, 0x01];
        fields.extend(tlv(0x31, digest_algorithms));
        fields.extend(tlv(0x30, DATA_OID));
        if !certificates.is_empty() {
            fields.extend(tlv(0xA0, certificates));
        }
        fields.extend([0x31, 0x00]);
        let signed = tlv(0x30, &fields);
        let mut content = SIGNED_DATA_OID.to_vec();
        content.extend(tlv(0xA0, &signed));
        tlv(0x30, &content)
    }

    #[test]
    fn quando_p7b_der_deve_extrair_cadeia_completa() {
        let certs = extract_pkcs7_certs(&fixture("chain-3.p7b"), &Limits::default()).unwrap();
        assert_eq!(certs.len(), 3);
        for der in certs {
            assert!(der.len() <= Limits::default().max_cert_der_bytes);
        }
    }

    #[test]
    fn quando_limite_exato_de_certificados_e_usado_nao_deve_marcar_truncamento() {
        let limits = Limits {
            max_certs_per_source: 3,
            ..Limits::default()
        };
        let extracted =
            extract_pkcs7_certs_with_metadata(&fixture("chain-3.p7b"), &limits).unwrap();
        assert_eq!(extracted.certs.len(), 3);
        assert!(!extracted.truncated);
    }

    #[test]
    fn quando_limite_de_der_e_menor_que_certificado_deve_ignorar_sem_conteudo() {
        let limits = Limits {
            max_cert_der_bytes: 1,
            ..Limits::default()
        };
        let extracted =
            extract_pkcs7_certs_with_metadata(&fixture("chain-3.p7b"), &limits).unwrap();
        assert_eq!(extracted.certs, Vec::<Vec<u8>>::new());
        assert_eq!(extracted.oversized, 3);
    }

    #[test]
    fn quando_der_tem_tamanho_exato_do_limite_deve_aceitar() {
        let der = fixture("chain-3.p7b");
        let all = extract_pkcs7_certs(&der, &Limits::default()).unwrap();
        let exact_limit = all.iter().map(Vec::len).max().unwrap();
        let limits = Limits {
            max_cert_der_bytes: exact_limit,
            ..Limits::default()
        };
        let extracted = extract_pkcs7_certs_with_metadata(&der, &limits).unwrap();
        assert_eq!(extracted.certs.len(), all.len());
        assert_eq!(extracted.oversized, 0);
    }

    #[test]
    fn quando_p7b_truncado_deve_retornar_erro_sanitizado() {
        let der = fixture("chain-3.p7b");
        let result = extract_pkcs7_certs(&der[..32], &Limits::default());
        assert_eq!(
            result,
            Err(LoadError::Malformed(
                "incomplete PKCS#7/CMS value".to_owned()
            ))
        );
        assert!(has_cms_content_info_prefix(&der[..32]));
        assert!(has_cms_content_info_prefix(&der[..6]));
    }

    #[test]
    fn quando_contem_choice_de_certificado_nao_x509_deve_manter_x509() {
        let certificate = fixture("rsa2048-leaf.der");
        let mut choices = certificate.clone();
        choices.extend(tlv(0xA1, &[0x02, 0x01, 0x00]));
        choices.extend(tlv(0xA2, &[0x02, 0x01, 0x00]));
        choices.extend(tlv(0xA3, &[0x30, 0x00]));
        let result = extract_pkcs7_certs(&signed_data(&choices, &[]), &Limits::default()).unwrap();
        assert_eq!(result, vec![certificate]);
    }

    #[test]
    fn quando_choice_sequence_nao_e_x509_deve_contar_como_ilegivel() {
        let certificate = fixture("rsa2048-leaf.der");
        let mut choices = certificate.clone();
        choices.extend(tlv(0x30, &[0x02, 0x01, 0x00]));
        choices.extend(tlv(0x30, &[0x02, 0x01, 0x01]));
        let extracted =
            extract_pkcs7_certs_with_metadata(&signed_data(&choices, &[]), &Limits::default())
                .unwrap();
        assert_eq!(extracted.certs, vec![certificate]);
        assert_eq!(extracted.unparsable, 2);
        assert_eq!(extracted.oversized, 0);
    }

    #[test]
    fn quando_der_tem_forma_conhecida_deve_classificar_o_prefixo() {
        let pfx = [0x30, 0x08, 0x02, 0x01, 0x03, 0x30, 0x03, 0x02, 0x01, 0x00];
        assert!(has_pkcs12_pfx_prefix(&pfx));
        assert!(!has_cms_content_info_prefix(&pfx));
        assert!(!has_certificate_like_prefix(&pfx));
        let cert = fixture("rsa2048-leaf.der");
        assert!(has_certificate_like_prefix(&cert));
        assert!(has_certificate_like_prefix(&cert[..40]));
        assert!(!has_pkcs12_pfx_prefix(&cert));
        assert!(has_cms_content_info_prefix(&fixture("chain-3.p7b")));
        // A log line starting with "0" is none of them.
        assert!(!has_certificate_like_prefix(b"09:15:02 INFO"));
        assert!(!has_pkcs12_pfx_prefix(b"09:15:02 INFO"));
        assert!(!has_cms_content_info_prefix(b"09:15:02 INFO"));
        assert!(!has_certificate_like_prefix(&[]));
    }

    #[test]
    fn quando_certificate_set_repete_x509_deve_deduplicar_preservando_bytes() {
        let certificate = fixture("rsa2048-leaf.der");
        let mut choices = certificate.clone();
        choices.extend_from_slice(&certificate);
        let result = extract_pkcs7_certs(&signed_data(&choices, &[]), &Limits::default()).unwrap();
        assert_eq!(result, vec![certificate]);
    }

    #[test]
    fn quando_cms_tem_length_interno_maior_que_bytes_disponiveis_deve_rejeitar() {
        const OID: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
        ];
        let mut content = OID.to_vec();
        content.extend([0xA0, 0x84, 0x00, 0x10, 0x00, 0x00]);
        let der = tlv(0x30, &content);
        assert!(matches!(
            extract_pkcs7_certs(&der, &Limits::default()),
            Err(LoadError::Malformed(_))
        ));
    }

    #[test]
    fn quando_cms_tem_muitos_algoritmos_nao_usados_deve_extrair_sem_materializa_los() {
        let mut algorithms = Vec::new();
        for value in 128_u16..4_128 {
            let oid_value = [
                0x2A,
                0x03,
                0x80 | u8::try_from(value >> 7).unwrap(),
                u8::try_from(value & 0x7F).unwrap(),
            ];
            let mut algorithm = tlv(0x06, &oid_value);
            algorithms.extend(tlv(0x30, &algorithm));
            algorithm.clear();
        }
        let der = signed_data(&[], &algorithms);
        let limits = Limits {
            max_certs_per_source: 1,
            ..Limits::default()
        };
        assert_eq!(
            extract_pkcs7_certs(&der, &limits).unwrap(),
            Vec::<Vec<u8>>::new()
        );
    }
}
