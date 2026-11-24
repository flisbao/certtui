//! Bounded extraction of X.509 certificates from CMS / PKCS#7 `SignedData`.

use std::collections::HashSet;

use certtui_app::error::LoadError;
use certtui_domain::limits::Limits;
use certtui_domain::model::{Digest, Fingerprints};
use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::{Decode, Encode};

/// Extraction output used by the source loader to report partial results.
#[derive(Debug, Default)]
pub(crate) struct Pkcs7Extraction {
    /// Certificate DER encodings kept within the configured limits.
    pub(crate) certs: Vec<Vec<u8>>,
    /// Whether another usable certificate was present beyond the cap.
    pub(crate) truncated: bool,
    /// Number of certificate choices exceeding the per-certificate size cap.
    pub(crate) oversized: usize,
}

/// Extracts only X.509 certificates from CMS `SignedData`.
///
/// # Errors
///
/// Returns a sanitized [`LoadError::Malformed`] when the input is not a valid
/// CMS `ContentInfo` / `SignedData` structure.
// Justificativa: este é o contrato planejado para consumidores sem metadados
// de truncamento; o loader usa o helper interno com metadados.
#[allow(dead_code)]
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

/// Extracts certificates while accounting for unique DER values already kept.
pub(crate) fn extract_pkcs7_certs_excluding(
    der: &[u8],
    limits: &Limits,
    already_seen: &HashSet<Digest<32>>,
) -> Result<Pkcs7Extraction, LoadError> {
    let content_info = ContentInfo::from_der(der)
        .map_err(|_| LoadError::Malformed("invalid PKCS#7/CMS structure".to_owned()))?;
    if content_info.content_type.to_der().ok().as_deref() != Some(SIGNED_DATA_OID) {
        return Ok(Pkcs7Extraction::default());
    }
    let signed_data = content_info
        .content
        .decode_as::<SignedData>()
        .map_err(|_| LoadError::Malformed("invalid PKCS#7/CMS SignedData".to_owned()))?;

    let mut output = Pkcs7Extraction::default();
    let mut seen = HashSet::new();
    let Some(certificates) = signed_data.certificates else {
        return Ok(output);
    };
    for choice in certificates.0.iter() {
        let CertificateChoices::Certificate(certificate) = choice else {
            continue;
        };
        let encoded_len = certificate
            .encoded_len()
            .map_err(|_| LoadError::Malformed("invalid certificate in PKCS#7/CMS".to_owned()))?;
        let Ok(encoded_len) = usize::try_from(encoded_len) else {
            output.oversized = output.oversized.saturating_add(1);
            continue;
        };
        if encoded_len > limits.max_cert_der_bytes {
            output.oversized = output.oversized.saturating_add(1);
            continue;
        }
        let encoded = certificate
            .to_der()
            .map_err(|_| LoadError::Malformed("invalid certificate in PKCS#7/CMS".to_owned()))?;
        let fingerprint = Fingerprints::compute(&encoded).sha256;
        if already_seen.contains(&fingerprint) || !seen.insert(fingerprint) {
            continue;
        }
        if output.certs.len() >= limits.max_certs_per_source {
            output.truncated = true;
            break;
        }
        output.certs.push(encoded);
    }
    Ok(output)
}

/// Whether the DER has a top-level CMS `ContentInfo` shape.
///
/// Used only to distinguish a malformed `.p7b` from the existing unsupported
/// PKCS#12 fallback, without formatting or retaining input bytes.
pub(crate) fn has_cms_content_info_prefix(der: &[u8]) -> bool {
    if der.first() != Some(&0x30) {
        return false;
    }
    let Some(length_byte) = der.get(1).copied() else {
        return false;
    };
    let header_len = if length_byte & 0x80 == 0 {
        2
    } else {
        2_usize.saturating_add(usize::from(length_byte & 0x7F))
    };
    der.get(header_len) == Some(&0x06)
}

const SIGNED_DATA_OID: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];

#[cfg(test)]
mod tests {
    use std::fs;

    use certtui_app::error::LoadError;

    use super::{
        extract_pkcs7_certs, extract_pkcs7_certs_with_metadata, has_cms_content_info_prefix,
    };
    use certtui_domain::limits::Limits;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(format!("{FIXTURES}/{name}")).unwrap()
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
                "invalid PKCS#7/CMS structure".to_owned()
            ))
        );
        assert!(has_cms_content_info_prefix(&der[..32]));
        assert!(has_cms_content_info_prefix(&der[..6]));
    }
}
