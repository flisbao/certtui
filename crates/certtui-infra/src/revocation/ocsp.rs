//! OCSP (RFC 6960): request encoding and response verification.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use certtui_app::revocation::{OcspRequest, RevocationError};
use certtui_domain::model::RevocationStatus;
use certtui_domain::time::Timestamp;
use der::{Decode, Encode};
use sha1::Digest as _;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspGeneralizedTime, OcspResponse, OcspResponseStatus,
    ResponderId, SingleResponse,
};
use x509_parser::asn1_rs::BitString;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo};

use super::{CLOCK_SKEW_SECS, canonical_integer, ensure_issued_by, parse_cert};

/// A response without `nextUpdate` cannot say how long it stays valid; accept
/// it only when it is this fresh (7 days), in seconds.
const OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS: i64 = 7 * 24 * 60 * 60;

const OID_SHA1: &str = "1.3.14.3.2.26";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_PKIX_OCSP_BASIC: &str = "1.3.6.1.5.5.7.48.1.1";

#[derive(Clone, Copy)]
enum HashAlg {
    Sha1,
    Sha256,
}

impl HashAlg {
    fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            OID_SHA1 => Some(Self::Sha1),
            OID_SHA256 => Some(Self::Sha256),
            _ => None,
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
        }
    }
}

fn malformed(what: &str) -> RevocationError {
    RevocationError::Malformed(what.to_owned())
}

/// Big-endian bytes of a length, without leading zeros (DER long form).
fn significant_be_bytes(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes.get(first..).unwrap_or_default()
}

/// What identifies `cert` to its `issuer` in a `CertID`.
struct CertIdInput<'a> {
    issuer_name_raw: &'a [u8],
    issuer_key_bits: &'a [u8],
    serial: &'a [u8],
}

impl<'a> CertIdInput<'a> {
    fn new(cert: &'a X509Certificate<'_>, issuer: &'a X509Certificate<'_>) -> Self {
        Self {
            issuer_name_raw: issuer.subject().as_raw(),
            issuer_key_bits: &issuer.public_key().subject_public_key.data,
            serial: canonical_integer(cert.raw_serial()),
        }
    }

    fn matches(&self, id: &CertId) -> bool {
        let Some(alg) = HashAlg::from_oid(&id.hash_algorithm.oid.to_string()) else {
            return false;
        };
        id.issuer_name_hash.as_bytes() == alg.hash(self.issuer_name_raw)
            && id.issuer_key_hash.as_bytes() == alg.hash(self.issuer_key_bits)
            && canonical_integer(id.serial_number.as_bytes()) == self.serial
    }
}

// --- request ---------------------------------------------------------------

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![u8::try_from(len).unwrap_or(0)];
    }
    let bytes = len.to_be_bytes();
    let significant = significant_be_bytes(&bytes);
    let mut out = vec![0x80 | u8::try_from(significant.len()).unwrap_or(0)];
    out.extend_from_slice(significant);
    out
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// INTEGER body for a serial already in minimal two's-complement form.
fn integer_body(serial: &[u8]) -> Vec<u8> {
    if serial.is_empty() {
        vec![0]
    } else {
        serial.to_vec()
    }
}

/// Percent-encodes the characters of standard base64 that are not URL-safe.
fn percent_encode_base64(encoded: &str) -> String {
    encoded
        .chars()
        .map(|c| match c {
            '+' => "%2B".to_owned(),
            '/' => "%2F".to_owned(),
            '=' => "%3D".to_owned(),
            other => other.to_string(),
        })
        .collect()
}

pub(super) fn build_request(
    cert_der: &[u8],
    issuer_der: &[u8],
) -> Result<OcspRequest, RevocationError> {
    let cert = parse_cert(cert_der)?;
    let issuer = parse_cert(issuer_der)?;
    ensure_issued_by(&cert, &issuer)?;
    let input = CertIdInput::new(&cert, &issuer);
    let name_hash = HashAlg::Sha1.hash(input.issuer_name_raw);
    let key_hash = HashAlg::Sha1.hash(input.issuer_key_bits);

    let sha1_alg = tlv(
        0x30,
        &[tlv(0x06, &[0x2B, 0x0E, 0x03, 0x02, 0x1A]), vec![0x05, 0x00]].concat(),
    );
    let cert_id = tlv(
        0x30,
        &[
            sha1_alg,
            tlv(0x04, &name_hash),
            tlv(0x04, &key_hash),
            tlv(0x02, &integer_body(input.serial)),
        ]
        .concat(),
    );
    // OCSPRequest { TBSRequest { requestList { Request { reqCert } } } }
    let body = tlv(0x30, &tlv(0x30, &tlv(0x30, &tlv(0x30, &cert_id))));
    let get_url_suffix = percent_encode_base64(&STANDARD.encode(&body));
    Ok(OcspRequest {
        body,
        get_url_suffix,
        cache_key: (key_hash, input.serial.to_vec()),
    })
}

// --- response --------------------------------------------------------------

fn unix(time: &OcspGeneralizedTime) -> i64 {
    i64::try_from(time.0.to_unix_duration().as_secs()).unwrap_or(i64::MAX)
}

/// `KeyCompromise` becomes `keyCompromise`, the RFC 5280 spelling.
fn lower_first(name: &str) -> String {
    let mut chars = name.chars();
    chars
        .next()
        .map(|c| c.to_lowercase().chain(chars).collect())
        .unwrap_or_default()
}

fn check_status(status: OcspResponseStatus) -> Result<(), RevocationError> {
    if status == OcspResponseStatus::Successful {
        return Ok(());
    }
    Err(RevocationError::Unsuccessful(lower_first(&format!(
        "{status:?}"
    ))))
}

fn responder_matches(id: &ResponderId, subject_raw: &[u8], key_bits: &[u8]) -> bool {
    match id {
        ResponderId::ByName(name) => name.to_der().is_ok_and(|der| der == subject_raw),
        ResponderId::ByKey(hash) => hash.as_bytes() == HashAlg::Sha1.hash(key_bits),
    }
}

/// A delegated responder must be issued by the CA, carry `OCSPSigning` and be
/// valid now (RFC 6960 section 4.2.2.2).
fn delegated_is_authorized(
    responder: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
    now: i64,
) -> bool {
    let signed_by_issuer = responder
        .verify_signature(Some(issuer.public_key()))
        .is_ok();
    let has_eku = responder
        .extended_key_usage()
        .ok()
        .flatten()
        .is_some_and(|eku| eku.value.ocsp_signing);
    let valid_now =
        ASN1Time::from_timestamp(now).is_ok_and(|at| responder.validity().is_valid_at(at));
    signed_by_issuer && has_eku && valid_now
}

fn verify_signature(
    basic: &BasicOcspResponse,
    key: &SubjectPublicKeyInfo<'_>,
) -> Result<(), RevocationError> {
    let tbs = basic
        .tbs_response_data
        .to_der()
        .map_err(|_| malformed("response data does not encode"))?;
    let alg_der = basic
        .signature_algorithm
        .to_der()
        .map_err(|_| malformed("signature algorithm does not encode"))?;
    let (_, alg) = AlgorithmIdentifier::from_der(&alg_der)
        .map_err(|_| malformed("signature algorithm does not parse"))?;
    let bytes = basic
        .signature
        .as_bytes()
        .ok_or_else(|| malformed("signature has unused bits"))?;
    x509_parser::verify::verify_signature(key, &alg, &BitString::new(0, bytes), &tbs)
        .map_err(|_| RevocationError::BadSignature)
}

/// Verifies the response signature with the issuer's key or with an
/// authorized delegated responder embedded in the response.
fn verify_by_authorized_signer(
    basic: &BasicOcspResponse,
    issuer: &X509Certificate<'_>,
    now: i64,
) -> Result<(), RevocationError> {
    let id = &basic.tbs_response_data.responder_id;
    let issuer_key = issuer.public_key();
    if responder_matches(
        id,
        issuer.subject().as_raw(),
        &issuer_key.subject_public_key.data,
    ) {
        return verify_signature(basic, issuer_key);
    }
    for embedded in basic.certs.iter().flatten() {
        let Ok(der) = embedded.to_der() else { continue };
        let Ok(responder) = parse_cert(&der) else {
            continue;
        };
        let key = responder.public_key();
        if !responder_matches(
            id,
            responder.subject().as_raw(),
            &key.subject_public_key.data,
        ) {
            continue;
        }
        if !delegated_is_authorized(&responder, issuer, now) {
            return Err(RevocationError::ResponderNotAuthorized);
        }
        return verify_signature(basic, key);
    }
    Err(RevocationError::ResponderNotAuthorized)
}

fn check_freshness(single: &SingleResponse, now: i64) -> Result<(), RevocationError> {
    let this_update = unix(&single.this_update);
    if this_update > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(RevocationError::NotYetValid);
    }
    let stale = match &single.next_update {
        Some(next) => unix(next) < now.saturating_sub(CLOCK_SKEW_SECS),
        None => this_update < now.saturating_sub(OCSP_MAX_AGE_WITHOUT_NEXT_UPDATE_SECS),
    };
    if stale {
        return Err(RevocationError::Stale);
    }
    Ok(())
}

fn status_of(single: &SingleResponse) -> RevocationStatus {
    match &single.cert_status {
        CertStatus::Good(_) => RevocationStatus::Good,
        CertStatus::Revoked(info) => RevocationStatus::Revoked {
            reason: info
                .revocation_reason
                .map(|reason| lower_first(&format!("{reason:?}"))),
            at: Some(Timestamp::from_unix_saturating(unix(&info.revocation_time))),
        },
        CertStatus::Unknown(_) => RevocationStatus::Unknown {
            why: "the responder does not know this certificate".to_owned(),
        },
    }
}

pub(super) fn evaluate(
    response: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    now: Timestamp,
) -> Result<RevocationStatus, RevocationError> {
    let cert = parse_cert(cert_der)?;
    let issuer = parse_cert(issuer_der)?;
    ensure_issued_by(&cert, &issuer)?;
    let parsed =
        OcspResponse::from_der(response).map_err(|_| malformed("OCSP response does not parse"))?;
    check_status(parsed.response_status)?;
    let body = parsed
        .response_bytes
        .ok_or_else(|| malformed("successful response without a body"))?;
    if body.response_type.to_string() != OID_PKIX_OCSP_BASIC {
        return Err(malformed("unsupported OCSP response type"));
    }
    let basic = BasicOcspResponse::from_der(body.response.as_bytes())
        .map_err(|_| malformed("basic OCSP response does not parse"))?;
    let input = CertIdInput::new(&cert, &issuer);
    let single = basic
        .tbs_response_data
        .responses
        .iter()
        .find(|single| input.matches(&single.cert_id))
        .ok_or(RevocationError::CertIdMismatch)?;
    let now = now.unix();
    verify_by_authorized_signer(&basic, &issuer, now)?;
    check_freshness(single, now)?;
    Ok(status_of(single))
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/revocation/",
                $name
            ))
        };
    }

    const CA: &[u8] = fixture!("ca.der");
    const GOOD: &[u8] = fixture!("leaf-good.der");
    const REVOKED: &[u8] = fixture!("leaf-revoked.der");
    const UNKNOWN: &[u8] = fixture!("leaf-unknown.der");

    /// 2026-11-02T00:00:00Z: inside the validity of every "good" fixture.
    fn now() -> Timestamp {
        Timestamp::from_unix_saturating(1_793_577_600)
    }

    fn eval(response: &[u8], cert: &[u8]) -> Result<RevocationStatus, RevocationError> {
        evaluate(response, cert, CA, now())
    }

    #[test]
    fn quando_resposta_good_deve_dar_good() {
        assert_eq!(
            eval(fixture!("ocsp-good.der"), GOOD),
            Ok(RevocationStatus::Good)
        );
    }

    #[test]
    fn quando_revoked_deve_dar_revoked_com_reason_key_compromise_e_data() {
        let got = eval(fixture!("ocsp-revoked.der"), REVOKED);
        // 2026-10-15T00:00:00Z
        let at = Timestamp::from_unix_saturating(1_792_022_400);
        assert_eq!(
            got,
            Ok(RevocationStatus::Revoked {
                reason: Some("keyCompromise".to_owned()),
                at: Some(at),
            })
        );
    }

    #[test]
    fn quando_unknown_deve_dar_unknown() {
        let got = eval(fixture!("ocsp-unknown.der"), UNKNOWN);
        assert!(
            matches!(got, Ok(RevocationStatus::Unknown { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn quando_assinatura_invalida_deve_dar_bad_signature() {
        let got = eval(fixture!("ocsp-bad-signature.der"), GOOD);
        assert_eq!(got, Err(RevocationError::BadSignature));
    }

    #[test]
    fn quando_responder_delegado_com_eku_deve_aceitar() {
        let got = eval(fixture!("ocsp-delegated.der"), GOOD);
        assert_eq!(got, Ok(RevocationStatus::Good));
    }

    #[test]
    fn quando_responder_delegado_sem_eku_deve_dar_responder_not_authorized() {
        let got = eval(fixture!("ocsp-delegated-no-eku.der"), GOOD);
        assert_eq!(got, Err(RevocationError::ResponderNotAuthorized));
    }

    #[test]
    fn quando_resposta_e_de_outro_cert_deve_dar_cert_id_mismatch() {
        let got = eval(fixture!("ocsp-other-cert.der"), GOOD);
        assert_eq!(got, Err(RevocationError::CertIdMismatch));
    }

    #[test]
    fn quando_next_update_passou_deve_dar_stale() {
        let got = eval(fixture!("ocsp-expired.der"), GOOD);
        assert_eq!(got, Err(RevocationError::Stale));
    }

    #[test]
    fn quando_this_update_esta_no_futuro_deve_dar_not_yet_valid() {
        // 2026-10-15, two weeks before `thisUpdate`.
        let early = Timestamp::from_unix_saturating(1_793_577_600 - 18 * 86_400);
        let got = evaluate(fixture!("ocsp-good.der"), GOOD, CA, early);
        assert_eq!(got, Err(RevocationError::NotYetValid));
    }

    #[test]
    fn quando_try_later_deve_dar_unsuccessful() {
        let got = eval(fixture!("ocsp-try-later.der"), GOOD);
        assert_eq!(
            got,
            Err(RevocationError::Unsuccessful("tryLater".to_owned()))
        );
        let got = eval(fixture!("ocsp-unauthorized.der"), GOOD);
        assert_eq!(
            got,
            Err(RevocationError::Unsuccessful("unauthorized".to_owned()))
        );
    }

    #[test]
    fn quando_resposta_e_lixo_deve_dar_malformed() {
        for junk in [
            &b""[..],
            b"<html>502 Bad Gateway</html>",
            &[0x30, 0x03, 0x0A, 0x01],
        ] {
            let got = eval(junk, GOOD);
            assert!(
                matches!(got, Err(RevocationError::Malformed(_))),
                "{junk:?} -> {got:?}"
            );
        }
    }

    #[test]
    fn quando_cert_nao_foi_emitido_pelo_emissor_dado_deve_dar_issuer_mismatch() {
        let stranger = fixture!("responder.der");
        let got = evaluate(fixture!("ocsp-good.der"), GOOD, stranger, now());
        assert_eq!(got, Err(RevocationError::IssuerMismatch));
        assert_eq!(
            build_request(GOOD, stranger).map(|_| ()),
            Err(RevocationError::IssuerMismatch)
        );
    }

    #[test]
    fn quando_cert_forjado_tem_o_nome_do_emissor_mas_outra_assinatura_deve_dar_issuer_mismatch() {
        let got = evaluate(
            fixture!("ocsp-good.der"),
            fixture!("leaf-forged.der"),
            CA,
            now(),
        );
        assert_eq!(got, Err(RevocationError::IssuerMismatch));
    }

    #[test]
    fn quando_cert_ou_emissor_sao_lixo_deve_dar_malformed() {
        let got = evaluate(fixture!("ocsp-good.der"), b"nope", CA, now());
        assert!(matches!(got, Err(RevocationError::Malformed(_))));
        let got = evaluate(fixture!("ocsp-good.der"), GOOD, b"nope", now());
        assert!(matches!(got, Err(RevocationError::Malformed(_))));
    }

    #[test]
    fn quando_build_request_deve_gerar_der_parseavel_e_cache_key_estavel() {
        use x509_ocsp::OcspRequest as WireRequest;

        let first = build_request(REVOKED, CA).unwrap();
        let second = build_request(REVOKED, CA).unwrap();
        assert_eq!(first, second);

        let wire = WireRequest::from_der(&first.body).unwrap();
        let ids: Vec<_> = wire
            .tbs_request
            .request_list
            .iter()
            .map(|r| &r.req_cert)
            .collect();
        assert_eq!(ids.len(), 1);
        let id = ids.first().unwrap();
        assert_eq!(id.serial_number.as_bytes(), &[0x10, 0x02][..]);
        assert_eq!(id.issuer_key_hash.as_bytes(), first.cache_key.0.as_slice());
        assert_eq!(first.cache_key.1, vec![0x10, 0x02]);

        let other = build_request(GOOD, CA).unwrap();
        assert_ne!(other.cache_key, first.cache_key);
        assert_eq!(other.cache_key.0, first.cache_key.0);
    }

    #[test]
    fn quando_build_request_deve_gerar_sufixo_get_sem_caracteres_inseguros() {
        let req = build_request(GOOD, CA).unwrap();
        assert!(
            !req.get_url_suffix.contains(['+', '/', '=', ' ']),
            "{}",
            req.get_url_suffix
        );
        assert_ne!(req.get_url_suffix, "");
    }

    #[test]
    fn quando_pedido_e_resposta_do_mesmo_cert_deve_casar_o_cert_id() {
        // The CertID we encode must be the one OpenSSL-compatible responders echo.
        let req = build_request(GOOD, CA).unwrap();
        let wire = x509_ocsp::OcspRequest::from_der(&req.body).unwrap();
        let sent = wire
            .tbs_request
            .request_list
            .first()
            .unwrap()
            .req_cert
            .clone();
        let cert = parse_cert(GOOD).unwrap();
        let issuer = parse_cert(CA).unwrap();
        assert!(CertIdInput::new(&cert, &issuer).matches(&sent));
    }
}
