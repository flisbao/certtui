//! CRL (RFC 5280): signature, freshness, scope and serial lookup.

use certtui_app::revocation::RevocationError;
use certtui_domain::limits::Limits;
use certtui_domain::model::RevocationStatus;
use certtui_domain::time::Timestamp;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::extensions::{
    DistributionPointName, GeneralName, IssuingDistributionPoint, X509Extension,
};
use x509_parser::revocation_list::CertificateRevocationList;

use super::{CLOCK_SKEW_SECS, canonical_integer, ensure_issued_by, parse_cert};

/// `deltaCRLIndicator`.
const OID_DELTA_CRL_INDICATOR: &str = "2.5.29.27";

/// `issuingDistributionPoint`.
const OID_ISSUING_DISTRIBUTION_POINT: &str = "2.5.29.28";

/// Critical CRL extensions this module understands: `cRLNumber`,
/// `issuerAltName`, `issuingDistributionPoint`, `authorityKeyIdentifier`,
/// `freshestCRL`. `deltaCRLIndicator` is handled apart.
const KNOWN_CRITICAL_OIDS: [&str; 5] = [
    "2.5.29.20",
    "2.5.29.18",
    "2.5.29.28",
    "2.5.29.35",
    "2.5.29.46",
];

fn malformed(what: &str) -> RevocationError {
    RevocationError::Malformed(what.to_owned())
}

fn unknown(why: &str) -> RevocationStatus {
    RevocationStatus::Unknown {
        why: why.to_owned(),
    }
}

/// RFC 5280 `CRLReason` names (same spelling as the OCSP path).
fn reason_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "unspecified",
        1 => "keyCompromise",
        2 => "caCompromise",
        3 => "affiliationChanged",
        4 => "superseded",
        5 => "cessationOfOperation",
        6 => "certificateHold",
        8 => "removeFromCRL",
        9 => "privilegeWithdrawn",
        10 => "aaCompromise",
        _ => return None,
    })
}

fn check_freshness(crl: &CertificateRevocationList<'_>, now: i64) -> Result<(), RevocationError> {
    if crl.last_update().timestamp() > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(RevocationError::NotYetValid);
    }
    if let Some(next) = crl.next_update()
        && next.timestamp() < now.saturating_sub(CLOCK_SKEW_SECS)
    {
        return Err(RevocationError::Stale);
    }
    Ok(())
}

fn is_ca(cert: &X509Certificate<'_>) -> bool {
    cert.basic_constraints()
        .ok()
        .flatten()
        .is_some_and(|bc| bc.value.ca)
}

/// Whether `idp` names a distribution point the certificate does not list in
/// its own `cRLDistributionPoints` (RFC 5280 6.3.3 (b)(2)).
fn dp_mismatch(idp: &IssuingDistributionPoint<'_>, cert: &X509Certificate<'_>) -> bool {
    let Some(DistributionPointName::FullName(wanted)) = &idp.distribution_point else {
        return false;
    };
    let uris = |names: &[GeneralName<'_>]| -> Vec<String> {
        names
            .iter()
            .filter_map(|n| match n {
                GeneralName::URI(uri) => Some((*uri).to_owned()),
                _ => None,
            })
            .collect()
    };
    let wanted = uris(wanted);
    let listed = cert
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::CRLDistributionPoints(points) => Some(points),
            _ => None,
        });
    let Some(listed) = listed else { return true };
    !listed
        .points
        .iter()
        .any(|point| match &point.distribution_point {
            Some(DistributionPointName::FullName(names)) => {
                uris(names).iter().any(|uri| wanted.contains(uri))
            }
            _ => false,
        })
}

/// Why `idp` makes the CRL unusable for `cert`, if it does.
fn idp_excludes(
    idp: &IssuingDistributionPoint<'_>,
    cert: &X509Certificate<'_>,
) -> Option<&'static str> {
    if idp.indirect_crl {
        return Some("unsupported crl scope: indirect crl");
    }
    if idp.only_contains_attribute_certs {
        return Some("unsupported crl scope: attribute certificates only");
    }
    if idp.only_some_reasons.is_some() {
        return Some("unsupported crl scope: covers only some revocation reasons");
    }
    if idp.only_contains_ca_certs && !is_ca(cert) {
        return Some("unsupported crl scope: covers only CA certificates");
    }
    if idp.only_contains_user_certs && is_ca(cert) {
        return Some("unsupported crl scope: covers only end-entity certificates");
    }
    if matches!(
        idp.distribution_point,
        Some(DistributionPointName::NameRelativeToCRLIssuer(_))
    ) {
        return Some("unsupported crl scope: relative distribution point name");
    }
    if dp_mismatch(idp, cert) {
        return Some("unsupported crl scope: distribution point does not match the certificate");
    }
    None
}

/// Why this CRL cannot answer for `cert`, when it cannot (RFC 5280 5.2.5).
fn unsupported_scope(
    extensions: &[X509Extension<'_>],
    cert: &X509Certificate<'_>,
) -> Option<&'static str> {
    if extensions
        .iter()
        .any(|ext| ext.oid.to_id_string() == OID_DELTA_CRL_INDICATOR)
    {
        return Some("unsupported crl scope: delta crl");
    }
    let unknown_critical = extensions
        .iter()
        .any(|ext| ext.critical && !KNOWN_CRITICAL_OIDS.contains(&ext.oid.to_id_string().as_str()));
    if unknown_critical {
        return Some("unsupported crl scope: unknown critical extension");
    }
    for ext in extensions {
        if ext.oid.to_id_string() != OID_ISSUING_DISTRIBUTION_POINT {
            continue;
        }
        let ParsedExtension::IssuingDistributionPoint(idp) = ext.parsed_extension() else {
            return Some("unsupported crl scope: unreadable issuingDistributionPoint");
        };
        if let Some(why) = idp_excludes(idp, cert) {
            return Some(why);
        }
    }
    None
}

pub(super) fn evaluate(
    crl_der: &[u8],
    cert_der: &[u8],
    issuer_der: &[u8],
    now: Timestamp,
) -> Result<RevocationStatus, RevocationError> {
    if crl_der.len() > Limits::HARD_CAPS.max_crl_bytes {
        return Err(RevocationError::TooLarge);
    }
    let cert = parse_cert(cert_der)?;
    let issuer = parse_cert(issuer_der)?;
    ensure_issued_by(&cert, &issuer)?;
    if issuer
        .key_usage()
        .ok()
        .flatten()
        .is_some_and(|ku| !ku.value.crl_sign())
    {
        return Ok(unknown(
            "issuer is not allowed to sign CRLs (keyUsage lacks cRLSign)",
        ));
    }
    let (_, crl) =
        x509_parser::parse_x509_crl(crl_der).map_err(|_| malformed("CRL does not parse"))?;
    crl.verify_signature(issuer.public_key())
        .map_err(|_| RevocationError::BadSignature)?;
    if crl.issuer().as_raw() != issuer.subject().as_raw() {
        return Ok(unknown("crl was issued by a different CA"));
    }
    if crl.next_update().is_none() {
        return Ok(unknown("crl has no nextUpdate"));
    }
    check_freshness(&crl, now.unix())?;
    if let Some(why) = unsupported_scope(crl.extensions(), &cert) {
        return Ok(unknown(why));
    }
    let serial = canonical_integer(cert.raw_serial());
    let listed = crl
        .iter_revoked_certificates()
        .find(|entry| canonical_integer(entry.raw_serial()) == serial);
    Ok(match listed {
        None => RevocationStatus::Good,
        Some(entry) => RevocationStatus::Revoked {
            reason: entry
                .reason_code()
                .and_then(|(_, code)| reason_name(code.0))
                .map(str::to_owned),
            at: Some(Timestamp::from_unix_saturating(
                entry.revocation_date.timestamp(),
            )),
        },
    })
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

    /// 2026-11-02T00:00:00Z.
    fn now() -> Timestamp {
        Timestamp::from_unix_saturating(1_793_577_600)
    }

    fn eval(crl: &[u8], cert: &[u8]) -> Result<RevocationStatus, RevocationError> {
        evaluate(crl, cert, CA, now())
    }

    fn assert_unknown_with(got: &Result<RevocationStatus, RevocationError>, needle: &str) {
        match got {
            Ok(RevocationStatus::Unknown { why }) => {
                assert!(why.contains(needle), "why = {why:?}, wanted {needle:?}");
            }
            other => panic!("expected Unknown containing {needle:?}, got {other:?}"),
        }
    }

    #[test]
    fn quando_serial_esta_na_crl_deve_dar_revoked_com_motivo() {
        let got = eval(fixture!("crl-with-revoked.der"), REVOKED);
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
    fn quando_serial_nao_esta_deve_dar_good() {
        assert_eq!(
            eval(fixture!("crl-with-revoked.der"), GOOD),
            Ok(RevocationStatus::Good)
        );
        assert_eq!(
            eval(fixture!("crl-without-leaf.der"), REVOKED),
            Ok(RevocationStatus::Good)
        );
    }

    #[test]
    fn quando_assinatura_invalida_deve_dar_bad_signature() {
        let got = eval(fixture!("crl-bad-signature.der"), REVOKED);
        assert_eq!(got, Err(RevocationError::BadSignature));
    }

    #[test]
    fn quando_sem_next_update_deve_dar_unknown_com_motivo() {
        let got = eval(fixture!("crl-no-next-update.der"), REVOKED);
        assert_unknown_with(&got, "no nextUpdate");
    }

    #[test]
    fn quando_crl_delta_deve_dar_unknown_scope() {
        let got = eval(fixture!("crl-delta.der"), REVOKED);
        assert_unknown_with(&got, "unsupported crl scope");
    }

    #[test]
    fn quando_idp_cobre_so_cas_e_o_cert_e_folha_deve_dar_unknown_scope() {
        let got = eval(fixture!("crl-idp-ca-only.der"), REVOKED);
        assert_unknown_with(&got, "only CA certificates");
    }

    #[test]
    fn quando_idp_tem_distribution_point_igual_ao_do_cert_deve_valer() {
        let got = eval(fixture!("crl-idp-matching-dp.der"), REVOKED);
        assert!(
            matches!(got, Ok(RevocationStatus::Revoked { .. })),
            "{got:?}"
        );
    }

    #[test]
    fn quando_idp_tem_distribution_point_diferente_do_cert_deve_dar_unknown_scope() {
        // The CRL does not list the serial, but it is another partition: never `Good`.
        let got = eval(fixture!("crl-idp-other-dp.der"), REVOKED);
        assert_unknown_with(&got, "distribution point does not match");
    }

    #[test]
    fn quando_idp_nao_pode_ser_lido_deve_dar_unknown_e_nao_ignorar() {
        let got = eval(fixture!("crl-idp-garbage.der"), REVOKED);
        assert_unknown_with(&got, "unreadable issuingDistributionPoint");
    }

    #[test]
    fn quando_emissor_nao_tem_crl_sign_deve_dar_unknown_com_motivo() {
        let got = evaluate(
            fixture!("crl-no-crlsign.der"),
            fixture!("leaf-no-crlsign.der"),
            fixture!("ca-no-crlsign.der"),
            now(),
        );
        assert_unknown_with(&got, "cRLSign");
    }

    #[test]
    fn quando_cert_nao_foi_emitido_pelo_emissor_deve_dar_issuer_mismatch() {
        let got = evaluate(
            fixture!("crl-with-revoked.der"),
            fixture!("leaf-forged.der"),
            CA,
            now(),
        );
        assert_eq!(got, Err(RevocationError::IssuerMismatch));
        let got = evaluate(
            fixture!("crl-with-revoked.der"),
            REVOKED,
            fixture!("ca-no-crlsign.der"),
            now(),
        );
        assert_eq!(got, Err(RevocationError::IssuerMismatch));
    }

    #[test]
    fn quando_crl_vencida_deve_dar_stale() {
        let got = eval(fixture!("crl-stale.der"), REVOKED);
        assert_eq!(got, Err(RevocationError::Stale));
    }

    #[test]
    fn quando_crl_ainda_nao_vale_deve_dar_not_yet_valid() {
        let early = Timestamp::from_unix_saturating(1_793_577_600 - 18 * 86_400);
        let got = evaluate(fixture!("crl-with-revoked.der"), REVOKED, CA, early);
        assert_eq!(got, Err(RevocationError::NotYetValid));
    }

    #[test]
    fn quando_crl_passa_do_limite_deve_dar_too_large() {
        let big = vec![0_u8; Limits::HARD_CAPS.max_crl_bytes + 1];
        assert_eq!(eval(&big, REVOKED), Err(RevocationError::TooLarge));
    }

    #[test]
    fn quando_crl_e_lixo_deve_dar_malformed() {
        for junk in [
            &b""[..],
            b"<html>not a crl</html>",
            &[0x30, 0x03, 0x02, 0x01],
        ] {
            let got = eval(junk, REVOKED);
            assert!(
                matches!(got, Err(RevocationError::Malformed(_))),
                "{junk:?} -> {got:?}"
            );
        }
    }
}
