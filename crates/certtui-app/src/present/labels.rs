//! Human-readable labels for domain values, shared by the text and JSON
//! renderers. Pure functions; free text is sanitized and kept on one line by
//! `single_line`.

use certtui_domain::finding::{Finding, Severity};
use certtui_domain::model::{
    CertOrigin, ExtendedKeyUsage, HashAlgorithm, KeyUsage, LoadNote, PublicKeyAlgorithm,
    RejectReason, SubjectAltName, TrustVerdict,
};
use certtui_domain::sanitize::sanitize_display;

/// Single-line display form of certificate-derived text.
///
/// `sanitize_display` keeps `\n` and `\t`, and most certificate strings (SAN
/// and AIA/CRL URLs, paths, ...) are not escaped by the domain, so they could
/// forge output lines. Line breaks and tabs are shown as the literal sequences
/// `\n`, `\r` and `\t` (nothing is dropped), then the remaining terminal
/// controls are removed.
#[must_use]
pub fn single_line(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    sanitize_display(&escaped).into_owned()
}

/// One-line description of a trust verdict.
#[must_use]
pub fn trust_text(trust: &TrustVerdict) -> String {
    match trust {
        TrustVerdict::Trusted { anchor } => format!("trusted (anchor: {})", single_line(anchor)),
        TrustVerdict::Untrusted { reason } => format!("untrusted ({})", single_line(reason)),
        TrustVerdict::NotEvaluated => "not evaluated".to_owned(),
    }
}

/// Lower-case name of a severity.
#[must_use]
pub fn severity_text(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    }
}

/// One-line description of a finding: `error EXPIRED [cert 0]: message`.
#[must_use]
pub fn finding_text(finding: &Finding) -> String {
    let cert = finding
        .cert_index
        .map_or_else(String::new, |index| format!(" [cert {index}]"));
    format!(
        "{} {}{cert}: {}",
        severity_text(finding.severity),
        finding.code.as_str(),
        single_line(&finding.message)
    )
}

/// Name of a public key algorithm family.
#[must_use]
pub fn public_key_algorithm(algorithm: &PublicKeyAlgorithm) -> String {
    match algorithm {
        PublicKeyAlgorithm::Rsa => "RSA".to_owned(),
        PublicKeyAlgorithm::EcP256 => "EC P-256".to_owned(),
        PublicKeyAlgorithm::EcP384 => "EC P-384".to_owned(),
        PublicKeyAlgorithm::EcP521 => "EC P-521".to_owned(),
        PublicKeyAlgorithm::Ed25519 => "Ed25519".to_owned(),
        PublicKeyAlgorithm::Ed448 => "Ed448".to_owned(),
        PublicKeyAlgorithm::Other(oid) => oid.clone(),
    }
}

/// Lower-case name of a signature hash.
#[must_use]
pub fn hash_name(hash: HashAlgorithm) -> &'static str {
    match hash {
        HashAlgorithm::Md5 => "md5",
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha224 => "sha224",
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha384 => "sha384",
        HashAlgorithm::Sha512 => "sha512",
        HashAlgorithm::None => "none",
        HashAlgorithm::Other => "other",
    }
}

/// RFC 5280 names of the set key usage bits, in bit order.
#[must_use]
pub fn key_usage_names(usage: &KeyUsage) -> Vec<&'static str> {
    [
        (usage.digital_signature, "digitalSignature"),
        (usage.non_repudiation, "nonRepudiation"),
        (usage.key_encipherment, "keyEncipherment"),
        (usage.data_encipherment, "dataEncipherment"),
        (usage.key_agreement, "keyAgreement"),
        (usage.key_cert_sign, "keyCertSign"),
        (usage.crl_sign, "cRLSign"),
        (usage.encipher_only, "encipherOnly"),
        (usage.decipher_only, "decipherOnly"),
    ]
    .into_iter()
    .filter_map(|(set, name)| set.then_some(name))
    .collect()
}

/// Name of an extended key usage purpose (the dotted OID when unknown).
#[must_use]
pub fn extended_key_usage(usage: &ExtendedKeyUsage) -> String {
    match usage {
        ExtendedKeyUsage::ServerAuth => "serverAuth".to_owned(),
        ExtendedKeyUsage::ClientAuth => "clientAuth".to_owned(),
        ExtendedKeyUsage::CodeSigning => "codeSigning".to_owned(),
        ExtendedKeyUsage::EmailProtection => "emailProtection".to_owned(),
        ExtendedKeyUsage::TimeStamping => "timeStamping".to_owned(),
        ExtendedKeyUsage::OcspSigning => "OCSPSigning".to_owned(),
        ExtendedKeyUsage::Any => "anyExtendedKeyUsage".to_owned(),
        ExtendedKeyUsage::Other(oid) => oid.clone(),
    }
}

/// Kind tag and value of a subject alternative name.
#[must_use]
pub fn san_parts(san: &SubjectAltName) -> (&'static str, String) {
    match san {
        SubjectAltName::Dns(name) => ("dns", name.clone()),
        SubjectAltName::Ip(ip) => ("ip", ip.to_string()),
        SubjectAltName::Email(email) => ("email", email.clone()),
        SubjectAltName::Uri(uri) => ("uri", uri.clone()),
        SubjectAltName::Other { kind } => ("other", kind.clone()),
    }
}

/// `DNS:example.com`-style rendering of a subject alternative name.
#[must_use]
pub fn san_text(san: &SubjectAltName) -> String {
    match san {
        SubjectAltName::Dns(name) => format!("DNS:{name}"),
        SubjectAltName::Ip(ip) => format!("IP:{ip}"),
        SubjectAltName::Email(email) => format!("email:{email}"),
        SubjectAltName::Uri(uri) => format!("URI:{uri}"),
        SubjectAltName::Other { kind } => format!("other:{kind}"),
    }
}

/// One-line description of where a certificate came from.
#[must_use]
pub fn origin_text(origin: &CertOrigin) -> String {
    match origin {
        CertOrigin::Presented { position } => format!("presented by server, position {position}"),
        CertOrigin::AiaFetched { url } => format!("fetched from {url}"),
        CertOrigin::File { path, index } => format!("file {} #{index}", path.display()),
        CertOrigin::Stdin { index } => format!("stdin #{index}"),
        CertOrigin::Keystore { path, alias } => {
            format!("keystore {} alias {alias}", path.display())
        }
    }
}

fn reject_reason(reason: RejectReason) -> &'static str {
    match reason {
        RejectReason::UnterminatedPem => "PEM block without END line",
        RejectReason::LabelMismatch => "PEM BEGIN and END labels differ",
        RejectReason::InvalidBase64 => "invalid base64 body",
        RejectReason::NotDerSequence => "decoded bytes are not a DER sequence",
        RejectReason::LengthMismatch => "DER length does not match the data",
        RejectReason::TooLarge => "block exceeds the size limit",
        RejectReason::UnsupportedLabel => "PEM label is not a certificate",
        RejectReason::NestingTooDeep => "DER nesting is too deep",
    }
}

/// One-line description of a load diagnostic (never any content).
#[must_use]
pub fn note_text(note: &LoadNote) -> String {
    match note {
        LoadNote::HandshakeFailedAfterClientCertRequest { peer_ip } => {
            format!("TLS handshake with {peer_ip} failed after a client certificate request")
        }
        LoadNote::Rejected { offset, reason } => {
            format!(
                "candidate at offset {offset} rejected: {}",
                reject_reason(*reason)
            )
        }
        LoadNote::PrivateKeyBlocksIgnored { count } => {
            format!("{count} private key block(s) ignored")
        }
        LoadNote::Unparsable {
            offset: Some(offset),
        } => {
            format!("data at offset {offset} is not a parsable certificate")
        }
        LoadNote::Unparsable { offset: None } => {
            "a candidate is not a parsable certificate".to_owned()
        }
        LoadNote::TruncatedAtCertLimit { limit } => {
            format!("stopped at the limit of {limit} certificates")
        }
        LoadNote::DiagnosticsTruncated { limit } => {
            format!("more diagnostics dropped (limit {limit})")
        }
        LoadNote::DirectoryTruncated { limit } => {
            format!("directory scan stopped at {limit} entries")
        }
        LoadNote::Unreadable { path } => path_note(
            path.as_deref(),
            "could not be read",
            "an entry could not be read",
        ),
        LoadNote::UnsupportedFormat { path } => path_note(
            path.as_deref(),
            "unsupported format (JKS and PKCS#12 keystores arrive in a later release)",
            "unsupported format (JKS and PKCS#12 keystores arrive in a later release)",
        ),
        LoadNote::NoCandidates { path } => path_note(
            path.as_deref(),
            "no certificate candidates found",
            "no certificate candidates found",
        ),
        LoadNote::FileTooLarge { path, limit } => {
            let message = format!("larger than the limit of {limit} bytes");
            path_note(path.as_deref(), &message, &format!("input is {message}"))
        }
        LoadNote::MalformedInput { path } => {
            path_note(path.as_deref(), "malformed input", "malformed input")
        }
    }
}

/// `"<path>: <with_path>"` when the note names a path, else `without_path`.
/// The path is rendered on one line without control characters.
fn path_note(path: Option<&str>, with_path: &str, without_path: &str) -> String {
    match path {
        Some(path) => format!("{}: {with_path}", single_line(path)),
        None => without_path.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_key_usage_deve_listar_so_os_bits_ligados_em_ordem() {
        let usage = KeyUsage {
            key_cert_sign: true,
            digital_signature: true,
            ..KeyUsage::default()
        };
        assert_eq!(key_usage_names(&usage), ["digitalSignature", "keyCertSign"]);
        assert_eq!(key_usage_names(&KeyUsage::default()), Vec::<&str>::new());
    }

    #[test]
    fn quando_san_deve_ter_prefixo_estilo_openssl() {
        let ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
        assert_eq!(
            san_text(&SubjectAltName::Dns("a.test".to_owned())),
            "DNS:a.test"
        );
        assert_eq!(san_text(&SubjectAltName::Ip(ip)), "IP:192.0.2.1");
        assert_eq!(
            san_text(&SubjectAltName::Other {
                kind: "directoryName".to_owned()
            }),
            "other:directoryName"
        );
    }

    #[test]
    fn quando_single_line_deve_escapar_quebras_sem_perder_nada() {
        assert_eq!(single_line("a\nb\tc\rd"), r"a\nb\tc\rd");
        assert_eq!(single_line("a\u{1b}[31mb\u{202E}"), "a[31mb");
        assert_eq!(single_line("limpo ção"), "limpo ção");
    }

    #[test]
    fn quando_note_tem_caminho_deve_nomear_o_arquivo_em_uma_linha() {
        assert_eq!(
            note_text(&LoadNote::Unreadable {
                path: Some("sub/a.pem".to_owned())
            }),
            "sub/a.pem: could not be read"
        );
        assert_eq!(
            note_text(&LoadNote::UnsupportedFormat {
                path: Some("k.jks".to_owned())
            }),
            "k.jks: unsupported format (JKS and PKCS#12 keystores arrive in a later release)"
        );
        assert_eq!(
            note_text(&LoadNote::NoCandidates {
                path: Some("notes.txt".to_owned())
            }),
            "notes.txt: no certificate candidates found"
        );
        assert_eq!(
            note_text(&LoadNote::FileTooLarge {
                path: Some("big".to_owned()),
                limit: 7
            }),
            "big: larger than the limit of 7 bytes"
        );
        assert_eq!(
            note_text(&LoadNote::MalformedInput {
                path: Some("x.p7b".to_owned())
            }),
            "x.p7b: malformed input"
        );
        assert_eq!(
            note_text(&LoadNote::Unreadable {
                path: Some("a\nb\u{1b}[31m".to_owned())
            }),
            r"a\nb[31m: could not be read"
        );
    }

    #[test]
    fn quando_note_sem_caminho_deve_descrever_sem_prefixo() {
        assert_eq!(
            note_text(&LoadNote::NoCandidates { path: None }),
            "no certificate candidates found"
        );
        assert_eq!(
            note_text(&LoadNote::Unreadable { path: None }),
            "an entry could not be read"
        );
        assert_eq!(
            note_text(&LoadNote::FileTooLarge {
                path: None,
                limit: 7
            }),
            "input is larger than the limit of 7 bytes"
        );
    }

    #[test]
    fn quando_note_deve_descrever_sem_conteudo() {
        assert_eq!(
            note_text(&LoadNote::PrivateKeyBlocksIgnored { count: 2 }),
            "2 private key block(s) ignored"
        );
        assert_eq!(
            note_text(&LoadNote::Rejected {
                offset: 7,
                reason: RejectReason::InvalidBase64
            }),
            "candidate at offset 7 rejected: invalid base64 body"
        );
    }
}
