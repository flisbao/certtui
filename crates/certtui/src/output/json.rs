//! `--json`: the public, versioned machine-readable report.
//!
//! Contract: `schema_version` stays `1`; later milestones may only add fields.
//! Network targets add `tls`, `timings` and `ocsp_staple` (and the `sni` and
//! `connect_to` of the target); the documents of local targets do not carry
//! them.
//! Text taken from the certificate is passed through `sanitize_display` so the
//! output is also safe to show in a terminal (JSON escaping alone leaves C1
//! controls and bidi overrides untouched).

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io::{self, Write};

use std::time::Duration;

use certtui_domain::model::{
    CertOrigin, CertificateRecord, FingerprintAlgorithm, FingerprintFormat, InspectionReport,
    KeyId, LoadNote, Timings, TlsSessionInfo,
};
use certtui_domain::sanitize::sanitize_display;
use certtui_domain::target::Target;
use serde::Serialize;

use super::{View, labels};

/// Current JSON schema version.
pub const SCHEMA_VERSION: u8 = 1;

fn clean(text: &str) -> Cow<'_, str> {
    sanitize_display(text)
}

#[derive(Serialize)]
struct Document<'a> {
    schema_version: u8,
    target: JsonTarget<'a>,
    #[serde(flatten)]
    network: Option<JsonNetwork<'a>>,
    notes: &'a [LoadNote],
    certificates: Vec<JsonCertificate<'a>>,
}

#[derive(Serialize)]
struct JsonNetwork<'a> {
    tls: Option<JsonTls<'a>>,
    timings: JsonTimings,
    ocsp_staple: JsonStaple,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JsonTarget<'a> {
    Network {
        host: Cow<'a, str>,
        port: u16,
        sni: Option<Cow<'a, str>>,
        connect_to: Option<String>,
    },
    File {
        path: Cow<'a, str>,
    },
    Directory {
        path: Cow<'a, str>,
        recursive: bool,
    },
    Stdin,
}

#[derive(Serialize)]
struct JsonTls<'a> {
    version: Cow<'a, str>,
    cipher_suite: Cow<'a, str>,
    key_exchange_group: Option<Cow<'a, str>>,
    alpn: Option<Cow<'a, str>>,
    peer_ip: String,
}

/// Phase durations in whole milliseconds (`null` for a phase that did not run).
#[derive(Serialize)]
struct JsonTimings {
    dns: Option<u64>,
    connect: Option<u64>,
    handshake: Option<u64>,
    total: Option<u64>,
}

#[derive(Serialize)]
struct JsonStaple {
    present: bool,
    bytes: usize,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JsonOrigin<'a> {
    Presented {
        position: usize,
    },
    AiaFetched {
        url: Cow<'a, str>,
    },
    File {
        path: Cow<'a, str>,
        index: usize,
    },
    Stdin {
        index: usize,
    },
    Keystore {
        path: Cow<'a, str>,
        alias: Cow<'a, str>,
    },
}

#[derive(Serialize)]
struct JsonName<'a> {
    rfc4514: Cow<'a, str>,
    common_name: Option<Cow<'a, str>>,
}

#[derive(Serialize)]
struct JsonPublicKey<'a> {
    algorithm: String,
    bits: u32,
    curve: Option<Cow<'a, str>>,
}

#[derive(Serialize)]
struct JsonSignature<'a> {
    oid: Cow<'a, str>,
    name: Cow<'a, str>,
    hash: &'static str,
}

#[derive(Serialize)]
struct JsonSan<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    value: Cow<'a, str>,
}

#[derive(Serialize)]
struct JsonBasicConstraints {
    ca: bool,
    path_len: Option<u32>,
}

#[derive(Serialize)]
struct JsonAia<'a> {
    ocsp: Vec<Cow<'a, str>>,
    ca_issuers: Vec<Cow<'a, str>>,
}

#[derive(Serialize)]
struct JsonSct {
    version: u8,
    log_id: String,
    timestamp: String,
}

#[derive(Serialize)]
struct JsonExtension<'a> {
    oid: Cow<'a, str>,
    critical: bool,
    name: Cow<'a, str>,
    decode_error: bool,
}

#[derive(Serialize)]
struct JsonFingerprints {
    sha1: String,
    sha256: String,
    sha512: String,
}

#[derive(Serialize)]
struct JsonCertificate<'a> {
    index: usize,
    origin: JsonOrigin<'a>,
    version: u8,
    serial: String,
    subject: JsonName<'a>,
    issuer: JsonName<'a>,
    not_before: String,
    not_after: String,
    public_key: JsonPublicKey<'a>,
    signature_algorithm: JsonSignature<'a>,
    subject_alt_names: Vec<JsonSan<'a>>,
    basic_constraints: Option<JsonBasicConstraints>,
    key_usage: Option<Vec<&'static str>>,
    extended_key_usage: Vec<String>,
    subject_key_id: Option<String>,
    authority_key_id: Option<String>,
    aia: JsonAia<'a>,
    crl_distribution_points: Vec<Cow<'a, str>>,
    scts: Vec<JsonSct>,
    extensions: Vec<JsonExtension<'a>>,
    fingerprints: JsonFingerprints,
}

/// Writes the JSON document (pretty-printed, newline-terminated).
///
/// # Errors
///
/// Any I/O error of `out`.
pub fn write(out: &mut dyn Write, view: &View<'_>) -> io::Result<()> {
    let report = view.report;
    let is_network = matches!(report.target, Target::Network(_));
    let document = Document {
        schema_version: SCHEMA_VERSION,
        target: target(&report.target),
        network: is_network.then(|| JsonNetwork {
            tls: report.tls.as_ref().map(tls),
            timings: timings(&report.timings),
            ocsp_staple: staple(report),
        }),
        notes: &view.report.notes,
        certificates: view
            .certs()
            .map(|(index, record)| certificate(index, record, view.fingerprint_format))
            .collect(),
    };
    serde_json::to_writer_pretty(&mut *out, &document).map_err(io::Error::from)?;
    writeln!(out)
}

fn tls(info: &TlsSessionInfo) -> JsonTls<'_> {
    JsonTls {
        version: clean(&info.version),
        cipher_suite: clean(&info.cipher_suite),
        key_exchange_group: info.key_exchange_group.as_deref().map(clean),
        alpn: info.alpn.as_deref().map(clean),
        peer_ip: info.peer_ip.to_string(),
    }
}

fn timings(timings: &Timings) -> JsonTimings {
    let millis = |duration: Option<Duration>| {
        duration.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    };
    JsonTimings {
        dns: millis(timings.dns),
        connect: millis(timings.connect),
        handshake: millis(timings.handshake),
        total: millis(timings.total),
    }
}

fn staple(report: &InspectionReport) -> JsonStaple {
    JsonStaple {
        present: report.ocsp_staple.is_some(),
        bytes: report.ocsp_staple.as_ref().map_or(0, Vec::len),
    }
}

fn target(target: &Target) -> JsonTarget<'_> {
    match target {
        Target::Network(network) => JsonTarget::Network {
            host: clean(&network.host),
            port: network.port,
            sni: network.sni.as_deref().map(clean),
            connect_to: network.connect_to.map(|addr| addr.to_string()),
        },
        Target::File(path) => JsonTarget::File {
            path: lossy_path(path),
        },
        Target::Directory { path, recursive } => JsonTarget::Directory {
            path: lossy_path(path),
            recursive: *recursive,
        },
        Target::Stdin => JsonTarget::Stdin,
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, byte| {
        // Writing to a `String` cannot fail.
        let _ = write!(acc, "{byte:02X}");
        acc
    })
}

fn lossy_path(path: &std::path::Path) -> Cow<'_, str> {
    match path.to_string_lossy() {
        Cow::Borrowed(text) => clean(text),
        Cow::Owned(text) => Cow::Owned(clean(&text).into_owned()),
    }
}

fn origin(origin: &CertOrigin) -> JsonOrigin<'_> {
    match origin {
        CertOrigin::Presented { position } => JsonOrigin::Presented {
            position: *position,
        },
        CertOrigin::AiaFetched { url } => JsonOrigin::AiaFetched { url: clean(url) },
        CertOrigin::File { path, index } => JsonOrigin::File {
            path: lossy_path(path),
            index: *index,
        },
        CertOrigin::Stdin { index } => JsonOrigin::Stdin { index: *index },
        CertOrigin::Keystore { path, alias } => JsonOrigin::Keystore {
            path: lossy_path(path),
            alias: clean(alias),
        },
    }
}

fn name(name: &certtui_domain::model::DistinguishedName) -> JsonName<'_> {
    JsonName {
        rfc4514: clean(&name.rfc4514),
        common_name: name.common_name.as_deref().map(clean),
    }
}

fn certificate(
    index: usize,
    record: &CertificateRecord,
    format: FingerprintFormat,
) -> JsonCertificate<'_> {
    let summary = &record.summary;
    let fingerprint =
        |algorithm: FingerprintAlgorithm| record.fingerprints.format(algorithm, format);
    JsonCertificate {
        index,
        origin: origin(&record.origin),
        version: summary.version,
        serial: summary.serial.to_hex(),
        subject: name(&summary.subject),
        issuer: name(&summary.issuer),
        not_before: summary.not_before.to_string(),
        not_after: summary.not_after.to_string(),
        public_key: JsonPublicKey {
            algorithm: labels::public_key_algorithm(&summary.public_key.algorithm),
            bits: summary.public_key.bits,
            curve: summary.public_key.curve.as_deref().map(clean),
        },
        signature_algorithm: JsonSignature {
            oid: clean(&summary.signature_algorithm.oid),
            name: clean(&summary.signature_algorithm.name),
            hash: labels::hash_name(summary.signature_algorithm.hash),
        },
        subject_alt_names: summary
            .subject_alt_names
            .iter()
            .map(|san| {
                let (kind, value) = labels::san_parts(san);
                JsonSan {
                    kind,
                    value: Cow::Owned(clean(&value).into_owned()),
                }
            })
            .collect(),
        basic_constraints: summary
            .basic_constraints
            .as_ref()
            .map(|bc| JsonBasicConstraints {
                ca: bc.ca,
                path_len: bc.path_len,
            }),
        key_usage: summary.key_usage.as_ref().map(labels::key_usage_names),
        extended_key_usage: summary
            .extended_key_usage
            .iter()
            .map(|usage| clean(&labels::extended_key_usage(usage)).into_owned())
            .collect(),
        subject_key_id: summary.subject_key_id.as_ref().map(KeyId::to_hex),
        authority_key_id: summary.authority_key_id.as_ref().map(KeyId::to_hex),
        aia: JsonAia {
            ocsp: summary.aia.ocsp.iter().map(|url| clean(url)).collect(),
            ca_issuers: summary
                .aia
                .ca_issuers
                .iter()
                .map(|url| clean(url))
                .collect(),
        },
        crl_distribution_points: summary
            .crl_distribution_points
            .iter()
            .map(|url| clean(url))
            .collect(),
        scts: summary
            .embedded_scts
            .iter()
            .map(|sct| JsonSct {
                version: sct.version,
                log_id: hex_upper(&sct.log_id),
                timestamp: sct.timestamp.to_string(),
            })
            .collect(),
        extensions: summary
            .extensions
            .iter()
            .map(|extension| JsonExtension {
                oid: clean(&extension.oid),
                critical: extension.critical,
                name: clean(&extension.name),
                decode_error: extension.decode_error,
            })
            .collect(),
        fingerprints: JsonFingerprints {
            sha1: fingerprint(FingerprintAlgorithm::Sha1),
            sha256: fingerprint(FingerprintAlgorithm::Sha256),
            sha512: fingerprint(FingerprintAlgorithm::Sha512),
        },
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::super::testing::{network_report, report};
    use super::*;

    fn render(report: &certtui_domain::model::InspectionReport, only: Option<usize>) -> Value {
        let mut out = Vec::new();
        let view = View {
            report,
            only,
            fingerprint_format: FingerprintFormat::default(),
        };
        write(&mut out, &view).unwrap();
        assert!(out.ends_with(b"\n"));
        serde_json::from_slice(&out).unwrap()
    }

    #[test]
    fn quando_report_deve_ter_schema_1_target_notes_e_certificados() {
        let report = report(
            &["rsa2048-leaf", "expired"],
            vec![LoadNote::PrivateKeyBlocksIgnored { count: 1 }],
        );
        let json = render(&report, None);
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["target"]["kind"], "file");
        assert_eq!(json["target"]["path"], "x.pem");
        assert_eq!(json["notes"][0]["kind"], "private_key_blocks_ignored");
        assert_eq!(json["notes"][0]["count"], 1);
        assert_eq!(json["certificates"].as_array().unwrap().len(), 2);
        assert_eq!(json["certificates"][1]["origin"]["kind"], "file");
        assert_eq!(json["certificates"][1]["origin"]["index"], 1);
    }

    #[test]
    fn quando_cert_deve_serializar_campos_do_dominio() {
        let report = report(&["san-multi"], Vec::new());
        let json = render(&report, None);
        let cert = &json["certificates"][0];
        let record = report.chain.get(0).unwrap();
        assert_eq!(cert["serial"], record.summary.serial.to_hex());
        assert_eq!(cert["subject"]["rfc4514"], record.summary.subject.rfc4514);
        assert_eq!(cert["not_after"], record.summary.not_after.to_string());
        assert_eq!(
            cert["public_key"]["algorithm"],
            labels::public_key_algorithm(&record.summary.public_key.algorithm)
        );
        assert!(cert["subject_alt_names"].as_array().unwrap().len() > 1);
        assert_eq!(cert["subject_alt_names"][0]["type"], "dns");
        assert_eq!(cert["aia"]["ocsp"], serde_json::json!([]));
        assert_eq!(cert["scts"], serde_json::json!([]));
    }

    #[test]
    fn quando_leaf_publico_deve_listar_scts_aia_e_crl() {
        let report = report(&["public-leaf-with-sct"], Vec::new());
        let cert = &render(&report, None)["certificates"][0];
        assert_ne!(cert["scts"].as_array().unwrap().len(), 0);
        let sct = &cert["scts"][0];
        assert_eq!(sct["version"], 1);
        let log_id = sct["log_id"].as_str().unwrap();
        assert_eq!(log_id.len(), 64);
        assert_eq!(
            log_id,
            log_id.to_uppercase(),
            "log_id must be upper-case hex"
        );
        assert_ne!(cert["aia"]["ocsp"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn quando_only_deve_filtrar_mantendo_o_indice_original() {
        let report = report(&["rsa2048-leaf", "expired"], Vec::new());
        let json = render(&report, Some(1));
        assert_eq!(json["certificates"].as_array().unwrap().len(), 1);
        assert_eq!(json["certificates"][0]["index"], 1);
    }

    #[test]
    fn quando_texto_do_cert_tem_controle_deve_sair_sanitizado() {
        let mut report = report(&["rsa2048-leaf"], Vec::new());
        let mut hostile = report.chain.get(0).unwrap().clone();
        hostile.summary.subject.rfc4514 = "CN=a\u{9b}b\u{202E}c".to_owned();
        report.chain = certtui_domain::model::Chain::new(
            vec![hostile],
            &certtui_domain::limits::Limits::default(),
        )
        .unwrap();
        let json = render(&report, None);
        assert_eq!(json["certificates"][0]["subject"]["rfc4514"], "CN=abc");
    }

    #[test]
    fn quando_alvo_stdin_ou_diretorio_deve_marcar_kind() {
        let mut report = report(&["rsa2048-leaf"], Vec::new());
        report.target = Target::Stdin;
        assert_eq!(
            render(&report, None)["target"],
            serde_json::json!({"kind": "stdin"})
        );
        report.target = Target::Directory {
            path: "d".into(),
            recursive: true,
        };
        assert_eq!(
            render(&report, None)["target"],
            serde_json::json!({"kind": "directory", "path": "d", "recursive": true})
        );
    }

    #[test]
    fn quando_alvo_de_rede_deve_ter_tls_timings_staple_e_target_completo() {
        let mut report = network_report(&["rsa2048-leaf"]);
        report.ocsp_staple = Some(vec![1, 2, 3]);
        let json = render(&report, None);
        assert_eq!(
            json["target"],
            serde_json::json!({
                "kind": "network",
                "host": "example.test",
                "port": 8443,
                "sni": "alt.example.test",
                "connect_to": "127.0.0.1:9443",
            })
        );
        assert_eq!(
            json["tls"],
            serde_json::json!({
                "version": "TLSv1.3",
                "cipher_suite": "TLS_AES_256_GCM_SHA384",
                "key_exchange_group": "X25519",
                "alpn": "h2",
                "peer_ip": "93.184.216.34",
            })
        );
        assert_eq!(
            json["timings"],
            serde_json::json!({"dns": null, "connect": 12, "handshake": 41, "total": 60})
        );
        assert_eq!(
            json["ocsp_staple"],
            serde_json::json!({"present": true, "bytes": 3})
        );
    }

    #[test]
    fn quando_alvo_de_rede_sem_staple_nem_sni_deve_ter_nulls_e_present_false() {
        let mut report = network_report(&["rsa2048-leaf"]);
        report.ocsp_staple = None;
        if let Target::Network(network) = &mut report.target {
            network.sni = None;
            network.connect_to = None;
        }
        let json = render(&report, None);
        assert_eq!(json["target"]["sni"], serde_json::Value::Null);
        assert_eq!(json["target"]["connect_to"], serde_json::Value::Null);
        assert_eq!(
            json["ocsp_staple"],
            serde_json::json!({"present": false, "bytes": 0})
        );
    }

    #[test]
    fn quando_alvo_local_nao_deve_ter_chaves_de_rede() {
        let json = render(&report(&["rsa2048-leaf"], Vec::new()), None);
        for key in ["tls", "timings", "ocsp_staple"] {
            assert!(json.get(key).is_none(), "{key}");
        }
        assert!(json["target"].get("sni").is_none());
    }

    #[test]
    fn quando_tls_tem_controles_deve_sair_sanitizado() {
        let mut report = network_report(&["rsa2048-leaf"]);
        if let Some(tls) = &mut report.tls {
            tls.alpn = Some("h2\u{9b}\u{202E}x".to_owned());
        }
        assert_eq!(render(&report, None)["tls"]["alpn"], "h2x");
    }
}
