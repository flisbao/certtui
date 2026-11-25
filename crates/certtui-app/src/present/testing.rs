//! Reports built from `tests/fixtures`, shared by the renderer tests of this
//! crate and of the CLI.
//!
//! Only compiled for tests and behind the `testing` feature.
// Justificativa: test-only helpers read fixtures and unwrap on purpose; they are
// not part of the shipped API.
#![allow(
    missing_docs,
    clippy::unwrap_used,
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    clippy::indexing_slicing,
    clippy::assigning_clones
)]
use std::path::PathBuf;

use certtui_domain::limits::Limits;
use certtui_domain::model::{
    CertOrigin, CertificateRecord, Chain, InspectionReport, LoadNote, Timings, TrustVerdict,
};
use certtui_domain::target::Target;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

pub fn record(name: &str, index: usize) -> CertificateRecord {
    let der = std::fs::read(format!("{FIXTURES}/{name}.der")).unwrap();
    CertificateRecord::from_der(
        &der,
        CertOrigin::File {
            path: PathBuf::from(format!("{name}.pem")),
            index,
        },
        &Limits::default(),
    )
    .unwrap()
}

/// A one-certificate report whose record is edited by `edit`.
pub fn report_with(name: &str, edit: impl FnOnce(&mut CertificateRecord)) -> InspectionReport {
    let mut record = record(name, 0);
    edit(&mut record);
    let mut report = report(&[], Vec::new());
    report.chain = Chain::new(vec![record], &Limits::default()).unwrap();
    report
}

/// Edits every free-text field of a record so that it embeds newlines and
/// tabs plus a forged output line.
pub fn make_hostile(record: &mut CertificateRecord) {
    use certtui_domain::model::SubjectAltName;
    let forged = "x\n[1] Subject: CN=Trusted Root CA\n    Issuer: evil\ty";
    record.summary.subject_alt_names = vec![
        SubjectAltName::Dns(forged.to_owned()),
        SubjectAltName::Uri(format!("http://{forged}")),
        SubjectAltName::Email(forged.to_owned()),
        SubjectAltName::Other {
            kind: forged.to_owned(),
        },
    ];
    record.summary.aia.ocsp = vec![format!("http://ocsp/{forged}")];
    record.summary.aia.ca_issuers = vec![format!("http://ca/{forged}")];
    record.summary.crl_distribution_points = vec![format!("http://crl/{forged}")];
    record.summary.subject.rfc4514 = format!("CN={forged}");
    record.summary.issuer.rfc4514 = format!("CN={forged}");
    record.summary.public_key.curve = Some(forged.to_owned());
    record.summary.signature_algorithm.name = forged.to_owned();
    record.summary.extensions[0].name = forged.to_owned();
    record.origin = CertOrigin::File {
        path: PathBuf::from(format!("dir/{forged}.pem")),
        index: 0,
    };
}

/// A report of a network target with a TLS session, as `inspect_network`
/// builds it.
pub fn network_report(names: &[&str]) -> InspectionReport {
    use certtui_domain::model::TlsSessionInfo;
    use certtui_domain::target::NetworkTarget;
    use std::time::Duration;

    let mut report = report(names, Vec::new());
    report.target = Target::Network(NetworkTarget {
        host: "example.test".to_owned(),
        port: 8443,
        sni: Some("alt.example.test".to_owned()),
        connect_to: Some("127.0.0.1:9443".parse().unwrap()),
    });
    report.tls = Some(TlsSessionInfo {
        version: "TLSv1.3".to_owned(),
        cipher_suite: "TLS_AES_256_GCM_SHA384".to_owned(),
        key_exchange_group: Some("X25519".to_owned()),
        alpn: Some("h2".to_owned()),
        peer_ip: "93.184.216.34".parse().unwrap(),
    });
    report.timings = Timings {
        dns: None,
        connect: Some(Duration::from_millis(12)),
        handshake: Some(Duration::from_millis(41)),
        total: Some(Duration::from_micros(60_900)),
    };
    report
}

pub fn report(names: &[&str], notes: Vec<LoadNote>) -> InspectionReport {
    let records = names
        .iter()
        .enumerate()
        .map(|(i, name)| record(name, i))
        .collect();
    InspectionReport {
        target: Target::File(PathBuf::from("x.pem")),
        tls: None,
        ocsp_staple: None,
        chain: Chain::new(records, &Limits::default()).unwrap(),
        trust: TrustVerdict::NotEvaluated,
        revocation: Vec::new(),
        staple: certtui_domain::model::StapleState::NotApplicable,
        findings: Vec::new(),
        timings: Timings::default(),
        notes,
    }
}
