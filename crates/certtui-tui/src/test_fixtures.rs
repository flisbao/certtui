//! Reports built from fixtures, for the unit tests.

use std::sync::Arc;
use std::time::Instant;

use certtui_domain::finding::{Finding, FindingCategory, FindingCode, Severity};
use certtui_domain::limits::Limits;
use certtui_domain::model::{
    CertOrigin, CertificateRecord, Chain, InspectionReport, Timings, TlsSessionInfo, TrustVerdict,
};
use certtui_domain::target::{NetworkTarget, Target};

use crate::app_state::{AppState, InspectState, Phase, Screen};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

/// A certificate of `tests/fixtures`, presented at `position`.
pub fn fixture_record(name: &str, position: usize) -> CertificateRecord {
    let der = std::fs::read(format!("{FIXTURES}/{name}.der")).unwrap();
    CertificateRecord::from_der(&der, CertOrigin::Presented { position }, &Limits::default())
        .unwrap()
}

/// A self-signed certificate whose subject CN is `cn`.
pub fn record_with_cn(cn: &str, position: usize) -> CertificateRecord {
    let mut params = rcgen::CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    CertificateRecord::from_der(
        cert.der(),
        CertOrigin::Presented { position },
        &Limits::default(),
    )
    .unwrap()
}

pub fn finding(code: FindingCode, severity: Severity, cert_index: Option<usize>) -> Finding {
    Finding {
        code,
        severity,
        category: FindingCategory::Quality,
        cert_index,
        message: format!("{} happened", code.as_str()),
    }
}

/// A report over `records` with a TLS session and no findings.
pub fn report_of(records: Vec<CertificateRecord>) -> InspectionReport {
    InspectionReport {
        target: Target::Network(NetworkTarget {
            host: "example.com".to_owned(),
            port: 443,
            sni: None,
            connect_to: None,
        }),
        tls: Some(TlsSessionInfo {
            version: "TLSv1.3".to_owned(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".to_owned(),
            key_exchange_group: Some("X25519".to_owned()),
            alpn: Some("h2".to_owned()),
            peer_ip: "192.0.2.7".parse().unwrap(),
        }),
        ocsp_staple: None,
        chain: Chain::new(records, &Limits::default()).unwrap(),
        trust: TrustVerdict::Untrusted {
            reason: "unknown issuer".to_owned(),
        },
        revocation: Vec::new(),
        findings: Vec::new(),
        timings: Timings {
            handshake: Some(std::time::Duration::from_millis(42)),
            total: Some(std::time::Duration::from_millis(120)),
            ..Timings::default()
        },
        notes: Vec::new(),
    }
}

/// Three fixture certificates with a warning on the leaf and an error on the root.
pub fn sample_report() -> InspectionReport {
    let mut report = report_of(vec![
        fixture_record("rsa2048-leaf", 0),
        fixture_record("ec-p256-leaf", 1),
        fixture_record("expired", 2),
    ]);
    report.findings = vec![
        finding(FindingCode::Expired, Severity::Error, Some(2)),
        finding(FindingCode::MissingSan, Severity::Warning, Some(0)),
        finding(FindingCode::TrustUntrusted, Severity::Error, None),
    ];
    report
}

/// A state already showing `report` on the Inspect screen.
pub fn inspect_state(report: InspectionReport) -> AppState {
    let mut state = AppState::new(Instant::now());
    let id = state.jobs.start();
    state.screen = Screen::Inspect;
    let mut inspect = InspectState::loading(id);
    inspect.phase = Phase::Ready(Arc::new(report));
    state.inspect = Some(inspect);
    state
}
