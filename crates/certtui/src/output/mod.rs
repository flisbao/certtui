//! Pure renderers of an [`InspectionReport`]: they only write to a
//! `&mut dyn Write` handed in by the caller.

use certtui_domain::model::{CertificateRecord, FingerprintFormat, InspectionReport};

pub mod field;
pub mod json;
mod labels;
pub mod pem;
pub mod text;

pub use labels::note_text;

/// What to render: a report, optionally narrowed to one certificate, with the
/// fingerprint format to display.
#[derive(Debug, Clone, Copy)]
pub struct View<'a> {
    /// The inspected report.
    pub report: &'a InspectionReport,
    /// Render only the certificate at this chain index.
    pub only: Option<usize>,
    /// Display format of the fingerprints.
    pub fingerprint_format: FingerprintFormat,
}

impl<'a> View<'a> {
    /// The selected certificates with their chain index.
    pub fn certs(&self) -> impl Iterator<Item = (usize, &'a CertificateRecord)> + use<'a> {
        let only = self.only;
        self.report
            .chain
            .records()
            .iter()
            .enumerate()
            .filter(move |(index, _)| only.is_none_or(|wanted| wanted == *index))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! Helpers to build reports from fixtures in renderer tests.

    use std::path::PathBuf;

    use certtui_domain::limits::Limits;
    use certtui_domain::model::{
        CertOrigin, CertificateRecord, Chain, InspectionReport, LoadNote, Timings, TrustVerdict,
    };
    use certtui_domain::target::Target;

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

    pub(crate) fn record(name: &str, index: usize) -> CertificateRecord {
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

    pub(crate) fn report(names: &[&str], notes: Vec<LoadNote>) -> InspectionReport {
        let records = names
            .iter()
            .enumerate()
            .map(|(i, name)| record(name, i))
            .collect();
        InspectionReport {
            target: Target::File(PathBuf::from("x.pem")),
            tls: None,
            chain: Chain::new(records, &Limits::default()).unwrap(),
            trust: TrustVerdict::NotEvaluated,
            revocation: Vec::new(),
            findings: Vec::new(),
            timings: Timings::default(),
            notes,
        }
    }
}
