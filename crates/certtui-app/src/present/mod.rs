//! Pure presentation helpers shared by the CLI renderers and the TUI.

pub mod json;
pub mod labels;
pub mod pem;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

use certtui_domain::model::{CertificateRecord, FingerprintFormat, InspectionReport};

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
