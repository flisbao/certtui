//! The `export` use case: certificates of a report as PEM, DER or JSON.
//!
//! Pure: it only produces bytes. Writing them to disk (atomically, never over
//! an existing file without consent) is the infrastructure's job.

use certtui_domain::model::{FingerprintFormat, InspectionReport};
use thiserror::Error;

use crate::present::{View, json, pem};

/// The file format of an export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// PEM, 64-column base64 between `BEGIN`/`END CERTIFICATE`.
    Pem,
    /// DER: one certificate, raw.
    Der,
    /// The same JSON document `inspect --json` prints.
    Json,
}

/// What to export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportSelection {
    /// The certificate at this chain index.
    Index(usize),
    /// Every certificate, in the order they were presented.
    Chain,
}

/// Why an export could not be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ExportError {
    /// The chosen certificate does not exist.
    #[error("--index {index} is out of range: {len} certificate(s) found")]
    IndexOutOfRange {
        /// The requested index.
        index: usize,
        /// How many certificates there are.
        len: usize,
    },
    /// DER holds a single certificate; a chain needs PEM or JSON.
    #[error(
        "DER cannot hold a certificate chain: use --format pem or --format json, or pick one certificate with --index"
    )]
    DerCannotRepresentChain,
}

/// The bytes of `format` for `sel`.
///
/// # Errors
///
/// [`ExportError::IndexOutOfRange`] for a missing certificate (an empty chain
/// included) and [`ExportError::DerCannotRepresentChain`] for DER of a chain.
pub fn render_export(
    report: &InspectionReport,
    format: ExportFormat,
    sel: ExportSelection,
) -> Result<Vec<u8>, ExportError> {
    let len = report.chain.len();
    let only = match sel {
        ExportSelection::Index(index) if index >= len => {
            return Err(ExportError::IndexOutOfRange { index, len });
        }
        ExportSelection::Chain if len == 0 => {
            return Err(ExportError::IndexOutOfRange { index: 0, len });
        }
        ExportSelection::Index(index) => Some(index),
        ExportSelection::Chain => None,
    };
    if format == ExportFormat::Der && only.is_none() {
        return Err(ExportError::DerCannotRepresentChain);
    }
    let view = View {
        report,
        only,
        fingerprint_format: FingerprintFormat::default(),
    };
    Ok(match format {
        ExportFormat::Pem => view
            .certs()
            .flat_map(|(_, record)| pem::encode(&record.der).into_bytes())
            .collect(),
        ExportFormat::Der => view
            .certs()
            .flat_map(|(_, record)| record.der.to_vec())
            .collect(),
        ExportFormat::Json => {
            let mut out = Vec::new();
            // Writing to a `Vec` cannot fail.
            let _ = json::write(&mut out, &view);
            out
        }
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;
    use crate::present::testing::report;

    fn chain3() -> InspectionReport {
        report(&["chain-3", "rsa2048-leaf", "ec-p256-leaf"], Vec::new())
    }

    /// Decodes the PEM blocks of `text` back to DER.
    fn pem_blocks(text: &str) -> Vec<Vec<u8>> {
        text.split("-----BEGIN CERTIFICATE-----")
            .skip(1)
            .map(|block| {
                let body: String = block
                    .split("-----END CERTIFICATE-----")
                    .next()
                    .unwrap()
                    .lines()
                    .collect();
                STANDARD.decode(body).unwrap()
            })
            .collect()
    }

    #[test]
    fn quando_pem_de_um_cert_deve_ter_64_colunas_e_bater_com_o_der_original() {
        let report = chain3();
        let got = render_export(&report, ExportFormat::Pem, ExportSelection::Index(1)).unwrap();
        let text = String::from_utf8(got).unwrap();

        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));
        let body: Vec<&str> = text.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(body.iter().all(|line| line.len() <= 64), "{body:?}");
        assert!(body[..body.len() - 1].iter().all(|line| line.len() == 64));
        assert_eq!(
            pem_blocks(&text),
            vec![report.chain.get(1).unwrap().der.to_vec()]
        );
    }

    #[test]
    fn quando_chain_pem_deve_manter_ordem_apresentada() {
        let report = chain3();
        let got = render_export(&report, ExportFormat::Pem, ExportSelection::Chain).unwrap();

        let expected: Vec<Vec<u8>> = report
            .chain
            .records()
            .iter()
            .map(|r| r.der.to_vec())
            .collect();
        assert_eq!(pem_blocks(&String::from_utf8(got).unwrap()), expected);
        assert_eq!(expected.len(), report.chain.len());
    }

    #[test]
    fn quando_der_com_index_deve_devolver_bytes_do_cert() {
        let report = chain3();
        let got = render_export(&report, ExportFormat::Der, ExportSelection::Index(2)).unwrap();
        assert_eq!(got, report.chain.get(2).unwrap().der.to_vec());
    }

    #[test]
    fn quando_der_com_chain_deve_dar_der_cannot_represent_chain() {
        let got = render_export(&chain3(), ExportFormat::Der, ExportSelection::Chain);
        assert_eq!(got, Err(ExportError::DerCannotRepresentChain));
        assert!(
            ExportError::DerCannotRepresentChain
                .to_string()
                .contains("--format pem")
        );
    }

    #[test]
    fn quando_index_fora_deve_dar_erro_tipado() {
        let report = chain3();
        let len = report.chain.len();
        for format in [ExportFormat::Pem, ExportFormat::Der, ExportFormat::Json] {
            let got = render_export(&report, format, ExportSelection::Index(len));
            assert_eq!(got, Err(ExportError::IndexOutOfRange { index: len, len }));
        }
    }

    #[test]
    fn quando_cadeia_vazia_deve_dar_index_fora_mesmo_para_chain() {
        let report = report(&[], Vec::new());
        let got = render_export(&report, ExportFormat::Pem, ExportSelection::Chain);
        assert_eq!(got, Err(ExportError::IndexOutOfRange { index: 0, len: 0 }));
    }

    #[test]
    fn quando_json_deve_ter_schema_version_1_e_ser_o_mesmo_do_inspect() {
        let report = chain3();
        let got = render_export(&report, ExportFormat::Json, ExportSelection::Chain).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&got).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(
            value["certificates"].as_array().unwrap().len(),
            report.chain.len()
        );

        let mut same = Vec::new();
        json::write(
            &mut same,
            &View {
                report: &report,
                only: None,
                fingerprint_format: FingerprintFormat::default(),
            },
        )
        .unwrap();
        assert_eq!(got, same);
    }

    #[test]
    fn quando_json_de_um_indice_deve_ter_so_aquele_certificado() {
        let report = chain3();
        let got = render_export(&report, ExportFormat::Json, ExportSelection::Index(1)).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&got).unwrap();
        assert_eq!(value["certificates"].as_array().unwrap().len(), 1);
        assert_eq!(value["certificates"][0]["index"], 1);
    }
}
