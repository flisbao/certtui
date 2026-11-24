//! `--field`: the bare value of one certificate field, without decoration.

use std::io::{self, Write};

use certtui_domain::model::{CertificateRecord, FingerprintAlgorithm, FingerprintFormat};
use certtui_domain::sanitize::sanitize_display;

use super::{labels, pem};

/// A certificate field that `--field` can print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Field {
    /// Subject DN (RFC 4514).
    #[value(name = "subject")]
    Subject,
    /// Issuer DN (RFC 4514).
    #[value(name = "issuer")]
    Issuer,
    /// Serial number in hex.
    #[value(name = "serial")]
    Serial,
    /// Start of validity (RFC 3339, UTC).
    #[value(name = "not_before")]
    NotBefore,
    /// End of validity (RFC 3339, UTC).
    #[value(name = "not_after")]
    NotAfter,
    /// Subject alternative names, one per line.
    #[value(name = "sans")]
    Sans,
    /// SHA-1 fingerprint.
    #[value(name = "fingerprint.sha1")]
    FingerprintSha1,
    /// SHA-256 fingerprint.
    #[value(name = "fingerprint.sha256")]
    FingerprintSha256,
    /// SHA-512 fingerprint.
    #[value(name = "fingerprint.sha512")]
    FingerprintSha512,
    /// The certificate as PEM.
    #[value(name = "pem")]
    Pem,
}

/// The value of `field` for `record`, with a final newline when non-empty.
///
/// Text taken from the certificate is sanitized for terminal display.
#[must_use]
pub fn value(record: &CertificateRecord, field: Field, format: FingerprintFormat) -> String {
    let summary = &record.summary;
    let mut text = match field {
        Field::Subject => sanitize_display(&summary.subject.rfc4514).into_owned(),
        Field::Issuer => sanitize_display(&summary.issuer.rfc4514).into_owned(),
        Field::Serial => summary.serial.to_hex(),
        Field::NotBefore => summary.not_before.to_string(),
        Field::NotAfter => summary.not_after.to_string(),
        Field::Sans => summary
            .subject_alt_names
            .iter()
            .map(|san| sanitize_display(&labels::san_text(san)).into_owned())
            .collect::<Vec<_>>()
            .join("\n"),
        Field::FingerprintSha1 => record
            .fingerprints
            .format(FingerprintAlgorithm::Sha1, format),
        Field::FingerprintSha256 => record
            .fingerprints
            .format(FingerprintAlgorithm::Sha256, format),
        Field::FingerprintSha512 => record
            .fingerprints
            .format(FingerprintAlgorithm::Sha512, format),
        Field::Pem => return pem::encode(&record.der),
    };
    if !text.is_empty() {
        text.push('\n');
    }
    text
}

/// Writes the value of `field` for `record`.
///
/// # Errors
///
/// Any I/O error of `out`.
pub fn write(
    out: &mut dyn Write,
    record: &CertificateRecord,
    field: Field,
    format: FingerprintFormat,
) -> io::Result<()> {
    out.write_all(value(record, field, format).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::super::testing::record;
    use super::*;

    #[test]
    fn quando_sha256_colon_deve_bater_com_o_fixture_e_terminar_em_newline() {
        let record = record("rsa2048-leaf", 0);
        assert_eq!(
            value(
                &record,
                Field::FingerprintSha256,
                FingerprintFormat::ColonHexUpper
            ),
            "DD:DB:9B:86:33:47:FC:84:96:10:30:C3:F4:C5:7C:66:CA:BF:92:1E:D4:B4:3A:15:CE:41:B7:9F:39:A6:63:BB\n"
        );
    }

    #[test]
    fn quando_sha1_e_sha512_em_hex_deve_ter_os_tamanhos_certos() {
        let record = record("rsa2048-leaf", 0);
        let sha1 = value(&record, Field::FingerprintSha1, FingerprintFormat::HexLower);
        let sha512 = value(
            &record,
            Field::FingerprintSha512,
            FingerprintFormat::HexLower,
        );
        assert_eq!(sha1.trim_end().len(), 40);
        assert_eq!(sha512.trim_end().len(), 128);
    }

    #[test]
    fn quando_subject_issuer_serial_validade_deve_vir_como_texto_simples() {
        let record = record("rsa2048-leaf", 0);
        let fmt = FingerprintFormat::default();
        assert_eq!(
            value(&record, Field::Subject, fmt),
            format!("{}\n", record.summary.subject.rfc4514)
        );
        assert_eq!(
            value(&record, Field::Issuer, fmt),
            format!("{}\n", record.summary.issuer.rfc4514)
        );
        assert_eq!(
            value(&record, Field::Serial, fmt),
            format!("{}\n", record.summary.serial.to_hex())
        );
        assert_eq!(
            value(&record, Field::NotBefore, fmt),
            format!("{}\n", record.summary.not_before)
        );
        assert_eq!(
            value(&record, Field::NotAfter, fmt),
            format!("{}\n", record.summary.not_after)
        );
    }

    #[test]
    fn quando_sans_deve_listar_um_por_linha() {
        let record = record("san-multi", 0);
        let text = value(&record, Field::Sans, FingerprintFormat::default());
        assert!(text.lines().count() > 1);
        assert!(text.lines().any(|l| l.starts_with("DNS:")));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn quando_sem_sans_deve_ser_vazio_sem_newline() {
        let mut record = record("rsa2048-leaf", 0);
        record.summary.subject_alt_names.clear();
        assert_eq!(
            value(&record, Field::Sans, FingerprintFormat::default()),
            ""
        );
    }

    #[test]
    fn quando_subject_tem_controle_deve_remover() {
        let mut record = record("rsa2048-leaf", 0);
        record.summary.subject.rfc4514 = "CN=a\u{1b}[31mb\u{202E}".to_owned();
        assert_eq!(
            value(&record, Field::Subject, FingerprintFormat::default()),
            "CN=a[31mb\n"
        );
    }

    #[test]
    fn quando_pem_deve_ser_o_pem_do_cert() {
        let record = record("rsa2048-leaf", 0);
        assert_eq!(
            value(&record, Field::Pem, FingerprintFormat::default()),
            pem::encode(&record.der)
        );
    }
}
