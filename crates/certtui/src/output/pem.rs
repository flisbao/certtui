//! PEM encoding of certificates (RFC 7468: 64-column base64 lines).

use std::io::{self, Write};

use super::View;

pub use certtui_app::present::pem::encode;

/// Writes the PEM of every selected certificate.
///
/// # Errors
///
/// Any I/O error of `out`.
pub fn write(out: &mut dyn Write, view: &View<'_>) -> io::Result<()> {
    for (_, record) in view.certs() {
        out.write_all(encode(&record.der).as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use certtui_domain::model::FingerprintFormat;

    use super::super::testing::{record, report};
    use super::*;

    #[test]
    fn quando_der_pequeno_deve_ter_cabecalho_corpo_e_rodape() {
        assert_eq!(
            encode(&[0x01, 0x02, 0x03]),
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn quando_der_grande_deve_quebrar_em_64_colunas() {
        let pem = encode(&[0xAB; 200]);
        let body: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(body.len() > 1);
        for line in &body[..body.len() - 1] {
            assert_eq!(line.len(), 64);
        }
        assert!(body[body.len() - 1].len() <= 64);
    }

    #[test]
    fn quando_cert_real_deve_bater_com_o_pem_do_fixture() {
        let expected = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/rsa2048-leaf.pem"
        ))
        .unwrap();
        assert_eq!(encode(&record("rsa2048-leaf", 0).der), expected);
    }

    #[test]
    fn quando_view_filtra_indice_deve_emitir_so_aquele_cert() {
        let report = report(&["rsa2048-leaf", "expired"], Vec::new());
        let mut out = Vec::new();
        let view = View {
            report: &report,
            only: Some(1),
            fingerprint_format: FingerprintFormat::default(),
        };
        write(&mut out, &view).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            encode(&report.chain.get(1).unwrap().der)
        );
    }
}
