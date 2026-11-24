//! PEM encoding of certificates (RFC 7468: 64-column base64 lines).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

const COLUMNS: usize = 64;

/// PEM text of one DER certificate, ending in a newline.
#[must_use]
pub fn encode(der: &[u8]) -> String {
    let body: Vec<char> = STANDARD.encode(der).chars().collect();
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in body.chunks(COLUMNS) {
        out.extend(line);
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_der_pequeno_deve_ter_cabecalho_corpo_e_rodape() {
        assert_eq!(
            encode(&[0x01, 0x02, 0x03]),
            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn quando_der_longo_deve_quebrar_em_64_colunas() {
        let pem = encode(&[0xAB; 100]);
        assert!(pem.lines().skip(1).all(|line| line.len() <= 64), "{pem}");
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    }
}
