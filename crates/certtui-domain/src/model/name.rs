//! Serial numbers and distinguished names.

use super::fingerprint::join_hex;

/// A certificate serial number: the raw big-endian bytes of the ASN.1
/// INTEGER (possibly with a leading `0x00` sign byte).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SerialNumber(Vec<u8>);

impl SerialNumber {
    /// Wraps the raw serial bytes exactly as encoded in the certificate.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// The raw bytes, as encoded (including any leading zero byte).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Upper-case hex without separators and without leading zero bytes;
    /// an all-zero or empty serial renders as `"00"`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let start = self.0.iter().position(|b| *b != 0).unwrap_or(self.0.len());
        let significant = self.0.get(start..).unwrap_or_default();
        if significant.is_empty() {
            return "00".to_owned();
        }
        join_hex(significant, "", true)
    }
}

/// A distinguished name (subject or issuer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistinguishedName {
    /// RFC 4514 string form (most specific RDN first, e.g.
    /// `CN=example.com,O=Example,C=US`). Raw certificate text: pass it
    /// through `sanitize` before displaying it.
    pub rfc4514: String,
    /// The first `commonName` value, when it is a UTF-8-compatible string.
    pub common_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_serial_tem_zeros_a_esquerda_deve_normalizar() {
        assert_eq!(
            SerialNumber::from_bytes(&[0x00, 0x00, 0x0A, 0xFF]).to_hex(),
            "0AFF"
        );
        assert_eq!(
            SerialNumber::from_bytes(&[0x00, 0x80, 0x01]).to_hex(),
            "8001"
        );
    }

    #[test]
    fn quando_serial_e_zero_ou_vazio_deve_dar_00() {
        assert_eq!(SerialNumber::from_bytes(&[0x00, 0x00]).to_hex(), "00");
        assert_eq!(SerialNumber::from_bytes(&[]).to_hex(), "00");
    }
}
