//! Certificate fingerprints (SHA-1, SHA-256, SHA-512) and their display formats.
//!
//! Fingerprints are always computed over the full DER encoding of the
//! certificate. SHA-1 is included for identification only (it is what many
//! tools and CAs still display); it must never be used for any security
//! decision.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha512};

/// A raw `N`-byte digest value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest<const N: usize>(pub [u8; N]);

/// How many leading bytes [`Digest::short`] keeps.
const SHORT_HEAD: usize = 3;
/// How many trailing bytes [`Digest::short`] keeps.
const SHORT_TAIL: usize = 2;

/// Hash algorithm of a fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FingerprintAlgorithm {
    /// SHA-1 (20 bytes). Identification only, not a security guarantee.
    Sha1,
    /// SHA-256 (32 bytes).
    Sha256,
    /// SHA-512 (64 bytes).
    Sha512,
}

/// Textual representation of a digest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum FingerprintFormat {
    /// Upper-case hex pairs separated by colons (`AB:CD:EF`), like OpenSSL.
    #[default]
    ColonHexUpper,
    /// Lower-case hex without separators (`abcdef`).
    HexLower,
    /// Standard base64 alphabet with padding.
    Base64,
}

/// The three fingerprints of one certificate, over its full DER encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprints {
    /// SHA-1 digest. Identification only.
    pub sha1: Digest<20>,
    /// SHA-256 digest.
    pub sha256: Digest<32>,
    /// SHA-512 digest.
    pub sha512: Digest<64>,
}

impl<const N: usize> Digest<N> {
    /// Formats the digest in the requested representation.
    #[must_use]
    pub fn format(&self, fmt: FingerprintFormat) -> String {
        match fmt {
            FingerprintFormat::ColonHexUpper => join_hex(&self.0, ":", true),
            FingerprintFormat::HexLower => join_hex(&self.0, "", false),
            FingerprintFormat::Base64 => STANDARD.encode(self.0),
        }
    }

    /// Abbreviated colon-hex form for tight layouts: the first 3 bytes, an
    /// ellipsis, then the last 2 bytes (`AB:CD:EF…12:34`). Digests of 5 bytes
    /// or fewer are shown in full.
    #[must_use]
    pub fn short(&self) -> String {
        if N <= SHORT_HEAD + SHORT_TAIL {
            return join_hex(&self.0, ":", true);
        }
        let head = self.0.get(..SHORT_HEAD).unwrap_or_default();
        let tail = self.0.get(N - SHORT_TAIL..).unwrap_or_default();
        format!(
            "{}…{}",
            join_hex(head, ":", true),
            join_hex(tail, ":", true)
        )
    }
}

impl Fingerprints {
    /// Computes all three fingerprints over `der`, the full DER encoding of
    /// the certificate.
    #[must_use]
    pub fn compute(der: &[u8]) -> Self {
        Self {
            sha1: Digest(Sha1::digest(der).into()),
            sha256: Digest(Sha256::digest(der).into()),
            sha512: Digest(Sha512::digest(der).into()),
        }
    }

    /// Formats the fingerprint of `alg` in the requested representation.
    #[must_use]
    pub fn format(&self, alg: FingerprintAlgorithm, fmt: FingerprintFormat) -> String {
        match alg {
            FingerprintAlgorithm::Sha1 => self.sha1.format(fmt),
            FingerprintAlgorithm::Sha256 => self.sha256.format(fmt),
            FingerprintAlgorithm::Sha512 => self.sha512.format(fmt),
        }
    }
}

/// Hex-encodes `bytes`, joining the byte pairs with `sep`.
fn join_hex(bytes: &[u8], sep: &str, upper: bool) -> String {
    let mut out = String::with_capacity(bytes.len() * (2 + sep.len()));
    for (i, byte) in bytes.iter().enumerate() {
        if i > 0 {
            out.push_str(sep);
        }
        let pair = if upper {
            format!("{byte:02X}")
        } else {
            format!("{byte:02x}")
        };
        out.push_str(&pair);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Test-only inverse of `ColonHexUpper`.
    fn parse_colon_hex(text: &str) -> Vec<u8> {
        text.split(':')
            .map(|pair| u8::from_str_radix(pair, 16).unwrap())
            .collect()
    }

    #[test]
    fn quando_formato_hex_deve_ser_minusculo_sem_separador() {
        let digest = Digest([0xAB, 0xCD]);
        assert_eq!(digest.format(FingerprintFormat::HexLower), "abcd");
    }

    #[test]
    fn quando_formato_colon_deve_ser_maiusculo_com_dois_pontos() {
        let digest = Digest([0xAB, 0x01, 0xCD]);
        assert_eq!(digest.format(FingerprintFormat::ColonHexUpper), "AB:01:CD");
        assert_eq!(
            FingerprintFormat::default(),
            FingerprintFormat::ColonHexUpper
        );
    }

    #[test]
    fn quando_formato_base64_deve_usar_alfabeto_padrao_com_padding() {
        // 0xFB 0xFF 0xFE exercises '+' and '/'; a lone byte exercises '=' padding.
        assert_eq!(
            Digest([0xFB, 0xFF, 0xFE]).format(FingerprintFormat::Base64),
            "+//+"
        );
        assert_eq!(Digest([0xAB]).format(FingerprintFormat::Base64), "qw==");
    }

    #[test]
    fn quando_digest_curto_deve_abreviar_com_reticencias() {
        let digest = Digest([0xAB, 0xCD, 0xEF, 0x00, 0x12, 0x34]);
        assert_eq!(digest.short(), "AB:CD:EF…12:34");
    }

    #[test]
    fn quando_digest_menor_que_cinco_bytes_deve_mostrar_tudo() {
        assert_eq!(Digest([0xAB, 0xCD]).short(), "AB:CD");
    }

    #[test]
    fn quando_calcular_vazio_deve_bater_com_vetores_conhecidos() {
        let fps = Fingerprints::compute(b"");
        assert_eq!(
            fps.format(FingerprintAlgorithm::Sha1, FingerprintFormat::HexLower),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            fps.format(FingerprintAlgorithm::Sha256, FingerprintFormat::HexLower),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            fps.format(FingerprintAlgorithm::Sha512, FingerprintFormat::HexLower),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    proptest! {
        #[test]
        fn quando_colon_hex_faz_ida_e_volta_deve_dar_mesmos_bytes(bytes in any::<[u8; 32]>()) {
            let text = Digest(bytes).format(FingerprintFormat::ColonHexUpper);
            prop_assert_eq!(parse_colon_hex(&text), bytes.to_vec());
        }
    }
}
