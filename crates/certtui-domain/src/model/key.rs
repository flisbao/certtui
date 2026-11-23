//! Public key and signature algorithm descriptions.

/// The public key algorithm of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// RSA.
    Rsa,
    /// ECDSA/ECDH on NIST P-256 (`prime256v1`).
    EcP256,
    /// ECDSA/ECDH on NIST P-384 (`secp384r1`).
    EcP384,
    /// ECDSA/ECDH on NIST P-521 (`secp521r1`).
    EcP521,
    /// Ed25519.
    Ed25519,
    /// Ed448.
    Ed448,
    /// Anything else; carries the dotted OID of the algorithm (or of the
    /// curve for an unrecognised EC curve).
    Other(String),
}

/// Public key details shown in the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyInfo {
    /// Algorithm family.
    pub algorithm: PublicKeyAlgorithm,
    /// Key size in bits (RSA modulus bits, EC curve bits, ...); `0` when it
    /// cannot be determined.
    pub bits: u32,
    /// Curve name for EC keys (OpenSSL naming, e.g. `prime256v1`); for an
    /// unrecognised curve, its dotted OID.
    pub curve: Option<String>,
}

/// The hash used by a signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// MD5 (broken).
    Md5,
    /// SHA-1 (deprecated).
    Sha1,
    /// SHA-224.
    Sha224,
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// No separate hash (e.g. Ed25519 hashes internally).
    None,
    /// Unknown, or not determinable from the OID alone (e.g. RSASSA-PSS).
    Other,
}

/// The signature algorithm of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureAlgorithm {
    /// Dotted OID.
    pub oid: String,
    /// Human-readable name (e.g. `sha256WithRSAEncryption`); the dotted OID
    /// when the algorithm is unknown.
    pub name: String,
    /// The hash component.
    pub hash: HashAlgorithm,
}

impl SignatureAlgorithm {
    /// Builds the description for a signature algorithm OID.
    #[must_use]
    pub fn from_oid(oid: &str) -> Self {
        let (name, hash) = match oid {
            "1.2.840.113549.1.1.4" => ("md5WithRSAEncryption", HashAlgorithm::Md5),
            "1.2.840.113549.1.1.5" => ("sha1WithRSAEncryption", HashAlgorithm::Sha1),
            "1.2.840.113549.1.1.14" => ("sha224WithRSAEncryption", HashAlgorithm::Sha224),
            "1.2.840.113549.1.1.11" => ("sha256WithRSAEncryption", HashAlgorithm::Sha256),
            "1.2.840.113549.1.1.12" => ("sha384WithRSAEncryption", HashAlgorithm::Sha384),
            "1.2.840.113549.1.1.13" => ("sha512WithRSAEncryption", HashAlgorithm::Sha512),
            "1.2.840.113549.1.1.10" => ("RSASSA-PSS", HashAlgorithm::Other),
            "1.2.840.10045.4.1" => ("ecdsa-with-SHA1", HashAlgorithm::Sha1),
            "1.2.840.10045.4.3.1" => ("ecdsa-with-SHA224", HashAlgorithm::Sha224),
            "1.2.840.10045.4.3.2" => ("ecdsa-with-SHA256", HashAlgorithm::Sha256),
            "1.2.840.10045.4.3.3" => ("ecdsa-with-SHA384", HashAlgorithm::Sha384),
            "1.2.840.10045.4.3.4" => ("ecdsa-with-SHA512", HashAlgorithm::Sha512),
            "1.2.840.10040.4.3" => ("dsa-with-sha1", HashAlgorithm::Sha1),
            "2.16.840.1.101.3.4.3.2" => ("dsa-with-sha256", HashAlgorithm::Sha256),
            "1.3.101.112" => ("Ed25519", HashAlgorithm::None),
            "1.3.101.113" => ("Ed448", HashAlgorithm::None),
            other => (other, HashAlgorithm::Other),
        };
        Self {
            oid: oid.to_owned(),
            name: name.to_owned(),
            hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_oid_conhecido_deve_dar_nome_e_hash() {
        let sig = SignatureAlgorithm::from_oid("1.2.840.10045.4.3.2");
        assert_eq!(sig.name, "ecdsa-with-SHA256");
        assert_eq!(sig.hash, HashAlgorithm::Sha256);
    }

    #[test]
    fn quando_oid_desconhecido_deve_usar_o_proprio_oid_como_nome() {
        let sig = SignatureAlgorithm::from_oid("1.2.3.4");
        assert_eq!(sig.name, "1.2.3.4");
        assert_eq!(sig.hash, HashAlgorithm::Other);
    }
}
