//! The `KeystoreReader` port: certificates out of PKCS#12 and JKS keystores.
//!
//! Private keys never cross this port. [`KeystoreEntry`] has no field that
//! could hold one, so no adapter can return a key and no caller can show,
//! export or log one by accident (design principle 6).

use std::fmt;

use certtui_domain::limits::Limits;
use thiserror::Error;

pub use secrecy::{ExposeSecret, SecretString};

/// Which keystore format a byte sequence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeystoreFormat {
    /// `PKCS#12` (`.p12`, `.pfx`).
    Pkcs12,
    /// Java `KeyStore` (magic `0xFEEDFEED`).
    Jks,
}

/// What kind of entry a certificate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A trusted certificate entry.
    TrustedCert,
    /// A certificate of the chain of a private key entry (the key itself is
    /// never read).
    CertOfKeyEntry,
}

/// One certificate of a keystore. There is deliberately no key field.
///
/// `Debug` prints the DER length, not the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct KeystoreEntry {
    /// The entry alias (`cert-<n>` when the keystore gives none).
    pub alias: String,
    /// The certificate, DER encoded.
    pub der: Vec<u8>,
    /// Where it came from.
    pub kind: EntryKind,
}

impl fmt::Debug for KeystoreEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeystoreEntry")
            .field("alias", &self.alias)
            .field("der_len", &self.der.len())
            .field("kind", &self.kind)
            .finish()
    }
}

/// What reading a keystore produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeystoreContents {
    /// The certificates, in keystore order.
    pub entries: Vec<KeystoreEntry>,
    /// `true` when the integrity check was skipped (a JKS read without a
    /// password): the certificates are listed but not authenticated.
    pub integrity_unverified: bool,
    /// Entries skipped because they are not X.509 certificates.
    pub ignored: usize,
}

/// Why a keystore could not be read. Messages carry no password and no bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum KeystoreError {
    /// The keystore is encrypted and no password was given.
    #[error("keystore requires a password")]
    PasswordRequired,
    /// The password does not open it, or the keystore is damaged; the two
    /// cannot be told apart without leaking which one it is.
    #[error("wrong password or corrupt keystore")]
    WrongPasswordOrCorrupt,
    /// An algorithm the reader does not support (for example RC2-40).
    #[error("unsupported keystore algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// The structure is invalid.
    #[error("malformed keystore: {0}")]
    Malformed(String),
    /// The keystore is larger than the byte limit.
    #[error("keystore is larger than the limit of {limit} bytes")]
    TooLarge {
        /// The configured maximum in bytes.
        limit: usize,
    },
    /// More entries than `Limits::max_certs_per_source`.
    #[error("keystore has more than {max} entries")]
    TooManyEntries {
        /// The configured maximum.
        max: usize,
    },
}

/// Reads the certificates of a keystore.
///
/// Object safe. Implementations apply `limits.max_keystore_bytes` and
/// `limits.max_certs_per_source` before allocating, never panic on hostile
/// input, never return key material and never echo the password.
pub trait KeystoreReader: Send + Sync {
    /// Reads the certificates of `bytes`; `password` is `None` when none was
    /// given.
    ///
    /// # Errors
    ///
    /// [`KeystoreError`], never carrying the password or any keystore bytes.
    fn read_certs(
        &self,
        bytes: &[u8],
        password: Option<&SecretString>,
        limits: &Limits,
    ) -> Result<KeystoreContents, KeystoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_keystore_entry_e_debugado_deve_nao_ter_dado_de_chave() {
        let entry = KeystoreEntry {
            alias: "server".to_owned(),
            der: vec![0xDE, 0xAD, 0xBE, 0xEF],
            kind: EntryKind::CertOfKeyEntry,
        };
        // Every field of the type is listed here: adding one (a key, say)
        // makes this destructuring stop compiling.
        let KeystoreEntry { alias, der, kind } = &entry;
        assert_eq!(
            (alias.as_str(), der.len(), *kind),
            ("server", 4, EntryKind::CertOfKeyEntry)
        );
        let debug = format!("{entry:?}");
        assert_eq!(
            debug,
            "KeystoreEntry { alias: \"server\", der_len: 4, kind: CertOfKeyEntry }"
        );
        assert!(!debug.contains("222"), "no DER bytes in Debug: {debug}");
    }

    #[test]
    fn quando_senha_e_debugada_deve_mostrar_redacted() {
        let password = SecretString::from("hunter2".to_owned());
        let debug = format!("{password:?}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("REDACTED"), "{debug}");
    }

    #[test]
    fn quando_erro_de_keystore_deve_ter_mensagem_clara_sem_dados() {
        assert_eq!(
            KeystoreError::WrongPasswordOrCorrupt.to_string(),
            "wrong password or corrupt keystore"
        );
        assert_eq!(
            KeystoreError::PasswordRequired.to_string(),
            "keystore requires a password"
        );
        assert_eq!(
            KeystoreError::UnsupportedAlgorithm("RC2-40".to_owned()).to_string(),
            "unsupported keystore algorithm: RC2-40"
        );
    }

    #[test]
    fn quando_load_error_de_keystore_deve_repetir_a_mensagem() {
        use crate::error::LoadError;
        let error = LoadError::Keystore(KeystoreError::WrongPasswordOrCorrupt);
        assert_eq!(error.to_string(), "wrong password or corrupt keystore");
        assert_eq!(
            LoadError::PasswordRequired.to_string(),
            "keystore requires a password"
        );
    }

    #[test]
    fn quando_keystore_sem_senha_jks_deve_virar_nota() {
        use certtui_domain::model::LoadNote;
        let note = LoadNote::KeystoreIntegrityUnverified;
        assert_eq!(
            crate::present::labels::note_text(&note),
            "keystore read without a password: its integrity was not verified"
        );
        assert_eq!(
            serde_json::to_string(&note).unwrap(),
            r#"{"kind":"keystore_integrity_unverified"}"#
        );
    }
}
