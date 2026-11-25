//! Keystore readers: PKCS#12 and JKS behind the `KeystoreReader` port.
//!
//! They return certificates only. A private key is never copied out of the
//! keystore: the PKCS#12 reader drops what the library decrypts before it
//! returns, and the JKS reader skips key entries without reading them.

mod jks;
mod kdf_guard;
mod pkcs12;

pub use jks::JksReader;
pub use pkcs12::Pkcs12Reader;

/// Entry points exposed only to the `cargo-fuzz` crate (feature `fuzzing`).
///
/// Not part of the public API: absent from default builds and hidden from the
/// documentation.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use certtui_app::keystore::{KeystoreReader, SecretString};
    use certtui_domain::limits::Limits;

    use super::{JksReader, Pkcs12Reader};

    /// Runs the PKCS#12 reader over `data`, with the fixture password and
    /// without one, and returns how many certificates it found in total.
    #[must_use]
    pub fn read_pkcs12(data: &[u8], limits: &Limits) -> usize {
        run(&Pkcs12Reader, data, limits)
    }

    /// Runs the JKS reader over `data`, with the fixture password and without
    /// one, and returns how many certificates it found in total.
    #[must_use]
    pub fn read_jks(data: &[u8], limits: &Limits) -> usize {
        run(&JksReader, data, limits)
    }

    fn run(reader: &dyn KeystoreReader, data: &[u8], limits: &Limits) -> usize {
        let password = SecretString::from("changeit".to_owned());
        [Some(&password), None]
            .into_iter()
            .filter_map(|pw| reader.read_certs(data, pw, limits).ok())
            .map(|contents| contents.entries.len())
            .sum()
    }
}
