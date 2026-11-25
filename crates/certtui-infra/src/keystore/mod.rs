//! Keystore readers: PKCS#12 and JKS behind the `KeystoreReader` port.
//!
//! They return certificates only. A private key is never copied out of the
//! keystore: the PKCS#12 reader drops what the library decrypts before it
//! returns, and the JKS reader skips key entries without reading them.

mod pkcs12;

pub use pkcs12::Pkcs12Reader;
