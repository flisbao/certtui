//! Filesystem and standard-input source loading with bounded content detection.

mod bounded;
mod dir;
mod format;
mod fs;
mod pkcs7;
mod text;

pub use fs::FsSourceLoader;

/// Entry points exposed only to the `cargo-fuzz` crate (feature `fuzzing`).
///
/// Not part of the public API: absent from default builds and hidden from the
/// documentation.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    use certtui_domain::limits::Limits;

    /// Runs the loader's bounded PKCS#7 / CMS extraction over `der` and returns
    /// how many certificates it kept, or `None` when the envelope is malformed.
    #[must_use]
    pub fn extract_pkcs7_certs(der: &[u8], limits: &Limits) -> Option<usize> {
        super::pkcs7::extract_pkcs7_certs_with_metadata(der, limits)
            .ok()
            .map(|extraction| extraction.certs.len())
    }
}
