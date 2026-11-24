//! Filesystem and standard-input source loading with bounded content detection.

mod bounded;
mod dir;
mod format;
mod fs;
mod pkcs7;
mod text;

pub use fs::FsSourceLoader;
