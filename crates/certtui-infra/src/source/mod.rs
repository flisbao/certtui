//! Filesystem and standard-input source loading with bounded content detection.

mod bounded;
mod format;
mod fs;
mod text;

pub use fs::FsSourceLoader;
