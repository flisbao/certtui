//! Content-based format detection for bounded local input.

/// Format selected from the first bytes of a local source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetectedFormat {
    /// Java `KeyStore` magic.
    Jks,
    /// UTF-16 text with a byte-order mark.
    Utf16Text,
    /// A DER sequence at byte zero.
    BinaryDer,
    /// Any other byte sequence, scanned as free text.
    Text,
}

/// Detects input format from content, in the required precedence order.
pub(crate) fn detect_format(bytes: &[u8]) -> DetectedFormat {
    if bytes.starts_with(&[0xFE, 0xED, 0xFE, 0xED]) {
        DetectedFormat::Jks
    } else if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        DetectedFormat::Utf16Text
    } else if bytes.first() == Some(&0x30) {
        DetectedFormat::BinaryDer
    } else {
        DetectedFormat::Text
    }
}
