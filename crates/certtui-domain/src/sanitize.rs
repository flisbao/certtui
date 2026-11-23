//! Sanitization of untrusted certificate strings before rendering or copying.

use std::borrow::Cow;

/// Removes characters that are unsafe to render or copy from untrusted text.
///
/// Strips Unicode control characters (`char::is_control`: C0, DEL and C1,
/// including ESC and CSI) except `\n` and `\t`, plus bidirectional
/// override/isolate formatting characters (U+202A..=U+202E, U+2066..=U+2069),
/// which can be used for homograph/spoofing attacks in a certificate CN.
/// Returns `Cow::Borrowed` when the input needs no change.
#[must_use]
pub fn sanitize_display(input: &str) -> Cow<'_, str> {
    if input.chars().any(is_unsafe_for_display) {
        Cow::Owned(
            input
                .chars()
                .filter(|c| !is_unsafe_for_display(*c))
                .collect(),
        )
    } else {
        Cow::Borrowed(input)
    }
}

/// Whether `c` must be dropped: control (except `\n`, `\t`) or bidi override/isolate.
fn is_unsafe_for_display(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)] // Justificativa: código de teste.
mod tests {
    use super::*;

    #[test]
    fn quando_texto_limpo_deve_devolver_borrowed() {
        let out = sanitize_display("example.com ção\n\tok");
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, "example.com ção\n\tok");
    }

    #[test]
    fn quando_tem_esc_e_csi_deve_remover() {
        let out = sanitize_display("a\x1b[31mb");
        assert!(matches!(out, Cow::Owned(_)));
        assert_eq!(out, "a[31mb");
    }

    #[test]
    fn quando_tem_nul_ou_c1_deve_remover() {
        assert_eq!(sanitize_display("\u{0}\u{9b}x"), "x");
    }

    #[test]
    fn quando_tem_newline_e_tab_deve_preservar() {
        assert_eq!(sanitize_display("a\nb\tc\x07"), "a\nb\tc");
    }

    #[test]
    fn quando_tem_bidi_override_deve_remover() {
        // U+202E (RLO) permite spoofing/homograph em CN: "evil\u{202E}moc.com".
        assert_eq!(sanitize_display("evil\u{202E}moc.com"), "evilmoc.com");
        assert_eq!(sanitize_display("a\u{2066}b\u{2069}c"), "abc");
    }
}
