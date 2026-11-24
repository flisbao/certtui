//! Lossy, bounded-size transcoding of BOM-marked UTF-16 input.

/// Converts UTF-16 with a byte-order mark to UTF-8, replacing invalid
/// surrogate sequences with U+FFFD. The output size is bounded by three bytes
/// per input code unit; a BMP character may expand from two to three bytes.
pub(crate) fn utf16_to_utf8_bytes(bytes: &[u8]) -> Vec<u8> {
    let (payload, little_endian) = match bytes {
        [0xFF, 0xFE, rest @ ..] => (rest, true),
        [0xFE, 0xFF, rest @ ..] => (rest, false),
        _ => (bytes, true),
    };
    let decoded = || {
        let words = payload
            .chunks(2)
            .filter_map(|pair| match pair {
                [first, second] => Some([*first, *second]),
                _ => None,
            })
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes(pair)
                } else {
                    u16::from_be_bytes(pair)
                }
            });
        char::decode_utf16(words).map(|item| item.unwrap_or(char::REPLACEMENT_CHARACTER))
    };

    let mut output_len = decoded().fold(0_usize, |size, ch| size.saturating_add(ch.len_utf8()));
    if payload.len() % 2 != 0 {
        output_len = output_len.saturating_add(char::REPLACEMENT_CHARACTER.len_utf8());
    }
    let mut output = Vec::with_capacity(output_len);
    for character in decoded() {
        let mut encoded = [0; 4];
        output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
    }
    if payload.len() % 2 != 0 {
        let mut encoded = [0; 4];
        output.extend_from_slice(
            char::REPLACEMENT_CHARACTER
                .encode_utf8(&mut encoded)
                .as_bytes(),
        );
    }
    output
}
