//! Total length of a DER `SEQUENCE` from its header.

/// Total size (header plus content) of the DER `SEQUENCE` at the start of
/// `bytes`, as declared by its own header.
///
/// Returns `None` when the tag is not `0x30`, the header is truncated, the
/// length uses the indefinite form or more than four length bytes, or the sum
/// overflows. It does not check that `bytes` holds that many bytes.
pub(crate) fn der_total_len(bytes: &[u8]) -> Option<usize> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x30 {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    if first < 0x80 {
        return 2usize.checked_add(usize::from(first));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return None;
    }
    let len_bytes = rest.get(..n)?;
    let mut len: u32 = 0;
    for &b in len_bytes {
        len = (len << 8) | u32::from(b);
    }
    let len = usize::try_from(len).ok()?;
    2usize.checked_add(n)?.checked_add(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quando_der_curto_deve_somar_cabecalho() {
        assert_eq!(der_total_len(&[0x30, 0x03, 0x01, 0x01, 0x00]), Some(5));
    }

    #[test]
    fn quando_der_longo_82_deve_somar_cabecalho_de_4_bytes() {
        // 30 82 01 00 -> header 4 bytes + 256 content bytes.
        assert_eq!(der_total_len(&[0x30, 0x82, 0x01, 0x00]), Some(260));
    }

    #[test]
    fn quando_comprimento_estoura_usize_deve_dar_none() {
        // Five length bytes are outside the accepted range.
        assert_eq!(der_total_len(&[0x30, 0x85, 1, 0, 0, 0, 0]), None);
        // Indefinite form.
        assert_eq!(der_total_len(&[0x30, 0x80, 0, 0]), None);
        // Truncated long form.
        assert_eq!(der_total_len(&[0x30, 0x82, 0x01]), None);
    }

    #[test]
    fn quando_comprimento_maximo_de_4_bytes_deve_somar_sem_estourar() {
        let total = der_total_len(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(total, usize::try_from(0xffff_ffff_u64 + 6).ok());
    }

    #[test]
    fn quando_tag_nao_e_sequence_deve_dar_none() {
        assert_eq!(der_total_len(&[0x31, 0x00]), None);
        assert_eq!(der_total_len(&[]), None);
    }
}
