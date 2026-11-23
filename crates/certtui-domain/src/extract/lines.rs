//! Line splitting tolerant to CR, LF and escaped (literal) line breaks.

/// Splits `input` into `(offset, line)` pairs.
///
/// Separators are `\n`, `\r`, `\r\n` and the two-character literal sequences
/// backslash-`n` and backslash-`r` (as found in JSON strings), including the
/// literal `\r\n` pair. Empty lines are kept; a trailing empty segment is not.
pub(crate) fn split_lines(input: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    Lines { input, pos: 0 }
}

struct Lines<'a> {
    input: &'a [u8],
    pos: usize,
}

/// Length of the separator at `i`, or `None` when there is none.
fn separator_len(input: &[u8], i: usize) -> Option<usize> {
    match input.get(i)? {
        b'\n' => Some(1),
        b'\r' => Some(if input.get(i + 1) == Some(&b'\n') {
            2
        } else {
            1
        }),
        b'\\' => match input.get(i + 1)? {
            b'n' => Some(2),
            b'r' => {
                let crlf = input.get(i + 2) == Some(&b'\\') && input.get(i + 3) == Some(&b'n');
                Some(if crlf { 4 } else { 2 })
            }
            _ => None,
        },
        _ => None,
    }
}

impl<'a> Iterator for Lines<'a> {
    type Item = (usize, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.input.len() {
            return None;
        }
        let start = self.pos;
        let mut i = start;
        while i < self.input.len() {
            if let Some(sep) = separator_len(self.input, i) {
                self.pos = i + sep;
                return Some((start, self.input.get(start..i)?));
            }
            i += 1;
        }
        self.pos = self.input.len();
        Some((start, self.input.get(start..)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(input: &[u8]) -> Vec<(usize, &[u8])> {
        split_lines(input).collect()
    }

    #[test]
    fn quando_split_lines_tem_backslash_n_literal_deve_separar() {
        let got = lines(b"a\\nb\nc");
        assert_eq!(got, vec![(0, &b"a"[..]), (3, &b"b"[..]), (5, &b"c"[..])]);
    }

    #[test]
    fn quando_split_lines_tem_crlf_deve_tratar_como_um_separador() {
        let got = lines(b"a\r\nb\rc");
        assert_eq!(got, vec![(0, &b"a"[..]), (3, &b"b"[..]), (5, &b"c"[..])]);
    }

    #[test]
    fn quando_split_lines_tem_crlf_literal_deve_tratar_como_um_separador() {
        let got = lines(b"a\\r\\nb\\rc");
        assert_eq!(got, vec![(0, &b"a"[..]), (5, &b"b"[..]), (8, &b"c"[..])]);
    }

    #[test]
    fn quando_split_lines_tem_barra_solta_deve_manter_na_linha() {
        assert_eq!(lines(b"a\\xb\\"), vec![(0, &b"a\\xb\\"[..])]);
    }

    #[test]
    fn quando_split_lines_entrada_vazia_deve_nao_devolver_linhas() {
        assert_eq!(lines(b"").len(), 0);
    }
}
