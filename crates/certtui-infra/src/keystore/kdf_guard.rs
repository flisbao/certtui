//! A budget for the key derivation a PKCS#12 file can demand.
//!
//! `p12-keystore` caps each key derivation (PBKDF2 up to 1 000 000
//! iterations, scrypt up to 1 GiB) but not how many a file asks for, so a few
//! hundred bytes can cost a gigabyte or minutes of CPU, and a file made for
//! the empty password gets there with no flag at all. This guard reads the
//! parameters that sit in the clear and refuses the file before the library
//! derives anything. Parameters hidden inside an encrypted part are out of
//! its sight; the deadline in `pkcs12.rs` covers those.

use certtui_app::keystore::KeystoreError;

/// `06 09` + OID 1.2.840.113549.1.5.12 (PBKDF2).
const PBKDF2: [u8; 11] = [
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C,
];
/// `06 09` + OID 1.3.6.1.4.1.11591.4.11 (scrypt).
const SCRYPT: [u8; 11] = [
    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x04, 0x0B,
];

/// What a file may demand in the clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfBudget {
    /// Most key derivations.
    pub max_calls: usize,
    /// Most PBKDF2 iterations over all of them (about 0.5 s per million).
    pub max_total_iterations: u64,
}

impl Default for KdfBudget {
    /// Generous for real files (OpenSSL: 2 048 iterations, Java: 10 000, a
    /// few derivations), tight for hostile ones (about 4 s of CPU).
    fn default() -> Self {
        Self {
            max_calls: 64,
            max_total_iterations: 8_000_000,
        }
    }
}

/// What an iteration count that cannot be read is charged: the library's
/// own ceiling per call, so an odd encoding never makes a file cheaper.
const UNREADABLE_ITERATIONS: u64 = 1_000_000;

impl KdfBudget {
    /// Checks the clear-text key derivations of `bytes` against the budget.
    ///
    /// # Errors
    ///
    /// [`KeystoreError::UnsupportedAlgorithm`] for scrypt (its memory cost
    /// cannot be bounded from outside the library) and
    /// [`KeystoreError::TooExpensive`] when the PBKDF2 work exceeds the budget.
    pub fn check(&self, bytes: &[u8]) -> Result<(), KeystoreError> {
        if find_all(bytes, &SCRYPT).next().is_some() {
            return Err(KeystoreError::UnsupportedAlgorithm("scrypt".to_owned()));
        }
        let mut calls = 0_usize;
        let mut total = 0_u64;
        for at in find_all(bytes, &PBKDF2) {
            calls = calls.saturating_add(1);
            let after = bytes.get(at + PBKDF2.len()..).unwrap_or_default();
            total = total.saturating_add(iterations_after_oid(after));
            if calls > self.max_calls || total > self.max_total_iterations {
                return Err(KeystoreError::TooExpensive);
            }
        }
        Ok(())
    }
}

/// Start offsets of every occurrence of `needle` (overlaps included).
fn find_all<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(move |(_, window)| *window == needle)
        .map(|(at, _)| at)
}

/// Reads `SEQUENCE { OCTET STRING salt, INTEGER iterations, ... }` right after
/// the PBKDF2 OID; anything else is charged the worst case.
fn iterations_after_oid(after: &[u8]) -> u64 {
    read_iterations(after).unwrap_or(UNREADABLE_ITERATIONS)
}

fn read_iterations(after: &[u8]) -> Option<u64> {
    let (tag, body) = tlv(after)?;
    if tag != 0x30 {
        return None;
    }
    let (salt_tag, rest) = tlv_rest(body)?;
    if salt_tag != 0x04 {
        return None;
    }
    let (int_tag, int_body) = tlv(rest)?;
    if int_tag != 0x02 || int_body.is_empty() || int_body.len() > 8 {
        return None;
    }
    Some(
        int_body
            .iter()
            .fold(0_u64, |acc, byte| (acc << 8) | u64::from(*byte)),
    )
}

/// `(tag, content)` of the first TLV of `data`, short and long forms.
fn tlv(data: &[u8]) -> Option<(u8, &[u8])> {
    let (tag, content, _) = split_tlv(data)?;
    Some((tag, content))
}

/// `(tag, what follows the first TLV)`.
fn tlv_rest(data: &[u8]) -> Option<(u8, &[u8])> {
    let (tag, _, rest) = split_tlv(data)?;
    Some((tag, rest))
}

fn split_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let first = *data.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2_usize)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let raw = data.get(2..2 + count)?;
        (
            raw.iter()
                .fold(0_usize, |acc, b| (acc << 8) | usize::from(*b)),
            2 + count,
        )
    };
    let end = header.checked_add(len)?;
    let content = data.get(header..end)?;
    Some((tag, content, data.get(end..)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/keystores/",
                $name
            ))
        };
    }

    fn pbkdf2(iterations: &[u8]) -> Vec<u8> {
        // OID, SEQUENCE { OCTET STRING salt(2), INTEGER iterations }
        let mut out = PBKDF2.to_vec();
        let mut inner = vec![
            0x04,
            0x02,
            0xAA,
            0xBB,
            0x02,
            u8::try_from(iterations.len()).unwrap(),
        ];
        inner.extend_from_slice(iterations);
        out.push(0x30);
        out.push(u8::try_from(inner.len()).unwrap());
        out.extend(inner);
        out
    }

    #[test]
    fn quando_arquivos_reais_deve_caber_no_orcamento() {
        for bytes in [
            &fixture!("chain-with-key.p12")[..],
            fixture!("certs-only.p12"),
            fixture!("empty-password.p12"),
            fixture!("no-mac.p12"),
            fixture!("trusted-certs.jks"),
        ] {
            assert_eq!(KdfBudget::default().check(bytes), Ok(()));
        }
    }

    #[test]
    fn quando_scrypt_deve_recusar_pelo_nome() {
        let got = KdfBudget::default().check(fixture!("kdf-scrypt.p12"));
        assert_eq!(
            got,
            Err(KeystoreError::UnsupportedAlgorithm("scrypt".to_owned()))
        );
    }

    #[test]
    fn quando_muitas_derivacoes_caras_deve_dar_too_expensive() {
        let got = KdfBudget::default().check(fixture!("kdf-many-pbkdf2.p12"));
        assert_eq!(got, Err(KeystoreError::TooExpensive));
    }

    #[test]
    fn quando_iteracoes_somam_ate_o_teto_deve_aceitar_e_acima_deve_recusar() {
        // 4 x 2 000 000 = 8 000 000, exactly the budget.
        let two_million = [0x1E, 0x84, 0x80];
        let mut four = Vec::new();
        for _ in 0..4 {
            four.extend(pbkdf2(&two_million));
        }
        assert_eq!(KdfBudget::default().check(&four), Ok(()));
        four.extend(pbkdf2(&[0x01]));
        assert_eq!(
            KdfBudget::default().check(&four),
            Err(KeystoreError::TooExpensive)
        );
    }

    #[test]
    fn quando_muitas_chamadas_baratas_deve_dar_too_expensive() {
        let mut many = Vec::new();
        for _ in 0..65 {
            many.extend(pbkdf2(&[0x01]));
        }
        assert_eq!(
            KdfBudget::default().check(&many),
            Err(KeystoreError::TooExpensive)
        );
        many.truncate(many.len() / 65 * 64);
        assert_eq!(KdfBudget::default().check(&many), Ok(()));
    }

    #[test]
    fn quando_parametros_ilegiveis_deve_cobrar_o_pior_caso() {
        // The OID with nothing readable after it costs a full million.
        let mut bytes = Vec::new();
        for _ in 0..9 {
            bytes.extend_from_slice(&PBKDF2);
            bytes.extend_from_slice(&[0xFF, 0xFF]);
        }
        assert_eq!(
            KdfBudget::default().check(&bytes),
            Err(KeystoreError::TooExpensive)
        );
    }

    #[test]
    fn quando_lixo_ou_vazio_deve_nao_panicar_e_aceitar() {
        for sample in [&b""[..], b"x", &[0x06, 0x09], &[0xFF; 64]] {
            assert_eq!(KdfBudget::default().check(sample), Ok(()));
        }
    }

    #[test]
    fn quando_tlv_tem_comprimento_enorme_deve_dar_none_sem_panic() {
        assert_eq!(split_tlv(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]), None);
        assert_eq!(split_tlv(&[0x30, 0x80]), None);
        assert_eq!(split_tlv(&[0x30]), None);
    }
}
