//! JKS (Java KeyStore): certificates only, key entries skipped unread.
//!
//! Layout (big endian), version 1 or 2:
//!
//! ```text
//! magic 0xFEEDFEED | version u32 | count u32
//! count x entry:
//!   tag u32 (1 = private key, 2 = trusted certificate) | alias (u16 length + bytes) | time u64
//!   tag 1: key length u32 + key bytes | chain count u32 | chain count x certificate
//!   tag 2: certificate
//! certificate: type (v2 only; u16 length + bytes, "X.509") | length u32 + DER
//! trailer: SHA-1(password as UTF-16BE | "Mighty Aphrodite" | everything before it)
//! ```
//!
//! Every length comes from the file, so every read goes through a cursor
//! that checks it against what is left, and counts are checked against the
//! limits *before* anything is allocated.

use certtui_app::keystore::{
    EntryKind, ExposeSecret, KeystoreContents, KeystoreEntry, KeystoreError, KeystoreReader,
    SecretString,
};
use certtui_domain::limits::Limits;
use sha1::{Digest as _, Sha1};

const MAGIC: [u8; 4] = [0xFE, 0xED, 0xFE, 0xED];
const TAG_PRIVATE_KEY: u32 = 1;
const TAG_TRUSTED_CERT: u32 = 2;
/// The constant Java mixes into the integrity hash.
const WHITENER: &[u8] = b"Mighty Aphrodite";
const DIGEST_LEN: usize = 20;

/// `KeystoreReader` for JKS.
#[derive(Debug, Clone, Copy, Default)]
pub struct JksReader;

fn malformed(what: &str) -> KeystoreError {
    KeystoreError::Malformed(format!("not a valid JKS keystore: {what}"))
}

/// A bounds-checked cursor: no read goes past the end, none panics.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], KeystoreError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| malformed("length overflow"))?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| malformed("unexpected end of data"))?;
        self.pos = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, KeystoreError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([
            *bytes.first().unwrap_or(&0),
            *bytes.get(1).unwrap_or(&0),
        ]))
    }

    fn u32(&mut self) -> Result<u32, KeystoreError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| malformed("short integer"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn skip(&mut self, len: usize) -> Result<(), KeystoreError> {
        self.take(len).map(|_| ())
    }

    fn is_at_end(&self) -> bool {
        self.pos == self.data.len()
    }

    /// A `u16`-prefixed string (modified UTF-8; invalid bytes become U+FFFD).
    fn string(&mut self) -> Result<String, KeystoreError> {
        let len = usize::from(self.u16()?);
        Ok(String::from_utf8_lossy(self.take(len)?).into_owned())
    }
}

/// Counters shared by the entry readers.
struct Tally<'a> {
    limits: &'a Limits,
    certs: usize,
    entries: Vec<KeystoreEntry>,
    ignored: usize,
}

impl Tally<'_> {
    fn too_many(&self) -> KeystoreError {
        KeystoreError::TooManyEntries {
            max: self.limits.max_certs_per_source,
        }
    }

    /// Reads one certificate; keeps it only when it is X.509.
    fn certificate(
        &mut self,
        cursor: &mut Cursor<'_>,
        version: u32,
        alias: &str,
        kind: EntryKind,
    ) -> Result<(), KeystoreError> {
        let is_x509 = if version == 1 {
            true
        } else {
            cursor.string()?.eq_ignore_ascii_case("X.509")
        };
        let len = usize::try_from(cursor.u32()?).map_err(|_| malformed("length overflow"))?;
        if len > self.limits.max_cert_der_bytes {
            return Err(malformed("certificate larger than the limit"));
        }
        let der = cursor.take(len)?;
        if !is_x509 {
            self.ignored = self.ignored.saturating_add(1);
            return Ok(());
        }
        if self.certs >= self.limits.max_certs_per_source {
            return Err(self.too_many());
        }
        self.certs = self.certs.saturating_add(1);
        self.entries.push(KeystoreEntry {
            alias: alias.to_owned(),
            der: der.to_vec(),
            kind,
        });
        Ok(())
    }
}

/// `SHA-1(password UTF-16BE | WHITENER | content)`, the JKS integrity digest.
fn integrity_digest(password: &str, content: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha1::new();
    for unit in password.encode_utf16() {
        hasher.update(unit.to_be_bytes());
    }
    hasher.update(WHITENER);
    hasher.update(content);
    hasher.finalize().into()
}

/// Equality that does not stop at the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl KeystoreReader for JksReader {
    fn read_certs(
        &self,
        bytes: &[u8],
        password: Option<&SecretString>,
        limits: &Limits,
    ) -> Result<KeystoreContents, KeystoreError> {
        if bytes.len() > limits.max_keystore_bytes {
            return Err(KeystoreError::TooLarge {
                limit: limits.max_keystore_bytes,
            });
        }
        let content_len = bytes
            .len()
            .checked_sub(DIGEST_LEN)
            .ok_or_else(|| malformed("shorter than its digest"))?;
        let (content, digest) = bytes.split_at(content_len);
        let mut cursor = Cursor {
            data: content,
            pos: 0,
        };
        if cursor.take(MAGIC.len())? != MAGIC {
            return Err(malformed("bad magic"));
        }
        let version = cursor.u32()?;
        if version != 1 && version != 2 {
            return Err(malformed("unsupported version"));
        }
        let count = usize::try_from(cursor.u32()?).map_err(|_| malformed("count overflow"))?;
        // Before anything is allocated or looped over.
        if count > limits.max_certs_per_source {
            return Err(KeystoreError::TooManyEntries {
                max: limits.max_certs_per_source,
            });
        }
        let mut tally = Tally {
            limits,
            certs: 0,
            entries: Vec::new(),
            ignored: 0,
        };
        for _ in 0..count {
            read_entry(&mut cursor, version, &mut tally)?;
        }
        if !cursor.is_at_end() {
            return Err(malformed("trailing data before the digest"));
        }
        let integrity_unverified = match password {
            Some(secret) => {
                let expected = integrity_digest(secret.expose_secret(), content);
                if !constant_time_eq(&expected, digest) {
                    return Err(KeystoreError::WrongPasswordOrCorrupt);
                }
                false
            }
            None => true,
        };
        Ok(KeystoreContents {
            entries: tally.entries,
            integrity_unverified,
            ignored: tally.ignored,
        })
    }
}

fn read_entry(
    cursor: &mut Cursor<'_>,
    version: u32,
    tally: &mut Tally<'_>,
) -> Result<(), KeystoreError> {
    let tag = cursor.u32()?;
    let alias = cursor.string()?;
    cursor.skip(8)?; // creation time
    match tag {
        TAG_PRIVATE_KEY => {
            // The key is skipped unread: never copied, never decoded.
            let key_len =
                usize::try_from(cursor.u32()?).map_err(|_| malformed("length overflow"))?;
            cursor.skip(key_len)?;
            let chain = usize::try_from(cursor.u32()?).map_err(|_| malformed("count overflow"))?;
            if chain > tally.limits.max_certs_per_source {
                return Err(tally.too_many());
            }
            for _ in 0..chain {
                tally.certificate(cursor, version, &alias, EntryKind::CertOfKeyEntry)?;
            }
            Ok(())
        }
        TAG_TRUSTED_CERT => tally.certificate(cursor, version, &alias, EntryKind::TrustedCert),
        _ => Err(malformed("unknown entry type")),
    }
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

    const LEAF: &[u8] = fixture!("leaf.der");
    const INT: &[u8] = fixture!("int.der");
    const ROOT: &[u8] = fixture!("root.der");

    fn password(text: &str) -> SecretString {
        SecretString::from(text.to_owned())
    }

    fn read(bytes: &[u8], pw: Option<&SecretString>) -> Result<KeystoreContents, KeystoreError> {
        JksReader.read_certs(bytes, pw, &Limits::default())
    }

    fn sorted_ders(contents: &KeystoreContents) -> Vec<Vec<u8>> {
        let mut ders: Vec<Vec<u8>> = contents.entries.iter().map(|e| e.der.clone()).collect();
        ders.sort_unstable();
        ders
    }

    fn expected() -> Vec<Vec<u8>> {
        let mut all = vec![LEAF.to_vec(), INT.to_vec(), ROOT.to_vec()];
        all.sort_unstable();
        all
    }

    // --- a tiny JKS writer, so tests can build shapes keytool never makes ----

    fn put_string(out: &mut Vec<u8>, text: &str) {
        out.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    }

    fn put_cert(out: &mut Vec<u8>, version: u32, kind: &str, der: &[u8]) {
        if version == 2 {
            put_string(out, kind);
        }
        out.extend_from_slice(&u32::try_from(der.len()).unwrap().to_be_bytes());
        out.extend_from_slice(der);
    }

    fn trusted_entry(out: &mut Vec<u8>, version: u32, alias: &str, kind: &str, der: &[u8]) {
        out.extend_from_slice(&TAG_TRUSTED_CERT.to_be_bytes());
        put_string(out, alias);
        out.extend_from_slice(&[0; 8]);
        put_cert(out, version, kind, der);
    }

    fn jks(version: u32, count: u32, entries: &[u8], pw: &str) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(entries);
        let digest = integrity_digest(pw, &out);
        out.extend_from_slice(&digest);
        out
    }

    #[test]
    fn quando_jks_com_senha_correta_deve_listar_certs_e_verificar_integridade() {
        let got = read(fixture!("trusted-certs.jks"), Some(&password("changeit"))).unwrap();

        assert_eq!(sorted_ders(&got), expected());
        assert!(!got.integrity_unverified);
        assert_eq!(got.ignored, 0);
        // Java stores entries in hash order, so compare as a set.
        let mut aliases: Vec<_> = got.entries.iter().map(|e| e.alias.as_str()).collect();
        aliases.sort_unstable();
        assert_eq!(aliases, ["int", "leaf", "root"]);
        assert!(got.entries.iter().all(|e| e.kind == EntryKind::TrustedCert));
    }

    #[test]
    fn quando_senha_errada_deve_dar_wrong_password_or_corrupt() {
        let got = read(fixture!("trusted-certs.jks"), Some(&password("nope")));
        assert_eq!(got, Err(KeystoreError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn quando_sem_senha_deve_listar_certs_e_marcar_integrity_unverified() {
        let got = read(fixture!("trusted-certs.jks"), None).unwrap();

        assert_eq!(sorted_ders(&got), expected());
        assert!(got.integrity_unverified);
    }

    #[test]
    fn quando_jks_tem_chave_privada_deve_devolver_so_certs_da_cadeia_e_nenhum_byte_da_chave() {
        let bytes = fixture!("with-private-key.jks");

        let got = read(bytes, Some(&password("changeit"))).unwrap();

        assert_eq!(sorted_ders(&got), expected());
        assert!(
            got.entries
                .iter()
                .all(|e| e.kind == EntryKind::CertOfKeyEntry)
        );
        assert!(got.entries.iter().all(|e| e.alias == "server"));
        // The encrypted key blob sits between the alias and the chain; none
        // of it may appear in what came back.
        // header (12) | tag (4) | alias "server" (2 + 6) | time (8) | key length (4) | key
        let key_len_at = 12 + 4 + 2 + 6 + 8;
        let key_len = usize::try_from(u32::from_be_bytes(
            bytes[key_len_at..key_len_at + 4].try_into().unwrap(),
        ))
        .unwrap();
        let key = &bytes[key_len_at + 4..key_len_at + 4 + key_len];
        assert!(key.len() > 32, "the fixture must hold a key blob");
        let mut haystack = format!("{got:?}").into_bytes();
        for entry in &got.entries {
            haystack.extend_from_slice(&entry.der);
        }
        for window in key.windows(16) {
            assert!(
                !haystack.windows(16).any(|h| h == window),
                "a 16-byte window of the key blob leaked"
            );
        }
    }

    #[test]
    fn quando_truncado_deve_dar_malformed_sem_panic() {
        let got = read(fixture!("truncated.jks"), Some(&password("changeit")));
        assert!(matches!(got, Err(KeystoreError::Malformed(_))), "{got:?}");
    }

    #[test]
    fn quando_qualquer_prefixo_do_arquivo_deve_dar_erro_e_nunca_panic() {
        let bytes = fixture!("with-private-key.jks");
        for len in 0..bytes.len() {
            for pw in [None, Some(&password("changeit"))] {
                let got = read(&bytes[..len], pw);
                assert!(got.is_err(), "prefix {len}: {got:?}");
            }
        }
    }

    #[test]
    fn quando_um_byte_muda_e_ha_senha_deve_dar_erro() {
        let original = fixture!("trusted-certs.jks");
        for at in 0..original.len() {
            let mut bytes = original.to_vec();
            if let Some(byte) = bytes.get_mut(at) {
                *byte ^= 0x01;
            }
            let got = read(&bytes, Some(&password("changeit")));
            assert!(got.is_err(), "flip at {at} went unnoticed");
        }
    }

    #[test]
    fn quando_contagem_e_gigante_deve_dar_too_many_entries_sem_alocar() {
        let got = read(fixture!("bad-count.jks"), Some(&password("changeit")));
        assert_eq!(got, Err(KeystoreError::TooManyEntries { max: 500 }));
        let got = read(fixture!("bad-count.jks"), None);
        assert_eq!(got, Err(KeystoreError::TooManyEntries { max: 500 }));
    }

    #[test]
    fn quando_entradas_passam_do_limite_configurado_deve_dar_too_many_entries() {
        let limits = Limits {
            max_certs_per_source: 2,
            ..Limits::default()
        };
        let got = JksReader.read_certs(
            fixture!("trusted-certs.jks"),
            Some(&password("changeit")),
            &limits,
        );
        assert_eq!(got, Err(KeystoreError::TooManyEntries { max: 2 }));
    }

    #[test]
    fn quando_cadeia_de_chave_e_gigante_deve_dar_too_many_entries() {
        let mut entries = Vec::new();
        entries.extend_from_slice(&TAG_PRIVATE_KEY.to_be_bytes());
        put_string(&mut entries, "k");
        entries.extend_from_slice(&[0; 8]);
        entries.extend_from_slice(&4_u32.to_be_bytes());
        entries.extend_from_slice(b"KEY!");
        entries.extend_from_slice(&u32::MAX.to_be_bytes());
        let bytes = jks(2, 1, &entries, "pw");
        let got = read(&bytes, Some(&password("pw")));
        assert_eq!(got, Err(KeystoreError::TooManyEntries { max: 500 }));
    }

    #[test]
    fn quando_tamanho_da_chave_passa_do_arquivo_deve_dar_malformed() {
        let mut entries = Vec::new();
        entries.extend_from_slice(&TAG_PRIVATE_KEY.to_be_bytes());
        put_string(&mut entries, "k");
        entries.extend_from_slice(&[0; 8]);
        entries.extend_from_slice(&u32::MAX.to_be_bytes());
        let bytes = jks(2, 1, &entries, "pw");
        let got = read(&bytes, Some(&password("pw")));
        assert!(matches!(got, Err(KeystoreError::Malformed(_))), "{got:?}");
    }

    #[test]
    fn quando_tipo_de_cert_nao_e_x509_deve_ignorar_a_entrada_e_contar() {
        let mut entries = Vec::new();
        trusted_entry(&mut entries, 2, "pgp", "OpenPGP", b"not an x509");
        trusted_entry(&mut entries, 2, "ok", "X.509", LEAF);
        let bytes = jks(2, 2, &entries, "pw");

        let got = read(&bytes, Some(&password("pw"))).unwrap();

        assert_eq!(got.entries.len(), 1);
        assert_eq!(got.entries[0].der, LEAF);
        assert_eq!(got.ignored, 1);
    }

    #[test]
    fn quando_versao_1_deve_ler_certs_sem_tipo() {
        let mut entries = Vec::new();
        trusted_entry(&mut entries, 1, "old", "", LEAF);
        let bytes = jks(1, 1, &entries, "pw");

        let got = read(&bytes, Some(&password("pw"))).unwrap();

        assert_eq!(got.entries.len(), 1);
        assert_eq!(got.entries[0].alias, "old");
    }

    #[test]
    fn quando_senha_tem_caractere_fora_do_bmp_deve_verificar_com_pares_substitutos() {
        let mut entries = Vec::new();
        trusted_entry(&mut entries, 2, "a", "X.509", LEAF);
        let bytes = jks(2, 1, &entries, "p\u{1F511}w");
        assert!(read(&bytes, Some(&password("p\u{1F511}w"))).is_ok());
        assert!(read(&bytes, Some(&password("pw"))).is_err());
    }

    #[test]
    fn quando_acima_de_max_keystore_bytes_deve_dar_too_large() {
        let limits = Limits {
            max_keystore_bytes: 100,
            ..Limits::default()
        };
        let got = JksReader.read_certs(fixture!("trusted-certs.jks"), None, &limits);
        assert_eq!(got, Err(KeystoreError::TooLarge { limit: 100 }));
    }

    #[test]
    fn quando_magic_ou_versao_ruins_deve_dar_malformed() {
        let mut bad_magic = fixture!("trusted-certs.jks").to_vec();
        bad_magic[0] = 0;
        assert!(matches!(
            read(&bad_magic, None),
            Err(KeystoreError::Malformed(_))
        ));
        let mut bad_version = fixture!("trusted-certs.jks").to_vec();
        bad_version[7] = 9;
        assert!(matches!(
            read(&bad_version, None),
            Err(KeystoreError::Malformed(_))
        ));
    }

    #[test]
    fn quando_erro_deve_nao_conter_a_senha() {
        let secret = "s3cr3t-Pa55w0rd-xyz";
        for file in [
            &fixture!("trusted-certs.jks")[..],
            fixture!("truncated.jks"),
            fixture!("bad-count.jks"),
        ] {
            let error = read(file, Some(&password(secret))).unwrap_err();
            assert!(!format!("{error} {error:?}").contains(secret));
        }
    }

    #[test]
    fn quando_lixo_deve_dar_erro_sem_panic() {
        for sample in [&b""[..], b"x", &[0xFE, 0xED, 0xFE, 0xED], &[0xFF; 100]] {
            assert!(read(sample, None).is_err());
        }
    }
}
