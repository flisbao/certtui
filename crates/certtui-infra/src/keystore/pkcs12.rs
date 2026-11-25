//! PKCS#12 (`.p12`, `.pfx`): certificates out of the bags, keys dropped at once.

use certtui_app::keystore::{
    EntryKind, ExposeSecret, KeystoreContents, KeystoreEntry, KeystoreError, KeystoreReader,
    SecretString,
};
use certtui_domain::limits::Limits;
use p12_keystore::Pkcs12Archive;
use p12_keystore::error::Error as P12Error;

/// `KeystoreReader` for PKCS#12, on `p12-keystore`.
///
/// The library decrypts every bag it can, keys included. This adapter keeps
/// the certificates and lets everything else go out of scope before
/// returning, so a key is never held past this function, never stored in the
/// result and never printed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs12Reader;

impl KeystoreReader for Pkcs12Reader {
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
        // Without a password the empty one is still tried: a PKCS#12 made
        // with an empty password opens, any other asks for one.
        let given = password.map_or("", |secret| secret.expose_secret());
        let archive = Pkcs12Archive::from_pkcs12(bytes, given).map_err(|error| {
            let mapped = map_error(&error, bytes);
            if password.is_none() && mapped == KeystoreError::WrongPasswordOrCorrupt {
                KeystoreError::PasswordRequired
            } else {
                mapped
            }
        })?;
        // Keep the certificates only: the key and secret bags die here.
        let Pkcs12Archive {
            certs,
            keys,
            secrets,
        } = archive;
        drop(keys);
        drop(secrets);
        if certs.len() > limits.max_certs_per_source {
            return Err(KeystoreError::TooManyEntries {
                max: limits.max_certs_per_source,
            });
        }
        let entries = certs
            .into_iter()
            .enumerate()
            .map(|(index, bag)| KeystoreEntry {
                alias: bag
                    .friendly_name
                    .unwrap_or_else(|| format!("cert-{}", index.saturating_add(1))),
                der: bag.cert.as_der().to_vec(),
                kind: if bag.local_key_id.is_some() {
                    EntryKind::CertOfKeyEntry
                } else {
                    EntryKind::TrustedCert
                },
            })
            .collect();
        Ok(KeystoreContents {
            entries,
            integrity_unverified: false,
        })
    }
}

/// OID bodies (after the `06 <len>` header) of the PKCS#12 and PKCS#5
/// password-based schemes that need the legacy ciphers, with their names.
const LEGACY_SCHEMES: [(&[u8], &str); 6] = [
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x01],
        "pbeWithSHA1And128BitRC4",
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x02],
        "pbeWithSHA1And40BitRC4",
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x03],
        "pbeWithSHA1And3-KeyTripleDES-CBC",
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x04],
        "pbeWithSHA1And2-KeyTripleDES-CBC",
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x05],
        "pbeWithSHA1And128BitRC2-CBC",
    ),
    (
        &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x06],
        "pbeWithSHA1And40BitRC2-CBC",
    ),
];

/// The legacy scheme named in `bytes`, if one of the known OIDs appears.
fn legacy_scheme_name(bytes: &[u8]) -> &'static str {
    LEGACY_SCHEMES
        .iter()
        .find(|(oid, _)| bytes.windows(oid.len()).any(|window| window == *oid))
        .map_or("unknown encryption scheme", |(_, name)| name)
}

fn map_error(error: &P12Error, bytes: &[u8]) -> KeystoreError {
    match error {
        P12Error::MacError(_) | P12Error::UnpadError | P12Error::Pkcs5Error(_) => {
            KeystoreError::WrongPasswordOrCorrupt
        }
        P12Error::UnsupportedEncryptionScheme => {
            KeystoreError::UnsupportedAlgorithm(legacy_scheme_name(bytes).to_owned())
        }
        P12Error::UnsupportedMacAlgorithm => {
            KeystoreError::UnsupportedAlgorithm("unsupported MAC algorithm".to_owned())
        }
        // The library's own text can quote data; a fixed description cannot.
        _ => KeystoreError::Malformed("not a valid PKCS#12 structure".to_owned()),
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
        Pkcs12Reader.read_certs(bytes, pw, &Limits::default())
    }

    fn ders(contents: &KeystoreContents) -> Vec<&[u8]> {
        let mut ders: Vec<&[u8]> = contents.entries.iter().map(|e| e.der.as_slice()).collect();
        ders.sort_unstable();
        ders
    }

    fn expected() -> Vec<&'static [u8]> {
        let mut all = vec![LEAF, INT, ROOT];
        all.sort_unstable();
        all
    }

    #[test]
    fn quando_senha_correta_deve_listar_3_certs() {
        let got = read(fixture!("chain-with-key.p12"), Some(&password("changeit"))).unwrap();

        assert_eq!(ders(&got), expected());
        assert!(!got.integrity_unverified);
    }

    #[test]
    fn quando_p12_com_chave_deve_devolver_so_certificados_e_nenhum_byte_da_chave() {
        let bytes = fixture!("chain-with-key.p12");
        // The key, taken straight from the library the way the reader sees it.
        let archive = Pkcs12Archive::from_pkcs12(bytes, "changeit").unwrap();
        let key_bytes: Vec<u8> = archive
            .keys
            .iter()
            .flat_map(|bag| bag.key.as_der().to_vec())
            .collect();
        assert!(key_bytes.len() >= 32, "the fixture must hold a key");

        let got = read(bytes, Some(&password("changeit"))).unwrap();

        let everything = format!("{got:?}");
        let mut haystack = everything.into_bytes();
        for entry in &got.entries {
            haystack.extend_from_slice(&entry.der);
            haystack.extend_from_slice(entry.alias.as_bytes());
        }
        // The PKCS#8 key also holds the public point and the algorithm OIDs,
        // which the certificates legitimately repeat: only the windows that
        // appear nowhere in the certificates are private material.
        let public_bytes = [LEAF, INT, ROOT].concat();
        let private_windows: Vec<&[u8]> = key_bytes
            .windows(16)
            .filter(|window| !public_bytes.windows(16).any(|p| p == *window))
            .collect();
        assert!(
            !private_windows.is_empty(),
            "the key has private-only bytes"
        );
        for window in private_windows {
            assert!(
                !haystack.windows(16).any(|h| h == window),
                "a 16-byte window of the private key leaked"
            );
        }
        assert_eq!(ders(&got), expected(), "only the three certificates");
    }

    #[test]
    fn quando_alias_e_friendly_name_deve_usar_o_nome_senao_cert_n() {
        let got = read(fixture!("chain-with-key.p12"), Some(&password("changeit"))).unwrap();
        assert!(got.entries.iter().any(|e| e.alias == "server"), "{got:?}");
        let got = read(fixture!("certs-only.p12"), Some(&password("changeit"))).unwrap();
        for entry in &got.entries {
            assert_ne!(entry.alias, "");
        }
    }

    #[test]
    fn quando_senha_errada_deve_dar_wrong_password_or_corrupt() {
        let got = read(fixture!("chain-with-key.p12"), Some(&password("nope")));
        assert_eq!(got, Err(KeystoreError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn quando_sem_senha_e_p12_exige_deve_dar_password_required() {
        let got = read(fixture!("chain-with-key.p12"), None);
        assert_eq!(got, Err(KeystoreError::PasswordRequired));
    }

    #[test]
    fn quando_senha_vazia_e_p12_usa_vazia_deve_abrir() {
        let bytes = fixture!("empty-password.p12");
        let without = read(bytes, None).unwrap();
        let with_empty = read(bytes, Some(&password(""))).unwrap();
        assert_eq!(ders(&without), expected());
        assert_eq!(without, with_empty);
    }

    #[test]
    fn quando_cifra_legada_nao_suportada_deve_dar_unsupported_algorithm_com_nome() {
        let got = read(fixture!("legacy-rc2.p12"), Some(&password("changeit")));
        assert_eq!(
            got,
            Err(KeystoreError::UnsupportedAlgorithm(
                "pbeWithSHA1And40BitRC2-CBC".to_owned()
            ))
        );
    }

    #[test]
    fn quando_mac_esta_corrompido_deve_dar_wrong_password_or_corrupt() {
        let got = read(fixture!("corrupt-mac.p12"), Some(&password("changeit")));
        assert_eq!(got, Err(KeystoreError::WrongPasswordOrCorrupt));
    }

    #[test]
    fn quando_truncado_deve_dar_malformed() {
        let got = read(fixture!("truncated.p12"), Some(&password("changeit")));
        assert!(matches!(got, Err(KeystoreError::Malformed(_))), "{got:?}");
    }

    #[test]
    fn quando_entrada_e_lixo_ou_vazia_deve_dar_erro_tipado_sem_panic() {
        let samples: [&[u8]; 6] = [
            b"",
            b"0",
            &[0x30, 0x82, 0xFF, 0xFF],
            &[0x30, 0x03, 0x02, 0x01, 0x03],
            b"not a keystore at all",
            &[0xFF; 64],
        ];
        for sample in samples {
            for pw in [None, Some(&password("changeit"))] {
                let got = read(sample, pw);
                assert!(got.is_err(), "{sample:?} -> {got:?}");
            }
        }
    }

    #[test]
    fn quando_acima_de_max_keystore_bytes_deve_dar_too_large() {
        let limits = Limits {
            max_keystore_bytes: 100,
            ..Limits::default()
        };
        let got = Pkcs12Reader.read_certs(
            fixture!("chain-with-key.p12"),
            Some(&password("changeit")),
            &limits,
        );
        assert_eq!(got, Err(KeystoreError::TooLarge { limit: 100 }));
    }

    #[test]
    fn quando_entradas_passam_do_limite_deve_dar_too_many_entries() {
        let limits = Limits {
            max_certs_per_source: 2,
            ..Limits::default()
        };
        let got = Pkcs12Reader.read_certs(
            fixture!("certs-only.p12"),
            Some(&password("changeit")),
            &limits,
        );
        assert_eq!(got, Err(KeystoreError::TooManyEntries { max: 2 }));
    }

    #[test]
    fn quando_erro_deve_nao_conter_a_senha_no_display_nem_no_debug() {
        let secret = "s3cr3t-Pa55w0rd-xyz";
        for file in [
            &fixture!("chain-with-key.p12")[..],
            fixture!("truncated.p12"),
            fixture!("corrupt-mac.p12"),
            fixture!("legacy-rc2.p12"),
        ] {
            let error = read(file, Some(&password(secret))).unwrap_err();
            let shown = format!("{error} {error:?}");
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}
