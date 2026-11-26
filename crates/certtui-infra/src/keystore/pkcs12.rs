//! PKCS#12 (`.p12`, `.pfx`): certificates out of the bags, keys dropped at once.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use certtui_app::keystore::{
    EntryKind, ExposeSecret, KeystoreContents, KeystoreEntry, KeystoreError, KeystoreReader,
    SecretString,
};
use certtui_domain::limits::Limits;
use p12_keystore::Pkcs12Archive;
use p12_keystore::error::Error as P12Error;

use super::kdf_guard::KdfBudget;

/// How long the library may take to open one keystore. Real files open in
/// well under a second; this bounds what hides inside encrypted parts, which
/// the clear-text budget cannot see.
const DEADLINE: Duration = Duration::from_secs(10);

/// Workers allowed to run at once. A worker that missed its deadline keeps
/// burning CPU until the library returns (a thread cannot be killed), so the
/// next attempts are refused rather than piled on top of it.
const MAX_WORKERS: usize = 2;

static WORKERS: Workers = Workers::new(MAX_WORKERS);

/// How many workers run, and how many may.
struct Workers {
    running: AtomicUsize,
    max: usize,
}

impl Workers {
    const fn new(max: usize) -> Self {
        Self {
            running: AtomicUsize::new(0),
            max,
        }
    }
}

/// A worker slot, released when the worker ends, whatever its fate.
struct Slot(&'static Workers);

impl Slot {
    fn take(workers: &'static Workers) -> Option<Slot> {
        workers
            .running
            .try_update(Ordering::AcqRel, Ordering::Acquire, |now| {
                (now < workers.max).then_some(now + 1)
            })
            .ok()
            .map(|_| Slot(workers))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.running.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A certificate bag, keys already gone.
struct Bag {
    friendly_name: Option<String>,
    der: Vec<u8>,
    has_key_id: bool,
}

/// `KeystoreReader` for PKCS#12, on `p12-keystore`.
///
/// The library decrypts every bag it can, keys included. This adapter keeps
/// the certificates and lets everything else go out of scope before
/// returning, so a key is never held past this function, never stored in the
/// result and never printed. The library runs in a worker thread under a
/// clear-text budget ([`KdfBudget`]) and a deadline, so a hostile file costs
/// the caller a bounded wait, not a hang or a gigabyte.
#[derive(Debug, Clone, Copy, Default)]
pub struct Pkcs12Reader;

impl KeystoreReader for Pkcs12Reader {
    fn read_certs(
        &self,
        bytes: &[u8],
        password: Option<&SecretString>,
        limits: &Limits,
    ) -> Result<KeystoreContents, KeystoreError> {
        read_with(
            bytes,
            password,
            limits,
            &KdfBudget::default(),
            DEADLINE,
            &WORKERS,
        )
    }
}

/// [`Pkcs12Reader::read_certs`] with the budget and the deadline given, so
/// tests can make them small.
fn read_with(
    bytes: &[u8],
    password: Option<&SecretString>,
    limits: &Limits,
    budget: &KdfBudget,
    deadline: Duration,
    workers: &'static Workers,
) -> Result<KeystoreContents, KeystoreError> {
    if bytes.len() > limits.max_keystore_bytes {
        return Err(KeystoreError::TooLarge {
            limit: limits.max_keystore_bytes,
        });
    }
    budget.check(bytes)?;
    let bags = open_in_worker(bytes, password, deadline, workers)?;
    if bags.len() > limits.max_certs_per_source {
        return Err(KeystoreError::TooManyEntries {
            max: limits.max_certs_per_source,
        });
    }
    let entries = bags
        .into_iter()
        .enumerate()
        .map(|(index, bag)| KeystoreEntry {
            alias: bag
                .friendly_name
                .unwrap_or_else(|| format!("cert-{}", index.saturating_add(1))),
            der: bag.der,
            kind: if bag.has_key_id {
                EntryKind::CertOfKeyEntry
            } else {
                EntryKind::TrustedCert
            },
        })
        .collect();
    Ok(KeystoreContents {
        entries,
        // The library verifies the MAC only when the file has one; a file
        // without it opens with any password and nothing vouches for it.
        integrity_unverified: !has_mac(bytes),
        ignored: 0,
    })
}

/// Runs the library on its own thread and waits at most `deadline`.
fn open_in_worker(
    bytes: &[u8],
    password: Option<&SecretString>,
    deadline: Duration,
    workers: &'static Workers,
) -> Result<Vec<Bag>, KeystoreError> {
    let slot = Slot::take(workers).ok_or(KeystoreError::TooExpensive)?;
    let data = bytes.to_vec();
    let secret = password.cloned();
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("pkcs12".to_owned())
        .spawn(move || {
            // Without a password the empty one is still tried: a PKCS#12 made
            // with an empty password opens, any other asks for one.
            let given = secret.as_ref().map_or("", |s| s.expose_secret());
            let outcome = Pkcs12Archive::from_pkcs12(&data, given)
                .map(|archive| {
                    // Keep the certificates only: key and secret bags die here.
                    let Pkcs12Archive {
                        certs,
                        keys,
                        secrets,
                    } = archive;
                    drop(keys);
                    drop(secrets);
                    certs
                        .into_iter()
                        .map(|bag| Bag {
                            friendly_name: bag.friendly_name,
                            der: bag.cert.as_der().to_vec(),
                            has_key_id: bag.local_key_id.is_some(),
                        })
                        .collect::<Vec<_>>()
                })
                .map_err(|error| {
                    let mapped = map_error(&error, &data);
                    if secret.is_none() && mapped == KeystoreError::WrongPasswordOrCorrupt {
                        KeystoreError::PasswordRequired
                    } else {
                        mapped
                    }
                });
            // Free the slot before answering: whoever reads the outcome may
            // start the next keystore at once and must find the slot free.
            drop(slot);
            // The receiver is gone when the deadline passed.
            let _ = tx.send(outcome);
        });
    if spawned.is_err() {
        return Err(KeystoreError::Malformed(
            "could not start the keystore reader".to_owned(),
        ));
    }
    match rx.recv_timeout(deadline) {
        Ok(outcome) => outcome,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(KeystoreError::TooExpensive),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(KeystoreError::Malformed(
            "the keystore reader stopped unexpectedly".to_owned(),
        )),
    }
}

/// Whether the PFX carries a `MacData`: `PFX ::= SEQUENCE { version, authSafe,
/// macData OPTIONAL }`, so three elements. Anything unreadable counts as no MAC.
fn has_mac(bytes: &[u8]) -> bool {
    use der::asn1::AnyRef;
    use der::{Decode, Reader, SliceReader};

    let count = || -> Option<usize> {
        let outer = AnyRef::decode(&mut SliceReader::new(bytes).ok()?).ok()?;
        let mut inner = SliceReader::new(outer.value()).ok()?;
        let mut count = 0_usize;
        while !inner.is_finished() && count < 4 {
            AnyRef::decode(&mut inner).ok()?;
            count += 1;
        }
        Some(count)
    };
    count().is_some_and(|elements| elements >= 3)
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

    /// Plenty of workers: the tests run in parallel and the limiter is tested apart.
    static TEST_WORKERS: Workers = Workers::new(256);

    fn read_limited(
        bytes: &[u8],
        pw: Option<&SecretString>,
        limits: &Limits,
    ) -> Result<KeystoreContents, KeystoreError> {
        read_with(
            bytes,
            pw,
            limits,
            &KdfBudget::default(),
            DEADLINE,
            &TEST_WORKERS,
        )
    }

    fn read(bytes: &[u8], pw: Option<&SecretString>) -> Result<KeystoreContents, KeystoreError> {
        read_limited(bytes, pw, &Limits::default())
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
        assert!(!got.integrity_unverified, "the MAC was verified");
    }

    #[test]
    fn quando_scrypt_deve_recusar_sem_derivar_nada() {
        // 190 bytes that would cost ~1 GiB of memory in the library.
        let started = std::time::Instant::now();
        let got = read(fixture!("kdf-scrypt.p12"), None);
        assert_eq!(
            got,
            Err(KeystoreError::UnsupportedAlgorithm("scrypt".to_owned()))
        );
        let got = read(fixture!("kdf-scrypt.p12"), Some(&password("changeit")));
        assert_eq!(
            got,
            Err(KeystoreError::UnsupportedAlgorithm("scrypt".to_owned()))
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn quando_muitas_derivacoes_caras_deve_recusar_sem_gastar_cpu() {
        // 10 x 1 000 000 iterations, no MAC: ~5 s of CPU if obeyed.
        let started = std::time::Instant::now();
        let got = read(fixture!("kdf-many-pbkdf2.p12"), None);
        assert_eq!(got, Err(KeystoreError::TooExpensive));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn quando_o_trabalho_passa_do_prazo_deve_dar_too_expensive_no_prazo() {
        // The budget is lifted so the work really starts; the deadline stops the wait.
        let lifted = KdfBudget {
            max_calls: usize::MAX,
            max_total_iterations: u64::MAX,
        };
        let started = std::time::Instant::now();

        let got = read_with(
            fixture!("kdf-many-pbkdf2.p12"),
            None,
            &Limits::default(),
            &lifted,
            Duration::from_millis(100),
            &TEST_WORKERS,
        );

        assert_eq!(got, Err(KeystoreError::TooExpensive));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn quando_ha_trabalhadores_demais_deve_recusar_o_proximo() {
        // Its own counter: the shared one is used by the tests running beside it.
        static OWN: Workers = Workers::new(MAX_WORKERS);
        let read_with_own = || {
            read_with(
                fixture!("certs-only.p12"),
                Some(&password("changeit")),
                &Limits::default(),
                &KdfBudget::default(),
                DEADLINE,
                &OWN,
            )
        };
        let held: Vec<Slot> = (0..MAX_WORKERS).filter_map(|_| Slot::take(&OWN)).collect();
        assert_eq!(held.len(), MAX_WORKERS);

        assert_eq!(read_with_own(), Err(KeystoreError::TooExpensive));

        drop(held);
        assert!(read_with_own().is_ok(), "released slots work again");
        assert_eq!(OWN.running.load(Ordering::Acquire), 0, "no slot leaked");
    }

    #[test]
    fn quando_p12_nao_tem_mac_deve_marcar_integrity_unverified() {
        let got = read(fixture!("no-mac.p12"), Some(&password("changeit"))).unwrap();

        assert_eq!(ders(&got), expected());
        assert!(
            got.integrity_unverified,
            "nothing authenticates a file without a MAC"
        );
    }

    #[test]
    fn quando_p12_tem_mac_deve_ser_reconhecido_e_lixo_nao() {
        assert!(has_mac(fixture!("certs-only.p12")));
        assert!(has_mac(fixture!("chain-with-key.p12")));
        assert!(!has_mac(fixture!("no-mac.p12")));
        assert!(!has_mac(b""));
        assert!(!has_mac(b"garbage"));
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
        let got = read_limited(
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
        let got = read_limited(
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
