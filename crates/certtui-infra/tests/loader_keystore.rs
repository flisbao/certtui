//! The filesystem loader opens keystores by content, with the password it was given.

// Justificativa: clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies;
// the helpers below are test-only code where a panic is the failure.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use certtui_app::error::LoadError;
use certtui_app::keystore::{KeystoreError, SecretString};
use certtui_app::ports::{LocalSource, SourceLoader};
use certtui_domain::limits::Limits;
use certtui_domain::model::{CertOrigin, LoadNote};
use certtui_infra::source::FsSourceLoader;

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/keystores"
);

/// The PKCS#12 reader allows few concurrent workers (a hostile file can keep
/// one busy), so the tests that open one take turns.
fn one_at_a_time() -> std::sync::MutexGuard<'static, ()> {
    static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());
    TURN.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A scratch directory removed on drop (no `tempfile` crate).
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "certtui-loader-keystore-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// Copies a fixture under `name`, whatever its extension.
    fn copy(&self, fixture: &str, name: &str) -> PathBuf {
        let target = self.0.join(name);
        fs::copy(Path::new(FIXTURES).join(fixture), &target).unwrap();
        target
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn changeit() -> SecretString {
    SecretString::from("changeit".to_owned())
}

fn load(
    loader: &FsSourceLoader,
    path: &Path,
) -> Result<certtui_app::ports::LoadedCerts, LoadError> {
    loader.load(&LocalSource::File(path.to_path_buf()), &Limits::default())
}

#[test]
fn quando_arquivo_e_p12_deve_ser_detectado_por_conteudo_mesmo_com_extensao_errada() {
    let _turn = one_at_a_time();
    let scratch = Scratch::new();
    let path = scratch.copy("chain-with-key.p12", "not-a-keystore.txt");
    let loader = FsSourceLoader::new().with_password(Some(changeit()));

    let got = load(&loader, &path).unwrap();

    assert_eq!(got.certs.len(), 3);
    assert_eq!(got.notes, Vec::new());
    assert!(
        got.certs
            .iter()
            .all(|c| matches!(&c.origin, CertOrigin::Keystore { path: p, .. } if *p == path)),
        "{:?}",
        got.certs
    );
    let aliases: Vec<&str> = got
        .certs
        .iter()
        .filter_map(|c| match &c.origin {
            CertOrigin::Keystore { alias, .. } => Some(alias.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        aliases,
        ["server", "cert-2", "cert-3"],
        "friendlyName, else cert-<n>"
    );
}

#[test]
fn quando_jks_e_detectado_pelo_magic_mesmo_com_extensao_errada() {
    let scratch = Scratch::new();
    let path = scratch.copy("trusted-certs.jks", "data.bin");
    let loader = FsSourceLoader::new().with_password(Some(changeit()));

    let got = load(&loader, &path).unwrap();

    assert_eq!(got.certs.len(), 3);
    assert_eq!(got.notes, Vec::new(), "integrity was verified");
}

#[test]
fn quando_jks_sem_senha_deve_listar_certs_e_anotar_integridade_nao_verificada() {
    let scratch = Scratch::new();
    let path = scratch.copy("trusted-certs.jks", "store.jks");

    let got = load(&FsSourceLoader::new(), &path).unwrap();

    assert_eq!(got.certs.len(), 3);
    assert_eq!(got.notes, vec![LoadNote::KeystoreIntegrityUnverified]);
}

#[test]
fn quando_p12_sem_senha_deve_pedir_senha() {
    let _turn = one_at_a_time();
    let scratch = Scratch::new();
    let path = scratch.copy("chain-with-key.p12", "store.p12");

    let got = load(&FsSourceLoader::new(), &path);

    assert_eq!(got.unwrap_err(), LoadError::PasswordRequired);
}

#[test]
fn quando_senha_errada_deve_dar_keystore_wrong_password() {
    let _turn = one_at_a_time();
    let scratch = Scratch::new();
    let path = scratch.copy("chain-with-key.p12", "store.p12");
    let loader = FsSourceLoader::new().with_password(Some(SecretString::from("nope".to_owned())));

    let got = load(&loader, &path);

    assert_eq!(
        got.unwrap_err(),
        LoadError::Keystore(KeystoreError::WrongPasswordOrCorrupt)
    );
}

#[test]
fn quando_p12_sem_mac_deve_anotar_integridade_nao_verificada() {
    let _turn = one_at_a_time();
    let scratch = Scratch::new();
    let path = scratch.copy("no-mac.p12", "store.p12");
    let loader = FsSourceLoader::new().with_password(Some(changeit()));

    let got = load(&loader, &path).unwrap();

    assert_eq!(got.notes, vec![LoadNote::KeystoreIntegrityUnverified]);
}

#[test]
fn quando_set_password_muda_deve_valer_para_a_proxima_carga() {
    let _turn = one_at_a_time();
    let scratch = Scratch::new();
    let path = scratch.copy("chain-with-key.p12", "store.p12");
    let loader = FsSourceLoader::new();
    assert_eq!(
        load(&loader, &path).unwrap_err(),
        LoadError::PasswordRequired
    );

    loader.set_password(Some(changeit()));

    assert_eq!(load(&loader, &path).unwrap().certs.len(), 3);
}

#[test]
fn quando_keystore_esta_em_diretorio_deve_nao_ser_aberto() {
    let scratch = Scratch::new();
    scratch.copy("trusted-certs.jks", "store.jks");
    let loader = FsSourceLoader::new().with_password(Some(changeit()));

    let got = loader.load(
        &LocalSource::Directory {
            path: scratch.0.clone(),
            recursive: false,
        },
        &Limits::default(),
    );

    // The only file is a keystore, which directory scans leave closed.
    assert!(
        matches!(got, Err(LoadError::NoCertificatesFound { .. })),
        "{got:?}"
    );
}

#[test]
fn quando_arquivo_tem_chave_privada_em_texto_deve_continuar_ignorando_a_chave() {
    // Regression of M1: a PEM private key block is skipped, not decoded.
    let scratch = Scratch::new();
    let path = scratch.0.join("mixed.pem");
    let leaf = fs::read(Path::new(FIXTURES).join("leaf.der")).unwrap();
    let mut text =
        String::from("-----BEGIN PRIVATE KEY-----\nQUJDREVGR0g=\n-----END PRIVATE KEY-----\n");
    text.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in leaf.chunks(48) {
        text.push_str(&base64_line(chunk));
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    fs::write(&path, text).unwrap();

    let got = load(&FsSourceLoader::new(), &path).unwrap();

    assert_eq!(got.certs.len(), 1);
    assert_eq!(
        got.notes,
        vec![LoadNote::PrivateKeyBlocksIgnored { count: 1 }]
    );
}

/// Standard base64 of `bytes`, enough for a test PEM.
fn base64_line(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn quando_uma_carga_esta_em_andamento_deve_set_password_nao_esperar_por_ela() {
    // A FIFO makes `load` block opening the file, a stand-in for a slow keystore.
    let scratch = Scratch::new();
    let fifo = scratch.0.join("slow.p12");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !made.is_ok_and(|status| status.success()) {
        return; // no mkfifo here: nothing to simulate with
    }
    let loader = std::sync::Arc::new(FsSourceLoader::new());
    let blocked = {
        let loader = std::sync::Arc::clone(&loader);
        let fifo = fifo.clone();
        std::thread::spawn(move || load(&loader, &fifo))
    };
    std::thread::sleep(std::time::Duration::from_millis(200)); // let it block in open()

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    {
        let loader = std::sync::Arc::clone(&loader);
        std::thread::spawn(move || {
            loader.set_password(Some(changeit()));
            let _ = done_tx.send(());
        });
    }
    let waited = done_rx.recv_timeout(std::time::Duration::from_secs(2));

    // Unblock the first load whatever happened, so the test never hangs.
    drop(fs::OpenOptions::new().write(true).open(&fifo));
    let _ = blocked.join();
    assert!(
        waited.is_ok(),
        "set_password waited for the load in progress"
    );
}
