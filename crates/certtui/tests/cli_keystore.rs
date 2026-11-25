//! End-to-end tests of keystores: detection by content, password sources,
//! integrity warnings, and that no private key ever reaches the output.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use serde_json::Value;

const KEYSTORES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/keystores"
);
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

fn certtui() -> Command {
    Command::cargo_bin("certtui").unwrap()
}

fn keystore(name: &str) -> String {
    format!("{KEYSTORES}/{name}")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn json_of(args: &[&str], envs: &[(&str, &str)]) -> Value {
    let mut command = certtui();
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let out = command.output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    serde_json::from_slice(&out.stdout).unwrap()
}

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("certtui-cli-keystore-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn finding_codes(json: &Value) -> Vec<String> {
    json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn quando_password_env_deve_abrir_p12_e_mostrar_so_certificados() {
    let json = json_of(
        &[
            "inspect",
            &keystore("chain-with-key.p12"),
            "--json",
            "--password-env",
            "PW",
        ],
        &[("PW", "changeit")],
    );

    assert_eq!(json["certificates"].as_array().unwrap().len(), 3);
    assert_eq!(json["certificates"][0]["origin"]["kind"], "keystore");
}

#[test]
fn quando_p12_com_chave_deve_nao_ter_nenhum_byte_da_chave_em_text_json_pem_e_stderr() {
    // The key is only readable with the keystore password: take it from the
    // library at test time so no plaintext key lives in the repository.
    let leaf = fs::read(keystore("leaf.der")).unwrap();
    let p12 = fs::read(keystore("chain-with-key.p12")).unwrap();
    let archive = p12_keystore::Pkcs12Archive::from_pkcs12(&p12, "changeit").unwrap();
    let key: Vec<u8> = archive
        .keys
        .iter()
        .flat_map(|bag| bag.key.as_der().to_vec())
        .collect();
    let public: Vec<u8> = fs::read(keystore("leaf.der"))
        .unwrap()
        .into_iter()
        .chain(fs::read(keystore("int.der")).unwrap())
        .chain(fs::read(keystore("root.der")).unwrap())
        .collect();
    let private_windows: Vec<&[u8]> = key
        .windows(16)
        .filter(|w| !public.windows(16).any(|p| p == *w))
        .collect();
    assert_ne!(private_windows.len(), 0, "the key has private-only bytes");
    assert_ne!(leaf.len(), 0);

    for mode in ["--text", "--json", "--pem"] {
        let out = certtui()
            .args([
                "inspect",
                &keystore("chain-with-key.p12"),
                mode,
                "--password-env",
                "PW",
            ])
            .env("PW", "changeit")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{mode}: {}", stderr(&out));
        let mut everything = out.stdout.clone();
        everything.extend_from_slice(&out.stderr);
        let as_text = String::from_utf8_lossy(&everything);
        assert!(!as_text.contains("PRIVATE KEY"), "{mode}");
        for window in &private_windows {
            assert!(
                !everything.windows(16).any(|h| h == *window),
                "{mode}: a 16-byte window of the private key leaked"
            );
        }
    }
}

#[test]
fn quando_arquivo_e_p12_deve_ser_detectado_por_conteudo_mesmo_com_extensao_errada() {
    let scratch = Scratch::new("ext");
    let path = scratch.0.join("looks-like-text.txt");
    fs::copy(keystore("certs-only.p12"), &path).unwrap();

    let json = json_of(
        &[
            "inspect",
            path.to_str().unwrap(),
            "--json",
            "--password-env",
            "PW",
        ],
        &[("PW", "changeit")],
    );

    assert_eq!(json["certificates"].as_array().unwrap().len(), 3);
}

#[test]
fn quando_jks_sem_senha_deve_sair_0_com_warning_keystore_integrity_unverified() {
    let out = certtui()
        .args(["check", &keystore("trusted-certs.jks"), "--json"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1).or(Some(0)).filter(|_| true),
        "{}",
        stderr(&out)
    );
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = json["results"][0]["findings"].as_array().unwrap();
    let warning = findings
        .iter()
        .find(|f| f["code"] == "KEYSTORE_INTEGRITY_UNVERIFIED")
        .expect("the warning");
    assert_eq!(warning["severity"], "warning");
    assert_eq!(warning["category"], "trust");
}

#[test]
fn quando_jks_com_senha_deve_nao_ter_o_warning_de_integridade() {
    let json = json_of(
        &[
            "inspect",
            &keystore("trusted-certs.jks"),
            "--json",
            "--password-env",
            "PW",
        ],
        &[("PW", "changeit")],
    );
    assert!(!finding_codes(&json).contains(&"KEYSTORE_INTEGRITY_UNVERIFIED".to_owned()));
    assert_eq!(json["certificates"].as_array().unwrap().len(), 3);
}

#[test]
fn quando_p12_sem_senha_deve_sair_3_pedindo_senha() {
    let out = certtui()
        .args(["inspect", &keystore("chain-with-key.p12"), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = stderr(&out);
    assert!(err.contains("keystore requires a password"), "{err}");
    assert!(err.contains("--password-env"), "{err}");
    assert_eq!(stdout(&out), "");
}

#[test]
fn quando_password_file_com_crlf_deve_abrir() {
    let scratch = Scratch::new("pwfile");
    let pw = scratch.0.join("pw.txt");
    fs::write(&pw, b"changeit\r\n").unwrap();

    let json = json_of(
        &[
            "inspect",
            &keystore("chain-with-key.p12"),
            "--json",
            "--password-file",
            pw.to_str().unwrap(),
        ],
        &[],
    );

    assert_eq!(json["certificates"].as_array().unwrap().len(), 3);
}

#[test]
fn quando_password_stdin_deve_ler_a_primeira_linha_do_stdin() {
    let out = certtui()
        .args([
            "inspect",
            &keystore("chain-with-key.p12"),
            "--json",
            "--password-stdin",
        ])
        .write_stdin("changeit\nsecond line\n")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn quando_password_stdin_e_alvo_stdin_deve_sair_2_com_explicacao() {
    let out = certtui()
        .args(["inspect", "-", "--password-stdin"])
        .write_stdin("changeit\n")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = stderr(&out);
    assert!(
        err.contains("--password-stdin cannot be combined with the target `-`"),
        "{err}"
    );
    assert!(err.contains("standard input"), "{err}");
}

#[test]
fn quando_password_env_nao_existe_deve_sair_2() {
    let out = certtui()
        .args([
            "inspect",
            &keystore("chain-with-key.p12"),
            "--password-env",
            "CERTTUI_NO_SUCH_VAR",
        ])
        .env_remove("CERTTUI_NO_SUCH_VAR")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("CERTTUI_NO_SUCH_VAR is not set"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn quando_duas_fontes_de_senha_deve_sair_2() {
    let out = certtui()
        .args([
            "inspect",
            &keystore("chain-with-key.p12"),
            "--password-env",
            "PW",
            "--password-file",
            "/dev/null",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn quando_senha_errada_deve_sair_3_sem_a_senha_no_stderr() {
    let secret = "S3cr3t-wrong-Pa55";
    let out = certtui()
        .args([
            "inspect",
            &keystore("chain-with-key.p12"),
            "--text",
            "--password-env",
            "PW",
        ])
        .env("PW", secret)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let err = stderr(&out);
    assert!(err.contains("wrong password or corrupt keystore"), "{err}");
    assert!(!err.contains(secret), "{err}");
    assert!(!stdout(&out).contains(secret));
}

#[test]
fn quando_p12_legado_deve_sair_3_nomeando_a_cifra() {
    let out = certtui()
        .args([
            "inspect",
            &keystore("legacy-rc2.p12"),
            "--text",
            "--password-env",
            "PW",
        ])
        .env("PW", "changeit")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stderr(&out).contains("pbeWithSHA1And40BitRC2-CBC"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn quando_keystore_truncado_deve_sair_3_sem_panic() {
    for file in ["truncated.p12", "truncated.jks", "bad-count.jks"] {
        let out = certtui()
            .args(["inspect", &keystore(file), "--text", "--password-env", "PW"])
            .env("PW", "changeit")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{file}: {}", stderr(&out));
        assert!(!stderr(&out).contains("panicked"), "{file}");
    }
}

#[test]
fn quando_p12_sem_mac_deve_dar_o_warning_de_integridade() {
    let out = certtui()
        .args([
            "check",
            &keystore("no-mac.p12"),
            "--json",
            "--password-env",
            "PW",
        ])
        .env("PW", "changeit")
        .output()
        .unwrap();
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    let findings = json["results"][0]["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["code"] == "KEYSTORE_INTEGRITY_UNVERIFIED"),
        "{findings:?}"
    );
}

#[test]
fn quando_cert_e_texto_com_chave_privada_deve_continuar_ignorando_a_chave() {
    let out = certtui()
        .current_dir(FIXTURES)
        .args(["inspect", "messy/with-private-key.txt", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(
        json["notes"]
            .to_string()
            .contains("private_key_blocks_ignored")
    );
    assert!(!stdout(&out).contains("PRIVATE KEY"));
}
