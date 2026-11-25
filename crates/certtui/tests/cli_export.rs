//! End-to-end tests of `certtui export`: formats, atomic writes, refusals.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");
const KEYSTORES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/keystores"
);

fn certtui() -> Command {
    Command::cargo_bin("certtui").unwrap()
}

fn chain3() -> String {
    format!("{FIXTURES}/chain-3.pem")
}

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("certtui-cli-export-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(&self.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> std::process::Output {
    certtui().args(args).output().unwrap()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn quando_export_pem_deve_criar_arquivo_e_sair_0() {
    let dir = Scratch::new("pem");
    let out_path = dir.path("leaf.pem");

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--out",
        path_str(&out_path),
    ]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let written = fs::read_to_string(&out_path).unwrap();
    assert_eq!(
        written.matches("-----BEGIN CERTIFICATE-----").count(),
        1,
        "default --index 0"
    );
    assert_eq!(dir.names(), ["leaf.pem"]);
    assert!(stderr(&out).contains("wrote"), "{}", stderr(&out));
}

#[test]
fn quando_export_chain_pem_deve_ter_os_tres_certificados_na_ordem() {
    let dir = Scratch::new("chain");
    let out_path = dir.path("chain.pem");

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--chain",
        "--out",
        path_str(&out_path),
    ]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let written = fs::read_to_string(&out_path).unwrap();
    assert_eq!(written.matches("-----BEGIN CERTIFICATE-----").count(), 3);
    // Same blocks, same order as the source file.
    let source = fs::read_to_string(chain3()).unwrap();
    let blocks = |text: &str| -> Vec<String> {
        text.split("-----END CERTIFICATE-----")
            .filter(|b| b.contains("-----BEGIN CERTIFICATE-----"))
            .map(|b| {
                b[b.find("-----BEGIN CERTIFICATE-----").unwrap()..]
                    .trim()
                    .to_owned()
            })
            .collect()
    };
    assert_eq!(blocks(&written), blocks(&source));
}

#[test]
fn quando_export_der_com_index_deve_gravar_os_bytes_do_certificado() {
    let dir = Scratch::new("der");
    let out_path = dir.path("leaf.der");

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "der",
        "--index",
        "0",
        "--out",
        path_str(&out_path),
    ]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        fs::read(&out_path).unwrap(),
        fs::read(format!("{FIXTURES}/chain-3.der")).unwrap()
    );
}

#[test]
fn quando_export_json_deve_ter_schema_version_1() {
    let dir = Scratch::new("json");
    let out_path = dir.path("chain.json");

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "json",
        "--chain",
        "--out",
        path_str(&out_path),
    ]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let json: Value = serde_json::from_slice(&fs::read(&out_path).unwrap()).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["certificates"].as_array().unwrap().len(), 3);
}

#[test]
fn quando_export_sem_force_em_arquivo_existente_deve_sair_2_e_preservar_o_original() {
    let dir = Scratch::new("exists");
    let out_path = dir.path("keep.pem");
    fs::write(&out_path, b"precious").unwrap();

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--out",
        path_str(&out_path),
    ]);

    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("already exists"), "{}", stderr(&out));
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert_eq!(fs::read(&out_path).unwrap(), b"precious");
    assert_eq!(dir.names(), ["keep.pem"], "no temporary file left");
}

#[test]
fn quando_export_com_force_deve_substituir() {
    let dir = Scratch::new("force");
    let out_path = dir.path("replace.pem");
    fs::write(&out_path, b"old").unwrap();

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--force",
        "--out",
        path_str(&out_path),
    ]);

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        fs::read_to_string(&out_path)
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    assert_eq!(dir.names(), ["replace.pem"]);
}

#[test]
fn quando_der_com_chain_deve_sair_2_e_nao_criar_arquivo() {
    let dir = Scratch::new("derchain");
    let out_path = dir.path("chain.der");

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "der",
        "--chain",
        "--out",
        path_str(&out_path),
    ]);

    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("DER cannot hold a certificate chain"),
        "{}",
        stderr(&out)
    );
    assert_eq!(dir.names(), Vec::<String>::new());
}

#[test]
fn quando_index_e_chain_juntos_deve_sair_2() {
    let dir = Scratch::new("conflict");
    let out_path = dir.path("x.pem");
    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--index",
        "1",
        "--chain",
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn quando_index_fora_do_intervalo_deve_sair_2() {
    let dir = Scratch::new("range");
    let out_path = dir.path("x.pem");
    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--index",
        "9",
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("out of range"), "{}", stderr(&out));
    assert_eq!(dir.names(), Vec::<String>::new());
}

#[test]
fn quando_destino_e_diretorio_ou_pai_nao_existe_deve_sair_2() {
    let dir = Scratch::new("badpath");
    let sub = dir.path("sub");
    fs::create_dir(&sub).unwrap();

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--out",
        path_str(&sub),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("is a directory"), "{}", stderr(&out));

    let missing = dir.path("missing").join("x.pem");
    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--out",
        path_str(&missing),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("does not exist"), "{}", stderr(&out));
    assert_eq!(dir.names(), ["sub"]);
}

#[test]
fn quando_destino_e_symlink_e_sem_force_deve_sair_2_sem_tocar_no_alvo() {
    let dir = Scratch::new("symlink");
    let real = dir.path("real.pem");
    fs::write(&real, b"real").unwrap();
    let link = dir.path("link.pem");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let out = run(&[
        "export",
        &chain3(),
        "--format",
        "pem",
        "--out",
        path_str(&link),
    ]);

    assert_eq!(out.status.code(), Some(2));
    assert_eq!(fs::read(&real).unwrap(), b"real");
}

#[test]
fn quando_export_de_keystore_deve_conter_so_certificados() {
    let dir = Scratch::new("keystore");
    let out_path = dir.path("from-p12.pem");

    let out = certtui()
        .args([
            "export",
            &format!("{KEYSTORES}/chain-with-key.p12"),
            "--format",
            "pem",
            "--chain",
            "--password-env",
            "PW",
            "--out",
            path_str(&out_path),
        ])
        .env("PW", "changeit")
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let written = fs::read_to_string(&out_path).unwrap();
    assert_eq!(written.matches("-----BEGIN CERTIFICATE-----").count(), 3);
    assert!(!written.contains("PRIVATE KEY"));
    assert!(
        written
            .lines()
            .all(|line| line.starts_with("-----") || line.len() <= 64)
    );
}

#[test]
fn quando_export_de_keystore_sem_senha_deve_sair_3() {
    let dir = Scratch::new("nopw");
    let out_path = dir.path("x.pem");
    let out = run(&[
        "export",
        &format!("{KEYSTORES}/chain-with-key.p12"),
        "--format",
        "pem",
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(dir.names(), Vec::<String>::new());
}

#[test]
fn quando_der_com_chain_e_alvo_exige_senha_deve_sair_2_antes_de_carregar_o_alvo() {
    // The usage error comes first: not exit 3 ("requires a password").
    let dir = Scratch::new("derchain-first");
    let out_path = dir.path("x.der");
    let out = run(&[
        "export",
        &format!("{KEYSTORES}/chain-with-key.p12"),
        "--format",
        "der",
        "--chain",
        "--out",
        path_str(&out_path),
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("DER cannot hold a certificate chain"));
    assert_eq!(dir.names(), Vec::<String>::new());
}
