//! End-to-end tests of how `certtui [TARGET]` decides between the interactive
//! UI and the headless text output. Without a terminal (as under `assert_cmd`)
//! it must never block waiting for keys.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

fn certtui() -> Command {
    let mut command = Command::cargo_bin("certtui").unwrap();
    command.timeout(std::time::Duration::from_secs(20));
    command
}

fn fixture(name: &str) -> String {
    format!("{FIXTURES}/{name}")
}

#[test]
fn quando_stdout_nao_e_tty_e_alvo_e_arquivo_deve_cair_no_modo_text() {
    let path = fixture("rsa2048-leaf.pem");
    let direct = certtui().arg(&path).output().unwrap();
    let inspect = certtui()
        .args(["inspect", "--text", &path])
        .output()
        .unwrap();
    assert_eq!(direct.status.code(), Some(0));
    assert_eq!(direct.stdout, inspect.stdout);
    let text = String::from_utf8(direct.stdout).unwrap();
    assert!(text.contains("Subject: CN=rsa2048.example.test"), "{text}");
}

#[test]
fn quando_stdin_e_pipe_e_sem_tty_deve_cair_no_modo_text_e_sair_0() {
    let pem = std::fs::read(fixture("rsa2048-leaf.pem")).unwrap();
    let out = certtui().arg("-").write_stdin(pem).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Subject: CN=rsa2048.example.test"), "{text}");
}

#[test]
fn quando_stdin_pipe_traz_lixo_deve_sair_com_erro_de_entrada_sem_travar() {
    let out = certtui()
        .arg("-")
        .write_stdin("not a certificate")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn quando_sem_args_e_sem_terminal_deve_sair_2_e_explicar() {
    let out = certtui().output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no terminal available"));
}

#[test]
fn quando_opcoes_vem_depois_do_alvo_implicito_deve_sair_2_com_orientacao() {
    let path = fixture("rsa2048-leaf.pem");
    let out = certtui()
        .args([path.as_str(), "--sni", "x"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("options go before the target"));
}
