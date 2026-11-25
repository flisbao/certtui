//! End-to-end tests of the log file: it exists only when asked for, never
//! shares stdout or stderr with the program, honors the precedence of the
//! flag over the config, and never holds a secret.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_cmd::Command;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("certtui-cli-log-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn config(&self, text: &str) -> String {
        let path = self.path("config.json");
        fs::write(&path, text).unwrap();
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn certtui() -> Command {
    let mut command = Command::cargo_bin("certtui").unwrap();
    command
        .env_remove("CERTTUI_CONFIG")
        .env_remove("RUST_LOG")
        .env_remove("NO_COLOR");
    command
}

fn chain3() -> String {
    format!("{FIXTURES}/chain-3.pem")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn log_text(path: &PathBuf) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn quando_log_file_definido_deve_escrever_no_arquivo() {
    let dir = Scratch::new();
    let log = dir.path("run.log");
    let out = certtui()
        .args([
            "--log-file",
            log.to_str().unwrap(),
            "inspect",
            &chain3(),
            "--text",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = log_text(&log);
    assert!(!text.is_empty(), "the log file is empty");
    assert!(text.contains("INFO"), "{text}");
    assert!(text.contains("certtui"), "{text}");
    // Plain text, one event per line, no color codes.
    assert!(!text.contains('\u{1b}'), "{text:?}");
}

#[test]
fn quando_sem_log_file_deve_nao_escrever_nada_em_stdout_nem_stderr() {
    let out = certtui()
        .args(["inspect", &chain3(), "--text"])
        .env("RUST_LOG", "trace")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stderr(&out), "");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SHA-256:"), "{stdout}");
    assert!(!stdout.contains("INFO"), "{stdout}");
}

#[test]
fn quando_logging_file_vem_da_config_deve_escrever_no_arquivo() {
    let dir = Scratch::new();
    let log = dir.path("cfg.log");
    let config = dir.config(&format!(
        r#"{{"logging":{{"file":{:?}}}}}"#,
        log.to_str().unwrap()
    ));
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_ne!(log_text(&log), "");
}

#[test]
fn quando_flag_e_config_definem_arquivo_deve_vencer_a_flag() {
    let dir = Scratch::new();
    let from_config = dir.path("config.log");
    let from_flag = dir.path("flag.log");
    let config = dir.config(&format!(
        r#"{{"logging":{{"file":{:?}}}}}"#,
        from_config.to_str().unwrap()
    ));
    let out = certtui()
        .args([
            "--config",
            &config,
            "--log-file",
            from_flag.to_str().unwrap(),
        ])
        .args(["inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_ne!(log_text(&from_flag), "");
    assert!(
        !from_config.exists(),
        "the config's file must not be created"
    );
}

#[test]
fn quando_log_de_aviso_de_limite_deve_aparecer_no_arquivo() {
    let dir = Scratch::new();
    let log = dir.path("limits.log");
    let config = dir.config(r#"{"limits":{"max_chain_len":9999}}"#);
    let out = certtui()
        .args(["--config", &config, "--log-file", log.to_str().unwrap()])
        .args(["inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = log_text(&log);
    let line = text
        .lines()
        .find(|l| l.contains("WARN"))
        .unwrap_or_default();
    assert!(line.contains("max_chain_len"), "{text}");
    assert!(line.contains("9999"), "{text}");
    assert_eq!(stderr(&out), "", "the warning belongs in the file only");
}

#[test]
fn quando_nivel_e_error_deve_omitir_info_e_aviso() {
    let dir = Scratch::new();
    let log = dir.path("quiet.log");
    let config = dir.config(r#"{"logging":{"level":"error"},"limits":{"max_chain_len":9999}}"#);
    let out = certtui()
        .args(["--config", &config, "--log-file", log.to_str().unwrap()])
        .args(["inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = log_text(&log);
    assert!(!text.contains("INFO") && !text.contains("WARN"), "{text}");
}

#[test]
fn quando_rust_log_pede_trace_deve_sobrepor_o_nivel_da_config() {
    let dir = Scratch::new();
    let log = dir.path("trace.log");
    let config = dir.config(r#"{"logging":{"level":"error"}}"#);
    let out = certtui()
        .env("RUST_LOG", "debug")
        .args(["--config", &config, "--log-file", log.to_str().unwrap()])
        .args(["inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(log_text(&log).contains("DEBUG"), "{}", log_text(&log));
}

#[test]
fn quando_nivel_e_off_deve_deixar_o_arquivo_vazio() {
    let dir = Scratch::new();
    let log = dir.path("off.log");
    let config = dir.config(r#"{"logging":{"level":"off"}}"#);
    let out = certtui()
        .args(["--config", &config, "--log-file", log.to_str().unwrap()])
        .args(["inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(log_text(&log), "");
}

#[test]
fn quando_senha_passa_por_env_deve_nao_aparecer_no_log_nivel_trace() {
    let dir = Scratch::new();
    let log = dir.path("secret.log");
    let out = certtui()
        .env("RUST_LOG", "trace")
        .env("KEYSTORE_PW", "changeit")
        .args([
            "--log-file",
            log.to_str().unwrap(),
            "--password-env",
            "KEYSTORE_PW",
        ])
        .args([
            "inspect",
            &format!("{FIXTURES}/keystores/chain-with-key.p12"),
            "--text",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = log_text(&log);
    assert_ne!(text, "");
    assert!(!text.contains("changeit"), "the password reached the log");
    // The variable name is not a secret and is useful to the reader.
    assert!(
        text.contains("KEYSTORE_PW") || text.contains("password"),
        "{text}"
    );
}

#[test]
fn quando_log_file_nao_pode_ser_criado_deve_sair_2_citando_o_caminho() {
    let dir = Scratch::new();
    let log = dir.path("missing-dir/run.log");
    let out = certtui()
        .args([
            "--log-file",
            log.to_str().unwrap(),
            "inspect",
            &chain3(),
            "--text",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("run.log"), "{}", stderr(&out));
}

#[cfg(unix)]
#[test]
fn quando_log_e_criado_deve_ter_modo_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = Scratch::new();
    let log = dir.path("mode.log");
    certtui()
        .args([
            "--log-file",
            log.to_str().unwrap(),
            "inspect",
            &chain3(),
            "--text",
        ])
        .output()
        .unwrap();
    let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn quando_log_ja_existe_deve_acrescentar_sem_apagar() {
    let dir = Scratch::new();
    let log = dir.path("append.log");
    fs::write(&log, "earlier line\n").unwrap();
    certtui()
        .args([
            "--log-file",
            log.to_str().unwrap(),
            "inspect",
            &chain3(),
            "--text",
        ])
        .output()
        .unwrap();
    let text = log_text(&log);
    assert!(text.starts_with("earlier line\n"), "{text}");
    assert!(text.lines().count() > 1);
}

#[test]
fn quando_nivel_da_config_e_invalido_deve_sair_2() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"logging":{"level":"loud"}}"#);
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("logging.level"), "{}", stderr(&out));
}
