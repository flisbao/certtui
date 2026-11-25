//! End-to-end tests of the configuration file: location, errors with field
//! and line, and the precedence flags > config > defaults.

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
        let dir =
            std::env::temp_dir().join(format!("certtui-cli-config-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// Writes `config.json` and returns its path as a string.
    fn config(&self, text: &str) -> String {
        let path = self.0.join("config.json");
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
    // A developer's own config or proxy must never leak into these tests.
    command.env_remove("CERTTUI_CONFIG").env_remove("NO_COLOR");
    command
}

fn chain3() -> String {
    format!("{FIXTURES}/chain-3.pem")
}

/// `certtui <extra> check chain-3.pem` trusting the chain's own CA.
fn check(config: &str, extra: &[&str]) -> Output {
    certtui()
        .args(["--config", config])
        .args(extra)
        .args(["check", &chain3(), "--ca-only", "--ca-file", &chain3()])
        .output()
        .unwrap()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn quando_config_invalida_deve_sair_2_com_mensagem_de_campo_e_linha() {
    let dir = Scratch::new();
    let config = dir.config("{\n  \"ui\": {\n    \"colour\": 1\n  }\n}");
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("ui.colour"), "{text}");
    assert!(text.contains("line 3"), "{text}");
    assert_eq!(stdout(&out), "");
}

#[test]
fn quando_config_tem_json_malformado_deve_sair_2_com_linha_e_coluna() {
    let dir = Scratch::new();
    let config = dir.config("{\n  \"ui\": {},\n}");
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("line 3"), "{text}");
    assert!(text.contains("column"), "{text}");
}

#[test]
fn quando_env_certtui_config_e_invalida_deve_sair_2() {
    let dir = Scratch::new();
    let config = dir.config("{\"nope\": 1}");
    let out = certtui()
        .env("CERTTUI_CONFIG", &config)
        .args(["inspect", &chain3()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("nope"), "{}", stderr(&out));
}

#[test]
fn quando_config_explicita_nao_existe_deve_sair_2() {
    let dir = Scratch::new();
    let missing = dir.0.join("missing.json");
    let out = certtui()
        .args(["--config", missing.to_str().unwrap(), "inspect", &chain3()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("missing.json"), "{}", stderr(&out));
}

#[test]
fn quando_config_valida_e_vazia_de_campos_deve_inspecionar_normalmente() {
    let dir = Scratch::new();
    let config = dir.config("{}");
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains("SHA-256:"), "{}", stdout(&out));
}

#[test]
fn quando_config_define_warn_days_deve_gerar_expires_soon() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"thresholds":{"warn_days":100000}}"#);
    let out = check(&config, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains("EXPIRES_SOON"), "{}", stdout(&out));
}

#[test]
fn quando_flag_warn_days_e_config_conflitam_deve_vencer_a_flag() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"thresholds":{"warn_days":100000}}"#);
    let out = certtui()
        .args(["--config", &config, "check", &chain3()])
        .args(["--ca-only", "--ca-file", &chain3(), "--warn-days", "10"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(!stdout(&out).contains("EXPIRES_SOON"), "{}", stdout(&out));
}

#[test]
fn quando_config_define_fail_on_warning_deve_sair_1() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"thresholds":{"warn_days":100000,"fail_on":"warning"}}"#);
    let out = check(&config, &[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn quando_flag_fail_on_e_config_conflitam_deve_vencer_a_flag() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"thresholds":{"warn_days":100000,"fail_on":"warning"}}"#);
    let out = certtui()
        .args(["--config", &config, "check", &chain3()])
        .args(["--ca-only", "--ca-file", &chain3(), "--fail-on", "error"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn quando_critical_days_da_config_passa_de_warn_days_deve_sair_2() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"thresholds":{"warn_days":5,"critical_days":10}}"#);
    let out = check(&config, &[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn quando_config_define_fingerprint_format_hex_deve_usar_hex_minusculo() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"ui":{"fingerprint_format":"hex"}}"#);
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout(&out);
    let line = text
        .lines()
        .find(|line| line.trim_start().starts_with("SHA-256:"))
        .unwrap();
    let value = line.split_once(':').unwrap().1.trim();
    assert_eq!(value.len(), 64, "{line}");
    assert!(
        value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "{line}"
    );
}

#[test]
fn quando_flag_fingerprint_format_e_config_conflitam_deve_vencer_a_flag() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"ui":{"fingerprint_format":"hex"}}"#);
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3(), "--text"])
        .args(["--fingerprint-format", "colon"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("SHA-256: 42:3A:5E"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn quando_config_define_trust_mozilla_sem_ca_deve_ser_untrusted() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"trust":{"sources":["custom"]}}"#);
    // `custom` without any `--ca-file`: no anchors, so the chain is untrusted.
    let out = certtui()
        .args(["--config", &config, "check", &chain3()])
        .output()
        .unwrap();
    assert!(
        stdout(&out).contains("untrusted"),
        "{} / {}",
        stdout(&out),
        stderr(&out)
    );
}

#[test]
fn quando_ui_clipboard_e_desconhecido_deve_sair_2() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"ui":{"clipboard":"magic"}}"#);
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("ui.clipboard"), "{}", stderr(&out));
}

#[cfg(not(feature = "native-clipboard"))]
#[test]
fn quando_ui_clipboard_native_sem_feature_deve_sair_2() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"ui":{"clipboard":"native"}}"#);
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("native-clipboard"),
        "{}",
        stderr(&out)
    );
}

#[cfg(feature = "native-clipboard")]
#[test]
fn quando_ui_clipboard_native_com_feature_deve_aceitar_a_config() {
    let dir = Scratch::new();
    let config = dir.config(r#"{"ui":{"clipboard":"native"}}"#);
    let out = certtui()
        .args(["--config", &config, "inspect", &chain3(), "--text"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}
