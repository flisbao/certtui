//! End-to-end tests of `certtui check`: validation, findings, `--fail-on` and
//! the exit codes, against an in-process TLS server whose CA is passed with
//! `--ca-file`. The host is `localhost` and nothing leaves the machine.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../certtui-infra/tests/support/tls_server.rs"]
mod tls_server;

use std::path::PathBuf;
use std::process::Output;

use assert_cmd::Command;
use base64::Engine as _;
use serde_json::Value;
use tls_server::{Behavior, TestServer};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

/// A running test server, the runtime that drives it and a scratch directory
/// holding the server's CA as PEM.
struct Fixture {
    // Declared first so the server stops before its runtime goes away.
    server: TestServer,
    _runtime: tokio::runtime::Runtime,
    dir: PathBuf,
}

impl Fixture {
    fn start(behavior: Behavior, tag: &str) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = runtime.block_on(TestServer::start(behavior)).unwrap();
        let dir = scratch_dir(tag);
        std::fs::write(dir.join("ca.pem"), pem(server.ca_der())).unwrap();
        Self {
            server,
            _runtime: runtime,
            dir,
        }
    }

    fn ca_file(&self) -> String {
        self.dir.join("ca.pem").to_string_lossy().into_owned()
    }

    fn connect_to(&self) -> String {
        format!("127.0.0.1:{}", self.server.addr().port())
    }

    /// `check localhost --connect-to <server> --ca-only --ca-file <CA>`.
    fn check(&self, extra: &[&str]) -> Output {
        certtui()
            .args(["check", "localhost", "--connect-to", &self.connect_to()])
            .args(["--ca-only", "--ca-file", &self.ca_file()])
            .args(extra)
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("certtui-check-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pem(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(chunk).unwrap());
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    text
}

fn certtui() -> Command {
    Command::cargo_bin("certtui").unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).unwrap()
}

fn fixture_path(name: &str) -> String {
    format!("{FIXTURES}/{name}")
}

/// A local port nothing listens on.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn quando_check_ok_deve_sair_0() {
    let fixture = Fixture::start(Behavior::Ok, "ok");
    let out = fixture.check(&[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with("localhost: trusted (anchor: "), "{text}");
    // The only finding is the informational "root sent".
    assert!(text.contains("info CHAIN_ROOT_SENT"), "{text}");
    assert_eq!(stderr(&out), "");
}

#[test]
fn quando_cert_expirado_deve_sair_1_e_listar_expired() {
    let fixture = Fixture::start(Behavior::Expired, "expired");
    let out = fixture.check(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("error EXPIRED [cert 0]"), "{text}");
    assert!(text.contains("untrusted"), "{text}");
}

#[test]
fn quando_fail_on_warning_e_ha_so_warning_deve_sair_1() {
    let fixture = Fixture::start(Behavior::WrongOrder, "warn-fail");
    let out = fixture.check(&["--fail-on", "warning"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stdout(&out).contains("warning CHAIN_ORDER_WRONG"));
}

#[test]
fn quando_fail_on_error_e_ha_so_warning_deve_sair_0() {
    let fixture = Fixture::start(Behavior::WrongOrder, "warn-pass");
    let out = fixture.check(&["--fail-on", "error"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains("warning CHAIN_ORDER_WRONG"));
}

#[test]
fn quando_flag_invalida_deve_sair_2() {
    for args in [
        vec!["check", "localhost", "--fail-on", "info"],
        vec!["check", "localhost", "--warn-days", "x"],
        vec!["check", "localhost", "--bogus"],
        vec!["check"],
        vec![
            "check",
            "localhost",
            "--warn-days",
            "3",
            "--critical-days",
            "9",
        ],
    ] {
        let out = certtui().args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
        assert_eq!(stdout(&out), "", "{args:?}");
    }
}

#[test]
fn quando_todos_os_alvos_falham_deve_sair_3() {
    let (a, b) = (closed_port(), closed_port());
    let out = certtui()
        .args([
            "check",
            &format!("127.0.0.1:{a}"),
            &format!("127.0.0.1:{b}"),
        ])
        .args(["--ca-only"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert_eq!(stderr(&out).lines().count(), 2, "{}", stderr(&out));
}

#[test]
fn quando_um_alvo_falha_e_outro_ok_deve_sair_1_e_listar_falha_no_stderr() {
    let fixture = Fixture::start(Behavior::Ok, "partial");
    let good = format!("localhost:{}", fixture.server.addr().port());
    let bad = format!("localhost:{}", closed_port());
    let out = certtui()
        .args(["check", &good, &bad])
        .args(["--ca-only", "--ca-file", &fixture.ca_file()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stdout(&out).starts_with(&format!("{good}: trusted")));
    let err = stderr(&out);
    assert!(
        err.starts_with(&format!("certtui: {bad}: ")),
        "failure not attributed to its target: {err}"
    );
    assert!(err.contains("connection failed"), "{err}");
}

#[test]
fn quando_ca_only_aponta_arquivo_ilegivel_deve_sair_2() {
    let missing = std::env::temp_dir().join("certtui-check-no-such-ca.pem");
    let out = certtui()
        .args(["check", &fixture_path("chain-3.pem")])
        .args(["--ca-only", "--ca-file", &missing.to_string_lossy()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("custom CA file"), "{}", stderr(&out));
}

#[test]
fn quando_ca_file_e_texto_sujo_deve_confiar_na_ca() {
    let fixture = Fixture::start(Behavior::Ok, "dirty-ca");
    let dirty = format!(
        "# exported by hand\nsubject=CN=certtui test CA\n> {}\n-- trailing noise --\n",
        pem(fixture.server.ca_der()).replace('\n', "\n> ")
    );
    let dirty_path = fixture.dir.join("dirty.txt");
    std::fs::write(&dirty_path, dirty).unwrap();
    let out = certtui()
        .args(["check", "localhost", "--connect-to", &fixture.connect_to()])
        .args(["--ca-only", "--ca-file", &dirty_path.to_string_lossy()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("trusted (anchor: "),
        "{}",
        stdout(&out)
    );
}

#[test]
fn quando_trust_store_vazia_deve_dar_untrusted_sem_panic() {
    // `--trust custom` without `--ca-file`: no anchors at all.
    let out = certtui()
        .args(["check", &fixture_path("chain-3.pem"), "--trust", "custom"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("untrusted (no trust anchors loaded)"),
        "{text}"
    );
    assert!(text.contains("error TRUST_UNTRUSTED"), "{text}");
    assert!(!stderr(&out).contains("panicked"), "{}", stderr(&out));
}

#[test]
fn quando_check_json_deve_ter_resultados_por_alvo_com_trust_e_findings() {
    let fixture = Fixture::start(Behavior::Ok, "json");
    // `--connect-to` would redirect every target, so address the server directly.
    let good = format!("localhost:{}", fixture.server.addr().port());
    let bad = format!("localhost:{}", closed_port());
    let out = certtui()
        .args(["check", &good, &bad, "--json"])
        .args(["--ca-only", "--ca-file", &fixture.ca_file()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    let results = json["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["target"], good.as_str());
    assert_eq!(results[0]["error"], Value::Null);
    assert_eq!(results[0]["trust"]["status"], "trusted");
    assert_eq!(results[0]["findings"][0]["code"], "CHAIN_ROOT_SENT");
    assert_eq!(results[1]["target"], bad.as_str());
    assert!(
        results[1]["error"]
            .as_str()
            .unwrap()
            .contains("connection failed")
    );
    assert_eq!(results[1]["trust"], Value::Null);
    assert_eq!(results[1]["findings"], serde_json::json!([]));
}

#[test]
fn quando_check_json_de_alvo_com_tres_achados_deve_bater_com_o_snapshot() {
    // `expired.pem` is self-signed and expired; with no anchors the verdict is
    // deterministic and independent of the machine's trust store.
    let out = certtui()
        .args([
            "check",
            &fixture_path("expired.pem"),
            "--trust",
            "custom",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut json = json;
    // The target is an absolute path of this machine.
    json["results"][0]["target"] = Value::String("<fixtures>/expired.pem".to_owned());
    let findings = json["results"][0]["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 3, "{findings:?}");
    insta::assert_snapshot!(
        "check_expired_json",
        serde_json::to_string_pretty(&json).unwrap()
    );
}

#[test]
fn quando_inspect_valida_deve_incluir_trust_e_findings_no_json() {
    let out = certtui()
        .args([
            "inspect",
            &fixture_path("expired.pem"),
            "--json",
            "--trust",
            "custom",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["trust"]["status"], "untrusted");
    let codes: Vec<&str> = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"EXPIRED"), "{codes:?}");
    for finding in json["findings"].as_array().unwrap() {
        for key in ["code", "severity", "category", "cert_index", "message"] {
            assert!(finding.get(key).is_some(), "{key}: {finding}");
        }
    }
}

#[test]
fn quando_inspect_valida_deve_mostrar_trust_e_findings_no_texto() {
    let out = certtui()
        .args(["inspect", &fixture_path("expired.pem"), "--trust", "custom"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("\nTrust: untrusted (no trust anchors loaded)\nFindings:\n"),
        "{text}"
    );
    assert!(
        text.contains("  - error EXPIRED [cert 0]: certificate expired on 2020-02-01T00:00:00Z\n"),
        "{text}"
    );
}
