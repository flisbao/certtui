//! End-to-end tests of `certtui batch`: the list of targets, the JSON and CSV
//! output, `--fail-on` and the exit codes, against in-process TLS servers
//! whose CAs are passed with `--ca-file`. Everything stays on `localhost`.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[path = "../../certtui-infra/tests/support/tls_server.rs"]
mod tls_server;

use std::path::PathBuf;
use std::process::Output;

use assert_cmd::Command;
use base64::Engine as _;
use serde_json::Value;
use tls_server::{Behavior, TestServer};

/// Servers, the runtime that drives them and a scratch directory holding
/// their CAs and the list file.
struct Fixture {
    // Declared first so the servers stop before their runtime goes away.
    servers: Vec<TestServer>,
    _runtime: tokio::runtime::Runtime,
    dir: PathBuf,
}

impl Fixture {
    fn start(behaviors: Vec<Behavior>, tag: &str) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let servers: Vec<TestServer> = behaviors
            .into_iter()
            .map(|behavior| runtime.block_on(TestServer::start(behavior)).unwrap())
            .collect();
        let dir = std::env::temp_dir().join(format!("certtui-batch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (index, server) in servers.iter().enumerate() {
            std::fs::write(dir.join(format!("ca{index}.pem")), pem(server.ca_der())).unwrap();
        }
        Self {
            servers,
            _runtime: runtime,
            dir,
        }
    }

    /// `localhost:PORT` of server `index`.
    fn target(&self, index: usize) -> String {
        format!("localhost:{}", self.servers[index].addr().port())
    }

    /// Writes `lines` as the list file and returns its path.
    fn list(&self, lines: &[String]) -> String {
        let path = self.dir.join("list.txt");
        std::fs::write(&path, lines.join("\n")).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// `batch <file> --ca-only --ca-file <every CA> <extra>`.
    fn batch(&self, file: &str, extra: &[&str]) -> Output {
        let mut cmd = self.command(file, extra);
        cmd.output().unwrap()
    }

    fn command(&self, file: &str, extra: &[&str]) -> Command {
        let mut cmd = certtui();
        cmd.arg("batch").arg(file).arg("--ca-only");
        for index in 0..self.servers.len() {
            cmd.arg("--ca-file")
                .arg(self.dir.join(format!("ca{index}.pem")));
        }
        cmd.args(extra);
        cmd
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
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

fn json(out: &Output) -> Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|error| panic!("{error}: {}", stdout(out)))
}

/// A local port nothing listens on.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

#[test]
fn quando_batch_de_3_alvos_deve_listar_3_rows_em_json() {
    let fixture = Fixture::start(vec![Behavior::Ok, Behavior::Ok, Behavior::Ok], "json3");
    let list = fixture.list(&[fixture.target(0), fixture.target(1), fixture.target(2)]);
    let out = fixture.batch(&list, &["--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let doc = json(&out);
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["summary"]["total"], 3);
    // The test certificates last for centuries, which is a warning on its own.
    assert_eq!(
        doc["summary"]["ok"].as_u64().unwrap() + doc["summary"]["warning"].as_u64().unwrap(),
        3
    );
    assert_eq!(doc["summary"]["error"], 0);
    assert_eq!(doc["summary"]["failed"], 0);
    let rows = doc["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row["target"], fixture.target(index).as_str());
        assert!(
            matches!(row["status"].as_str(), Some("ok" | "warning")),
            "{row}"
        );
        assert!(row["days_to_expiry"].as_i64().unwrap() > 0);
        assert_eq!(row["failure"], Value::Null);
    }
    assert_eq!(doc["skipped"].as_array().unwrap().len(), 0);
    assert_eq!(stderr(&out), "");
}

#[test]
fn quando_csv_deve_ter_cabecalho_e_uma_linha_por_alvo() {
    let fixture = Fixture::start(vec![Behavior::Ok, Behavior::Expired], "csv");
    let closed = format!("localhost:{}", closed_port());
    let list = fixture.list(&[fixture.target(0), fixture.target(1), closed]);
    let out = fixture.batch(&list, &["--csv"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    // Ports and the day count change on every run.
    let text = stdout(&out)
        .lines()
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                return line.to_owned();
            }
            let mut cells: Vec<String> = line.split(',').map(str::to_owned).collect();
            cells[0] = cells[0].split(':').next().unwrap().to_owned();
            cells[2] = if cells[2].is_empty() {
                String::new()
            } else {
                "N".to_owned()
            };
            if cells[1] == "failed" {
                cells[8] = "<reason>".to_owned();
            }
            cells.join(",")
        })
        .collect::<Vec<_>>()
        .join("\n");
    insta::assert_snapshot!(text);
}

#[test]
fn quando_todos_falham_deve_sair_3() {
    let fixture = Fixture::start(vec![Behavior::Ok], "allfail");
    let list = fixture.list(&[
        format!("localhost:{}", closed_port()),
        format!("localhost:{}", closed_port()),
    ]);
    let out = fixture.batch(&list, &["--json"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    let doc = json(&out);
    assert_eq!(doc["summary"]["failed"], 2);
    assert_eq!(doc["rows"][0]["status"], "failed");
    assert!(doc["rows"][0]["failure"].as_str().unwrap().len() <= 120);
}

#[test]
fn quando_um_tem_erro_e_fail_on_error_deve_sair_1() {
    let fixture = Fixture::start(vec![Behavior::Ok, Behavior::Expired], "failon-error");
    let list = fixture.list(&[fixture.target(0), fixture.target(1)]);
    let out = fixture.batch(&list, &["--json", "--fail-on", "error"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let doc = json(&out);
    assert!(matches!(
        doc["rows"][0]["status"].as_str(),
        Some("ok" | "warning")
    ));
    assert_eq!(doc["rows"][1]["status"], "error");
    assert!(doc["rows"][1]["days_to_expiry"].as_i64().unwrap() < 0);
}

#[test]
fn quando_so_ha_warning_deve_sair_0_com_fail_on_error_e_1_com_fail_on_warning() {
    let fixture = Fixture::start(vec![Behavior::Ok, Behavior::WrongOrder], "failon-warning");
    let list = fixture.list(&[fixture.target(0), fixture.target(1)]);
    let lenient = fixture.batch(&list, &["--json"]);
    assert_eq!(lenient.status.code(), Some(0), "{}", stderr(&lenient));
    assert_eq!(json(&lenient)["rows"][1]["status"], "warning");
    let strict = fixture.batch(&list, &["--json", "--fail-on", "warning"]);
    assert_eq!(strict.status.code(), Some(1), "{}", stderr(&strict));
}

#[test]
fn quando_um_falha_e_outros_ok_deve_sair_1() {
    let fixture = Fixture::start(vec![Behavior::Ok, Behavior::Ok], "partial");
    let list = fixture.list(&[
        fixture.target(0),
        format!("localhost:{}", closed_port()),
        fixture.target(1),
    ]);
    let out = fixture.batch(&list, &["--json"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let doc = json(&out);
    assert_eq!(doc["summary"]["error"], 0);
    assert_eq!(doc["summary"]["failed"], 1);
    assert_eq!(doc["summary"]["total"], 3);
    // Rows keep the order of the list.
    assert_eq!(doc["rows"][1]["status"], "failed");
}

#[test]
fn quando_arquivo_tem_alvo_invalido_deve_listar_em_skipped_e_seguir() {
    let fixture = Fixture::start(vec![Behavior::Ok], "skipped");
    let list = fixture.list(&[
        "# comment".to_owned(),
        "bad host".to_owned(),
        fixture.target(0),
        "ftp://x.test".to_owned(),
    ]);
    let out = fixture.batch(&list, &["--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let doc = json(&out);
    assert_eq!(doc["summary"]["total"], 1);
    let skipped = doc["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 2);
    assert_eq!(skipped[0]["line"], 2);
    assert_eq!(skipped[1]["line"], 4);
}

#[test]
fn quando_concorrencia_acima_do_teto_deve_truncar_e_avisar_no_stderr() {
    let fixture = Fixture::start(vec![Behavior::Ok], "cap");
    let list = fixture.list(&[fixture.target(0)]);
    let out = fixture.batch(&list, &["--json", "--concurrency", "1000"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("--concurrency 1000"), "{err}");
    assert!(err.contains("256"), "{err}");
}

#[test]
fn quando_concorrencia_e_zero_deve_sair_2() {
    let fixture = Fixture::start(vec![Behavior::Ok], "zero");
    let list = fixture.list(&[fixture.target(0)]);
    let out = fixture.batch(&list, &["--concurrency", "0"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn quando_stdin_deve_ler_lista() {
    let fixture = Fixture::start(vec![Behavior::Ok, Behavior::Ok], "stdin");
    let list = format!("{}\n{}\n", fixture.target(0), fixture.target(1));
    let out = fixture
        .command("-", &["--json"])
        .write_stdin(list)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(json(&out)["summary"]["total"], 2);
}

#[test]
fn quando_lista_sem_alvos_deve_sair_2() {
    let fixture = Fixture::start(vec![Behavior::Ok], "empty");
    let list = fixture.list(&["# nothing".to_owned(), String::new()]);
    let out = fixture.batch(&list, &["--json"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("no targets"), "{}", stderr(&out));
}

#[test]
fn quando_json_da_lista_e_invalido_deve_sair_2() {
    let fixture = Fixture::start(vec![Behavior::Ok], "badjson");
    let list = fixture.list(&["[\"a.com\"".to_owned()]);
    let out = fixture.batch(&list, &["--json"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn quando_arquivo_da_lista_nao_existe_deve_sair_3() {
    let fixture = Fixture::start(vec![Behavior::Ok], "missing");
    let missing = fixture.dir.join("nope.txt");
    let out = fixture.batch(&missing.to_string_lossy(), &["--json"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
}

#[test]
fn quando_sni_ou_connect_to_deve_sair_2() {
    let fixture = Fixture::start(vec![Behavior::Ok], "sni");
    let list = fixture.list(&[fixture.target(0)]);
    let out = fixture.batch(&list, &["--sni", "x.test"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("--sni"), "{}", stderr(&out));
}
