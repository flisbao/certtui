//! End-to-end tests of `--proxy`: the TLS fetch is tunnelled through an HTTP
//! CONNECT proxy, the environment is honored only when the config says so,
//! and a bad proxy is a usage error.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../certtui-infra/tests/support/fake_proxy.rs"]
mod fake_proxy;
#[path = "../../certtui-infra/tests/support/tls_server.rs"]
mod tls_server;

use std::fs;
use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_cmd::Command;
use base64::Engine as _;
use fake_proxy::{FakeProxy, ProxyBehavior};
use tls_server::{Behavior, TestServer};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A TLS server, a fake proxy that relays to it, and a scratch directory with
/// the server's CA.
struct Fixture {
    // Declared first so the servers stop before their runtime goes away.
    proxy: FakeProxy,
    server: TestServer,
    runtime: tokio::runtime::Runtime,
    dir: PathBuf,
}

impl Fixture {
    fn start(behavior: ProxyBehavior) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = runtime.block_on(TestServer::start(Behavior::Ok)).unwrap();
        let proxy = runtime.block_on(FakeProxy::start(behavior, Some(server.addr())));
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("certtui-cli-proxy-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("ca.pem"), pem(server.ca_der())).unwrap();
        Self {
            proxy,
            server,
            runtime,
            dir,
        }
    }

    fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.proxy.addr().port())
    }

    fn target(&self) -> String {
        format!("localhost:{}", self.server.addr().port())
    }

    fn ca_file(&self) -> String {
        self.dir.join("ca.pem").to_string_lossy().into_owned()
    }

    fn config(&self, text: &str) -> String {
        let path = self.dir.join("config.json");
        fs::write(&path, text).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// `certtui <before> inspect localhost:<port> --text --ca-only --ca-file <CA>`.
    fn inspect(&self, before: &[&str], envs: &[(&str, String)]) -> Output {
        let mut command = certtui();
        // A developer's own config must never leak into these tests: without an
        // explicit one, an empty config stands in.
        if !before.contains(&"--config") {
            let empty = self.config("{}");
            command.args(["--config", &empty]);
        }
        command.args(before);
        for (key, value) in envs {
            command.env(key, value);
        }
        command
            .args([
                "--trust",
                "custom",
                "--ca-only",
                "--ca-file",
                &self.ca_file(),
            ])
            .args(["inspect", &self.target(), "--text"])
            .output()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = &self.runtime;
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn pem(der: &[u8]) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn certtui() -> Command {
    let mut command = Command::cargo_bin("certtui").unwrap();
    for var in [
        "CERTTUI_CONFIG",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        command.env_remove(var);
    }
    command
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn quando_proxy_flag_deve_ser_usada_pelo_inspect() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let out = fixture.inspect(&["--proxy", &fixture.proxy_url()], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("SHA-256:"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(fixture.proxy.connections(), 1);
    assert_eq!(
        fixture.proxy.request_lines(),
        [format!("CONNECT {} HTTP/1.1", fixture.target())]
    );
}

#[test]
fn quando_proxy_vem_da_config_deve_ser_usada() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let config = fixture.config(&format!(
        r#"{{"network":{{"proxy":"{}"}}}}"#,
        fixture.proxy_url()
    ));
    let out = fixture.inspect(&["--config", &config], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fixture.proxy.connections(), 1);
}

#[test]
fn quando_flag_proxy_e_config_conflitam_deve_vencer_a_flag() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let config = fixture.config(r#"{"network":{"proxy":"http://127.0.0.1:1"}}"#);
    let out = fixture.inspect(&["--config", &config, "--proxy", &fixture.proxy_url()], &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fixture.proxy.connections(), 1);
}

#[test]
fn quando_use_env_proxy_false_deve_ignorar_https_proxy() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    // The server listens on loopback; with the proxy ignored the connection
    // is direct to `localhost:<port>`.
    let out = fixture.inspect(&[], &[("HTTPS_PROXY", fixture.proxy_url())]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fixture.proxy.connections(), 0);
}

#[test]
fn quando_use_env_proxy_true_deve_usar_https_proxy() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let config = fixture.config(r#"{"network":{"use_env_proxy":true}}"#);
    let out = fixture.inspect(
        &["--config", &config],
        &[("HTTPS_PROXY", fixture.proxy_url())],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fixture.proxy.connections(), 1);
}

#[test]
fn quando_use_env_proxy_true_e_no_proxy_casa_deve_conectar_direto() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let config = fixture.config(r#"{"network":{"use_env_proxy":true}}"#);
    let out = fixture.inspect(
        &["--config", &config],
        &[
            ("HTTPS_PROXY", fixture.proxy_url()),
            ("NO_PROXY", "localhost".to_owned()),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fixture.proxy.connections(), 0);
}

#[test]
fn quando_flag_proxy_e_env_definidos_deve_usar_a_flag() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let config = fixture.config(r#"{"network":{"use_env_proxy":true}}"#);
    let out = fixture.inspect(
        &["--config", &config, "--proxy", &fixture.proxy_url()],
        &[("HTTPS_PROXY", "http://127.0.0.1:1".to_owned())],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fixture.proxy.connections(), 1);
}

#[test]
fn quando_proxy_responde_407_deve_sair_3_explicando_a_autenticacao() {
    let fixture = Fixture::start(ProxyBehavior::Status407);
    let out = fixture.inspect(&["--proxy", &fixture.proxy_url()], &[]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(
        text.contains("proxy") && text.contains("authentication"),
        "{text}"
    );
}

#[test]
fn quando_proxy_tem_credenciais_deve_sair_2_sem_ecoar_a_senha() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let out = fixture.inspect(&["--proxy", "http://user:s3cret@127.0.0.1:3128"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    let text = stderr(&out);
    assert!(!text.contains("s3cret"), "{text}");
    assert!(!text.contains("user"), "{text}");
}

#[test]
fn quando_proxy_nao_e_http_deve_sair_2() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    for url in ["https://p:3128", "socks5://p:1080", "p:3128"] {
        let out = fixture.inspect(&["--proxy", url], &[]);
        assert_eq!(out.status.code(), Some(2), "{url}: {}", stderr(&out));
    }
    assert_eq!(fixture.proxy.connections(), 0);
}

#[test]
fn quando_proxy_da_config_e_invalido_deve_sair_2() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let config = fixture.config(r#"{"network":{"proxy":"socks5://p:1080"}}"#);
    let out = fixture.inspect(&["--config", &config], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn quando_https_proxy_do_ambiente_e_invalido_com_use_env_proxy_deve_sair_2_sem_ecoar() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let config = fixture.config(r#"{"network":{"use_env_proxy":true}}"#);
    for value in [
        "http://user:s3cret@127.0.0.1:3128",
        "https://127.0.0.1:3128",
        "socks5://p:1",
    ] {
        let out = fixture.inspect(&["--config", &config], &[("HTTPS_PROXY", value.to_owned())]);
        assert_eq!(out.status.code(), Some(2), "{value}: {}", stderr(&out));
        let text = stderr(&out);
        assert!(text.contains("HTTPS_PROXY"), "{text}");
        assert!(!text.contains("s3cret"), "{text}");
    }
    // Direct connections must not have happened behind the user's back.
    assert_eq!(fixture.proxy.connections(), 0);
}

#[test]
fn quando_https_proxy_do_ambiente_e_invalido_sem_use_env_proxy_deve_ser_ignorado() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let out = fixture.inspect(
        &[],
        &[("HTTPS_PROXY", "http://u:pw@127.0.0.1:3128".to_owned())],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
}

#[test]
fn quando_no_proxy_deve_ignorar_proxy_da_config_e_do_ambiente() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    // The config names a proxy that is not there; the environment names the
    // fake one. `--no-proxy` must send the connection straight to the server.
    let config =
        fixture.config(r#"{"network":{"proxy":"http://127.0.0.1:1","use_env_proxy":true}}"#);
    let out = fixture.inspect(
        &["--config", &config, "--no-proxy"],
        &[("HTTPS_PROXY", fixture.proxy_url())],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(fixture.proxy.connections(), 0);
}

#[test]
fn quando_proxy_e_no_proxy_juntos_deve_sair_2() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let out = fixture.inspect(&["--proxy", &fixture.proxy_url(), "--no-proxy"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn quando_aia_e_no_aia_juntos_deve_sair_2() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let out = fixture.inspect(&["--aia", "--no-aia"], &[]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

#[test]
fn quando_a_variavel_invalida_e_minuscula_a_mensagem_deve_citar_o_nome_minusculo() {
    let fixture = Fixture::start(ProxyBehavior::Ok);
    let config = fixture.config(r#"{"network":{"use_env_proxy":true}}"#);
    let out = fixture.inspect(
        &["--config", &config],
        &[("https_proxy", "socks5://127.0.0.1:1".to_owned())],
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stderr(&out).contains("https_proxy:"), "{}", stderr(&out));
}
