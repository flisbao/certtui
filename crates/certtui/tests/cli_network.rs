//! End-to-end tests of `certtui inspect` against an in-process TLS server.
//!
//! The server is the harness of `certtui-infra` (`tests/support`), compiled
//! into this crate with `#[path]`. The host is always `localhost` and
//! `--connect-to` points at the server, so nothing leaves the machine.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../certtui-infra/tests/support/tls_server.rs"]
mod tls_server;

use std::process::Output;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use base64::Engine as _;
use serde_json::{Value, json};
use tls_server::{Behavior, Observation, TestServer};

/// A running test server plus the runtime that drives it. The test body is
/// synchronous because the CLI runs as a child process.
struct Fixture {
    // Declared first so the server stops before its runtime goes away.
    server: TestServer,
    _runtime: tokio::runtime::Runtime,
}

impl Fixture {
    fn start(behavior: Behavior) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = runtime.block_on(TestServer::start(behavior)).unwrap();
        Self {
            server,
            _runtime: runtime,
        }
    }

    fn port(&self) -> u16 {
        self.server.addr().port()
    }

    /// `localhost --connect-to 127.0.0.1:PORT` plus `extra`.
    fn run(&self, extra: &[&str]) -> Output {
        let connect_to = format!("127.0.0.1:{}", self.port());
        certtui()
            .args(["inspect", "localhost", "--connect-to", &connect_to])
            .args(extra)
            .output()
            .unwrap()
    }

    fn json(&self, extra: &[&str]) -> Value {
        let out = self.run(&[extra, &["--json"]].concat());
        assert!(out.status.success(), "{}", stderr(&out));
        serde_json::from_slice(&out.stdout).unwrap()
    }
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

#[test]
fn quando_inspect_rede_deve_sair_0_com_tls_no_json() {
    let fixture = Fixture::start(Behavior::Ok);
    let json = fixture.json(&[]);

    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["target"]["kind"], "network");
    assert_eq!(json["target"]["host"], "localhost");
    assert_eq!(json["target"]["port"], 443);
    assert_eq!(json["target"]["sni"], Value::Null);
    assert_eq!(
        json["target"]["connect_to"],
        format!("127.0.0.1:{}", fixture.port())
    );
    let tls = &json["tls"];
    assert!(["TLSv1.2", "TLSv1.3"].contains(&tls["version"].as_str().unwrap()));
    assert_ne!(tls["cipher_suite"].as_str().unwrap(), "");
    assert!(["h2", "http/1.1"].contains(&tls["alpn"].as_str().unwrap()));
    assert_eq!(tls["peer_ip"], "127.0.0.1");
    assert!(tls.get("key_exchange_group").is_some());
    let timings = &json["timings"];
    assert_eq!(timings["dns"], Value::Null, "--connect-to skips DNS");
    for phase in ["connect", "handshake", "total"] {
        assert!(timings[phase].is_u64(), "{phase}: {timings}");
    }
    assert_eq!(json["ocsp_staple"], json!({"present": false, "bytes": 0}));
    let certs = json["certificates"].as_array().unwrap();
    assert_eq!(certs.len(), 3, "leaf, intermediate and CA");
    for (position, cert) in certs.iter().enumerate() {
        assert_eq!(cert["index"], position);
        assert_eq!(
            cert["origin"],
            json!({"kind": "presented", "position": position})
        );
    }
    assert_eq!(json["notes"], json!([]));
}

#[test]
fn quando_server_nao_responde_deve_sair_3_dentro_do_timeout() {
    let fixture = Fixture::start(Behavior::NeverResponds);
    let started = Instant::now();
    let out = fixture.run(&["--timeout", "2"]);
    let elapsed = started.elapsed();

    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(elapsed < Duration::from_secs(6), "took {elapsed:?}");
    assert_eq!(out.stdout, Vec::<u8>::new());
    let message = stderr(&out);
    assert!(message.contains("timed out"), "{message}");
}

/// Replaces everything random or timing-dependent so the document can be
/// compared with a stored snapshot.
fn masked(mut json: Value) -> Value {
    if let Some(target) = json.get_mut("target").and_then(Value::as_object_mut) {
        target.insert("port".to_owned(), json!("[port]"));
        target.insert("connect_to".to_owned(), json!("127.0.0.1:[port]"));
    }
    if let Some(timings) = json.get_mut("timings").and_then(Value::as_object_mut) {
        for value in timings.values_mut() {
            if !value.is_null() {
                *value = json!("[ms]");
            }
        }
    }
    let certs = json.get("certificates").and_then(Value::as_array).unwrap();
    let certs: Vec<Value> = certs
        .iter()
        .map(|cert| {
            // Keys, serials, validity and fingerprints are generated per run;
            // the names and the origin are fixed by the harness.
            json!({
                "index": cert["index"],
                "origin": cert["origin"],
                "subject": cert["subject"],
                "issuer": cert["issuer"],
                "basic_constraints": cert["basic_constraints"],
                "subject_alt_names": cert["subject_alt_names"],
                "keys": cert.as_object().unwrap().keys().collect::<Vec<_>>(),
            })
        })
        .collect();
    if let Some(document) = json.as_object_mut() {
        document.insert("certificates".to_owned(), Value::Array(certs));
    }
    json
}

#[test]
fn quando_json_de_rede_deve_bater_com_snapshot() {
    let fixture = Fixture::start(Behavior::Tls13Only);
    let json = masked(fixture.json(&["--sni", "Alt.Example.Test"]));
    insta::assert_snapshot!(
        "network_json_masked",
        serde_json::to_string_pretty(&json).unwrap()
    );
}

#[test]
fn quando_sni_e_invalido_deve_sair_2_antes_de_conectar() {
    let fixture = Fixture::start(Behavior::Ok);
    for sni in ["bad name", "", "a..b", "-x.example", "exa%mple.com"] {
        let out = fixture.run(&[&format!("--sni={sni}")]);
        assert_eq!(out.status.code(), Some(2), "{sni:?}: {}", stderr(&out));
        assert_eq!(out.stdout, Vec::<u8>::new());
        assert!(stderr(&out).contains("--sni"), "{}", stderr(&out));
    }
    let too_long = format!("{}.example", "a".repeat(64));
    let out = fixture.run(&[&format!("--sni={too_long}")]);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(fixture.server.accepted_connections(), 0);
    assert_eq!(fixture.server.last_sni(), Observation::NotYet);
}

#[test]
fn quando_sni_invalido_tem_controles_deve_nao_ecoar_no_erro() {
    let fixture = Fixture::start(Behavior::Ok);
    let sni = "bad\nname\ttest\u{202e}";
    let out = fixture.run(&[&format!("--sni={sni}")]);
    let message = stderr(&out);

    assert_eq!(out.status.code(), Some(2), "{message}");
    assert_eq!(out.stdout, Vec::<u8>::new());
    assert_eq!(message.lines().count(), 1, "{message:?}");
    assert!(!message.contains('\t'), "{message:?}");
    assert!(!message.contains('\u{202e}'), "{message:?}");
    assert_eq!(fixture.server.accepted_connections(), 0);
}

#[test]
fn quando_connect_to_e_invalido_deve_sair_2_sem_conectar() {
    let fixture = Fixture::start(Behavior::Ok);
    for value in ["localhost", "1.2.3.4:0", "1.2.3.4:99999", "[::1", "x"] {
        let out = certtui()
            .args(["inspect", "localhost", &format!("--connect-to={value}")])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{value}: {}", stderr(&out));
        assert_eq!(out.stdout, Vec::<u8>::new());
        assert!(stderr(&out).contains("--connect-to"), "{}", stderr(&out));
    }
    assert_eq!(fixture.server.accepted_connections(), 0);
}

#[test]
fn quando_timeout_e_zero_ou_nao_numerico_deve_sair_2() {
    let fixture = Fixture::start(Behavior::Ok);
    for value in ["0", "abc", "-3", "1.5", ""] {
        let out = certtui()
            .args(["inspect", "localhost", &format!("--timeout={value}")])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{value:?}: {}", stderr(&out));
        assert_eq!(out.stdout, Vec::<u8>::new());
        assert!(stderr(&out).contains("--timeout"), "{}", stderr(&out));
    }
    assert_eq!(fixture.server.accepted_connections(), 0);
}

#[test]
fn quando_flag_de_rede_em_alvo_local_deve_sair_2() {
    let file = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/chain-3.pem"
    );
    for (flag, value) in [
        ("--sni", "example.com"),
        ("--connect-to", "127.0.0.1"),
        ("--timeout", "5"),
    ] {
        for target in [file, "-", env!("CARGO_MANIFEST_DIR")] {
            let out = certtui()
                .args(["inspect", target, flag, value])
                .write_stdin("")
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(2), "{flag} {target}");
            assert_eq!(out.stdout, Vec::<u8>::new());
            let message = stderr(&out);
            assert!(
                message.contains(&format!("{flag} only applies to network targets")),
                "{message}"
            );
        }
    }
}

#[test]
fn quando_text_de_rede_deve_terminar_com_o_rodape_de_tls() {
    let fixture = Fixture::start(Behavior::Tls13Only);
    let out = fixture.run(&["--text"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("Origin: presented by server, position 0"),
        "{text}"
    );
    let footer = text.lines().find(|line| line.starts_with("TLSv")).unwrap();
    assert!(text.contains(&format!("{footer}\nkey exchange ")), "{text}");
    let parts: Vec<&str> = footer.split(" \u{b7} ").collect();
    assert_eq!(parts.len(), 4, "{footer}");
    assert_eq!(parts[0], "TLSv1.3");
    assert!(
        parts[1].contains("AES") || parts[1].contains("CHACHA"),
        "{footer}"
    );
    assert_eq!(parts[2], "127.0.0.1");
    let ms = parts[3].strip_prefix("handshake ").unwrap();
    assert!(
        ms.strip_suffix("ms").unwrap().parse::<u64>().is_ok(),
        "{footer}"
    );
}

#[test]
fn quando_text_local_nao_deve_ter_rodape_de_tls() {
    let file = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/chain-3.pem"
    );
    let out = certtui().args(["inspect", file]).output().unwrap();
    assert!(!stdout(&out).contains("handshake"));
}

#[test]
fn quando_json_local_nao_deve_ganhar_chaves_de_rede() {
    let file = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/chain-3.pem"
    );
    let out = certtui()
        .args(["inspect", file, "--json"])
        .output()
        .unwrap();
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    for key in ["tls", "timings", "ocsp_staple"] {
        assert!(json.get(key).is_none(), "{key} must be network-only");
    }
}

#[test]
fn quando_field_sobre_rede_deve_imprimir_so_o_valor() {
    let fixture = Fixture::start(Behavior::Ok);
    let out = fixture.run(&["--field", "fingerprint.sha256"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let value = stdout(&out);
    let expected = fixture.json(&[])["certificates"][0]["fingerprints"]["sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(value, format!("{expected}\n"));
    assert_eq!(value.matches(':').count(), 31, "{value}");
}

#[test]
fn quando_pem_sobre_rede_deve_emitir_os_ders_apresentados_na_ordem() {
    let fixture = Fixture::start(Behavior::Ok);
    let out = fixture.run(&["--pem"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let engine = base64::engine::general_purpose::STANDARD;
    let mut got = Vec::new();
    let mut body = String::new();
    for line in stdout(&out).lines() {
        match line {
            "-----BEGIN CERTIFICATE-----" => body.clear(),
            "-----END CERTIFICATE-----" => got.push(engine.decode(&body).unwrap()),
            other => body.push_str(other),
        }
    }
    assert_eq!(got, fixture.server.presented_chain());
}

#[test]
fn quando_index_sobre_rede_deve_filtrar_mantendo_o_indice() {
    let fixture = Fixture::start(Behavior::Ok);
    let json = fixture.json(&["--index", "1"]);
    assert_eq!(json["certificates"].as_array().unwrap().len(), 1);
    assert_eq!(json["certificates"][0]["index"], 1);
    assert_eq!(json["certificates"][0]["origin"]["position"], 1);
    assert_eq!(json["tls"]["peer_ip"], "127.0.0.1");
}

#[test]
fn quando_cadeia_e_incompleta_deve_mostrar_um_cert() {
    let fixture = Fixture::start(Behavior::IncompleteChain);
    let json = fixture.json(&[]);
    assert_eq!(json["certificates"].as_array().unwrap().len(), 1);
}

#[test]
fn quando_cadeia_esta_fora_de_ordem_deve_manter_a_ordem_apresentada() {
    let fixture = Fixture::start(Behavior::WrongOrder);
    let json = fixture.json(&[]);
    let certs = json["certificates"].as_array().unwrap();
    assert_eq!(certs.len(), 3);
    assert_eq!(certs[1]["subject"]["common_name"], "certtui test CA");
    assert_eq!(
        certs[2]["subject"]["common_name"],
        "certtui test intermediate"
    );
}

#[test]
fn quando_cert_expirado_deve_sair_0_e_mostrar_a_cadeia() {
    let fixture = Fixture::start(Behavior::Expired);
    let json = fixture.json(&[]);
    assert_eq!(json["certificates"].as_array().unwrap().len(), 3);
    assert_eq!(json["certificates"][0]["not_after"], "2001-01-01T00:00:00Z");
    assert_eq!(json["notes"], json!([]));
}

#[test]
fn quando_cert_e_autoassinado_deve_sair_0_e_mostrar_a_cadeia() {
    let fixture = Fixture::start(Behavior::SelfSigned);
    let json = fixture.json(&[]);
    let certs = json["certificates"].as_array().unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0]["subject"], certs[0]["issuer"]);
}

#[test]
fn quando_server_tem_staple_deve_informar_presenca_e_tamanho() {
    let fixture = Fixture::start(Behavior::WithStaple(vec![0x5A; 37]));
    let json = fixture.json(&[]);
    assert_eq!(json["ocsp_staple"], json!({"present": true, "bytes": 37}));
}

#[test]
fn quando_alvo_tem_credenciais_deve_sair_2_sem_ecoar() {
    let fixture = Fixture::start(Behavior::Ok);
    let target = format!("https://user:hunter2@localhost:{}", fixture.port());
    let out = certtui().args(["inspect", &target]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, Vec::<u8>::new());
    let message = stderr(&out);
    assert!(message.contains("credentials"), "{message}");
    assert!(
        !message.contains("hunter2") && !message.contains("user"),
        "{message}"
    );
    assert_eq!(fixture.server.accepted_connections(), 0);
}

#[test]
fn quando_alvo_e_ip_literal_sem_sni_deve_nao_enviar_sni() {
    let fixture = Fixture::start(Behavior::Ok);
    let target = format!("127.0.0.1:{}", fixture.port());
    let out = certtui()
        .args(["inspect", &target, "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(fixture.server.last_sni(), Observation::Absent);
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["target"]["host"], "127.0.0.1");
    assert_eq!(json["target"]["connect_to"], Value::Null);
}

#[test]
fn quando_alvo_e_ip_literal_com_sni_deve_enviar_o_sni_normalizado() {
    let fixture = Fixture::start(Behavior::Ok);
    let target = format!("127.0.0.1:{}", fixture.port());
    let out = certtui()
        .args(["inspect", &target, "--sni", "LocalHost", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        fixture.server.last_sni(),
        Observation::Present("localhost".to_owned())
    );
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["target"]["sni"], "localhost");
}

#[test]
fn quando_sni_e_literal_ip_deve_nao_enviar_sni() {
    let fixture = Fixture::start(Behavior::Ok);
    let json = fixture.json(&["--sni", "127.0.0.1"]);
    assert_eq!(json["target"]["sni"], "127.0.0.1");
    assert_eq!(fixture.server.last_sni(), Observation::Absent);
}

#[test]
fn quando_alvo_e_ipv6_com_connect_to_v4_e_sni_deve_conectar_e_enviar_o_sni() {
    let fixture = Fixture::start(Behavior::Ok);
    let target = format!("[::1]:{}", fixture.port());
    let connect_to = format!("127.0.0.1:{}", fixture.port());
    let out = certtui()
        .args(["inspect", &target, "--connect-to", &connect_to])
        .args(["--sni", "localhost", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["target"]["host"], "::1");
    assert_eq!(json["target"]["port"], fixture.port());
    assert_eq!(
        fixture.server.last_sni(),
        Observation::Present("localhost".to_owned())
    );
}

#[test]
fn quando_connect_to_sem_porta_deve_usar_a_porta_do_alvo() {
    let fixture = Fixture::start(Behavior::Ok);
    let target = format!("localhost:{}", fixture.port());
    let out = certtui()
        .args(["inspect", &target, "--connect-to", "127.0.0.1", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        json["target"]["connect_to"],
        format!("127.0.0.1:{}", fixture.port())
    );
    assert_eq!(
        fixture.server.last_sni(),
        Observation::Present("localhost".to_owned())
    );
}

#[test]
fn quando_server_fala_http_puro_deve_sair_3_com_mensagem_curta() {
    let fixture = Fixture::start(Behavior::PlainHttp);
    let out = fixture.run(&[]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert_eq!(out.stdout, Vec::<u8>::new());
    let message = stderr(&out);
    assert!(
        message.starts_with("certtui: TLS handshake failed"),
        "{message}"
    );
    assert_eq!(message.lines().count(), 1, "{message}");
}

#[test]
fn quando_porta_esta_fechada_deve_sair_3_com_connection_failed() {
    let out = certtui().args(["inspect", "127.0.0.1:1"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert_eq!(out.stdout, Vec::<u8>::new());
    assert!(
        stderr(&out).contains("connection failed"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn quando_idn_tem_formas_equivalentes_deve_usar_o_mesmo_host_e_sni() {
    let fixture = Fixture::start(Behavior::Ok);
    for (name, port) in [
        ("bücher.de", 443),
        ("bu\u{0308}cher.de", 443),
        ("bu\u{0308}cher.de:8443", 8443),
        ("bücher。de:8443", 8443),
        ("bücher．de｡", 443),
    ] {
        let out = certtui()
            .args([
                "inspect",
                name,
                "--connect-to",
                &fixture.server.addr().to_string(),
                "--json",
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{name:?}: {}", stderr(&out));
        let report: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(report["target"]["host"], "xn--bcher-kva.de");
        assert_eq!(report["target"]["port"], port);
        assert_eq!(
            fixture.server.last_sni(),
            Observation::Present("xn--bcher-kva.de".to_owned())
        );
    }
}

#[test]
fn quando_tls12_falha_apos_pedir_certificado_deve_relatar_captura_parcial() {
    let fixture = Fixture::start(Behavior::Tls12ClientAuth(vec![0x5A; 37]));
    let report = fixture.json(&[]);
    assert_eq!(report.get("tls"), Some(&Value::Null));
    assert_eq!(
        report["notes"],
        json!([{"kind": "handshake_failed_after_client_cert_request", "peer_ip": "127.0.0.1"}])
    );
    assert_eq!(report["ocsp_staple"], json!({"present": true, "bytes": 37}));
    assert_eq!(report["certificates"].as_array().unwrap().len(), 3);
    for phase in ["connect", "handshake", "total"] {
        assert!(report["timings"][phase].is_u64(), "{phase}");
    }
    assert_eq!(fixture.server.accepted_connections(), 1);
}

#[test]
fn quando_captura_parcial_deve_exibir_nota_em_texto_e_preservar_stdout_de_dados() {
    let fixture = Fixture::start(Behavior::Tls12ClientAuth(vec![0x5A; 37]));
    let notice = "TLS handshake with 127.0.0.1 failed after a client certificate request";
    let text = fixture.run(&["--text"]);
    assert!(text.status.success(), "{}", stderr(&text));
    assert!(stdout(&text).contains(notice));
    let pem = fixture.run(&["--pem"]);
    assert!(pem.status.success(), "{}", stderr(&pem));
    assert!(stderr(&pem).contains(notice));
    let mut expected = String::new();
    for der in fixture.server.presented_chain() {
        expected.push_str("-----BEGIN CERTIFICATE-----\n");
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        for line in encoded.as_bytes().chunks(64) {
            expected.push_str(std::str::from_utf8(line).unwrap());
            expected.push('\n');
        }
        expected.push_str("-----END CERTIFICATE-----\n");
    }
    assert_eq!(stdout(&pem), expected);
    let field = fixture.run(&["--field", "fingerprint.sha256"]);
    assert!(field.status.success(), "{}", stderr(&field));
    assert!(stderr(&field).contains(notice));
    let report = fixture.json(&[]);
    let fingerprint = report["certificates"][0]["fingerprints"]["sha256"]
        .as_str()
        .unwrap();
    assert_eq!(stdout(&field), format!("{fingerprint}\n"));
}
