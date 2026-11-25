//! End-to-end tests of `certtui inspect` (exit codes, JSON, text, fields).

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use serde_json::Value;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures");

fn certtui() -> Command {
    Command::cargo_bin("certtui").unwrap()
}

fn fixture(name: &str) -> String {
    format!("{FIXTURES}/{name}")
}

/// Drops the validation (`trust` and `findings`) from a `--json` document.
///
/// The verdict depends on the machine's trust store and the findings on the
/// date (a certificate that is about to expire), so the snapshots of the
/// certificate model leave them out; `cli_check.rs` covers validation.
fn without_validation_json(json: &str) -> String {
    let start = json.find("  \"trust\": ").unwrap();
    let end = json.find("  \"certificates\": [").unwrap();
    format!("{}{}", &json[..start], &json[end..])
}

/// Same for `--text`: the validation section closes the document of a local
/// target.
fn without_validation_text(text: &str) -> String {
    let start = text.find("\nTrust: ").unwrap();
    text[..start].to_owned()
}

fn stdout_json(args: &[&str]) -> Value {
    let out = certtui().args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn quando_inspect_pem_deve_sair_0_com_json_valido() {
    let path = fixture("chain-3.pem");
    let json = stdout_json(&["inspect", &path, "--json"]);

    assert_eq!(json["schema_version"], 1);
    let certs = json["certificates"].as_array().unwrap();
    assert_eq!(certs.len(), 3);
    for cert in certs {
        let fps = cert["fingerprints"].as_object().unwrap();
        assert_eq!(fps.len(), 3);
        for alg in ["sha1", "sha256", "sha512"] {
            assert!(fps[alg].as_str().is_some_and(|s| !s.is_empty()), "{alg}");
        }
    }
    assert_eq!(certs[0]["index"], 0);
    assert_eq!(certs[2]["index"], 2);
}

#[test]
fn quando_inspect_json_deve_ter_todas_as_chaves_do_contrato_na_ordem() {
    let out = certtui()
        .args(["inspect", &fixture("chain-3.pem"), "--json"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();

    // Pretty-printed with 2-space indent: top-level keys sit at 2 spaces and
    // the keys of the first certificate at 6.
    assert_keys_in_order(
        &text,
        2,
        &[
            "schema_version",
            "target",
            "notes",
            "trust",
            "findings",
            "certificates",
        ],
    );
    assert_keys_in_order(
        &text,
        6,
        &[
            "index",
            "origin",
            "version",
            "serial",
            "subject",
            "issuer",
            "not_before",
            "not_after",
            "public_key",
            "signature_algorithm",
            "subject_alt_names",
            "basic_constraints",
            "key_usage",
            "extended_key_usage",
            "subject_key_id",
            "authority_key_id",
            "aia",
            "crl_distribution_points",
            "scts",
            "extensions",
            "fingerprints",
        ],
    );
}

/// Asserts each key appears as a member at `indent` spaces, in the given order.
fn assert_keys_in_order(text: &str, indent: usize, keys: &[&str]) {
    let mut from = 0;
    for key in keys {
        let needle = format!("\n{}\"{key}\":", " ".repeat(indent));
        let found = text
            .get(from..)
            .and_then(|rest| rest.find(&needle))
            .unwrap_or_else(|| panic!("key {key} missing or out of order"));
        from += found + needle.len();
    }
}

#[test]
fn quando_inspect_arquivo_inexistente_deve_sair_3() {
    certtui()
        .args(["inspect", "/nonexistent-dir-certtui/missing.pem", "--json"])
        .assert()
        .code(3)
        .stdout("");
}

#[test]
fn quando_arquivo_inexistente_sem_barra_mas_com_extensao_de_cert_deve_sair_3() {
    certtui()
        .args(["inspect", "nonexistent-certtui.pem"])
        .assert()
        .code(3);
}

#[test]
fn quando_alvo_de_rede_e_inalcancavel_deve_sair_3_com_mensagem_curta() {
    // Syntactically valid network targets are no longer usage errors; a
    // closed local port fails fast and offline.
    for target in ["127.0.0.1:1", "localhost:1", "https://127.0.0.1:1/x"] {
        let out = certtui().args(["inspect", target]).output().unwrap();
        assert_eq!(out.status.code(), Some(3), "{target}");
        assert_eq!(out.stdout, Vec::<u8>::new(), "{target}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.starts_with("certtui: connection failed"),
            "{target}: {stderr}"
        );
        assert_eq!(stderr.lines().count(), 1, "{target}: {stderr}");
    }
}

#[test]
fn quando_alvo_de_rede_e_invalido_deve_sair_2_com_mensagem_especifica() {
    for (target, message) in [
        ("http://example.com", "unsupported scheme `http`"),
        ("example.com:99999", "invalid port"),
        ("https://user:pw@example.com", "credentials"),
        ("https://", "empty target"),
    ] {
        let out = certtui().args(["inspect", target]).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{target}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(message), "{target}: {stderr}");
        assert!(!stderr.contains("pw"), "{target}: {stderr}");
    }
}

#[test]
fn quando_stdin_e_texto_sujo_deve_achar_certs() {
    let dirty = std::fs::read(fixture("messy/bundle-mixed.txt")).unwrap();
    let out = certtui()
        .args(["inspect", "-", "--json"])
        .write_stdin(dirty)
        .output()
        .unwrap();
    assert!(out.status.success());
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["target"]["kind"], "stdin");
    assert_eq!(json["certificates"].as_array().unwrap().len(), 3);
}

#[test]
fn quando_texto_sem_cert_deve_sair_3_com_no_certificates_found() {
    let out = certtui()
        .args(["inspect", &fixture("messy/no-certs.txt")])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout, Vec::<u8>::new(), "stdout must stay empty (RF4)");
    assert!(String::from_utf8_lossy(&out.stderr).contains("no certificates found"));
}

#[test]
fn quando_stdin_vazio_deve_sair_3_com_no_certificates_found() {
    let out = certtui()
        .args(["inspect", "-"])
        .write_stdin("")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout, Vec::<u8>::new());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no certificates found"));
}

#[test]
fn quando_field_sha256_deve_imprimir_so_o_valor_com_newline_final() {
    let out = certtui()
        .args(["inspect", &fixture("rsa2048-leaf.pem")])
        .args(["--field", "fingerprint.sha256"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "DD:DB:9B:86:33:47:FC:84:96:10:30:C3:F4:C5:7C:66:CA:BF:92:1E:D4:B4:3A:15:CE:41:B7:9F:39:A6:63:BB\n"
    );
}

#[test]
fn quando_field_pem_deve_imprimir_pem_com_linhas_de_ate_64_colunas() {
    let out = certtui()
        .args(["inspect", &fixture("rsa2048-leaf.pem")])
        .args(["--field", "pem"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert_pem_shape(&text, 1);
}

#[test]
fn quando_field_invalido_deve_sair_2_listando_campos() {
    let out = certtui()
        .args(["inspect", &fixture("rsa2048-leaf.pem")])
        .args(["--field", "nope"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, Vec::<u8>::new());
    let stderr = String::from_utf8_lossy(&out.stderr);
    for field in [
        "subject",
        "issuer",
        "serial",
        "not_before",
        "not_after",
        "sans",
        "fingerprint.sha1",
        "fingerprint.sha256",
        "fingerprint.sha512",
        "pem",
    ] {
        assert!(stderr.contains(field), "{field} missing in: {stderr}");
    }
}

#[test]
fn quando_index_fora_do_intervalo_deve_sair_2() {
    let out = certtui()
        .args(["inspect", &fixture("chain-3.pem")])
        .args(["--field", "subject", "--index", "3"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(out.stdout, Vec::<u8>::new());
    assert!(String::from_utf8_lossy(&out.stderr).contains("out of range"));
}

#[test]
fn quando_index_seleciona_deve_valer_para_field_pem_e_json() {
    let path = fixture("chain-3.pem");
    let field = |index: &str| {
        let out = certtui()
            .args(["inspect", &path, "--field", "serial", "--index", index])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let (s0, s1) = (field("0"), field("1"));
    assert_ne!(s0, s1);

    let json = stdout_json(&["inspect", &path, "--json", "--index", "1"]);
    let certs = json["certificates"].as_array().unwrap();
    assert_eq!(certs.len(), 1);
    assert_eq!(certs[0]["index"], 1);
    assert_eq!(format!("{}\n", certs[0]["serial"].as_str().unwrap()), s1);

    let pem = certtui()
        .args(["inspect", &path, "--pem", "--index", "1"])
        .output()
        .unwrap();
    assert_pem_shape(&String::from_utf8(pem.stdout).unwrap(), 1);
}

#[test]
fn quando_pem_deve_emitir_todos_os_certs_e_reparsear_para_os_mesmos_fingerprints() {
    let path = fixture("chain-3.pem");
    let out = certtui()
        .args(["inspect", &path, "--pem"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let pem = String::from_utf8(out.stdout).unwrap();
    assert_pem_shape(&pem, 3);

    let again = certtui()
        .args(["inspect", "-", "--json"])
        .write_stdin(pem)
        .output()
        .unwrap();
    let json: Value = serde_json::from_slice(&again.stdout).unwrap();
    let original = stdout_json(&["inspect", &path, "--json"]);
    for i in 0..3 {
        assert_eq!(
            json["certificates"][i]["fingerprints"],
            original["certificates"][i]["fingerprints"]
        );
    }
}

#[test]
fn quando_flags_de_saida_conflitam_deve_sair_2() {
    certtui()
        .args(["inspect", &fixture("chain-3.pem"), "--json", "--pem"])
        .assert()
        .code(2);
    certtui()
        .args([
            "inspect",
            &fixture("chain-3.pem"),
            "--json",
            "--field",
            "pem",
        ])
        .assert()
        .code(2);
}

#[test]
fn quando_fingerprint_format_base64_deve_refletir_no_json_e_text() {
    let path = fixture("rsa2048-leaf.pem");
    let json = stdout_json(&["inspect", &path, "--json", "--fingerprint-format", "base64"]);
    let sha256 = json["certificates"][0]["fingerprints"]["sha256"]
        .as_str()
        .unwrap();
    // 32 bytes -> 44 base64 characters ending in a single '='.
    assert_eq!(sha256.len(), 44);
    assert!(sha256.ends_with('='));
    assert!(!sha256.contains(':'));

    let out = certtui()
        .args(["inspect", &path, "--text", "--fingerprint-format", "base64"])
        .output()
        .unwrap();
    assert!(String::from_utf8(out.stdout).unwrap().contains(sha256));

    let hex = stdout_json(&["inspect", &path, "--json", "--fingerprint-format", "hex"]);
    let hex256 = hex["certificates"][0]["fingerprints"]["sha256"]
        .as_str()
        .unwrap();
    assert_eq!(
        hex256,
        "dddb9b863347fc84961030c3f4c57c66cabf921ed4b43a15ce41b79f39a663bb"
    );
}

#[test]
fn quando_cn_tem_esc_deve_sair_sem_bytes_de_controle() {
    let dir = tempdir("esc");
    let path = dir.join("esc.pem");
    std::fs::write(&path, esc_cert_pem()).unwrap();
    let path = path.to_str().unwrap();

    let text = certtui()
        .args(["inspect", path, "--text"])
        .output()
        .unwrap();
    assert!(text.status.success());
    assert!(!text.stdout.contains(&0x1b), "ESC leaked in --text");
    assert!(String::from_utf8_lossy(&text.stdout).contains("31mb"));

    let field = certtui()
        .args(["inspect", path, "--field", "subject"])
        .output()
        .unwrap();
    assert!(field.status.success());
    assert!(!field.stdout.contains(&0x1b), "ESC leaked in --field");
    assert!(String::from_utf8_lossy(&field.stdout).contains("31mb"));

    let json = certtui()
        .args(["inspect", path, "--json"])
        .output()
        .unwrap();
    assert!(!json.stdout.contains(&0x1b), "ESC leaked in --json");
}

#[test]
fn quando_diretorio_deve_inspecionar_os_certs_dos_arquivos() {
    let dir = tempdir("dir");
    std::fs::copy(fixture("rsa2048-leaf.pem"), dir.join("a.pem")).unwrap();
    std::fs::copy(fixture("expired.pem"), dir.join("b.pem")).unwrap();
    let json = stdout_json(&["inspect", dir.to_str().unwrap(), "--json"]);
    assert_eq!(json["target"]["kind"], "directory");
    assert_eq!(json["target"]["recursive"], false);
    assert_eq!(json["certificates"].as_array().unwrap().len(), 2);
}

#[test]
fn quando_messy_bundle_mixed_deve_listar_os_certs_esperados() {
    let expected = std::fs::read_to_string(fixture("messy/expected.tsv")).unwrap();
    let want: usize = expected
        .lines()
        .find(|l| l.starts_with("bundle-mixed.txt"))
        .and_then(|l| l.split('\t').nth(1))
        .unwrap()
        .parse()
        .unwrap();
    let json = stdout_json(&["inspect", &fixture("messy/bundle-mixed.txt"), "--json"]);
    assert_eq!(json["certificates"].as_array().unwrap().len(), want);
}

#[test]
fn quando_s_client_via_stdin_text_deve_mostrar_3_certs_com_3_fingerprints() {
    let input = std::fs::read(fixture("messy/s_client-output.txt")).unwrap();
    let out = certtui()
        .args(["inspect", "-", "--text"])
        .write_stdin(input)
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for header in ["[0] Subject", "[1] Subject", "[2] Subject"] {
        assert!(text.contains(header), "{header}");
    }
    assert!(!text.contains("[3] Subject"));
    for label in ["SHA-1:", "SHA-256:", "SHA-512:"] {
        assert_eq!(text.matches(label).count(), 3, "{label}");
    }
}

#[test]
fn quando_json_do_chain_3_deve_bater_com_snapshot() {
    let out = certtui()
        .current_dir(FIXTURES)
        .args(["inspect", "chain-3.pem", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    insta::assert_snapshot!(
        "inspect_chain3_json",
        without_validation_json(&String::from_utf8(out.stdout).unwrap())
    );
}

#[test]
fn quando_text_do_chain_3_deve_bater_com_snapshot() {
    let out = certtui()
        .current_dir(FIXTURES)
        .args(["inspect", "chain-3.pem", "--text"])
        .output()
        .unwrap();
    assert!(out.status.success());
    insta::assert_snapshot!(
        "inspect_chain3_text",
        without_validation_text(&String::from_utf8(out.stdout).unwrap())
    );
}

#[test]
fn quando_cert_tem_scts_deve_listar_log_id_e_timestamp_no_text() {
    let out = certtui()
        .current_dir(FIXTURES)
        .args(["inspect", "public-leaf-with-sct.pem", "--text"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let scts: Vec<&str> = text
        .lines()
        .filter(|l| l.trim_start().starts_with("SCT "))
        .collect();
    assert_eq!(scts.len(), 2, "{text}");
    for sct in scts {
        // `SCT 1: log <64 hex digits> at <RFC 3339 time> (v1)`
        let rest = sct.split_once(": log ").expect(sct).1;
        let (id, tail) = rest.split_once(" at ").expect(sct);
        assert_eq!(id.len(), 64, "{sct}");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "{sct}");
        assert!(tail.ends_with("(v1)") && tail.contains('T'), "{sct}");
    }
}

#[test]
fn quando_text_de_leaf_com_scts_deve_bater_com_snapshot() {
    let out = certtui()
        .current_dir(FIXTURES)
        .args(["inspect", "public-leaf-with-sct.pem", "--text"])
        .output()
        .unwrap();
    assert!(out.status.success());
    insta::assert_snapshot!(
        "inspect_public_leaf_text",
        without_validation_text(&String::from_utf8(out.stdout).unwrap())
    );
}

#[test]
fn quando_json_do_leaf_publico_com_scts_deve_bater_com_snapshot() {
    let out = certtui()
        .current_dir(FIXTURES)
        .args(["inspect", "public-leaf-with-sct.pem", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success());
    insta::assert_snapshot!(
        "inspect_public_leaf_json",
        without_validation_json(&String::from_utf8(out.stdout).unwrap())
    );
}

#[test]
fn quando_sem_subcomando_deve_sair_2() {
    certtui().assert().code(2);
}

#[test]
fn quando_help_deve_sair_0_no_stdout() {
    let out = certtui().args(["inspect", "--help"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("--fingerprint-format"));
}

/// Asserts `text` is `count` PEM certificate blocks with <= 64-column body lines.
fn assert_pem_shape(text: &str, count: usize) {
    assert!(text.ends_with("-----END CERTIFICATE-----\n"));
    assert_eq!(text.matches("-----BEGIN CERTIFICATE-----\n").count(), count);
    assert_eq!(text.matches("-----END CERTIFICATE-----\n").count(), count);
    let mut body_lines = 0;
    for line in text.lines().filter(|l| !l.starts_with("-----")) {
        assert!(line.len() <= 64, "line too long: {line}");
        body_lines += 1;
    }
    assert!(body_lines >= count);
    // Full lines are exactly 64 columns: only the last line of a block may be short.
    let first_body = text.lines().nth(1).unwrap();
    assert_eq!(first_body.len(), 64);
}

/// A scratch directory removed when dropped, even if the test fails.
struct TempDir(std::path::PathBuf);

impl std::ops::Deref for TempDir {
    type Target = std::path::Path;

    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir(tag: &str) -> TempDir {
    let dir = std::env::temp_dir().join(format!("certtui-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    TempDir(dir)
}

fn esc_cert_pem() -> String {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "a\u{1b}[31mb");
    let key = rcgen::KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().pem()
}

/// `count` distinct self-signed certificates, each as a PEM block.
fn distinct_cert_pems(count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.distinguished_name.push(
                rcgen::DnType::CommonName,
                format!("bulk-{i:03}.example.test"),
            );
            let key = rcgen::KeyPair::generate().unwrap();
            params.self_signed(&key).unwrap().pem()
        })
        .collect()
}

#[test]
fn quando_diretorio_tem_mais_certs_que_max_chain_len_deve_listar_todos() {
    let limits = certtui_domain::limits::Limits::default();
    let count = limits.max_chain_len + 2;
    let dir = tempdir("many-files");
    for (i, pem) in distinct_cert_pems(count).iter().enumerate() {
        std::fs::write(dir.join(format!("c{i:03}.pem")), pem).unwrap();
    }

    let json = stdout_json(&["inspect", dir.to_str().unwrap(), "--json"]);

    assert_eq!(json["certificates"].as_array().unwrap().len(), count);
}

#[test]
fn quando_bundle_pem_tem_mais_certs_que_max_chain_len_deve_listar_todos() {
    let limits = certtui_domain::limits::Limits::default();
    let count = limits.max_chain_len + 2;
    let dir = tempdir("many-bundle");
    let path = dir.join("bundle.pem");
    std::fs::write(&path, distinct_cert_pems(count).concat()).unwrap();

    let json = stdout_json(&["inspect", path.to_str().unwrap(), "--json"]);

    assert_eq!(json["certificates"].as_array().unwrap().len(), count);
}

/// Runs the real loader through `inspect_local` with `max_certs_per_source`.
fn inspect_with_cap(
    src: &certtui_app::ports::LocalSource,
    target: certtui_domain::target::Target,
    cap: usize,
) -> certtui_domain::model::InspectionReport {
    let limits = certtui_domain::limits::Limits {
        max_certs_per_source: cap,
        ..certtui_domain::limits::Limits::default()
    };
    certtui_app::inspect::inspect_local(
        &certtui_infra::source::FsSourceLoader::new(),
        src,
        target,
        &limits,
    )
    .unwrap()
}

#[test]
fn quando_bundle_tem_exatamente_max_certs_per_source_deve_aceitar_sem_nota_de_truncamento() {
    let cap = 12;
    let dir = tempdir("cap-exact");
    let path = dir.join("bundle.pem");
    std::fs::write(&path, distinct_cert_pems(cap).concat()).unwrap();

    let report = inspect_with_cap(
        &certtui_app::ports::LocalSource::File(path.clone()),
        certtui_domain::target::Target::File(path.clone()),
        cap,
    );

    assert_eq!(report.chain.len(), cap);
    assert_eq!(report.notes, Vec::new());
}

#[test]
fn quando_bundle_passa_de_max_certs_per_source_deve_truncar_com_nota() {
    let cap = 12;
    let dir = tempdir("cap-over");
    let path = dir.join("bundle.pem");
    std::fs::write(&path, distinct_cert_pems(cap + 1).concat()).unwrap();

    let report = inspect_with_cap(
        &certtui_app::ports::LocalSource::File(path.clone()),
        certtui_domain::target::Target::File(path.clone()),
        cap,
    );

    assert_eq!(report.chain.len(), cap);
    assert_eq!(
        report.notes,
        vec![certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: cap }]
    );
}

#[test]
fn quando_diretorio_passa_de_max_certs_per_source_deve_truncar_com_nota() {
    let cap = 12;
    let dir = tempdir("cap-dir");
    for (i, pem) in distinct_cert_pems(cap + 1).iter().enumerate() {
        std::fs::write(dir.join(format!("c{i:03}.pem")), pem).unwrap();
    }

    let report = inspect_with_cap(
        &certtui_app::ports::LocalSource::Directory {
            path: dir.to_path_buf(),
            recursive: false,
        },
        certtui_domain::target::Target::Directory {
            path: dir.to_path_buf(),
            recursive: false,
        },
        cap,
    );

    assert_eq!(report.chain.len(), cap);
    assert_eq!(
        report.notes,
        vec![certtui_domain::model::LoadNote::TruncatedAtCertLimit { limit: cap }]
    );
}

#[test]
fn quando_diretorio_tem_arquivo_sem_candidatos_deve_nomear_o_arquivo_no_json_e_no_texto() {
    let dir = tempdir("dir-notes");
    std::fs::copy(fixture("rsa2048-leaf.pem"), dir.join("a.pem")).unwrap();
    std::fs::write(dir.join("prose.txt"), "only prose here\n").unwrap();
    std::fs::write(dir.join("store.jks"), [0xFE, 0xED, 0xFE, 0xED, 0, 2]).unwrap();
    let path = dir.to_str().unwrap();

    let json = stdout_json(&["inspect", path, "--json"]);
    assert_eq!(json["schema_version"], 1);
    let notes = json["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0]["kind"], "no_candidates");
    assert_eq!(notes[0]["path"], "prose.txt");
    assert_eq!(notes[1]["kind"], "unsupported_format");
    assert_eq!(notes[1]["path"], "store.jks");

    let out = certtui()
        .args(["inspect", path, "--text"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("prose.txt: no certificate candidates found"));
    assert!(text.contains("store.jks: unsupported format"));
}

#[test]
fn quando_diretorio_tem_varios_arquivos_deve_listar_em_ordem_de_nome() {
    let dir = tempdir("dir-order");
    let pems = distinct_cert_pems(4);
    for (name, pem) in ["d.pem", "b.pem", "a.pem", "c.pem"].iter().zip(&pems) {
        std::fs::write(dir.join(name), pem).unwrap();
    }
    let json = stdout_json(&["inspect", dir.to_str().unwrap(), "--json"]);
    let origins: Vec<String> = json["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|cert| {
            let path = cert["origin"]["path"].as_str().unwrap();
            path.rsplit('/').next().unwrap().to_owned()
        })
        .collect();
    assert_eq!(origins, ["a.pem", "b.pem", "c.pem", "d.pem"]);
}

#[cfg(unix)]
#[test]
fn quando_diretorio_alvo_e_symlink_deve_sair_3_dizendo_que_nao_segue() {
    let dir = tempdir("dir-link");
    let real = dir.join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::copy(fixture("rsa2048-leaf.pem"), real.join("a.pem")).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let out = certtui()
        .args(["inspect", link.to_str().unwrap()])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("symlinked directories are not followed"),
        "{stderr}"
    );
    assert!(!stderr.contains("no certificates found"), "{stderr}");
}

#[test]
fn quando_texto_comeca_com_0x30_e_tem_pem_deve_achar_o_certificado() {
    let mut input = b"09:15:02 INFO starting\n".to_vec();
    input.extend(std::fs::read(fixture("rsa2048-leaf.pem")).unwrap());
    let out = certtui()
        .args(["inspect", "-", "--json"])
        .write_stdin(input)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["certificates"].as_array().unwrap().len(), 1);
}
