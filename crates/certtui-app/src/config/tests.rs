//! Tests of the configuration types, defaults and precedence.

use std::path::PathBuf;
use std::time::Duration;

use certtui_domain::limits::{Limits, LimitsOverrides};

use super::*;
use crate::check::FailOn;
use crate::trust::TrustSource;

fn parse_ok(json: &str) -> Config {
    Config::from_json(json).unwrap_or_else(|e| panic!("config should parse: {e}"))
}

fn resolve(config: Config, flags: &CliOverrides) -> ResolvedConfig {
    config
        .resolve(flags)
        .unwrap_or_else(|e| panic!("config should resolve: {e}"))
}

#[test]
fn quando_config_e_default_deve_bater_com_a_secao_11() {
    let spec = serde_json::json!({
        "schema_version": 1,
        "trust": { "sources": ["system"], "ca_files": [] },
        "thresholds": { "warn_days": 30, "critical_days": 7, "fail_on": "error" },
        "network": {
            "timeout_secs": 20, "proxy": null, "use_env_proxy": false,
            "aia": false, "revocation": "leaf"
        },
        "batch": { "concurrency": 32 },
        "limits": {},
        "ui": {
            "theme": "dark", "keymap": {}, "mouse": false,
            "fingerprint_format": "colon",
            "clipboard": "auto"
        },
        "logging": { "file": null, "level": "info" }
    });
    let actual = serde_json::to_value(Config::default()).unwrap();
    // `limits` serializes its unset overrides as nulls; the spec shows `{}`.
    let mut actual = actual;
    actual["limits"] = serde_json::json!({});
    assert_eq!(actual, spec);
}

#[test]
fn quando_json_do_exemplo_da_secao_11_deve_carregar_igual_ao_default() {
    let json = r#"{
        "schema_version": 1,
        "trust": { "sources": ["system"], "ca_files": [] },
        "thresholds": { "warn_days": 30, "critical_days": 7, "fail_on": "error" },
        "network": { "timeout_secs": 20, "proxy": null, "use_env_proxy": false,
                     "aia": false, "revocation": "leaf" },
        "batch": { "concurrency": 32 },
        "limits": {},
        "ui": { "theme": "dark", "keymap": {}, "mouse": false,
                "fingerprint_format": "colon", "clipboard": "auto" },
        "logging": { "file": null, "level": "info" }
    }"#;
    assert_eq!(parse_ok(json), Config::default());
}

#[test]
fn quando_json_e_vazio_objeto_deve_usar_todos_os_padroes() {
    assert_eq!(parse_ok("{}"), Config::default());
}

#[test]
fn quando_flag_e_config_conflitam_deve_vencer_a_flag() {
    let config = parse_ok(
        r#"{"thresholds":{"warn_days":10,"fail_on":"warning"},
            "network":{"timeout_secs":40,"proxy":"http://cfg:3128","aia":false,"revocation":"full"},
            "trust":{"sources":["mozilla"]},
            "batch":{"concurrency":8},
            "logging":{"file":"/tmp/cfg.log"}}"#,
    );
    let flags = CliOverrides {
        trust_sources: vec![TrustSource::Custom],
        warn_days: Some(99),
        fail_on: Some(FailOn::Error),
        timeout_secs: Some(60),
        proxy: Some("http://flag:3128".to_owned()),
        aia: Some(true),
        revocation: Some(RevocationMode::Off),
        concurrency: Some(4),
        log_file: Some(PathBuf::from("/tmp/flag.log")),
        ..CliOverrides::default()
    };
    let r = resolve(config, &flags);
    assert_eq!(r.trust_sources, vec![TrustSource::Custom]);
    assert_eq!(r.thresholds.warn_days, 99);
    assert_eq!(r.thresholds.fail_on, FailOn::Error);
    assert_eq!(r.limits.target_total_timeout, Duration::from_secs(60));
    assert_eq!(r.proxy.as_deref(), Some("http://flag:3128"));
    assert!(r.aia);
    assert_eq!(r.revocation, RevocationMode::Off);
    assert_eq!(r.limits.batch_concurrency, 4);
    assert_eq!(r.log_file, Some(PathBuf::from("/tmp/flag.log")));
}

#[test]
fn quando_config_define_e_flag_ausente_deve_usar_config() {
    let config = parse_ok(
        r#"{"thresholds":{"warn_days":10,"critical_days":3,"fail_on":"warning"},
            "network":{"timeout_secs":40,"proxy":"http://cfg:3128","aia":true,"revocation":"full"},
            "trust":{"sources":["mozilla","custom"],"ca_files":["/etc/ca.pem"]},
            "batch":{"concurrency":8},
            "ui":{"theme":"mono","mouse":true,"fingerprint_format":"hex","clipboard":"osc52,native"},
            "logging":{"file":"/tmp/cfg.log","level":"debug"}}"#,
    );
    let r = resolve(config, &CliOverrides::default());
    assert_eq!(
        r.trust_sources,
        vec![TrustSource::Mozilla, TrustSource::Custom]
    );
    assert_eq!(r.ca_files, vec![PathBuf::from("/etc/ca.pem")]);
    assert_eq!(r.thresholds.warn_days, 10);
    assert_eq!(r.thresholds.critical_days, 3);
    assert_eq!(r.thresholds.fail_on, FailOn::Warning);
    assert_eq!(r.limits.target_total_timeout, Duration::from_secs(40));
    assert_eq!(r.proxy.as_deref(), Some("http://cfg:3128"));
    assert!(r.aia);
    assert_eq!(r.revocation, RevocationMode::Full);
    assert_eq!(r.limits.batch_concurrency, 8);
    assert_eq!(r.ui.theme, Theme::Mono);
    assert!(r.ui.mouse);
    assert_eq!(r.ui.fingerprint_format, FingerprintFormatConfig::Hex);
    assert_eq!(r.ui.clipboard, "osc52,native");
    assert_eq!(r.log_file, Some(PathBuf::from("/tmp/cfg.log")));
    assert_eq!(r.log_level, LogLevel::Debug);
}

#[test]
fn quando_ca_files_da_flag_e_da_config_existem_deve_somar_as_duas() {
    let config = parse_ok(r#"{"trust":{"ca_files":["/etc/a.pem"]}}"#);
    let flags = CliOverrides {
        ca_files: vec![PathBuf::from("/etc/b.pem")],
        ..CliOverrides::default()
    };
    let r = resolve(config, &flags);
    assert_eq!(
        r.ca_files,
        vec![PathBuf::from("/etc/a.pem"), PathBuf::from("/etc/b.pem")]
    );
}

#[test]
fn quando_limits_acima_do_teto_deve_truncar_e_gerar_aviso() {
    let config = parse_ok(r#"{"limits":{"max_chain_len":999,"dns_timeout_secs":7}}"#);
    let r = resolve(config, &CliOverrides::default());
    assert_eq!(r.limits.max_chain_len, Limits::HARD_CAPS.max_chain_len);
    assert_eq!(r.limits.dns_timeout, Duration::from_secs(7));
    assert_eq!(r.limit_warnings.len(), 1);
    let warning = r.limit_warnings.first().unwrap();
    assert_eq!(warning.field, "max_chain_len");
    assert_eq!(warning.requested, 999);
}

#[test]
fn quando_limits_tem_zero_invalido_deve_dar_invalid_value_com_campo() {
    let config = parse_ok(r#"{"limits":{"max_chain_len":0}}"#);
    let error = config.resolve(&CliOverrides::default()).unwrap_err();
    match error {
        ConfigError::InvalidValue { field, .. } => assert_eq!(field, "limits.max_chain_len"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_limits_e_network_definem_o_mesmo_teto_deve_vencer_limits() {
    let config = parse_ok(
        r#"{"network":{"timeout_secs":40},"limits":{"target_total_timeout_secs":50},
            "batch":{"concurrency":8}}"#,
    );
    let r = resolve(config, &CliOverrides::default());
    assert_eq!(r.limits.target_total_timeout, Duration::from_secs(50));
}

#[test]
fn quando_timeout_acima_do_teto_deve_truncar_e_gerar_aviso() {
    let config = parse_ok(r#"{"network":{"timeout_secs":9999}}"#);
    let r = resolve(config, &CliOverrides::default());
    assert_eq!(
        r.limits.target_total_timeout,
        Limits::HARD_CAPS.target_total_timeout
    );
    assert!(
        r.limit_warnings
            .iter()
            .any(|w| w.field == "target_total_timeout_secs")
    );
}

#[test]
fn quando_schema_version_e_futura_deve_dar_unsupported_schema_version() {
    let error = Config::from_json(r#"{"schema_version": 2}"#).unwrap_err();
    assert_eq!(error, ConfigError::UnsupportedSchemaVersion(2));
}

#[test]
fn quando_schema_version_e_zero_deve_dar_unsupported_schema_version() {
    let error = Config::from_json(r#"{"schema_version": 0}"#).unwrap_err();
    assert_eq!(error, ConfigError::UnsupportedSchemaVersion(0));
}

#[test]
fn quando_fail_on_invalido_deve_dar_invalid_value_com_campo() {
    let error = Config::from_json(r#"{"thresholds":{"fail_on":"nope"}}"#).unwrap_err();
    match error {
        ConfigError::InvalidValue { field, message } => {
            assert_eq!(field, "thresholds.fail_on");
            assert!(message.contains("nope"), "message: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_tipo_esta_errado_deve_citar_o_campo() {
    let error = Config::from_json(r#"{"network":{"timeout_secs":"vinte"}}"#).unwrap_err();
    match error {
        ConfigError::InvalidValue { field, .. } => assert_eq!(field, "network.timeout_secs"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_campo_e_desconhecido_deve_citar_campo_e_linha() {
    let json = "{\n  \"ui\": {\n    \"theme\": \"dark\",\n    \"colour\": 1\n  }\n}";
    let error = Config::from_json(json).unwrap_err();
    match error {
        ConfigError::UnknownField { field, line } => {
            assert_eq!(field, "ui.colour");
            assert_eq!(line, 4);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_secao_de_topo_e_desconhecida_deve_citar_o_nome() {
    let error = Config::from_json(r#"{"proxy": "x"}"#).unwrap_err();
    match error {
        ConfigError::UnknownField { field, .. } => assert_eq!(field, "proxy"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_json_tem_comentario_deve_dar_syntax_com_linha() {
    let error = Config::from_json("{\n  // nope\n  \"ui\": {}\n}").unwrap_err();
    match error {
        ConfigError::Syntax { line, .. } => assert_eq!(line, 2),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_json_tem_virgula_sobrando_deve_dar_syntax_com_linha_e_coluna() {
    let error = Config::from_json("{\n  \"ui\": {},\n}").unwrap_err();
    match error {
        ConfigError::Syntax { line, column, .. } => {
            assert_eq!(line, 3);
            assert!(column >= 1);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_clipboard_e_invalido_deve_dar_invalid_value_com_campo() {
    let config = parse_ok(r#"{"ui":{"clipboard":"magic"}}"#);
    let error = config.resolve(&CliOverrides::default()).unwrap_err();
    match error {
        ConfigError::InvalidValue { field, .. } => assert_eq!(field, "ui.clipboard"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_clipboard_e_lista_valida_deve_aceitar_a_ordem_dada() {
    for value in [
        "auto",
        "off",
        "osc52",
        "native",
        "osc52,native",
        "native,osc52",
    ] {
        let config = parse_ok(&format!(r#"{{"ui":{{"clipboard":"{value}"}}}}"#));
        let r = resolve(config, &CliOverrides::default());
        assert_eq!(r.ui.clipboard, value);
    }
}

#[test]
fn quando_clipboard_repete_estrategia_deve_dar_invalid_value() {
    let config = parse_ok(r#"{"ui":{"clipboard":"native,native"}}"#);
    assert!(config.resolve(&CliOverrides::default()).is_err());
}

#[test]
fn quando_nivel_de_log_e_invalido_deve_dar_invalid_value_com_campo() {
    let error = Config::from_json(r#"{"logging":{"level":"loud"}}"#).unwrap_err();
    match error {
        ConfigError::InvalidValue { field, .. } => assert_eq!(field, "logging.level"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_erro_de_config_e_exibido_deve_conter_campo_e_linha() {
    let error = Config::from_json("{\n \"ui\": {\"colour\": 1}\n}").unwrap_err();
    let text = error.to_string();
    assert!(text.contains("ui.colour"), "{text}");
    assert!(text.contains("line 2"), "{text}");
}

#[test]
fn quando_clipboard_tem_espaco_na_lista_deve_dar_invalid_value() {
    // The TUI parses the exact spelling, so the config must agree.
    let config = parse_ok(r#"{"ui":{"clipboard":"osc52, native"}}"#);
    let error = config.resolve(&CliOverrides::default()).unwrap_err();
    match error {
        ConfigError::InvalidValue { field, .. } => assert_eq!(field, "ui.clipboard"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn quando_timeout_ou_concorrencia_sao_zero_deve_citar_o_campo_que_o_usuario_escreveu() {
    for (json, field) in [
        (r#"{"network":{"timeout_secs":0}}"#, "network.timeout_secs"),
        (r#"{"batch":{"concurrency":0}}"#, "batch.concurrency"),
    ] {
        let error = parse_ok(json)
            .resolve(&CliOverrides::default())
            .unwrap_err();
        match error {
            ConfigError::InvalidValue { field: got, .. } => assert_eq!(got, field, "{json}"),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn quando_limite_e_zero_deve_aceitar_so_onde_o_zero_tem_sentido() {
    let names: Vec<String> = serde_json::to_value(LimitsOverrides::default())
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(names.len(), 27);
    for name in names {
        let config = parse_ok(&format!(r#"{{"limits":{{"{name}":0}}}}"#));
        let accepted = config.resolve(&CliOverrides::default()).is_ok();
        assert_eq!(
            accepted,
            ZERO_ALLOWED_LIMITS.contains(&name.as_str()),
            "{name}"
        );
    }
}

#[test]
fn quando_no_proxy_na_linha_de_comando_deve_ignorar_proxy_da_config_e_do_ambiente() {
    let config = parse_ok(r#"{"network":{"proxy":"http://p:3128","use_env_proxy":true}}"#);
    let flags = CliOverrides {
        no_proxy: true,
        ..CliOverrides::default()
    };
    let r = resolve(config, &flags);
    assert_eq!(r.proxy, None);
    assert!(!r.use_env_proxy);
}

#[test]
fn quando_no_aia_na_linha_de_comando_deve_vencer_a_config() {
    let config = parse_ok(r#"{"network":{"aia":true}}"#);
    let flags = CliOverrides {
        aia: Some(false),
        ..CliOverrides::default()
    };
    assert!(!resolve(config, &flags).aia);
}

#[test]
fn quando_campo_ou_valor_sao_enormes_o_erro_deve_continuar_curto() {
    let huge = "x".repeat(100_000);
    for json in [
        format!(r#"{{"ui":{{"{huge}":1}}}}"#),
        format!(r#"{{"{huge}":1}}"#),
        format!(r#"{{"thresholds":{{"fail_on":"{huge}"}}}}"#),
        format!(r#"{{"ui":{{"theme":"{huge}"}}}}"#),
    ] {
        let error = Config::from_json(&json).unwrap_err();
        let text = error.to_string();
        assert!(text.len() < 600, "{} bytes: {}", text.len(), &text[..80]);
    }
}
