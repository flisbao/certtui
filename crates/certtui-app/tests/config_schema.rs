//! The JSON Schema of the configuration is generated from the types and
//! published in `docs/config.schema.json`; this test keeps the two together.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;

use certtui_app::config::Config;
use serde_json::Value;

fn schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/config.schema.json")
}

/// The schema of [`Config`], pretty-printed with a final newline.
fn generated() -> String {
    let schema = schemars::schema_for!(Config);
    let mut text = serde_json::to_string_pretty(&schema).unwrap();
    text.push('\n');
    text
}

fn generated_value() -> Value {
    serde_json::from_str(&generated()).unwrap()
}

#[test]
fn quando_tipos_mudam_sem_atualizar_o_schema_deve_falhar() {
    let expected = generated();
    if std::env::var_os("UPDATE_SCHEMA").is_some() {
        std::fs::write(schema_path(), &expected).unwrap();
        return;
    }
    let published = std::fs::read_to_string(schema_path()).unwrap_or_default();
    assert!(
        published == expected,
        "docs/config.schema.json is out of date; run: \
         UPDATE_SCHEMA=1 cargo test -p certtui-app --test config_schema"
    );
}

/// Whether `value` satisfies `schema`: the subset of JSON Schema the
/// generated schema uses (`$ref`, `type`, `const`, `oneOf`, `properties`,
/// `additionalProperties`, `items`, `minimum`).
fn accepts(root: &Value, schema: &Value, value: &Value) -> bool {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        let name = reference.rsplit('/').next().unwrap();
        return accepts(root, &root["$defs"][name], value);
    }
    if let Some(options) = schema.get("oneOf").and_then(Value::as_array) {
        return options.iter().filter(|o| accepts(root, o, value)).count() == 1;
    }
    if let Some(expected) = schema.get("const") {
        return expected == value;
    }
    if let Some(types) = schema.get("type") {
        let names: Vec<&str> = match types {
            Value::String(one) => vec![one.as_str()],
            Value::Array(many) => many.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        let matches_type = |name: &str| match name {
            "string" => value.is_string(),
            "integer" => value.is_u64() || value.is_i64(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            "object" => value.is_object(),
            "array" => value.is_array(),
            _ => false,
        };
        if !names.iter().any(|name| matches_type(name)) {
            return false;
        }
    }
    if let (Some(minimum), Some(number)) = (
        schema.get("minimum").and_then(Value::as_i64),
        value.as_i64(),
    ) && number < minimum
    {
        return false;
    }
    if let Some(object) = value.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        for (key, child) in object {
            match properties.and_then(|p| p.get(key)) {
                Some(child_schema) => {
                    if !accepts(root, child_schema, child) {
                        return false;
                    }
                }
                None => match schema.get("additionalProperties") {
                    Some(Value::Bool(false)) => return false,
                    Some(extra @ Value::Object(_)) if !accepts(root, extra, child) => {
                        return false;
                    }
                    _ => {}
                },
            }
        }
    }
    if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
        return array.iter().all(|item| accepts(root, items, item));
    }
    true
}

#[test]
fn quando_config_default_serializada_deve_validar_contra_o_schema() {
    let schema = generated_value();
    let config = serde_json::to_value(Config::default()).unwrap();
    assert!(accepts(&schema, &schema, &config), "{config}");
    // The validator is not vacuous: it refuses what the schema forbids.
    for bad in [
        r#"{"colour": 1}"#,
        r#"{"ui": {"theme": "neon"}}"#,
        r#"{"network": {"timeout_secs": "20"}}"#,
        r#"{"network": {"timeout_secs": 0}}"#,
        r#"{"limits": {"max_chain_len": 0}}"#,
        r#"{"limits": {"nope": 1}}"#,
        r#"{"trust": {"sources": ["floppy"]}}"#,
    ] {
        let value: Value = serde_json::from_str(bad).unwrap();
        assert!(!accepts(&schema, &schema, &value), "{bad}");
    }
}

#[test]
fn quando_schema_e_runtime_julgam_a_mesma_config_devem_concordar() {
    let schema = generated_value();
    let cases = [
        "{}",
        r#"{"thresholds":{"warn_days":10,"critical_days":3,"fail_on":"warning"}}"#,
        r#"{"network":{"timeout_secs":30,"proxy":"http://p:3128","use_env_proxy":true,"aia":true,"revocation":"full"}}"#,
        r#"{"trust":{"sources":["system","mozilla"],"ca_files":["/etc/ca.pem"]}}"#,
        r#"{"batch":{"concurrency":8}}"#,
        r#"{"limits":{"max_chain_len":12,"max_http_redirects":0}}"#,
        r#"{"ui":{"theme":"mono","mouse":true,"fingerprint_format":"base64","keymap":{"quit":"z"}}}"#,
        r#"{"logging":{"file":"/tmp/x.log","level":"debug"}}"#,
        r#"{"ui":{"theme":"neon"}}"#,
        r#"{"thresholds":{"fail_on":"info"}}"#,
        r#"{"network":{"timeout_secs":0}}"#,
        r#"{"batch":{"concurrency":0}}"#,
        r#"{"limits":{"max_chain_len":0}}"#,
        r#"{"limits":{"max_dir_depth":0}}"#,
        r#"{"limits":{"unknown":1}}"#,
        r#"{"extra":1}"#,
        r#"{"trust":{"sources":["floppy"]}}"#,
        r#"{"logging":{"level":"loud"}}"#,
        r#"{"network":{"revocation":"sometimes"}}"#,
    ];
    for json in cases {
        let value: Value = serde_json::from_str(json).unwrap();
        let by_schema = accepts(&schema, &schema, &value);
        let by_runtime = Config::from_json(json)
            .and_then(|config| config.resolve(&certtui_app::config::CliOverrides::default()))
            .is_ok();
        assert_eq!(
            by_schema, by_runtime,
            "schema and runtime disagree on {json}"
        );
    }
}

/// Follows a `$ref` into `$defs`.
fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let name = reference.rsplit('/').next().unwrap();
            &root["$defs"][name]
        }
        None => schema,
    }
}

#[test]
fn quando_schema_tem_additional_properties_false_em_todos_os_objetos() {
    fn walk(value: &Value, path: &str, found: &mut usize) {
        match value {
            Value::Object(map) => {
                if map.contains_key("properties") && map.get("type") != Some(&Value::from("null")) {
                    assert_eq!(
                        map.get("additionalProperties"),
                        Some(&Value::Bool(false)),
                        "object at {path} accepts unknown fields"
                    );
                    *found += 1;
                }
                for (key, child) in map {
                    walk(child, &format!("{path}/{key}"), found);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    walk(child, &format!("{path}/{index}"), found);
                }
            }
            _ => {}
        }
    }
    let mut found = 0;
    walk(&generated_value(), "#", &mut found);
    // The root plus its seven sections, `limits` included.
    assert!(found >= 8, "only {found} objects with properties");
}

#[test]
fn quando_schema_descreve_limits_deve_listar_todos_os_campos_da_secao_9() {
    let schema = generated_value();
    let limits = resolve(&schema, &schema["properties"]["limits"]);
    let fields = limits["properties"].as_object().unwrap();
    for name in ["max_chain_len", "history_entries", "clipboard_timeout_secs"] {
        assert!(fields.contains_key(name), "{name}");
    }
    assert_eq!(fields.len(), 27);
}

#[test]
fn quando_schema_descreve_zero_deve_recusar_onde_o_runtime_recusa() {
    let schema = generated_value();
    let limits = resolve(&schema, &schema["properties"]["limits"]);
    for (name, field) in limits["properties"].as_object().unwrap() {
        let minimum = field["minimum"].as_u64().unwrap();
        let zero_ok = certtui_app::config::ZERO_ALLOWED_LIMITS.contains(&name.as_str());
        assert_eq!(minimum, u64::from(!zero_ok), "{name}");
    }
    for (section, field) in [("network", "timeout_secs"), ("batch", "concurrency")] {
        let section_schema = resolve(&schema, &schema["properties"][section]);
        assert_eq!(
            section_schema["properties"][field]["minimum"].as_u64(),
            Some(1),
            "{section}.{field}"
        );
    }
}
