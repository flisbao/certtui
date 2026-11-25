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

#[test]
fn quando_config_default_serializada_deve_validar_contra_o_schema() {
    let schema = generated_value();
    let config = serde_json::to_value(Config::default()).unwrap();
    let properties = schema["properties"].as_object().unwrap();
    let mut top_level: Vec<&String> = config.as_object().unwrap().keys().collect();
    let mut declared: Vec<&String> = properties.keys().collect();
    top_level.sort();
    declared.sort();
    assert_eq!(top_level, declared);
    // Every section of the default config has the keys the schema declares.
    for (section, value) in config.as_object().unwrap() {
        let Some(fields) = value.as_object() else {
            continue;
        };
        let section_schema = resolve(&schema, &properties[section]);
        let declared = section_schema["properties"].as_object().unwrap();
        for key in fields.keys() {
            assert!(
                declared.contains_key(key),
                "{section}.{key} missing from the schema"
            );
        }
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
