//! Types, defaults, parsing with precise errors, and the precedence
//! flags > config > defaults.

use std::collections::BTreeMap;
use std::path::PathBuf;

use certtui_domain::limits::{LimitWarning, Limits, LimitsOverrides};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::check::FailOn;
use crate::trust::TrustSource;

/// The only `schema_version` this build understands.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Why the configuration could not be used. Every variant that points at the
/// file carries the field or the position, so the message is actionable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The file is larger than the configuration size limit.
    #[error("config file too large (limit {limit} bytes)")]
    TooLarge {
        /// The size limit in bytes.
        limit: usize,
    },
    /// The file could not be read.
    #[error("cannot read config file: {0}")]
    Io(String),
    /// The text is not valid JSON (comments and trailing commas included).
    #[error("config syntax error at line {line}, column {column}: {message}")]
    Syntax {
        /// 1-based line of the error.
        line: usize,
        /// 1-based column of the error.
        column: usize,
        /// What the parser reported.
        message: String,
    },
    /// A field that the schema does not define.
    #[error("config has an unknown field `{field}` (line {line})")]
    UnknownField {
        /// Dotted path of the field, e.g. `ui.colour`.
        field: String,
        /// 1-based line where the parser stopped.
        line: usize,
    },
    /// A field with a value of the wrong type or outside its domain.
    #[error("config field `{field}` is invalid: {message}")]
    InvalidValue {
        /// Dotted path of the field, e.g. `thresholds.fail_on`.
        field: String,
        /// What is wrong with the value.
        message: String,
    },
    /// `schema_version` is not the one this build reads.
    #[error(
        "config schema_version {0} is not supported (this build reads version \
         {SUPPORTED_SCHEMA_VERSION})"
    )]
    UnsupportedSchemaVersion(u32),
}

/// Loads the configuration from wherever it lives.
pub trait ConfigRepository: Send + Sync {
    /// The configuration; an absent file yields the defaults.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] naming the field or the position when the
    /// file is unreadable or invalid.
    fn load(&self) -> Result<Config, ConfigError>;
}

/// Revocation checking mode (`network.revocation`, `--revocation`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RevocationMode {
    /// Only the leaf certificate.
    #[default]
    Leaf,
    /// The leaf and every intermediate.
    Full,
    /// No revocation request is made.
    Off,
}

/// Color theme (`ui.theme`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Light text on a dark background.
    #[default]
    Dark,
    /// Dark text on a light background.
    Light,
    /// No colors.
    Mono,
}

/// Fingerprint display format (`ui.fingerprint_format`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum FingerprintFormatConfig {
    /// Upper-case hex pairs separated by colons.
    #[default]
    Colon,
    /// Lower-case hex without separators.
    Hex,
    /// Standard base64.
    Base64,
}

/// Log verbosity (`logging.level`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Nothing is logged.
    Off,
    /// Errors only.
    Error,
    /// Errors and warnings.
    Warn,
    /// Normal operation (the default).
    #[default]
    Info,
    /// Diagnostic detail.
    Debug,
    /// Everything, still without secrets.
    Trace,
}

/// `trust` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct TrustConfig {
    /// Trust sources, in order.
    pub sources: Vec<TrustSource>,
    /// CA certificate files, in any format `inspect` reads.
    pub ca_files: Vec<PathBuf>,
}

impl Default for TrustConfig {
    fn default() -> Self {
        Self {
            sources: vec![TrustSource::System],
            ca_files: Vec::new(),
        }
    }
}

/// `thresholds` section; also the resolved form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct ThresholdsConfig {
    /// Warn when a certificate expires within this many days.
    pub warn_days: u32,
    /// Report an error when a certificate expires within this many days.
    pub critical_days: u32,
    /// Lowest severity that makes `check` fail.
    pub fail_on: FailOn,
}

impl Default for ThresholdsConfig {
    fn default() -> Self {
        Self {
            warn_days: 30,
            critical_days: 7,
            fail_on: FailOn::Error,
        }
    }
}

/// `network` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkConfig {
    /// Overall time limit for one target, in seconds (at least 1).
    #[schemars(range(min = 1))]
    pub timeout_secs: u64,
    /// `http://host:port` CONNECT proxy.
    pub proxy: Option<String>,
    /// Read `HTTPS_PROXY` and `NO_PROXY` from the environment.
    pub use_env_proxy: bool,
    /// Download missing intermediates from their AIA URLs.
    pub aia: bool,
    /// Revocation checking mode.
    pub revocation: RevocationMode,
}

/// The limit overrides where `0` is meaningful (no redirects, no recursion);
/// every other one must be at least 1. The JSON Schema says the same.
pub const ZERO_ALLOWED_LIMITS: [&str; 2] = ["max_http_redirects", "max_dir_depth"];

/// Default of `network.timeout_secs`, equal to the default
/// [`Limits::target_total_timeout`].
const DEFAULT_TIMEOUT_SECS: u64 = 20;

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            proxy: None,
            use_env_proxy: false,
            aia: false,
            revocation: RevocationMode::Leaf,
        }
    }
}

/// `batch` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct BatchConfig {
    /// Targets inspected at the same time (at least 1).
    #[schemars(range(min = 1))]
    pub concurrency: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self { concurrency: 32 }
    }
}

/// `ui` section; also the resolved form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct UiConfig {
    /// Color theme.
    pub theme: Theme,
    /// Key remapping: action name to key.
    pub keymap: BTreeMap<String, String>,
    /// Enable mouse support.
    pub mouse: bool,
    /// Fingerprint display format.
    pub fingerprint_format: FingerprintFormatConfig,
    /// Clipboard strategy: `auto`, `off` or an ordered list of `osc52` and
    /// `native`.
    pub clipboard: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            keymap: BTreeMap::new(),
            mouse: false,
            fingerprint_format: FingerprintFormatConfig::Colon,
            clipboard: "auto".to_owned(),
        }
    }
}

/// `logging` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    /// Log file; without one nothing is logged.
    pub file: Option<PathBuf>,
    /// Log verbosity.
    pub level: LogLevel,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            file: None,
            level: LogLevel::Info,
        }
    }
}

/// The schema of `limits`: every override of [`LimitsOverrides`] is an optional
/// whole number. The field names come from the type itself, so the schema
/// cannot drift from it (the type lives in the domain, which does not know
/// `schemars`).
fn limits_schema(_: &mut SchemaGenerator) -> Schema {
    let names: Vec<String> = serde_json::to_value(LimitsOverrides::default())
        .ok()
        .and_then(|value| match value {
            Value::Object(map) => Some(map.keys().cloned().collect()),
            _ => None,
        })
        .unwrap_or_default();
    let properties: serde_json::Map<String, Value> = names
        .into_iter()
        .map(|name| {
            let minimum = u8::from(!ZERO_ALLOWED_LIMITS.contains(&name.as_str()));
            (
                name,
                serde_json::json!({ "type": ["integer", "null"], "minimum": minimum }),
            )
        })
        .collect();
    Schema::try_from(serde_json::json!({
        "type": "object",
        "description": "Resource limit overrides (spec section 9); above the hard cap they are truncated.",
        "properties": properties,
        "additionalProperties": false,
    }))
    .unwrap_or_default()
}

/// The configuration file (spec section 11).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Version of this schema.
    pub schema_version: u32,
    /// Trust sources.
    pub trust: TrustConfig,
    /// Expiry thresholds and failure policy.
    pub thresholds: ThresholdsConfig,
    /// Network behavior.
    pub network: NetworkConfig,
    /// Batch behavior.
    pub batch: BatchConfig,
    /// Resource limit overrides (spec section 9).
    #[schemars(schema_with = "limits_schema")]
    pub limits: LimitsOverrides,
    /// Interface settings.
    pub ui: UiConfig,
    /// Logging settings.
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            trust: TrustConfig::default(),
            thresholds: ThresholdsConfig::default(),
            network: NetworkConfig::default(),
            batch: BatchConfig::default(),
            limits: LimitsOverrides::default(),
            ui: UiConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Values given on the command line; `None` or empty means "not given".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOverrides {
    /// `--trust`; replaces `trust.sources` when not empty.
    pub trust_sources: Vec<TrustSource>,
    /// `--ca-file`; added to `trust.ca_files`.
    pub ca_files: Vec<PathBuf>,
    /// `--warn-days`.
    pub warn_days: Option<u32>,
    /// `--critical-days`.
    pub critical_days: Option<u32>,
    /// `--fail-on`.
    pub fail_on: Option<FailOn>,
    /// `--timeout`, in seconds.
    pub timeout_secs: Option<u64>,
    /// `--proxy`.
    pub proxy: Option<String>,
    /// `--no-proxy`: no proxy at all, whatever the config or the environment say.
    pub no_proxy: bool,
    /// `--aia`.
    pub aia: Option<bool>,
    /// `--revocation` / `--no-revocation`.
    pub revocation: Option<RevocationMode>,
    /// `--concurrency`.
    pub concurrency: Option<u64>,
    /// `--fingerprint-format`.
    pub fingerprint_format: Option<FingerprintFormatConfig>,
    /// `--log-file`.
    pub log_file: Option<PathBuf>,
}

/// The configuration after flags, config and defaults are merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    /// Trust sources, in order.
    pub trust_sources: Vec<TrustSource>,
    /// CA certificate files: the config's, then the flags'.
    pub ca_files: Vec<PathBuf>,
    /// Expiry thresholds and failure policy.
    pub thresholds: ThresholdsConfig,
    /// Effective resource limits.
    pub limits: Limits,
    /// Overrides that exceeded a hard cap and were truncated; to be logged.
    pub limit_warnings: Vec<LimitWarning>,
    /// The CONNECT proxy, if any.
    pub proxy: Option<String>,
    /// Read the proxy variables from the environment.
    pub use_env_proxy: bool,
    /// Download missing intermediates from their AIA URLs.
    pub aia: bool,
    /// Revocation checking mode.
    pub revocation: RevocationMode,
    /// Interface settings.
    pub ui: UiConfig,
    /// Log file; without one nothing is logged.
    pub log_file: Option<PathBuf>,
    /// Log verbosity.
    pub log_level: LogLevel,
}

impl Config {
    /// Parses the text of a configuration file.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Syntax`] with line and column for malformed JSON,
    /// [`ConfigError::UnknownField`] and [`ConfigError::InvalidValue`] with
    /// the dotted field path, and [`ConfigError::UnsupportedSchemaVersion`].
    pub fn from_json(text: &str) -> Result<Config, ConfigError> {
        let config = match serde_json::from_str::<Config>(text) {
            Ok(config) => config,
            Err(error) => return Err(classify(text, &error)),
        };
        config.check_version()?;
        Ok(config)
    }

    fn check_version(&self) -> Result<(), ConfigError> {
        if self.schema_version == SUPPORTED_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(ConfigError::UnsupportedSchemaVersion(self.schema_version))
        }
    }

    /// Merges `flags` over `self` (flags > config > defaults) and applies the
    /// resource limits.
    ///
    /// Two settings can be given in more than one place; the more specific
    /// source wins after the flag: `limits.target_total_timeout_secs` over
    /// `network.timeout_secs`, and `limits.batch_concurrency` over
    /// `batch.concurrency`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::InvalidValue`] for a zero limit, a malformed
    /// `ui.clipboard` or an unsupported `schema_version`.
    pub fn resolve(self, flags: &CliOverrides) -> Result<ResolvedConfig, ConfigError> {
        self.check_version()?;
        validate_clipboard(&self.ui.clipboard)?;
        // Checked here, not left to the limit they feed, so the error names
        // the field the user wrote.
        for (field, value) in [
            ("network.timeout_secs", self.network.timeout_secs),
            ("batch.concurrency", self.batch.concurrency),
        ] {
            if value == 0 {
                return Err(ConfigError::InvalidValue {
                    field: field.to_owned(),
                    message: "must be at least 1".to_owned(),
                });
            }
        }

        let mut overrides = self.limits.clone();
        overrides.target_total_timeout_secs = flags
            .timeout_secs
            .or(overrides.target_total_timeout_secs)
            .or(Some(self.network.timeout_secs));
        overrides.batch_concurrency = flags
            .concurrency
            .or(overrides.batch_concurrency)
            .or(Some(self.batch.concurrency));
        let (limits, limit_warnings) =
            Limits::default()
                .with_overrides(&overrides)
                .map_err(|error| match error {
                    certtui_domain::limits::LimitsError::ZeroNotAllowed { field } => {
                        ConfigError::InvalidValue {
                            field: format!("limits.{field}"),
                            message: "must not be zero".to_owned(),
                        }
                    }
                })?;

        let trust_sources = if flags.trust_sources.is_empty() {
            self.trust.sources
        } else {
            flags.trust_sources.clone()
        };
        let mut ca_files = self.trust.ca_files;
        ca_files.extend(flags.ca_files.iter().cloned());

        let mut ui = self.ui;
        if let Some(format) = flags.fingerprint_format {
            ui.fingerprint_format = format;
        }

        Ok(ResolvedConfig {
            trust_sources,
            ca_files,
            thresholds: ThresholdsConfig {
                warn_days: flags.warn_days.unwrap_or(self.thresholds.warn_days),
                critical_days: flags.critical_days.unwrap_or(self.thresholds.critical_days),
                fail_on: flags.fail_on.unwrap_or(self.thresholds.fail_on),
            },
            limits,
            limit_warnings,
            proxy: if flags.no_proxy {
                None
            } else {
                flags.proxy.clone().or(self.network.proxy)
            },
            use_env_proxy: self.network.use_env_proxy && !flags.no_proxy,
            aia: flags.aia.unwrap_or(self.network.aia),
            revocation: flags.revocation.unwrap_or(self.network.revocation),
            ui,
            log_file: flags.log_file.clone().or(self.logging.file),
            log_level: self.logging.level,
        })
    }
}

/// Checks the shape of `ui.clipboard`: `auto`, `off`, or a list of distinct
/// `osc52` / `native` entries (the order is the order of attempts).
fn validate_clipboard(value: &str) -> Result<(), ConfigError> {
    let invalid = |message: &str| ConfigError::InvalidValue {
        field: "ui.clipboard".to_owned(),
        message: message.to_owned(),
    };
    if value == "auto" || value == "off" {
        return Ok(());
    }
    let mut seen: Vec<&str> = Vec::new();
    for part in value.split(',') {
        if part != "osc52" && part != "native" {
            return Err(invalid(
                "expected `auto`, `off` or a list of `osc52` and `native`",
            ));
        }
        if seen.contains(&part) {
            return Err(invalid("a strategy is listed twice"));
        }
        seen.push(part);
    }
    Ok(())
}

/// Turns a `serde_json` failure into a [`ConfigError`] that names the field.
fn classify(text: &str, error: &serde_json::Error) -> ConfigError {
    use serde_json::error::Category;

    let (message, _) = split_position(&error.to_string());
    match error.classify() {
        Category::Data => {
            let field = locate_field(text).unwrap_or_else(|| "<root>".to_owned());
            if message.starts_with("unknown field") {
                ConfigError::UnknownField {
                    field,
                    line: error.line(),
                }
            } else {
                ConfigError::InvalidValue { field, message }
            }
        }
        Category::Io | Category::Syntax | Category::Eof => ConfigError::Syntax {
            line: error.line(),
            column: error.column(),
            message,
        },
    }
}

/// Splits `message at line L column C` into the message and the suffix.
fn split_position(text: &str) -> (String, Option<&str>) {
    match text.rsplit_once(" at line ") {
        Some((message, position)) => (message.to_owned(), Some(position)),
        None => (text.to_owned(), None),
    }
}

/// Finds the dotted path of the first field that does not deserialize, by
/// trying each section and each of its fields alone.
fn locate_field(text: &str) -> Option<String> {
    let Value::Object(top) = serde_json::from_str::<Value>(text).ok()? else {
        return None;
    };
    for (section, value) in &top {
        if !rejects(section, value) {
            continue;
        }
        let Value::Object(fields) = value else {
            return Some(section.clone());
        };
        for (name, field) in fields {
            let mut inner = serde_json::Map::new();
            inner.insert(name.clone(), field.clone());
            if rejects(section, &Value::Object(inner)) {
                return Some(format!("{section}.{name}"));
            }
        }
        return Some(section.clone());
    }
    None
}

/// `true` when `{ section: value }` does not deserialize as a [`Config`].
fn rejects(section: &str, value: &Value) -> bool {
    let mut map = serde_json::Map::new();
    map.insert(section.to_owned(), value.clone());
    serde_json::from_value::<Config>(Value::Object(map)).is_err()
}
