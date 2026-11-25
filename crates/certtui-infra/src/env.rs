//! The environment variables the adapters read, injectable for tests.

use std::collections::HashMap;

/// The names [`EnvVars::from_process`] copies from the process environment.
const WATCHED: [&str; 5] = [
    "CERTTUI_CONFIG",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// A snapshot of the environment variables the adapters care about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvVars(HashMap<String, String>);

impl EnvVars {
    /// A view over the given variables.
    #[must_use]
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self(
            pairs
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .collect(),
        )
    }

    /// The watched variables of this process.
    #[must_use]
    pub fn from_process() -> Self {
        let pairs = WATCHED
            .into_iter()
            .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)));
        Self(pairs.collect())
    }

    /// The value of `key`, unless it is unset or empty.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
    }
}
