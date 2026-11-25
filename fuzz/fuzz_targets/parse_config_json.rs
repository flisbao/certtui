//! Fuzz target: parsing the configuration file and resolving it must never
//! panic or hang, and an error must always name something.

#![no_main]

use certtui_app::config::{CliOverrides, Config, ConfigError};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match Config::from_json(text) {
        Ok(config) => {
            // A config that parses may still be refused (zero limit, bad
            // clipboard); neither outcome may panic.
            let _ = config.resolve(&CliOverrides::default());
        }
        Err(error) => {
            // The message must be printable and bounded: it goes to stderr.
            let message = error.to_string();
            assert!(message.len() < 4096);
            if let ConfigError::Syntax { line, .. } = error {
                assert!(line >= 1);
            }
        }
    }
});
