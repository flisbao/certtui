//! Every command example of the root `README.md` marked with `<!-- test -->`
//! is run for real against the compiled `certtui`, using only the fixtures of
//! `tests/fixtures` (no network, no TTY).
//!
//! A marked example looks like this in the README:
//!
//! ````text
//! <!-- test -->
//! <!-- expect: text that stdout must contain -->
//! ```sh
//! certtui inspect tests/fixtures/chain-3.pem
//! ```
//! ````
//!
//! The block runs through `sh -e -c` from the repository root, with the
//! directory of the compiled `certtui` first in `PATH` (so `certtui ...` and
//! pipes such as `cat file | certtui inspect -` work as written), must exit 0
//! and its stdout must contain every `expect` line. The test also fails when
//! the README has too few marked blocks, so it cannot pass vacuously.

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use assert_cmd::Command;

/// At least this many marked blocks must exist and run.
const MIN_BLOCKS: usize = 6;

/// Marker line that announces an executable example.
const MARKER: &str = "<!-- test -->";

/// Prefix and suffix of an `expect` line.
const EXPECT_PREFIX: &str = "<!-- expect:";
const EXPECT_SUFFIX: &str = "-->";

/// One executable example of the README.
#[derive(Debug)]
struct Example {
    /// Line of the marker, for messages.
    line: usize,
    /// Strings stdout must contain.
    expects: Vec<String>,
    /// The shell script.
    script: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Extracts the marked examples from the README text.
fn extract_examples(readme: &str) -> Vec<Example> {
    let lines: Vec<&str> = readme.lines().collect();
    let mut examples = Vec::new();
    let mut index = 0;
    while let Some(current) = lines.get(index) {
        if current.trim() != MARKER {
            index += 1;
            continue;
        }
        let line = index + 1;
        index += 1;
        let mut expects = Vec::new();
        while let Some(text) = lines.get(index).map(|l| l.trim()) {
            let Some(rest) = text.strip_prefix(EXPECT_PREFIX) else {
                break;
            };
            let value = rest
                .strip_suffix(EXPECT_SUFFIX)
                .unwrap_or_else(|| panic!("README line {}: unterminated expect", index + 1));
            expects.push(value.trim().to_owned());
            index += 1;
        }
        assert!(
            !expects.is_empty(),
            "README line {line}: a marked example needs at least one `<!-- expect: ... -->`"
        );
        assert_eq!(
            lines.get(index).map(|l| l.trim_end()),
            Some("```sh"),
            "README line {line}: the marker must be followed by a ```sh block"
        );
        index += 1;
        let mut script = String::new();
        loop {
            let text = lines
                .get(index)
                .unwrap_or_else(|| panic!("README line {line}: unterminated ```sh block"));
            index += 1;
            if text.trim_end() == "```" {
                break;
            }
            script.push_str(text);
            script.push('\n');
        }
        examples.push(Example {
            line,
            expects,
            script,
        });
    }
    examples
}

fn scratch_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("certtui-readme-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn quando_readme_tem_exemplos_marcados_deve_executar_todos_com_exit_zero() {
    let root = repo_root();
    let readme = std::fs::read_to_string(root.join("README.md")).unwrap();
    let examples = extract_examples(&readme);
    assert!(
        examples.len() >= MIN_BLOCKS,
        "README.md has {} marked examples, expected at least {MIN_BLOCKS}",
        examples.len()
    );

    // The directory of the compiled binary goes first in PATH, so the
    // `certtui` of the examples is the one under test.
    let binary = Command::cargo_bin("certtui").unwrap();
    let bin_dir = Path::new(binary.get_program()).parent().unwrap().to_owned();
    let path = std::env::join_paths(
        std::iter::once(bin_dir.clone()).chain(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        )),
    )
    .unwrap();
    let scratch = scratch_dir();

    for example in &examples {
        let output = Command::new("sh")
            .args(["-e", "-c", &example.script])
            .current_dir(&root)
            .env("PATH", &path)
            // Isolate from the developer's own configuration and history.
            .env("HOME", &scratch)
            .env("XDG_CONFIG_HOME", &scratch)
            .env("XDG_DATA_HOME", &scratch)
            .env("TMPDIR", &scratch)
            .env_remove("CERTTUI_CONFIG")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env("NO_COLOR", "1")
            .timeout(Duration::from_secs(60))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "README line {}: exit {:?}\n--- script\n{}--- stdout\n{stdout}\n--- stderr\n{stderr}",
            example.line,
            output.status.code(),
            example.script,
        );
        for expect in &example.expects {
            assert!(
                stdout.contains(expect.as_str()),
                "README line {}: stdout lacks `{expect}`\n--- script\n{}--- stdout\n{stdout}\n--- stderr\n{stderr}",
                example.line,
                example.script,
            );
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn quando_marcador_nao_tem_bloco_deve_falhar_a_extracao() {
    let text = "<!-- test -->\n<!-- expect: x -->\nsem bloco\n";
    let result = std::panic::catch_unwind(|| extract_examples(text));
    assert!(result.is_err());
}

#[test]
fn quando_bloco_tem_marcador_e_expect_deve_extrair_o_script() {
    let text = "intro\n<!-- test -->\n<!-- expect: a -->\n<!-- expect: b -->\n```sh\necho 1\necho 2\n```\n```sh\nignorado\n```\n";
    let examples = extract_examples(text);
    assert_eq!(examples.len(), 1);
    assert_eq!(examples[0].expects, ["a", "b"]);
    assert_eq!(examples[0].script, "echo 1\necho 2\n");
}
