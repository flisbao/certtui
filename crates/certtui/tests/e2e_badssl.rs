//! Opt-in end-to-end checks of `certtui check` against the public badssl.com
//! hosts. They need network access, so every test is `#[ignore]`d and the
//! normal CI never runs them. Run them by hand:
//!
//! ```text
//! cargo test -p certtui --test e2e_badssl -- --ignored
//! ```

// Justificativa: an integration-test crate; its helpers (outside `#[test]`
// fns) may unwrap and panic, which is what a failing test should do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Output;

use assert_cmd::Command;
use serde_json::Value;

/// Runs `certtui check <host>:443 --json` against the system trust store.
fn check(host: &str) -> Output {
    Command::cargo_bin("certtui")
        .unwrap()
        .args(["check", host, "--json"])
        .output()
        .unwrap()
}

/// The finding codes of the single target in the `check --json` document.
fn finding_codes(out: &Output) -> Vec<String> {
    let json: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let result = json
        .get("results")
        .and_then(|results| results.get(0))
        .expect("one result");
    assert!(
        result["error"].is_null(),
        "the target failed to load: {}",
        result["error"]
    );
    result
        .get("findings")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|finding| finding["code"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
#[ignore = "needs network access to badssl.com"]
fn quando_expired_badssl_deve_sair_1_com_expired() {
    let out = check("expired.badssl.com");
    assert_eq!(out.status.code(), Some(1));
    assert!(finding_codes(&out).contains(&"EXPIRED".to_owned()));
}

#[test]
#[ignore = "needs network access to badssl.com"]
fn quando_self_signed_badssl_deve_listar_self_signed_leaf() {
    let out = check("self-signed.badssl.com");
    assert!(finding_codes(&out).contains(&"SELF_SIGNED_LEAF".to_owned()));
}

#[test]
#[ignore = "needs network access to badssl.com"]
fn quando_incomplete_chain_badssl_deve_listar_chain_incomplete() {
    let out = check("incomplete-chain.badssl.com");
    assert!(finding_codes(&out).contains(&"CHAIN_INCOMPLETE".to_owned()));
}

#[test]
#[ignore = "needs network access to badssl.com"]
fn quando_untrusted_root_badssl_deve_listar_trust_untrusted() {
    let out = check("untrusted-root.badssl.com");
    assert!(finding_codes(&out).contains(&"TRUST_UNTRUSTED".to_owned()));
}
