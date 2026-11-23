#!/usr/bin/env bash
# Quality gates (spec section 13), in order. Any failure blocks.
set -euo pipefail

cd "$(dirname "$0")/.."

require_tool() {
    local tool="$1" install="$2"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing tool: ${tool}; install with: ${install}" >&2
        exit 1
    fi
}

require_tool cargo-deny "cargo install cargo-deny --locked"
require_tool cargo-machete "cargo install cargo-machete --locked"
require_tool cargo-llvm-cov "cargo install cargo-llvm-cov --locked"
require_tool jq "sudo apt install jq"

# Instrumented line count of a coverage run (0 when nothing is instrumented).
instrumented_lines() {
    cargo llvm-cov "$@" --all-features --json --summary-only | jq '.data[0].totals.lines.count'
}

# coverage_gate <threshold> <cargo llvm-cov selector args...>
coverage_gate() {
    local threshold="$1"
    shift
    local lines
    lines="$(instrumented_lines "$@")"
    if [ "$lines" -eq 0 ]; then
        echo "coverage: no instrumented lines, skipped"
        return 0
    fi
    cargo llvm-cov "$@" --all-features --fail-under-lines "$threshold"
}

echo "== clean =="
cargo clean

echo "== fmt =="
cargo fmt --all -- --check

echo "== clippy =="
cargo clippy --workspace --all-targets --all-features -- -D warnings

echo "== layers =="
bash scripts/check_layers.sh

echo "== test =="
cargo test --workspace --all-features

echo "== deny =="
cargo deny check

echo "== machete =="
cargo machete

echo "== coverage =="
coverage_gate 70 --workspace
coverage_gate 90 -p certtui-domain
coverage_gate 90 -p certtui-app

echo "== msrv =="
msrv="$(sed -nE 's/^rust-version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' Cargo.toml | head -n 1)"
if [ -z "$msrv" ]; then
    echo "rust-version not found in Cargo.toml" >&2
    exit 1
fi
cargo "+${msrv}" check --workspace

echo "== release build + rss =="
cargo build --release --workspace
if [ -x scripts/rss_check.sh ]; then
    scripts/rss_check.sh
fi

echo "== all gates passed =="
