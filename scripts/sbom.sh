#!/usr/bin/env bash
# Software bill of materials (release artifact): CycloneDX JSON of the `certtui`
# binary crate and its whole dependency tree, written to ./certtui.cdx.json.
#
# The file is a release artifact, not a source file: it is git-ignored and the
# release workflow (.github/workflows/sbom.yml) attaches it, with its sha256, to
# the GitHub Release.
#
# Checks (any failure is fatal):
#   1. the output is a CycloneDX document (`.bomFormat == "CycloneDX"`);
#   2. no `openssl` / `openssl-sys` / `native-tls` component (RF1: zero OpenSSL).
#
# Needs: cargo-cyclonedx (cargo install --locked cargo-cyclonedx), jq.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

for tool in jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "missing tool: ${tool}; install with: sudo apt install jq" >&2
        exit 1
    fi
done
if ! cargo cyclonedx --version >/dev/null 2>&1; then
    echo "missing tool: cargo-cyclonedx; install with: cargo install --locked cargo-cyclonedx" >&2
    exit 1
fi

OUT="certtui.cdx.json"
# cargo-cyclonedx writes one `<override-filename>.json` next to the manifest of
# EVERY workspace member; only the binary crate's is the release SBOM, the
# others are removed so the working tree stays clean.
GENERATED="crates/certtui/certtui.cdx.json"

rm -f "$OUT" crates/*/certtui.cdx.json
cargo cyclonedx --format json --spec-version 1.5 --override-filename certtui.cdx
mv "$GENERATED" "$OUT"
rm -f crates/*/certtui.cdx.json

jq -e '.bomFormat == "CycloneDX"' "$OUT" >/dev/null \
    || { echo "${OUT}: not a CycloneDX document" >&2; exit 1; }

forbidden='^(openssl|openssl-sys|openssl-src|native-tls)$'
if jq -e --arg re "$forbidden" '[.. | objects | select(has("name")) | .name | select(test($re))] | length > 0' "$OUT" >/dev/null; then
    echo "${OUT}: forbidden TLS component (OpenSSL / native-tls) found:" >&2
    jq -r --arg re "$forbidden" '[.. | objects | select(has("name")) | .name | select(test($re))] | unique[]' "$OUT" >&2
    exit 1
fi

echo "${OUT}: $(jq '.components | length' "$OUT") components, CycloneDX $(jq -r .specVersion "$OUT"), no OpenSSL"
