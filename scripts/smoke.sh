#!/usr/bin/env bash
# Smoke test of a built `certtui` binary (release artifact gate).
#
# Usage: bash scripts/smoke.sh <path-to-certtui-or-certtui.exe>
#
# Runs offline (no network call) against the repository fixtures:
#   1. `--version` prints the program name;
#   2. `inspect <pem> --json` emits JSON with `schema_version == 1`;
#   3. `inspect - --text` reads a messy bundle from standard input and exits 0.
# The network path (`inspect host:port`, RF1) needs a live TLS server and is NOT
# part of this script; run it by hand: `certtui inspect example.com:443`.
#
# Used by the release workflow (.github/workflows/smoke.yml) on a native runner of
# every target, and by hand on a locally built binary.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <path-to-certtui-binary>" >&2
    exit 2
fi

# Resolve the binary before changing directory (it may be a relative path).
binary="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [ ! -f "$binary" ]; then
    echo "smoke: binary not found: $1" >&2
    exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "missing tool: jq; install with: sudo apt install jq" >&2
    exit 1
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "== smoke: ${binary} =="

echo "-- --version"
version="$("$binary" --version)"
echo "$version"
case "$version" in
    certtui\ *) ;;
    *)
        echo "smoke: unexpected --version output" >&2
        exit 1
        ;;
esac

echo "-- inspect chain-3.pem --json"
"$binary" inspect tests/fixtures/chain-3.pem --json | jq -e '.schema_version == 1' >/dev/null

echo "-- inspect - --text < bundle-mixed.txt"
"$binary" inspect - --text <tests/fixtures/messy/bundle-mixed.txt >/dev/null

echo "== smoke passed =="
