#!/usr/bin/env bash
# Gate 3b: enforces the dependency direction domain <- app <- infra/tui <- bin.
# Reads the direct dependencies of each crate from `cargo metadata`.
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
    echo "missing tool: jq; install with: sudo apt install jq" >&2
    exit 1
fi

metadata="$(cargo metadata --format-version 1 --no-deps)"
violations=0

# check_crate <crate> <forbidden-name-regex>
# The regex is matched against the full dependency name (anchored).
check_crate() {
    local crate="$1" forbidden="$2" dep
    while IFS= read -r dep; do
        [ -n "$dep" ] || continue
        echo "layer violation: ${crate} must not depend on ${dep}" >&2
        violations=$((violations + 1))
    done < <(
        jq -r --arg crate "$crate" --arg re "^(${forbidden})\$" '
            .packages[]
            | select(.name == $crate)
            | .dependencies[].name
            | select(test($re))
        ' <<<"$metadata" | sort -u
    )
}

check_crate certtui-domain 'certtui-.*|tokio|async-trait|reqwest|rustls|ratatui|crossterm'
check_crate certtui-app 'certtui-infra|certtui-tui|reqwest|rustls|tokio-rustls|ratatui|crossterm|arboard'
check_crate certtui-infra 'certtui-tui'
check_crate certtui-tui 'certtui-infra'

if [ "$violations" -gt 0 ]; then
    echo "layer check failed: ${violations} violation(s)" >&2
    exit 1
fi
echo "layer check ok"
