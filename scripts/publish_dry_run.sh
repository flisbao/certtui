#!/usr/bin/env bash
# Release gate (RF3): every crate must be publishable on its own, in order.
#
# Publication order (dependency direction domain <- app <- infra/tui <- bin):
#   certtui-domain, certtui-app, certtui-infra, certtui-tui, certtui
#
# NEVER publishes anything: every cargo call below is a dry run. The real
# `cargo publish` is a manual, human-gated step.
#
# What this script verifies:
#   1. PUBLISH_ORDER is exactly the set of workspace members and is a valid
#      topological order (no crate precedes one of its internal dependencies).
#   2. Mode "workspace" (cargo >= 1.90, the normal case; MSRV is 1.97):
#      `cargo publish --workspace --dry-run` packages every crate and then
#      builds each one from its own unpacked .crate tarball, in dependency
#      order. Internal dependencies that are not on crates.io yet are resolved
#      from a temporary overlay registry holding the crates packaged earlier in
#      the same run. So each crate is compiled with ONLY the dependencies and
#      features declared in its own manifest (no workspace feature
#      unification, no orphan path dependency) -- this is what catches a
#      missing `features = [...]` or a file left out of the tarball.
#   3. Mode "package-only" (fallback for a cargo without `publish --workspace`):
#      `cargo package --no-verify -p <crate>` per crate, in order. LIMITATION:
#      it only checks that the manifest and the tarball contents are valid
#      (metadata, license, readme, included files). It does NOT compile the
#      packaged crate, and a crate whose internal dependencies are not on
#      crates.io yet cannot be resolved by `cargo package` at all, so only
#      certtui-domain is fully checked in this mode.
#
# Extra arguments are passed to cargo (for example `--allow-dirty` while
# developing; the final run before a release must be on a clean tree).
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PUBLISH_ORDER=(certtui-domain certtui-app certtui-infra certtui-tui certtui)

if ! command -v jq >/dev/null 2>&1; then
    echo "missing tool: jq; install with: sudo apt install jq" >&2
    exit 1
fi

echo "== publish order =="
metadata="$(cargo metadata --format-version 1 --no-deps --locked)"
order_json="$(printf '%s\n' "${PUBLISH_ORDER[@]}" | jq -R . | jq -s .)"
# Prints one message per problem; empty output means the order is valid.
problems="$(
    jq -r --argjson order "$order_json" '
        ([.packages[].name] | sort) as $members
        | ($order | sort) as $listed
        | if $members != $listed then
            "PUBLISH_ORDER does not match the workspace members: \($members | join(", "))"
          else empty end,
          ( .packages[] as $p
            | [ $p.dependencies[].name | select(. as $d | $order | index($d)) ] | unique[]
            | . as $dep
            | select(($order | index($dep)) >= ($order | index($p.name)))
            | "\($p.name) must be published after \($dep)" )
    ' <<<"$metadata"
)"
if [ -n "$problems" ]; then
    echo "$problems" >&2
    exit 1
fi
echo "${PUBLISH_ORDER[*]}"

echo "== license texts =="
# Each crate tarball must ship the license texts (the crates.io tarball only
# holds files under the crate directory), so every crates/*/LICENSE-* must be a
# byte-identical copy of the root file.
license_problems=0
for crate_dir in crates/*/; do
    for lic in LICENSE-MIT LICENSE-APACHE; do
        if ! cmp -s "$lic" "${crate_dir}${lic}"; then
            echo "${crate_dir}${lic} is missing or differs from the root ${lic}" >&2
            license_problems=1
        fi
    done
done
if [ "$license_problems" -ne 0 ]; then
    exit 1
fi
echo "license texts match the root files"

# Capture the help text first: `cargo publish --help | grep -q` can die of
# SIGPIPE under pipefail and silently select the weaker fallback.
publish_help="$(cargo publish --help 2>/dev/null || true)"
if grep -q -- '--workspace' <<<"$publish_help"; then
    echo "== dry-run: workspace (each crate verified from its own tarball) =="
    cargo publish --workspace --dry-run --locked "$@"
else
    echo "== dry-run: package-only fallback (no compilation, see header) =="
    for crate in "${PUBLISH_ORDER[@]}"; do
        echo "-- ${crate}"
        cargo package --no-verify --locked -p "$crate" "$@"
    done
fi

echo "== publish dry-run passed =="
