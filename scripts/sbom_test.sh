#!/usr/bin/env bash
# Tests the gate of scripts/sbom.sh: it must fail when a forbidden TLS component
# is present AND when the check itself cannot run (fail closed).
#
# Runs the real script and the real jq in a throwaway tree; only `cargo
# cyclonedx` is replaced, by a stub that writes the SBOM given by the test case.
#
# Needs: jq.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v jq >/dev/null 2>&1; then
    echo "missing tool: jq; install with: sudo apt install jq" >&2
    exit 1
fi

tree="$(mktemp -d)"
trap 'rm -rf "$tree"' EXIT
mkdir -p "$tree/scripts" "$tree/bin" "$tree/crates/certtui"
cp scripts/sbom.sh "$tree/scripts/sbom.sh"
cat >"$tree/bin/cargo" <<'STUB'
#!/usr/bin/env bash
[ "${2:-}" = "--version" ] && exit 0
printf '%s\n' "$SBOM_JSON" >crates/certtui/certtui.cdx.json
STUB
chmod +x "$tree/bin/cargo"

failures=0

# expect <pass|fail> <case name> <components JSON array>
expect() {
    local want="$1" name="$2" got="pass" output
    local json="{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"components\":$3}"
    output="$(SBOM_JSON="$json" PATH="$tree/bin:$PATH" bash "$tree/scripts/sbom.sh" 2>&1)" || got="fail"
    if [ "$got" = "$want" ]; then
        echo "ok: ${name}"
    else
        echo "FAILED: ${name}: expected ${want}, got ${got}" >&2
        echo "$output" >&2
        failures=1
    fi
}

expect pass "clean SBOM passes" '[{"name":"rustls"},{"name":"openssl-probe"}]'
expect fail "openssl component fails" '[{"name":"rustls"},{"name":"openssl-sys"}]'
expect fail "nested native-tls component fails" '[{"name":"a","components":[{"name":"native-tls"}]}]'
# A non-string name makes jq error out: the script must not read that as "clean".
expect fail "jq error in the component check fails" '[{"name":123},{"name":"openssl"}]'

exit "$failures"
