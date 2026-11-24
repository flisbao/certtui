#!/usr/bin/env bash
# Measure one release-mode network inspect against the local TLS test server.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
    target_dir="$repo_root/$target_dir"
fi
export CARGO_TARGET_DIR="$target_dir"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/certtui-rss.XXXXXX")"
server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
        # The server is isolated in its own session so cleanup targets only
        # this process group.
        kill -TERM -- "-$server_pid" 2>/dev/null || kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! cargo build --locked --release -p certtui --bin certtui -p certtui-infra --example tls_test_server >"$tmp_dir/build.log" 2>&1; then
    cat "$tmp_dir/build.log" >&2
    exit 1
fi

if ! command -v setsid >/dev/null 2>&1; then
    echo "missing tool: setsid (needed to clean up the TLS server process group)" >&2
    exit 1
fi
setsid "$target_dir/release/examples/tls_test_server" \
    >"$tmp_dir/server.out" 2>"$tmp_dir/server.err" &
server_pid=$!

port_line=""
for ((attempt = 0; attempt < 100; attempt += 1)); do
    if [[ -s "$tmp_dir/server.out" ]]; then
        IFS= read -r port_line < "$tmp_dir/server.out" || true
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [[ "$port_line" =~ ^PORT=([0-9]{1,5})$ ]]; then
    port="${BASH_REMATCH[1]}"
else
    echo "TLS test server did not report a valid ephemeral port within 10 seconds" >&2
    cat "$tmp_dir/server.out" "$tmp_dir/server.err" >&2
    exit 1
fi
if (( 10#$port < 1 || 10#$port > 65535 )); then
    echo "TLS test server reported an out-of-range port: $port" >&2
    exit 1
fi

if ! /usr/bin/time -v -o "$tmp_dir/client.time" -- \
    "$target_dir/release/certtui" inspect "127.0.0.1:$port" \
    --connect-to "127.0.0.1:$port" --sni localhost --json \
    >"$tmp_dir/client.json" 2>"$tmp_dir/client.err"; then
    echo "release certtui inspect failed" >&2
    cat "$tmp_dir/client.err" >&2
    exit 1
fi

if ! jq -e '.tls != null and (.certificates | length > 0) and (.ocsp_staple != null)' \
    "$tmp_dir/client.json" >/dev/null; then
    echo "release certtui inspect did not produce a valid TLS JSON report" >&2
    cat "$tmp_dir/client.json" >&2
    exit 1
fi

rss_line="$(awk -F: '/^\tMaximum resident set size \(kbytes\):/ { gsub(/[[:space:]]/, "", $2); print $2 }' "$tmp_dir/client.time")"
if [[ ! "$rss_line" =~ ^[0-9]+$ ]]; then
    echo "could not parse GNU time Maximum resident set size metric" >&2
    cat "$tmp_dir/client.time" >&2
    exit 1
fi
rss_kib="$rss_line"
if (( rss_kib > 30720 )); then
    echo "rss=${rss_kib} KiB (limit 30720)" >&2
    exit 1
fi

echo "rss=${rss_kib} KiB (limit 30720)"
