#!/usr/bin/env bash
# Measure one release-mode `certtui batch` over 1000 local TLS servers.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

targets=1000
limit_kib=98304 # 96 MiB, spec section 9

target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
    target_dir="$repo_root/$target_dir"
fi
export CARGO_TARGET_DIR="$target_dir"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/certtui-rss-batch.XXXXXX")"
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

# One listener per target, plus the connections in flight and the runtime's own
# descriptors; the default soft limit of 1024 is not enough.
needed_fds=4096
hard_fds="$(ulimit -Hn)"
if [[ "$hard_fds" != "unlimited" ]] && (( hard_fds < needed_fds )); then
    echo "the hard limit of open files is ${hard_fds}; ${needed_fds} are needed" >&2
    exit 1
fi
ulimit -n "$needed_fds"

if ! cargo build --locked --release -p certtui --bin certtui -p certtui-infra --example tls_multi_server >"$tmp_dir/build.log" 2>&1; then
    cat "$tmp_dir/build.log" >&2
    exit 1
fi

if ! command -v setsid >/dev/null 2>&1; then
    echo "missing tool: setsid (needed to clean up the TLS server process group)" >&2
    exit 1
fi
setsid "$target_dir/release/examples/tls_multi_server" "$targets" "$tmp_dir/list.txt" \
    >"$tmp_dir/server.out" 2>"$tmp_dir/server.err" &
server_pid=$!

ready=""
for ((attempt = 0; attempt < 300; attempt += 1)); do
    if [[ -s "$tmp_dir/server.out" ]]; then
        IFS= read -r ready < "$tmp_dir/server.out" || true
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if [[ "$ready" != "READY" ]]; then
    echo "the TLS servers did not report READY within 30 seconds" >&2
    cat "$tmp_dir/server.out" "$tmp_dir/server.err" >&2
    exit 1
fi
if [[ "$(wc -l < "$tmp_dir/list.txt")" -ne "$targets" ]]; then
    echo "the list does not hold ${targets} targets" >&2
    exit 1
fi

# The servers' certificates are not trusted, so findings (exit 1) are expected;
# anything else is a failure of the command itself.
status=0
/usr/bin/time -v -o "$tmp_dir/client.time" -- \
    "$target_dir/release/certtui" batch "$tmp_dir/list.txt" --json --concurrency 32 \
    >"$tmp_dir/client.json" 2>"$tmp_dir/client.err" || status=$?
if (( status > 1 )); then
    echo "release certtui batch failed with exit ${status}" >&2
    cat "$tmp_dir/client.err" >&2
    exit 1
fi

if ! jq -e --argjson n "$targets" \
    '.summary.total == $n and .summary.failed == 0 and (.rows | length) == $n' \
    "$tmp_dir/client.json" >/dev/null; then
    echo "release certtui batch did not inspect every target" >&2
    jq '.summary' "$tmp_dir/client.json" >&2 || true
    exit 1
fi

rss_line="$(awk -F: '/^\tMaximum resident set size \(kbytes\):/ { gsub(/[[:space:]]/, "", $2); print $2 }' "$tmp_dir/client.time")"
if [[ ! "$rss_line" =~ ^[0-9]+$ ]]; then
    echo "could not parse GNU time Maximum resident set size metric" >&2
    cat "$tmp_dir/client.time" >&2
    exit 1
fi
rss_kib="$rss_line"
if (( rss_kib > limit_kib )); then
    echo "rss=${rss_kib} KiB (limit ${limit_kib})" >&2
    exit 1
fi

echo "rss=${rss_kib} KiB (limit ${limit_kib})"
