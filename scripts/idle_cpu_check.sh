#!/usr/bin/env bash
# Gate: the TUI must cost under 1% CPU while idle (spec section 9).
#
# Runs the release binary on the Home screen in a pty (`script`), keeps it
# idle for 10 seconds and reads its user+system time from /proc.
set -euo pipefail
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

limit_percent=1
seconds=10
binary="${CARGO_TARGET_DIR:-target}/release/certtui"

if ! command -v script >/dev/null 2>&1; then
    echo "idle cpu: 'script' not found, skipped"
    exit 0
fi
[ -x "$binary" ] || cargo build --locked --release -p certtui --bin certtui

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/certtui-idle.XXXXXX")"
fifo="$tmp_dir/stdin"
mkfifo "$fifo"
runner_pid=""
cleanup() {
    [ -z "$runner_pid" ] || kill "$runner_pid" 2>/dev/null || true
    pkill -TERM -x certtui 2>/dev/null || true
    exec 3>&- 2>/dev/null || true
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

# The fifo stays open for writing, so the pty never sees end of input.
exec 3<>"$fifo"
script -qfc "stty cols 100 rows 30; exec $binary" /dev/null <"$fifo" >/dev/null 2>&1 &
runner_pid=$!

pid=""
for _ in $(seq 1 50); do
    pid="$(pgrep -n -x certtui || true)"
    [ -z "$pid" ] || break
    sleep 0.1
done
if [ -z "$pid" ]; then
    echo "idle cpu: the TUI did not start" >&2
    exit 1
fi

# utime + stime (fields 14 and 15), in clock ticks. The command name may hold
# spaces, so cut after the closing parenthesis first.
ticks() {
    sed -E 's/^.*\) //' "/proc/$pid/stat" | awk '{print $12 + $13}'
}

sleep 1
start="$(ticks)"
sleep "$seconds"
end="$(ticks)"
clk="$(getconf CLK_TCK)"

percent="$(awk -v s="$start" -v e="$end" -v clk="$clk" -v secs="$seconds" \
    'BEGIN { printf "%.2f", (e - s) / (clk * secs) * 100 }')"
echo "idle cpu=${percent}% (limit ${limit_percent}%)"
awk -v p="$percent" -v l="$limit_percent" 'BEGIN { exit !(p < l) }'
