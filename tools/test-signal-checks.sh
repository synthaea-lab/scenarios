#!/usr/bin/env bash
# Checks signal.sh's preconditions and its PASS/FAIL verdict: a missing agent or a
# missing EVENTS/ALERTS file stops every mode that needs them with exit 2 before it
# signals anything, and a failed check prints its FAIL line, the failure count and
# exits 1. Runs unprivileged; `live` itself needs root and a running agent, so only
# its preconditions are exercised here. Takes about 30 s (`verify-kill` waits 30 s
# for an alert that never comes).
#
#   tools/test-signal-checks.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO/lib/common.sh"

SIGNAL="$REPO/scenarios/signal.sh"
STATE_NAME=synthaea-signal-scenario.sender

failures=0
work=$(mktemp -d)
add_cleanup rm -rf "$work"

pass() { echo "ok: $1"; }
fail() {
    echo "FAIL: $1"
    failures=$((failures + 1))
}

# expect_equal WANT GOT DESCRIPTION
expect_equal() {
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3: got '$2', want '$1'"; fi
}

# expect_output_has SUBSTRING OUTPUT DESCRIPTION
expect_output_has() {
    case "$2" in
        *"$1"*) pass "$3" ;;
        *) fail "$3: output was '$2'" ;;
    esac
}

runtime="$work/runtime"
mkdir -m 700 "$runtime"
: > "$work/events.jsonl"
: > "$work/alerts.ndjson"

# run_signal MODE [ENV...] — run signal.sh MODE with the test's files and runtime dir.
run_signal() {
    local mode=$1
    shift
    env EVENTS="$work/events.jsonl" ALERTS="$work/alerts.ndjson" \
        XDG_RUNTIME_DIR="$runtime" "$@" bash "$SIGNAL" "$mode"
}

# A pid that no longer names a process: a child that has exited and been reaped.
true &
gone_pid=$!
wait "$gone_pid"

# --- no running agent ---------------------------------------------------------------

for mode in live kill; do
    out=$(run_signal "$mode" AGENT_PID="$gone_pid" 2>&1)
    expect_equal 2 "$?" "$mode without a running agent exits 2"
    expect_output_has "No running agent found (set AGENT_PID)." "$out" \
        "$mode without a running agent says to set AGENT_PID"
done
[ ! -e "$runtime/$STATE_NAME" ] || fail "kill without an agent recorded a sender"

# --- missing EVENTS / ALERTS --------------------------------------------------------

sleep 300 &
fake_agent=$!
add_cleanup kill_process "$fake_agent"

for mode in live kill; do
    out=$(run_signal "$mode" AGENT_PID="$fake_agent" EVENTS="$work/missing.jsonl" 2>&1)
    expect_equal 2 "$?" "$mode without EVENTS exits 2"
    expect_output_has "$work/missing.jsonl not found (set EVENTS/ALERTS)." "$out" \
        "$mode without EVENTS names the missing file"

    out=$(run_signal "$mode" AGENT_PID="$fake_agent" ALERTS="$work/missing.ndjson" 2>&1)
    expect_equal 2 "$?" "$mode without ALERTS exits 2"
    expect_output_has "$work/missing.ndjson not found (set EVENTS/ALERTS)." "$out" \
        "$mode without ALERTS names the missing file"
done
if kill -0 "$fake_agent" 2>/dev/null; then
    pass "a failed precondition signals nothing"
else
    fail "the stand-in agent was killed by a failed precondition"
fi
[ ! -e "$runtime/$STATE_NAME" ] || fail "kill with a missing file recorded a sender"

# --- a failed check -----------------------------------------------------------------

echo 4242 > "$runtime/$STATE_NAME"
out=$(run_signal verify-kill 2>&1)
expect_equal 1 "$?" "verify-kill without a matching alert exits 1"
expect_output_has "  FAIL  SIGKILL alert naming the sender: expected 1, got 0" "$out" \
    "verify-kill prints the FAIL line with expected and actual"
expect_output_has "1 check(s) failed." "$out" "verify-kill prints the failure count"
case "$out" in
    *"All checks passed."*) fail "verify-kill also said all checks passed" ;;
    *) pass "verify-kill does not claim success" ;;
esac

if [ "$failures" -eq 0 ]; then
    echo "All signal check tests passed."
else
    echo "$failures signal check test(s) failed."
    exit 1
fi
