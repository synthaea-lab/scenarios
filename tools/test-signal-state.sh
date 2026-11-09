#!/usr/bin/env bash
# Checks where signal.sh keeps the sender state between `kill` and `verify-kill`:
# in the caller's private runtime directory, never in /tmp, and found again by
# `verify-kill`. Runs unprivileged: a `sleep` stands in for the agent, so the real
# SIGKILL lands on it. Takes about 15 s (`kill` waits 12 s on purpose).
#
#   tools/test-signal-state.sh

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

# --- verify-kill before kill -------------------------------------------------------

out=$(run_signal verify-kill 2>&1)
expect_equal 2 "$?" "verify-kill without a recorded sender exits 2"
case "$out" in
    *"$runtime/$STATE_NAME not found"*) pass "verify-kill names the state file it looked for" ;;
    *) fail "verify-kill said: $out" ;;
esac

# --- no usable runtime directory ----------------------------------------------------

if [ "$(id -u)" -ne 0 ] && [ ! -d "/run/user/$(id -u)" ]; then
    out=$(run_signal verify-kill XDG_RUNTIME_DIR="$work/missing" 2>&1)
    expect_equal 2 "$?" "no runtime directory: exits 2"
    case "$out" in
        *"set XDG_RUNTIME_DIR"*) pass "no runtime directory: says to set XDG_RUNTIME_DIR" ;;
        *) fail "no runtime directory said: $out" ;;
    esac
fi

# --- kill, then verify-kill ---------------------------------------------------------

sleep 300 &
fake_agent=$!
add_cleanup kill_process "$fake_agent"

out=$(run_signal kill AGENT_PID="$fake_agent" 2>&1)
expect_equal 0 "$?" "kill exits 0"
# The braces take bash's own "Killed" job report off the output.
{ wait "$fake_agent"; agent_rc=$?; } 2>/dev/null
expect_equal 137 "$agent_rc" "kill SIGKILLs the agent"
case "$out" in
    *"Sender pid recorded in $runtime/$STATE_NAME"*) pass "kill prints where it recorded the sender" ;;
    *) fail "kill said: $out" ;;
esac
sender=$(cat "$runtime/$STATE_NAME" 2>/dev/null)
case "$sender" in
    '' | *[!0-9]*) fail "kill recorded '$sender' in the runtime directory" ;;
    *) pass "kill records the sender pid in the runtime directory" ;;
esac
[ ! -e "/tmp/$STATE_NAME" ] || fail "kill wrote /tmp/$STATE_NAME"

printf '{"technique":"T1562.001","message":"pid=%s comm=bash sent SIGKILL (9) to the agent"}\n' \
    "$sender" > "$work/alerts.ndjson"
out=$(run_signal verify-kill 2>&1)
expect_equal 0 "$?" "verify-kill finds the alert naming the recorded sender"
case "$out" in
    *"PASS  SIGKILL alert naming the sender"*) pass "verify-kill reports PASS" ;;
    *) fail "verify-kill said: $out" ;;
esac
if [ ! -e "$runtime/$STATE_NAME" ]; then
    pass "verify-kill removes the state file"
else
    fail "verify-kill left $runtime/$STATE_NAME"
fi

if [ "$failures" -eq 0 ]; then
    echo "All signal state checks passed."
else
    echo "$failures signal state check(s) failed."
    exit 1
fi
