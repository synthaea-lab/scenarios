#!/usr/bin/env bash
# Signal-probe filter and tamper attribution scenario (issue #362).
#
# The eBPF kill/tgkill probes are filtered kernel-side by SIGNAL_WATCH_PID to
# signals aimed at the agent itself. This scenario asserts both sides of that
# filter, then the T1562.001 rule (check_security_process_signal) on top of it:
#
#   live         (default) signals between unrelated processes produce ZERO
#                Signal events; a probe (kill -0) to the agent produces one event
#                and no alert; an unprivileged SIGTERM and SIGKILL to the agent
#                (both fail with EPERM, the agent survives) each produce one
#                event and one T1562.001 alert. The probe fires at syscall entry,
#                before the permission check, which is what makes the attempt
#                visible at all.
#   kill         SIGKILLs the agent for real and records this shell's pid.
#   verify-kill  run after restarting the agent: asserts the restarted agent
#                replayed the SIGKILL from the pinned SIGNAL_TAMPER_LAST map and
#                alerted T1562.001 naming the sender recorded by `kill`.
#
# Usage (as root, agent already running, from the agent's working directory or
# with EVENTS/ALERTS pointing at its files):
#   sudo ./scenarios/signal.sh
#   sudo ./scenarios/signal.sh kill
#   (restart the agent)
#   sudo ./scenarios/signal.sh verify-kill
#
# Environment: EVENTS (default events.jsonl), ALERTS (default alerts.ndjson),
# AGENT_PID (default: oldest process named "agent" or "synthaea-agent").
#
# `kill` records the sender pid in a state file that `verify-kill` reads back. It
# lives in a directory only this user can write (see state_file), never in /tmp:
# the script runs as root, and a fixed name in a world-writable directory could be
# a planted symlink that the write would follow.

set -euo pipefail

EVENTS=${EVENTS:-events.jsonl}
ALERTS=${ALERTS:-alerts.ndjson}
STATE_NAME=synthaea-signal-scenario.sender
# Long enough for the enrich queue to append the event to events.jsonl.
FLUSH_WAIT=3
MODE=${1:-live}
FAILURES=0

agent_pid() {
    if [[ -n "${AGENT_PID:-}" ]]; then
        echo "$AGENT_PID"
    else
        pgrep -xo agent || pgrep -xo synthaea-agent || true
    fi
}

# state_file — print the path of the sender state file: in $XDG_RUNTIME_DIR, else
# /run/user/<uid>, else (root only) /run. The same lookup in `kill` and
# `verify-kill` finds the same file. Exits 2 if none of them is a writable directory.
state_file() {
    local uid dir candidates
    uid=$(id -u)
    candidates=("${XDG_RUNTIME_DIR:-}" "/run/user/$uid")
    if [[ "$uid" -eq 0 ]]; then
        candidates+=(/run)
    fi
    for dir in "${candidates[@]}"; do
        if [[ -n "$dir" && -d "$dir" && -w "$dir" ]]; then
            echo "$dir/$STATE_NAME"
            return
        fi
    done
    echo "No private runtime directory for the state file (set XDG_RUNTIME_DIR)." >&2
    exit 2
}

count_signal_events() { grep -c '"type":"signal"' "$EVENTS" || true; }
count_tamper_alerts() { grep -c '"technique":"T1562.001"' "$ALERTS" || true; }

# count_signal_events_to PID... — the Signal events whose target is one of PIDs.
count_signal_events_to() {
    local targets
    targets=$(IFS='|'; echo "$*")
    grep '"type":"signal"' "$EVENTS" | grep -cE "\"target_pid\":($targets)[,}]" || true
}

# Runs a command as `nobody`, so a signal to the (root) agent fails with EPERM.
as_nobody() {
    if command -v setpriv >/dev/null; then
        setpriv --reuid=65534 --regid=65534 --clear-groups "$@"
    else
        su -s /bin/sh nobody -c "$*"
    fi
}

# Self-check verdict. FAILURES counts the failed checks; it is the one global the
# helpers below change, and only fail_check changes it. The script's exit status
# is decided from it at the end.

# fail_check MESSAGE — print a FAIL line and count it in FAILURES.
fail_check() {
    echo "  FAIL  $1"
    FAILURES=$((FAILURES + 1))
}

# expect_equal LABEL EXPECTED ACTUAL — print a PASS line if ACTUAL equals
# EXPECTED, else a FAIL line (through fail_check).
expect_equal() {
    local label=$1 expected=$2 actual=$3
    if [[ "$actual" == "$expected" ]]; then
        echo "  PASS  $label ($actual)"
    else
        fail_check "$label: expected $expected, got $actual"
    fi
}

# running_agent_pid_or_exit — print the pid of the running agent (see agent_pid).
# Exits 2 if there is none. Call it as `pid=$(running_agent_pid_or_exit)` on its
# own line (not `local pid=$(...)`), so set -e carries the exit to the script; the
# signals the scenario sends stay in the main shell.
running_agent_pid_or_exit() {
    local pid
    pid=$(agent_pid)
    if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
        echo "No running agent found (set AGENT_PID)." >&2
        exit 2
    fi
    echo "$pid"
}

# require_event_files — exit 2 unless the agent's EVENTS and ALERTS files exist.
require_event_files() {
    local f
    for f in "$EVENTS" "$ALERTS"; do
        [[ -f "$f" ]] || { echo "$f not found (set EVENTS/ALERTS)." >&2; exit 2; }
    done
}

run_live() {
    local pid
    pid=$(running_agent_pid_or_exit)
    require_event_files
    echo "Agent pid $pid, kernel $(uname -r)"

    echo "1) Unrelated signal traffic (must stay invisible)"
    sleep 300 & local a=$!
    sleep 300 & local b=$!
    # Count only the events aimed at the two sleeps: the kill -0 liveness probe in
    # running_agent_pid_or_exit is a real signal to the agent, and its event can land
    # up to ~170 ms later, after a whole-file count would have been taken (#26).
    local before
    before=$(count_signal_events_to "$a" "$b")
    for _ in $(seq 1 20); do
        kill -0 "$a"
        kill -STOP "$b"
        kill -CONT "$b"
    done
    kill -TERM "$a" "$b"
    wait "$a" "$b" 2>/dev/null || true
    sleep "$FLUSH_WAIT"
    expect_equal "Signal events from 62 unrelated signals" 0 $(($(count_signal_events_to "$a" "$b") - before))

    echo "2) Existence probe to the agent (event, no alert)"
    before=$(count_signal_events)
    local alerts_before
    alerts_before=$(count_tamper_alerts)
    kill -0 "$pid"
    sleep "$FLUSH_WAIT"
    expect_equal "Signal events from kill -0" 1 $(($(count_signal_events) - before))
    expect_equal "T1562.001 alerts from kill -0" 0 $(($(count_tamper_alerts) - alerts_before))

    echo "3) Unprivileged SIGTERM and SIGKILL to the agent (EPERM, still attributed)"
    before=$(count_signal_events)
    alerts_before=$(count_tamper_alerts)
    as_nobody kill -TERM "$pid" 2>/dev/null || true
    as_nobody kill -KILL "$pid" 2>/dev/null || true
    sleep "$FLUSH_WAIT"
    expect_equal "Signal events from the two attempts" 2 $(($(count_signal_events) - before))
    expect_equal "T1562.001 alerts from the two attempts" 2 $(($(count_tamper_alerts) - alerts_before))
    if kill -0 "$pid" 2>/dev/null; then
        echo "  PASS  agent survived the EPERM attempts"
    else
        fail_check "agent is gone"
    fi
    echo "  The survived SIGKILL is cleared from the pinned slot within ~10s, so it"
    echo "  must NOT be reported on the next restart (checked by 'kill' + 'verify-kill')."
}

run_kill() {
    local pid state
    pid=$(running_agent_pid_or_exit)
    require_event_files
    state=$(state_file)   # before the kill: no state directory, no kill
    # Wait out the sweep of any SIGKILL attempt from a previous live run, so the
    # slot can only hold the kill below.
    sleep 12
    echo "$$" >"$state"
    echo "Sender pid recorded in $state"
    echo "SIGKILL to agent pid $pid from pid $$ (comm $(cat /proc/$$/comm))"
    kill -KILL "$pid"
    echo "Restart the agent, then run: $0 verify-kill"
}

run_verify_kill() {
    local state sender
    state=$(state_file)
    [[ -f "$state" ]] || { echo "$state not found: run '$0 kill' first." >&2; exit 2; }
    sender=$(cat "$state")
    echo "Waiting up to 30s for the restarted agent's T1562.001 alert (sender pid $sender)"
    local found=0
    for _ in $(seq 1 30); do
        if grep '"technique":"T1562.001"' "$ALERTS" | grep -q "pid=$sender .*SIGKILL (9)"; then
            found=1
            break
        fi
        sleep 1
    done
    expect_equal "SIGKILL alert naming the sender" 1 "$found"
    # Two alerts are fine: the dying agent sometimes drains the live event before
    # the kill lands, and the replay reports it again.
    rm -f "$state"
}

case "$MODE" in
    live) run_live ;;
    kill) run_kill ;;
    verify-kill) run_verify_kill ;;
    *) echo "usage: $0 [live|kill|verify-kill]" >&2; exit 2 ;;
esac

if [[ "$MODE" != kill ]]; then
    if [[ "$FAILURES" -eq 0 ]]; then
        echo "All checks passed."
    else
        echo "$FAILURES check(s) failed."
        exit 1
    fi
fi
