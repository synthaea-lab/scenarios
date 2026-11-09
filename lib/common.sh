# shellcheck shell=bash
#
# Shared helpers for the Linux/macOS scenarios, sourced (never executed) via
#   . "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
#
# This file lives in lib/, not next to the scenarios: rig's run-scenarios.sh
# --check demands a catalog sidecar for every scenarios/*.sh, and a sourced
# helper is not a scenario.

# Teardown steps registered by scenarios, run once on exit in reverse (LIFO)
# order. A per-step `trap ... EXIT` would silently replace the previous one and
# leak whatever it had been cleaning up; the registry composes instead.
_cleanup_steps=()

# add_cleanup CMD [ARG...] — queue a command to run at exit. Arguments are
# captured by value now, so a step registered with the live value of a variable
# still runs with that value after the variable is gone.
add_cleanup() {
    _cleanup_steps+=("$(printf '%q ' "$@")")
}

run_cleanups() {
    local index
    for (( index = ${#_cleanup_steps[@]} - 1; index >= 0; index-- )); do
        eval "${_cleanup_steps[index]}" || true
    done
}
trap run_cleanups EXIT

# kill_process_group PGID — tear down a whole process group, tolerating one that
# has already exited. Registered by start_loopback_listener.
kill_process_group() {
    kill -- -"$1" 2>/dev/null || true
}

# start_loopback_listener BODY [ARG...] — run BODY as a background listener in
# its own session (process group) and register that group's teardown.
#
# The listener gets its own session so cleanup reaches the nc child, not just
# the loop: `kill $!` alone leaves an orphaned nc holding the port, and the next
# run's `nc -l` then fails and the loop spins hot (#113).
#
# BODY is handed to a fresh bash as its `-c` string and ARG... as that bash's
# positional parameters ($1, $2, ...), so each scenario keeps its own listener
# body verbatim. The spawn is deliberately NOT wrapped in a subshell: a
# scenario's process tree, names, args and paths are the behaviour under test,
# and an extra shell between this one and setsid would change them.
start_loopback_listener() {
    local body=$1
    shift
    setsid bash -c "$body" bash "$@" &
    add_cleanup kill_process_group "$!"
}

# Precondition checks. A scenario that cannot run here (not root, a tool or a
# service missing) exits with PRECONDITION_EXIT_CODE, so a caller can tell "the
# host is not set up for this" (2) from "the scenario ran and its self-check
# failed" (1). The message carries the ERROR token the rig runner quotes from a
# failing scenario's log.
readonly PRECONDITION_EXIT_CODE=2

# die_precondition MESSAGE — report an unmet precondition and exit.
die_precondition() {
    echo "ERROR: precondition not met: $*" >&2
    exit "$PRECONDITION_EXIT_CODE"
}

# require_root REASON — exit unless running as root; REASON says why root is
# needed (e.g. "it writes under /var/log").
require_root() {
    [ "$(id -u)" -eq 0 ] || die_precondition "run as root ($1)"
}

# require_command COMMAND [HINT] — exit unless COMMAND is on PATH; HINT, if
# given, says how to install it.
require_command() {
    command -v "$1" >/dev/null 2>&1 || die_precondition "$1 not found${2:+ ($2)}"
}

# require_web_server URL — exit unless a web server answers at URL.
require_web_server() {
    curl -s -o /dev/null --max-time 3 "$1/" || die_precondition "no web server answers at $1"
}
