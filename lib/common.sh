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
