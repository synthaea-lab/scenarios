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

# kill_process PID — stop one process, tolerating one that has already exited.
kill_process() {
    kill "$1" 2>/dev/null || true
}

# remove_empty_dirs DIR... — remove each DIR, in order, if it is empty; a DIR that
# is not empty (or not there) is left alone.
remove_empty_dirs() {
    rmdir "$@" 2>/dev/null || true
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

# Throwaway work directory and files. Scenarios that rename, stomp or drop files do
# it in a fresh directory of their own, so no real data is touched and nothing is
# left behind.
#
# make_workdir VAR BASE PREFIX — create the directory BASE/PREFIXxxxxxx with
# `mktemp -d`, store its path in the variable named VAR, and register its removal.
# Exits 1 if the directory cannot be created.
#
# Keep PREFIX stable: detection rules and validate scripts may key on the path
# (e.g. $HOME/synthaea-scenario-*). The path comes back through VAR rather than
# through `$(make_workdir ...)`: a command substitution around the function would
# put a subshell between the scenario and mktemp (changing the process tree under
# test), and the removal registered in that subshell would be lost. Here mktemp
# stays a direct child of the scenario's shell, as with an inline `$(mktemp -d ...)`.
make_workdir() {
    # Not named `dir`: a caller passing VAR=dir would only set this local.
    local _workdir_path
    _workdir_path=$(mktemp -d "$2/$3XXXXXX") && [ -d "$_workdir_path" ] \
        || { echo "ERROR: cannot create a work directory under $2" >&2; exit 1; }
    add_cleanup rm -rf "$_workdir_path"
    printf -v "$1" '%s' "$_workdir_path"
}

# create_throwaway_files DIR COUNT PATTERN — create COUNT empty files in DIR, named
# by the printf format PATTERN applied to 0..COUNT-1 (e.g. 'file%d.docx'). Builtins
# only, so it adds no process to the scenario's tree.
create_throwaway_files() {
    local dir=$1 count=$2 pattern=$3 index name
    for (( index = 0; index < count; index++ )); do
        # shellcheck disable=SC2059  # PATTERN is the caller's printf format
        printf -v name "$pattern" "$index"
        : > "$dir/$name"
    done
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

# Fake web server: a copy of a real shell binary under a web server's name, so the
# processes it runs have a parent whose comm (the file's basename) is "nginx" or the
# like. Used by lineage, prevalence-lineage and web-webshell.
#
# make_fake_webserver PATH [SH] — copy the shell binary SH (default /bin/sh) to PATH.
# If SH resolves to busybox, copy $BASH instead: busybox is a multi-call binary that
# dispatches on argv[0], so a copy named "nginx" fails with "applet not found", and
# $BASH is the standalone interpreter running this script.
#
# It only copies, in the caller's shell: no subshell, so readlink and cp stay direct
# children of the scenario. The caller spawns from
# PATH itself, so the spawned shells' parent and argv stay exactly what the scenario
# documents, and it registers the removal of PATH (or of its directory). Spawn with
# an explicit subshell,
#   "$PATH" -c '(/bin/sh -c "id >/dev/null")'
# because bash and dash exec a `-c` body that is one simple command in place instead
# of forking, which would leave the child's ppid on the scenario.
make_fake_webserver() {
    local sh=${2:-/bin/sh} target
    target=$(readlink -f "$sh" 2>/dev/null || echo "$sh")
    if [[ "$target" == *busybox* ]]; then
        cp "$BASH" "$1"
    else
        cp "$sh" "$1"
    fi
}

# spawn_shells_from FAKE ITERATIONS — the lineage stimulus: ITERATIONS times, one
# second apart, have the fake web server FAKE (see make_fake_webserver) run a shell
# that runs a leaf command. Used by lineage and prevalence-lineage.
#
# The loop runs in the caller's shell (call it directly, never inside `$(...)` or a
# pipeline), so FAKE stays a direct child of the scenario and its ppid is unchanged.
# The inner shell is wrapped in an explicit subshell because bash and dash exec a
# `-c` body that is one simple command in place instead of forking, which would
# leave the leaf's ppid on the scenario rather than on FAKE.
spawn_shells_from() {
    local fake=$1 iterations=$2 i
    local inner_cmd='(/bin/sh -c "id >/dev/null")'
    for i in $(seq 1 "$iterations"); do
        # FAKE (comm 'nginx' or the like) execs a child shell, which execs the leaf.
        "$fake" -c "$inner_cmd"
        echo "  iteration $i done"
        sleep 1
    done
}

# Self-checking response scenarios (response, ransomware-reflex). They run once
# against an agent started with the response enabled and once against one started
# without it, and EXPECT says which, so the script knows what its own side should
# look like afterwards.
#
# require_expect_mode — validate EXPECT (enforce or observe) and leave it set.
# Unset or empty stops the script with bash's own `:?` error (exit 1); any other
# value exits 2.
require_expect_mode() {
    EXPECT="${EXPECT:?set EXPECT=enforce or EXPECT=observe to match how the agent was started}"
    case "$EXPECT" in
        enforce | observe) ;;
        *) echo "EXPECT must be enforce or observe" >&2; exit 2 ;;
    esac
}

# Self-check verdict. Each failed check is reported as it is found and every check
# still runs, so one run shows them all; exit_with_checks then turns them into the
# exit status. The FAIL token is what the rig runner quotes from a scenario's log.
_check_failed=0

# check_fail MESSAGE — report one failed self-check.
check_fail() {
    echo "FAIL: $*" >&2
    _check_failed=1
}

# exit_with_checks OK_MESSAGE — print OK_MESSAGE and exit 0 if no check failed,
# otherwise exit 1.
exit_with_checks() {
    if [ "$_check_failed" -eq 0 ]; then
        echo "$1"
    fi
    exit "$_check_failed"
}
