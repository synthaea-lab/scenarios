#!/usr/bin/env bash
# Checks the precondition helpers in lib/common.sh and that scenarios which cannot run
# on this host stop with the documented exit code (2), not 1. Runs unprivileged and
# touches nothing: every case stops at a precondition before the scenario does anything.
#
#   tools/test-preconditions.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

# expect_exit WANT_RC WANT_STDERR_SUBSTRING DESCRIPTION COMMAND [ARG...]
expect_exit() {
    local want_rc=$1 want_stderr=$2 description=$3 stderr rc
    shift 3
    stderr=$("$@" 2>&1 >/dev/null)
    rc=$?
    if [ "$rc" -ne "$want_rc" ] || [[ "$stderr" != *"$want_stderr"* ]]; then
        echo "FAIL: $description: exit $rc, stderr '$stderr' (want exit $want_rc, stderr containing '$want_stderr')"
        failures=$((failures + 1))
    else
        echo "ok: $description"
    fi
}

# with_common SNIPPET — run SNIPPET in a fresh bash that has sourced lib/common.sh.
with_common() {
    bash -c '. "$1/lib/common.sh"; eval "$2"' bash "$REPO" "$1"
}

expect_exit 2 "ERROR: precondition not met: the host is not set up" \
    "die_precondition exits 2 with an ERROR line" \
    with_common 'die_precondition "the host is not set up"; exit 0'
expect_exit 2 "no-such-command-synthaea not found (install it)" \
    "require_command exits 2 for a missing command and shows the hint" \
    with_common 'require_command no-such-command-synthaea "install it"; exit 0'
expect_exit 2 "no-such-command-synthaea not found" \
    "require_command works without a hint" \
    with_common 'require_command no-such-command-synthaea; exit 0'
expect_exit 0 "" "require_command returns for a present command" \
    with_common 'require_command bash'
expect_exit 2 "no web server answers at http://127.0.0.1:1" \
    "require_web_server exits 2 when nothing listens" \
    with_common 'require_web_server http://127.0.0.1:1; exit 0'
expect_exit 7 "" "die_precondition runs registered cleanups" \
    with_common 'add_cleanup exit 7; die_precondition x'

if [ "$(id -u)" -ne 0 ]; then
    expect_exit 2 "run as root (it needs to)" "require_root exits 2 when unprivileged" \
        with_common 'require_root "it needs to"; exit 0'
    for scenario in log-clear pid-reuse; do
        expect_exit 2 "precondition not met: run as root" "$scenario.sh unprivileged exits 2" \
            bash "$REPO/scenarios/$scenario.sh"
    done
    expect_exit 2 "precondition not met: run as root" "malicious-run.sh unprivileged exits 2" \
        bash "$REPO/ml-capture/malicious-run.sh" /nonexistent
else
    expect_exit 0 "" "require_root returns as root" with_common 'require_root "it needs to"'
fi

for scenario in web-custom-logformat web-webshell; do
    expect_exit 2 "no web server answers at http://127.0.0.1:1" \
        "$scenario.sh with no web server exits 2" \
        bash "$REPO/scenarios/$scenario.sh" http://127.0.0.1:1
done

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed."
    exit 1
fi
echo "All checks passed."
