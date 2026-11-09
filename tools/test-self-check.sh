#!/usr/bin/env bash
# Checks the self-check helpers in lib/common.sh (require_expect_mode, check_fail,
# exit_with_checks) and how the self-checking scenarios treat a missing or wrong EXPECT.
# Runs unprivileged and touches nothing: every scenario case stops at EXPECT, before the
# scenario does anything.
#
#   tools/test-self-check.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO/lib/common.sh"
failures=0

# expect_run WANT_RC WANT_STDOUT WANT_STDERR_SUBSTRING DESCRIPTION COMMAND [ARG...]
# WANT_STDOUT is matched exactly; WANT_STDERR_SUBSTRING as a substring.
expect_run() {
    local want_rc=$1 want_stdout=$2 want_stderr=$3 description=$4 out err rc
    shift 4
    out=$("$@" 2>"$stderr_file")
    rc=$?
    err=$(<"$stderr_file")
    if [ "$rc" -ne "$want_rc" ] || [ "$out" != "$want_stdout" ] || [[ "$err" != *"$want_stderr"* ]]; then
        echo "FAIL: $description: exit $rc, stdout '$out', stderr '$err'" \
            "(want exit $want_rc, stdout '$want_stdout', stderr containing '$want_stderr')"
        failures=$((failures + 1))
    else
        echo "ok: $description"
    fi
}

stderr_file=$(mktemp)
add_cleanup rm -f "$stderr_file"

# with_common SNIPPET — run SNIPPET in a fresh bash that has sourced lib/common.sh.
with_common() {
    bash -c '. "$1/lib/common.sh"; eval "$2"' bash "$REPO" "$1"
}

for mode in enforce observe; do
    expect_run 0 "$mode" "" "require_expect_mode accepts EXPECT=$mode" \
        env EXPECT="$mode" bash -c '. "$1/lib/common.sh"; require_expect_mode; echo "$EXPECT"' bash "$REPO"
done
expect_run 2 "" "EXPECT must be enforce or observe" "require_expect_mode exits 2 for EXPECT=bogus" \
    env EXPECT=bogus bash -c '. "$1/lib/common.sh"; require_expect_mode; exit 0' bash "$REPO"

expect_run 0 "all good" "" "exit_with_checks with no failure prints OK and exits 0" \
    with_common 'exit_with_checks "all good"'
expect_run 1 "" $'FAIL: first\nFAIL: second' "check_fail reports every failure and exit_with_checks exits 1 silently" \
    with_common 'check_fail first; check_fail second; exit_with_checks "all good"'
expect_run 7 "" "FAIL: x" "exit_with_checks still runs registered cleanups" \
    with_common 'add_cleanup exit 7; check_fail x; exit_with_checks ok'

# Unset or empty EXPECT is checked through the scenarios only: bash's `:?` exits 1 from a
# script file but 127 from a `bash -c` string, and the scripts are what callers run.
for scenario in response ransomware-reflex; do
    expect_run 2 "" "EXPECT must be enforce or observe" "$scenario.sh with EXPECT=bogus exits 2" \
        env EXPECT=bogus bash "$REPO/scenarios/$scenario.sh"
    expect_run 1 "" "EXPECT: set EXPECT=enforce or EXPECT=observe" "$scenario.sh with EXPECT unset exits 1" \
        env -u EXPECT bash "$REPO/scenarios/$scenario.sh"
    expect_run 1 "" "EXPECT: set EXPECT=enforce or EXPECT=observe" "$scenario.sh with EXPECT empty exits 1" \
        env EXPECT= bash "$REPO/scenarios/$scenario.sh"
done

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed."
    exit 1
fi
echo "All checks passed."
