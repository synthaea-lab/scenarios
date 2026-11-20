#!/usr/bin/env bash
# Checks the output helpers in lib/common.sh (say, done_msg), and that they are the only
# trailer convention: no scenario prints its own "Done."/"done:" line instead of calling
# done_msg.
#
#   tools/test-output.sh

# shellcheck disable=SC2016  # the single-quoted snippets run in an inner bash, which expands them

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failures=0

pass() { echo "ok: $1"; }
fail() { echo "FAIL: $1"; failures=$((failures + 1)); }

# expect_equal WANT GOT DESCRIPTION
expect_equal() {
    if [ "$1" = "$2" ]; then
        pass "$3"
    else
        fail "$3: got '$2', want '$1'"
    fi
}

# with_common SNIPPET — run SNIPPET in a fresh bash that has sourced lib/common.sh.
with_common() {
    bash -c '. "$1/lib/common.sh"; eval "$2"' bash "$REPO" "$1"
}

expect_equal "-n  two  words" "$(with_common 'say -n " two " words')" \
    "say prints its arguments verbatim on one line, even a leading -n"
expect_equal "Done. Expect in the agent's alerts: the T1571 alert." \
    "$(with_common 'done_msg "the T1571 alert"')" "done_msg prints the trailer in the shared style"
expect_equal "Done. Expect in the agent's alerts: one alert per run." \
    "$(with_common 'done_msg "one alert" "per run"')" "done_msg joins a long expectation split over arguments"
expect_equal "" "$(with_common 'done_msg x' 2>&1 >/dev/null)" "done_msg prints nothing on stderr"

# One convention: a scenario's trailer goes through done_msg. Read from the index, so the
# check sees what is committed even where an antivirus holds a scenario's working copy.
offenders=$(cd "$REPO" && git grep --cached -nE \
    '^[^#]*\b(echo|printf|say)[[:space:]]+["'\'']?[[:space:]]*[Dd]one\b' -- 'scenarios/*.sh')
expect_equal "" "$offenders" "no scenario prints its own Done trailer (use done_msg)"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
