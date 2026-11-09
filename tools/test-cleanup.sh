#!/usr/bin/env bash
# Checks the cleanup registry in lib/common.sh (add_cleanup, run_cleanups, kill_process,
# remove_empty_dirs), and that it is the only cleanup convention: no other shell script
# installs a `trap ... EXIT` of its own, which would silently replace the registry's.
#
#   tools/test-cleanup.sh

# shellcheck disable=SC2016  # the single-quoted snippets run in an inner bash, which expands them

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO/lib/common.sh"

failures=0
work=$(mktemp -d)
add_cleanup rm -rf "$work"

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

# with_common SNIPPET [ARG...] — run SNIPPET in a fresh bash that has sourced
# lib/common.sh, with ARG... as its $1, $2, ...
with_common() {
    bash -c '. "$1/lib/common.sh"; snippet=$2; shift 2; eval "$snippet"' bash "$REPO" "$@"
}

got=$(with_common 'add_cleanup echo first; add_cleanup echo second; add_cleanup echo third')
expect_equal "third
second
first" "$got" "steps run once each, last registered first"

got=$(with_common 'v="a b  c"; add_cleanup printf "[%s]\n" "$v"; v=changed')
expect_equal "[a b  c]" "$got" "arguments are captured by value when the step is registered"

got=$(with_common 'add_cleanup echo after; add_cleanup false; add_cleanup echo before')
expect_equal "before
after" "$got" "a failing step does not stop the others"

with_common 'add_cleanup true; exit 7'
expect_equal 7 "$?" "the script's own exit status survives the cleanup"

got=$(with_common 'set -e; add_cleanup echo cleaned; false; echo unreachable')
expect_equal cleaned "$got" "steps run when set -e stops the script"

got=$(with_common 'add_cleanup echo cleaned; die_precondition x' 2>/dev/null)
expect_equal cleaned "$got" "steps run on an unmet precondition"

with_common 'sleep 30 & add_cleanup kill_process "$!"; echo "$!"' > "$work/pid"
pid=$(<"$work/pid")
sleep 0.2
if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
    pass "kill_process stops the registered process"
else
    fail "process $pid is still running after cleanup"
    kill "$pid" 2>/dev/null
fi

with_common 'add_cleanup kill_process 999999999; exit 0' 2>"$work/err"
expect_equal 0 "$?" "kill_process tolerates a process that has already exited"
expect_equal "" "$(<"$work/err")" "kill_process prints nothing for a missing process"

mkdir -p "$work/empty/inner" "$work/full"
: > "$work/full/keep"
with_common 'add_cleanup remove_empty_dirs "$1/empty/inner" "$1/empty" "$1/full" "$1/missing"' "$work" 2>"$work/err"
if [ ! -e "$work/empty" ] && [ -e "$work/full/keep" ]; then
    pass "remove_empty_dirs removes the empty directories and leaves the others"
else
    fail "remove_empty_dirs: $(ls -A "$work")"
fi
expect_equal "" "$(<"$work/err")" "remove_empty_dirs prints nothing for a directory it leaves"

# One convention: only lib/common.sh traps EXIT.
offenders=$(cd "$REPO" && git ls-files -z '*.sh' | xargs -0 grep -lE '^[^#]*\btrap\b.*\bEXIT\b' | grep -vx 'lib/common.sh')
expect_equal "" "$offenders" "no script but lib/common.sh installs an EXIT trap (use add_cleanup)"

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
