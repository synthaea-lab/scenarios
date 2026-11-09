#!/usr/bin/env bash
# Checks write_run_json (ml-capture/run-json.sh), the writer of malicious-run.sh's run.json.
# The expected records for ordinary names are what the printf-built file held before; names
# that the printf version wrote as broken JSON must now round-trip.
#
#   tools/test-run-json.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../ml-capture/run-json.sh
. "$REPO/ml-capture/run-json.sh"
failures=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# expect_record DESCRIPTION WANT_COMPACT_JSON ARG... — write_run_json ARG... must succeed and
# write WANT_COMPACT_JSON (compared after a compact re-dump, keys in file order).
expect_record() {
    local description=$1 want=$2 got
    shift 2
    if ! write_run_json "$work/run.json" "$@" 2>"$work/err"; then
        echo "FAIL: $description: exit non-zero: $(<"$work/err")"
        failures=$((failures + 1))
        return
    fi
    got=$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), separators=(",", ":")))' "$work/run.json")
    if [ "$got" != "$want" ]; then
        echo "FAIL: $description: got $got, want $want"
        failures=$((failures + 1))
    else
        echo "ok: $description"
    fi
}

# expect_error DESCRIPTION ARG... — write_run_json ARG... must fail.
expect_error() {
    local description=$1
    shift
    if write_run_json "$work/bad.json" "$@" 2>/dev/null; then
        echo "FAIL: $description: succeeded"
        failures=$((failures + 1))
    else
        echo "ok: $description"
    fi
}

expect_record "ran and failed scenarios" \
    '{"root_pid":42,"start_ns":100,"end_ns":200,"ran":["beacon","lineage"],"failed":["argv"]}' \
    42 100 200 2 beacon lineage argv
expect_record "nothing ran or failed: empty lists" \
    '{"root_pid":42,"start_ns":100,"end_ns":200,"ran":[],"failed":[]}' \
    42 100 200 0
expect_record "an odd-parents name keeps its slash" \
    '{"root_pid":42,"start_ns":100,"end_ns":200,"ran":["odd-parents/webapp-spawns-shell"],"failed":[]}' \
    42 100 200 1 odd-parents/webapp-spawns-shell
expect_record "only failures" \
    '{"root_pid":1,"start_ns":1762600000000000000,"end_ns":1762600060000000000,"ran":[],"failed":["beacon","argv"]}' \
    1 1762600000000000000 1762600060000000000 0 beacon argv
expect_record "quotes, backslashes and spaces are escaped" \
    '{"root_pid":7,"start_ns":1,"end_ns":2,"ran":["a \"b\" c\\d"],"failed":[""]}' \
    7 1 2 1 'a "b" c\d' ''

expect_error "a non-numeric pid is refused" x 1 2 0
expect_error "an empty timestamp is refused" 7 '' 2 0
expect_error "a RAN_COUNT above the names given is refused" 7 1 2 3 beacon
expect_error "a missing argument is refused" 7 1 2

# The file is pretty-printed, one key per line, and ends with a newline (it is `cat`ed).
write_run_json "$work/run.json" 42 100 200 1 beacon
if [ "$(head -c 1 "$work/run.json")" = "{" ] && [ "$(tail -c 1 "$work/run.json" | od -An -c | tr -d ' ')" = '\n' ] \
    && grep -q '^  "root_pid": 42,$' "$work/run.json"; then
    echo "ok: the file is indented and ends with a newline"
else
    echo "FAIL: layout: $(cat "$work/run.json")"
    failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed."
    exit 1
fi
echo "All checks passed."
