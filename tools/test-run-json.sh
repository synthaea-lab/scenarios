#!/usr/bin/env bash
# Checks write_run_json (ml-capture/run-json.sh), the writer of malicious-run.sh's run.json.
# `ran` and `failed` keep the shape t1_lineage_gain reads; `scenarios` adds each scenario's own
# pid and window. Names that a printf-built file would have written as broken JSON round-trip.
#
#   tools/test-run-json.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO/lib/common.sh"
# shellcheck source=../ml-capture/run-json.sh
. "$REPO/ml-capture/run-json.sh"
failures=0
work=$(mktemp -d)
add_cleanup rm -rf "$work"
tsv_count=0

# tsv LINE... — write a scenarios file holding LINEs (fields already tab-separated) and print
# its path.
tsv() {
    tsv_count=$((tsv_count + 1))
    local file="$work/scenarios.$tsv_count.tsv" line
    : > "$file"
    for line in "$@"; do
        printf '%s\n' "$line" >> "$file"
    done
    echo "$file"
}

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

T=$'\t'

expect_record "ran and failed scenarios, in run order" \
    '{"root_pid":42,"start_ns":100,"end_ns":200,"ran":["beacon","lineage"],"failed":["argv"],"scenarios":[{"name":"beacon","pid":50,"start_ns":101,"end_ns":110,"exit_code":0},{"name":"argv","pid":60,"start_ns":120,"end_ns":130,"exit_code":1},{"name":"lineage","pid":70,"start_ns":140,"end_ns":150,"exit_code":0}]}' \
    42 100 200 "$(tsv "beacon${T}50${T}101${T}110${T}0" "argv${T}60${T}120${T}130${T}1" "lineage${T}70${T}140${T}150${T}0")"
expect_record "nothing started: empty lists" \
    '{"root_pid":42,"start_ns":100,"end_ns":200,"ran":[],"failed":[],"scenarios":[]}' \
    42 100 200 "$(tsv)"
expect_record "an odd-parents name keeps its slash" \
    '{"root_pid":42,"start_ns":100,"end_ns":200,"ran":["odd-parents/webapp-spawns-shell"],"failed":[],"scenarios":[{"name":"odd-parents/webapp-spawns-shell","pid":43,"start_ns":100,"end_ns":200,"exit_code":0}]}' \
    42 100 200 "$(tsv "odd-parents/webapp-spawns-shell${T}43${T}100${T}200${T}0")"
expect_record "a timeout (124) is a failure" \
    '{"root_pid":1,"start_ns":1762600000000000000,"end_ns":1762600060000000000,"ran":[],"failed":["beacon"],"scenarios":[{"name":"beacon","pid":2,"start_ns":1762600000000000001,"end_ns":1762600050000000000,"exit_code":124}]}' \
    1 1762600000000000000 1762600060000000000 "$(tsv "beacon${T}2${T}1762600000000000001${T}1762600050000000000${T}124")"
expect_record "quotes, backslashes and spaces are escaped" \
    '{"root_pid":7,"start_ns":1,"end_ns":2,"ran":["a \"b\" c\\d"],"failed":[""],"scenarios":[{"name":"a \"b\" c\\d","pid":8,"start_ns":1,"end_ns":2,"exit_code":0},{"name":"","pid":9,"start_ns":2,"end_ns":2,"exit_code":3}]}' \
    7 1 2 "$(tsv "a \"b\" c\\d${T}8${T}1${T}2${T}0" "${T}9${T}2${T}2${T}3")"

expect_error "a non-numeric root pid is refused" x 1 2 "$(tsv)"
expect_error "an empty timestamp is refused" 7 '' 2 "$(tsv)"
expect_error "a missing argument is refused" 7 1 2
expect_error "a missing scenarios file is refused" 7 1 2 "$work/absent.tsv"
expect_error "a line with four fields is refused" 7 1 9 "$(tsv "beacon${T}8${T}1${T}2")"
expect_error "a line with six fields is refused" 7 1 9 "$(tsv "beacon${T}8${T}1${T}2${T}0${T}x")"
expect_error "a non-numeric scenario pid is refused" 7 1 9 "$(tsv "beacon${T}x${T}1${T}2${T}0")"
expect_error "a non-numeric exit code is refused" 7 1 9 "$(tsv "beacon${T}8${T}1${T}2${T}ok")"
expect_error "a scenario starting before the run is refused" 7 5 9 "$(tsv "beacon${T}8${T}4${T}6${T}0")"
expect_error "a scenario ending after the run is refused" 7 1 9 "$(tsv "beacon${T}8${T}2${T}10${T}0")"
expect_error "a scenario ending before it starts is refused" 7 1 9 "$(tsv "beacon${T}8${T}6${T}5${T}0")"

# The file is pretty-printed, one key per line, and ends with a newline (it is `cat`ed).
write_run_json "$work/run.json" 42 100 200 "$(tsv "beacon${T}43${T}100${T}200${T}0")"
if [ "$(head -c 1 "$work/run.json")" = "{" ] && [ "$(tail -c 1 "$work/run.json" | od -An -c | tr -d ' ')" = '\n' ] \
    && grep -q '^  "root_pid": 42,$' "$work/run.json"; then
    echo "ok: the file is indented and ends with a newline"
else
    echo "FAIL: layout: $(cat "$work/run.json")"
    failures=$((failures + 1))
fi

# malicious-run.sh's capture of a scenario's pid: the subshell's $BASHPID survives the exec
# into `timeout`, so the recorded pid is the parent of the scenario's own process, the root of
# the tree it runs in. A script that prints its parent's pid must print the recorded one.
script="$work/prints-parent.sh"
# shellcheck disable=SC2016  # $PPID belongs to the generated script, not to this one
printf '#!/usr/bin/env bash\necho "$PPID"\n' > "$script"
chmod +x "$script"
( echo "$BASHPID" > "$work/pid"; exec timeout 10 "$script" ) > "$work/out" 2>&1
if [ -s "$work/pid" ] && [ "$(<"$work/pid")" = "$(<"$work/out")" ]; then
    echo "ok: the recorded pid is the scenario's parent (timeout)"
else
    echo "FAIL: recorded pid $(<"$work/pid"), scenario's parent $(<"$work/out")"
    failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed."
    exit 1
fi
echo "All checks passed."
