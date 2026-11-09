#!/usr/bin/env bash
# Checks make_workdir and create_throwaway_files in lib/common.sh, and that the
# unprivileged scenarios built on them run and leave nothing behind. Runs unprivileged
# and writes only to a temporary directory (passed to the scenarios as HOME).
#
#   tools/test-workdir.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO/lib/common.sh"

failures=0
work=$(mktemp -d)
add_cleanup rm -rf "$work"

pass() { echo "ok: $1"; }
fail() {
    echo "FAIL: $1"
    failures=$((failures + 1))
}

# expect_equal WANT GOT DESCRIPTION
expect_equal() {
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3: got '$2', want '$1'"; fi
}

# with_common SNIPPET [ARG...] — run SNIPPET in a fresh bash that has sourced
# lib/common.sh, with ARG... as its $1, $2, ...
with_common() {
    bash -c '. "$1/lib/common.sh"; snippet=$2; shift 2; eval "$snippet"' bash "$REPO" "$@"
}

# --- make_workdir ----------------------------------------------------------------

base="$work/base"
mkdir "$base"
path=$(with_common 'make_workdir DIR "$1" synthaea-scenario-test-; [ -d "$DIR" ] && echo "$DIR"' "$base" 2>&1) \
    || fail "make_workdir in a writable base"
case "$path" in
    "$base"/synthaea-scenario-test-??????) pass "make_workdir names the directory BASE/PREFIX + 6 characters" ;;
    *) fail "make_workdir created '$path'" ;;
esac
if [ -n "$path" ] && [ ! -e "$path" ]; then
    pass "make_workdir's directory is removed at exit"
else
    fail "make_workdir's directory '$path' is still there after exit"
fi

# The variable may be named like the helper's own locals.
got=$(with_common 'make_workdir dir "$1" p-; [ -d "$dir" ] && echo set' "$base")
expect_equal set "$got" "make_workdir sets a caller variable named 'dir'"

# Steps registered before and after it still run (the registry composes).
with_common 'add_cleanup touch "$1/first"; make_workdir D "$1" p-; add_cleanup touch "$1/last"' "$base"
if [ -e "$base/first" ] && [ -e "$base/last" ]; then
    pass "other cleanup steps still run"
else
    fail "a cleanup step registered next to make_workdir did not run"
fi
rm -f "$base/first" "$base/last"
expect_equal "" "$(ls -A "$base")" "nothing is left in BASE"

# A base that cannot hold the directory: exit 1 with an ERROR line, nothing created.
err=$(with_common 'make_workdir D "$1/missing" p-; echo reached' "$base" 2>&1)
rc=$?
expect_equal 1 "$rc" "make_workdir exits 1 when mktemp fails"
case "$err" in
    *"ERROR: cannot create a work directory under $base/missing"*) pass "make_workdir reports the failure" ;;
    *) fail "make_workdir failure output: '$err'" ;;
esac
[[ "$err" == *reached* ]] && fail "the caller continued after make_workdir failed"

# mktemp must stay a direct child of the scenario's shell, exactly like an inline
# DIR="$(mktemp -d ...)": the process tree is what the agent observes.
fakebin="$work/fakebin"
mkdir "$fakebin"
real_mktemp=$(command -v mktemp)
cat > "$fakebin/mktemp" <<EOF
#!/bin/sh
echo "\$PPID" > "$work/mktemp.ppid"
exec "$real_mktemp" "\$@"
EOF
chmod +x "$fakebin/mktemp"
for form in 'D="$(mktemp -d "$1/p-XXXXXX")"' 'make_workdir D "$1" p-'; do
    shell_pid=$(PATH="$fakebin:$PATH" with_common "$form; echo \$\$" "$base")
    expect_equal "$shell_pid" "$(cat "$work/mktemp.ppid" 2>/dev/null)" "mktemp's parent is the calling shell: $form"
done
rm -rf "${base:?}"/*

# --- create_throwaway_files ------------------------------------------------------

files="$work/files"
mkdir "$files"
create_throwaway_files "$files" 3 's%d.conf'
expect_equal "s0.conf s1.conf s2.conf" "$(cd "$files" && echo *)" "create_throwaway_files names 0..COUNT-1"
empty=$(find "$files" -type f -size 0 | wc -l)
expect_equal 3 "$empty" "create_throwaway_files creates empty files"
create_throwaway_files "$files" 0 'x%d'
expect_equal 3 "$(find "$files" -type f | wc -l)" "COUNT=0 creates nothing"

# --- scenarios built on them -------------------------------------------------------

# run_scenario DESCRIPTION WANT_OUTPUT_SUBSTRING [ENV=VALUE...] SCRIPT [ARG...] — run a
# scenario with HOME pointing at an empty directory; it must exit 0, print the
# substring, and leave HOME empty.
run_scenario() {
    local description=$1 want=$2 home="$work/home" out rc
    shift 2
    rm -rf "$home"
    mkdir "$home"
    out=$(env HOME="$home" "$@" 2>&1)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "$description: exit $rc: $out"
    elif [[ "$out" != *"$want"* ]]; then
        fail "$description: output lacks '$want': $out"
    elif [ -n "$(ls -A "$home")" ]; then
        fail "$description: left $(ls -A "$home") in HOME"
    else
        pass "$description"
    fi
}

if command -v python3 >/dev/null 2>&1; then
    for mode in single loop; do
        run_scenario "ransomware-rename-burst $mode" \
            "Creating 22 throwaway files in $work/home/synthaea-scenario-ransomware-" \
            bash "$REPO/scenarios/ransomware-rename-burst.sh" "$mode"
    done
    run_scenario "timestomp-linux" "" bash "$REPO/scenarios/timestomp-linux.sh"

    # ransomware-reflex against a hand-made canary, observe side: every throwaway
    # file is created and renamed, then removed.
    canaries="$work/canaries"
    mkdir "$canaries"
    printf '# SYNTHAEA DECOY\n' > "$canaries/decoy.txt"
    run_scenario "ransomware-reflex observe" "files renamed: 30 of 30" \
        CANARY_DIR="$canaries" EXPECT=observe COUNT=30 PAUSE=0 \
        bash "$REPO/scenarios/ransomware-reflex.sh"
    expect_equal "decoy.txt" "$(ls -A "$canaries")" "ransomware-reflex leaves only the canary"
else
    echo "skip: python3 not found, scenario runs skipped"
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed."
    exit 1
fi
echo "All checks passed."
