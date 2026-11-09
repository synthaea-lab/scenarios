#!/usr/bin/env bash
# Checks tools/check-python-snippets.py on small shell scripts: what it extracts, and that a
# broken snippet makes it fail. The ruff cases run only when RUFF names a ruff executable.
#
#   RUFF=ruff tools/test-python-snippets.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$REPO/tools/check-python-snippets.py"
RUFF="${RUFF:-}"
failures=0
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# expect DESCRIPTION WANT_RC WANT_OUTPUT_SUBSTRING SCRIPT_TEXT [CHECK_ARG...] — run the check
# on one script holding SCRIPT_TEXT.
expect() {
    local description=$1 want_rc=$2 want_output=$3 script=$4 output rc
    shift 4
    printf '%s\n' "$script" > "$work/script.sh"
    output=$(cd "$work" && python3 "$CHECK" "$@" script.sh 2>&1)
    rc=$?
    if [ "$rc" -ne "$want_rc" ] || [[ "$output" != *"$want_output"* ]]; then
        echo "FAIL: $description: exit $rc, output '$output' (want exit $want_rc, output containing '$want_output')"
        failures=$((failures + 1))
    else
        echo "ok: $description"
    fi
}

heredoc() { printf "python3 - <<'%s'\n%s\n%s\n" "$1" "$2" "$1"; }

expect "a PY heredoc and a -c string compile" 0 "1 heredoc and 1 -c Python snippets compile" \
    "$(heredoc PY 'import sys
print(sys.argv)')
python3 -c 'import os; print(os.sep)'"
expect "a syntax error in a heredoc fails on the shell script's line" 1 "script.sh:4: heredoc snippet" \
    "echo first
$(heredoc PY 'x = 1
def broken(:')"
expect "a syntax error in a -c string fails" 1 "script.sh:1: -c snippet" \
    "python3 -c 'print(('"
expect "a -c string through a renamed python3 copy is extracted" 0 "0 heredoc and 1 -c" \
    "\"\$TOOLS/user-python3\" -c 'print(1)'"
expect "a Python heredoc under another tag is reported" 1 "Python heredoc tagged 'EOF'" \
    "$(heredoc EOF 'print(1)')"
expect "a non-Python heredoc is ignored" 1 "no Python snippet found" \
    "cat > out.c <<'C'
int main(void) { return 0; }
C"
expect "a -c string quoted in a comment is ignored" 1 "no Python snippet found" \
    "# as \`python3 -c 'socket.getaddrinfo(...)'\` does"
expect "a -c string inside a heredoc body is ignored" 1 "no Python snippet found" \
    "cat > inner.sh <<'SH'
python3 -c 'print(('
SH"
expect "an unclosed heredoc is reported" 1 "is never closed" \
    "python3 - <<'PY'
print(1)"

if [ -n "$RUFF" ]; then
    expect "ruff: an undefined name in a heredoc fails on the shell script's line" 1 "script.sh:3:7: F821" \
        "echo first
$(heredoc PY 'print(undefined_name)')" --ruff "$RUFF"
    expect "ruff: an unused import in a heredoc fails" 1 "F401" \
        "$(heredoc PY 'import os')" --ruff "$RUFF"
    expect "ruff: one-line imports in a heredoc are allowed" 0 "lint clean" \
        "$(heredoc PY 'import os, sys
print(os.sep, sys.argv)')" --ruff "$RUFF"
    expect "ruff: an unused import in a -c string (frozen argv) is allowed" 0 "lint clean" \
        "python3 -c 'import os,sys; print(1)'" --ruff "$RUFF"
    expect "ruff: an undefined name in a -c string fails" 1 "F821" \
        "python3 -c 'print(undefined_name)'" --ruff "$RUFF"
else
    echo "skip: ruff cases (set RUFF to a ruff executable)"
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed"
    exit 1
fi
echo "all checks passed"
