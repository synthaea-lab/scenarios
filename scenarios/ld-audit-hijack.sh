#!/usr/bin/env bash
# Dynamic linker hijack through LD_AUDIT (T1574.006), the quieter sibling of LD_PRELOAD.
#
# check_ld_preload_hijack (agent crates/rules/src/stateless/privilege_escalation.rs) fires
# when an exec's captured security environment holds LD_PRELOAD or LD_AUDIT pointing outside
# the dynamic linker's trust set. ld-preload-hijack.sh covers LD_PRELOAD. LD_AUDIT loads an
# rtld-audit library into the process before any other object and is seen far less often,
# which is why an intruder reaches for it. The library here only proves it was loaded (its
# la_version writes a marker file): no symbol binding is changed, nothing is hidden.
#
# glibc only: musl's dynamic linker ignores LD_AUDIT. The agent still captures the variable
# and alerts there, but the marker is missing and the script says so.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./scenarios/ld-audit-hijack.sh (no root needed)
#   3) expected in terminal A:
#      T1574.006 — pid=... comm=sleep: LD_AUDIT=/tmp/synthaea-ldaudit-.../audit.so loads a
#      shared object outside the dynamic linker's trusted search path

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

require_command cc "install a C compiler: Debian apt install build-essential, Fedora dnf install gcc"

# Under /tmp, which the rule never trusts, whatever /etc/ld.so.conf lists.
make_workdir DIR "${TMPDIR:-/tmp}" synthaea-ldaudit-
SRC="$DIR/audit.c"
LIB="$DIR/audit.so"
MARKER="$DIR/loaded.marker"

cat > "$SRC" <<C
/* An rtld-audit library that only proves the dynamic linker loaded it: la_version is the
 * one entry point it must export, and it writes a marker file. No other hook. */
#include <stdio.h>
unsigned int la_version(unsigned int version) {
    FILE *f = fopen("$MARKER", "w");
    if (f) {
        fputs("loaded\n", f);
        fclose(f);
    }
    return version;
}
C

say "Compiling the benign audit library ($LIB, outside the linker trust set)..."
cc -fPIC -shared -o "$LIB" "$SRC"

say "Running 'sleep' with LD_AUDIT=$LIB (untrusted path)..."
LD_AUDIT="$LIB" sleep 0.3

if [ -f "$MARKER" ]; then
    say "la_version ran (marker file present): the audit library was loaded."
else
    echo "WARNING: marker file missing: this dynamic linker did not load the audit library (musl?)." >&2
fi

done_msg "the T1574.006 alert"
