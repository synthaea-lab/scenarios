#!/usr/bin/env bash
# System-wide shell-profile persistence scenario (T1546.004): a file written under
# /etc/profile.d/.
#
# check_persistence_write (agent crates/rules/src/stateless/persistence.rs) fires on a
# write-intent open whose path holds a known persistence location. persistence-write.sh
# covers one user's ~/.bashrc. This one covers the system-wide shape: an intruder with
# root drops a script in /etc/profile.d/, and every login shell of every user runs it.
#
# Safety: the file is named `*.marker`, not `*.sh`. /etc/profile sources only
# /etc/profile.d/*.sh, so no shell ever runs it. Its content is a single comment line, and
# it is removed on exit. The rule matches the directory, not the extension, so the alert is
# the one a real `*.sh` drop gets.
#
# Exactly one alert: the file is written by one redirection (one open). The removal is an
# unlink, which this rule does not watch.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: sudo ./scenarios/profile-d-write.sh (writes under /etc/profile.d/)
#   3) expected in terminal A:
#      T1546.004 — pid=... comm=...: write to a known persistence path (/etc/profile.d/):
#      /etc/profile.d/synthaea-scenario-<pid>.marker

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

require_root "it writes under /etc/profile.d/"
[ -d /etc/profile.d ] || die_precondition "/etc/profile.d does not exist on this host"

TARGET="/etc/profile.d/synthaea-scenario-$$.marker"
[ -e "$TARGET" ] && die_precondition "$TARGET already exists"

# [ -e ] first, so a clean run issues no second unlink after the script's own removal.
cleanup() { [ -e "$TARGET" ] && rm -f "$TARGET"; true; }
add_cleanup cleanup

say "Writing $TARGET (system-wide shell-profile persistence, T1546.004; never sourced: not *.sh)..."
MARKER_TEXT="# synthaea scenario marker"
MARKER_TEXT+=" (harmless; written and removed by scenarios/profile-d-write.sh)"
printf '%s\n' "$MARKER_TEXT" > "$TARGET"

say "Removing it..."
rm -f "$TARGET"

done_msg "the T1546.004 alert"
