#!/usr/bin/env bash
# Log-clearing scenario, exec side (T1070.002): journald vacuumed to nothing.
#
# check_log_clear_exec (agent crates/rules/src/stateless/indicator_removal.rs) fires when an
# exec's command line holds `journalctl` and `--vacuum`. An intruder runs
# `journalctl --vacuum-time=1s` to drop every archived journal file in one command, without
# touching a file under /var/log/ itself. That is the second way to clear Linux logs, next to
# log-clear.sh's file delete (check_log_file_delete).
#
# Here the command points `-D` at a throwaway journal directory the scenario creates, so the
# real system journal is never vacuumed. The rule reads only the command line, so the alert is
# the same as for the system journal.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./scenarios/journald-vacuum.sh (no root needed)
#   3) expected in terminal A:
#      T1070.002 — pid=... comm=journalctl: log-clearing command: journalctl -D ... --vacuum-time=1s

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

require_command journalctl "it is the command the rule watches (a systemd distro)"

make_workdir JOURNAL_DIR "${TMPDIR:-/tmp}" synthaea-journal-

say "Vacuuming a throwaway journal directory ($JOURNAL_DIR) to nothing (T1070.002)..."
journalctl -D "$JOURNAL_DIR" --vacuum-time=1s

done_msg "the T1070.002 alert"
