#!/usr/bin/env bash
# Command obfuscation by argument padding (T1027.010): a shell command line long enough
# that its middle is not captured, with the command that does the work placed there.
#
# The Linux eBPF probe keeps a whole argument block up to 1 KiB; past that it keeps the
# first 768 and the last 256 bytes (ADR-0045) and reports how many bytes it left out.
# check_truncated_cmdline (agent crates/rules/src/stateless/defense_evasion.rs) alerts on
# that cut, because every content rule is blind to the omitted bytes. Here a `sh -c`
# string carries 2 KiB of no-op `:` padding, then the command, then 1 KiB more padding:
# the command sits in the omitted middle, as an intruder would hide a payload. The command
# only prints a line.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./scenarios/argv-padding.sh (no root needed)
#   3) expected in terminal A:
#      T1027.010 — pid=... comm=sh image=...: command line not captured whole, N bytes
#      between its head and its tail were not captured; ...

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

# printf -v is a builtin: no extra process in the scenario's tree. `: : : ...` is one
# no-op command with many arguments.
printf -v HEAD_PAD ': %.0s' {1..1024}
printf -v TAIL_PAD ': %.0s' {1..512}
SCRIPT="${HEAD_PAD}; echo 'synthaea argv-padding: the hidden command ran'; ${TAIL_PAD}"

say "Running sh -c with a ${#SCRIPT}-byte script, the command in its middle..."
sh -c "$SCRIPT"

done_msg "the T1027.010 truncated command line alert"
