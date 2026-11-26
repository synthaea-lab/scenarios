#!/usr/bin/env bash
# Base64-staged shell script (T1059.004): an encoded script stored in a file, decoded with
# `base64 --decode` and piped into `sh`.
#
# check_base64_decode (agent crates/rules/src/stateless/execution.rs) matches a command
# line holding `base64` and a decode flag. argv.sh covers the one-liner shape
# (`echo ... | base64 -d` inside `sh -c`); this is the staged shape: the blob sits in a
# file, the long `--decode` flag is used, and no `sh -c` wrapper carries the decode, so the
# only matching exec is `base64` itself. The decoded script only prints a line.
#
# The blob is a constant in this script rather than encoded at run time: an encoding
# `base64` call would put the work directory in its command line, and a `mktemp` suffix
# starting with `d` makes that path contain `-d`, a second, accidental match.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./scenarios/encoded-stager.sh (no root needed)
#   3) expected in terminal A:
#      T1059.004 — pid=... comm=base64: command line contains a base64 decode:
#      base64 --decode .../stage.b64

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

# echo "synthaea encoded-stager: the decoded script ran"
BLOB='ZWNobyAic3ludGhhZWEgZW5jb2RlZC1zdGFnZXI6IHRoZSBkZWNvZGVkIHNjcmlwdCByYW4iCg=='

make_workdir DIR "${TMPDIR:-/tmp}" synthaea-stager-
printf '%s\n' "$BLOB" > "$DIR/stage.b64"

say "Decoding the staged script with base64 --decode and piping it into sh..."
base64 --decode "$DIR/stage.b64" | sh

done_msg "the T1059.004 base64 decode alert"
