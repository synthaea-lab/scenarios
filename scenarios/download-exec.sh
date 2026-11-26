#!/usr/bin/env bash
# Ingress tool transfer then execution (T1105): curl downloads a file, and a second
# process runs it within the download-to-execution window.
#
# check_download_then_exec (agent crates/rules/src/download_state.rs) remembers every
# write-intent open by a known downloader (curl, wget) and alerts when an exec's comm is
# the basename of such a path within 60 s. dropper-chain.sh only covers the correlator's
# single-pid chain (curl executes, connects and writes); here the written file is then
# executed, which is the join this rule makes and no other scenario exercises.
#
# The payload is a two-line shell script that only prints a line. It is served from a
# fresh work directory by a loopback HTTP server and downloaded into another fresh work
# directory, so no fixed path can be planted and nothing is left behind.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./scenarios/download-exec.sh (no root needed)
#   3) expected in terminal A:
#      T1105 — pid=... comm=syn-dl-payload executes .../syn-dl-payload, written ... earlier
#      by pid=... comm=curl

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

require_command curl "install curl: Debian apt install curl, Fedora dnf install curl"
require_command python3 "install python3: Debian apt install python3, Fedora dnf install python3"
require_command cmp "install diffutils: Debian apt install diffutils, Fedora dnf install diffutils"

PORT=8093
# 14 bytes: the kernel truncates comm to 15, and the rule compares comm to the basename.
PAYLOAD_NAME=syn-dl-payload

make_workdir SERVE_DIR "${TMPDIR:-/tmp}" synthaea-dl-serve-
# Always /tmp, whatever TMPDIR says: the correlator's rule_connect_filewrite counts an
# extension-less write as a payload only under /tmp, /var/tmp, /dev/shm or a downloads
# directory (is_payload_file), and the sidecar expects its T1105.
make_workdir DROP_DIR /tmp synthaea-dl-drop-

printf '#!/bin/sh\necho "synthaea download-exec payload ran"\n' > "$SERVE_DIR/$PAYLOAD_NAME"

# Whether anything listens on PORT, IPv4 or IPv6, read from /proc/net/tcp{,6} with builtins
# only. A probe that connects would be noise in this scenario's alerts: a probing curl is a
# downloader, and a bash /dev/tcp subshell is a shell making a network connection (BAYES,
# T1059/T1071).
printf -v PORT_HEX '%04X' "$PORT"
listening() {
    local table _slot local_addr _remote state _rest
    for table in /proc/net/tcp /proc/net/tcp6; do
        [ -r "$table" ] || continue
        while read -r _slot local_addr _remote state _rest; do
            [[ $local_addr == *":$PORT_HEX" && $state == 0A ]] && return 0
        done < "$table"
    done
    return 1
}

# The download must come from the server this script starts, never from a listener that
# was already there.
listening && die_precondition "port $PORT is already in use"

# shellcheck disable=SC2016  # $1 and $2 are the inner bash's positional parameters
start_loopback_listener '
  exec python3 -m http.server "$1" --bind 127.0.0.1 --directory "$2" >/dev/null 2>&1
' "$PORT" "$SERVE_DIR"

for _ in {1..50}; do
    listening && break
    sleep 0.1
done
listening || die_precondition "the loopback HTTP server did not come up on port $PORT"

say "curl -o $DROP_DIR/$PAYLOAD_NAME http://127.0.0.1:$PORT/$PAYLOAD_NAME (the download)..."
curl -sf -o "$DROP_DIR/$PAYLOAD_NAME" "http://127.0.0.1:$PORT/$PAYLOAD_NAME"

# Run only the bytes this script served: whatever else answered on the port is not executed.
if ! cmp -s "$SERVE_DIR/$PAYLOAD_NAME" "$DROP_DIR/$PAYLOAD_NAME"; then
    echo "ERROR: the downloaded file is not the payload this script served; not running it" >&2
    exit 1
fi
chmod +x "$DROP_DIR/$PAYLOAD_NAME"

say "Running the downloaded file (the execution)..."
"$DROP_DIR/$PAYLOAD_NAME"

done_msg "the T1105 download-then-exec alert"
