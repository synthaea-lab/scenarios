#!/usr/bin/env bash
# Validation scenario for the full dropper chain (T1105/T1059/T1071).
#
# Simulates a process that, within the same time window (60s by default) and under the
# same pid: (1) executes (Exec), (2) connects to the network (Connect), (3) writes a
# file to disk (FileOpen with O_CREAT|O_WRONLY). This is exactly the "download + write"
# pattern of a payload/dropper — curl combines all three in a single process, unlike
# `wget ... && ./payload` (two separate processes, already covered by the T1105 rule
# in crates/rules, based on the write-then-exec correlation).
#
# Exercises the correlator's spawn+connect+filewrite rule (crates/correlator —
# identifiers renamed to English during migration, issue #12).
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./scenarios/dropper-chain.sh
#   3) expected in terminal A:
#      T1105/T1059/T1071 — pid=...: spawn + network connection + file write — full dropper chain

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

PORT=8080
# A fresh, unpredictable name (mktemp creates it with O_EXCL), so the write cannot
# follow a file or symlink planted at a fixed path. The rule keys on curl's pid, not
# on the path; /tmp is kept as the directory the payload lands in.
OUT_FILE=$(mktemp /tmp/edr-test-dropper-payload.XXXXXX)

add_cleanup rm -f "$OUT_FILE"
# shellcheck disable=SC2016  # $1... are the inner bash's positional parameters
start_loopback_listener '
  resp="HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload"
  while true; do
    printf "$resp" | nc -l -p "$1" -q1 >/dev/null 2>&1 || printf "$resp" | nc -l "$1" >/dev/null 2>&1
  done
' "$PORT"

sleep 1

echo "curl -o $OUT_FILE http://127.0.0.1:$PORT/ (exec + connect + filewrite, same pid)..."
curl -s -o "$OUT_FILE" "http://127.0.0.1:$PORT/" || true

echo "Done. Check for the T1105/T1059/T1071 (full dropper chain) alert in the agent terminal."
echo "File written: $OUT_FILE ($( [ -f "$OUT_FILE" ] && wc -c < "$OUT_FILE" || echo 0) bytes)"
