#!/usr/bin/env bash
# Odd parent #3 for the T1 capture (#617): a binary dropped into a world-writable memory or temp
# directory (`/dev/shm`, `/var/tmp`) that then runs children (the dropper shape: a payload that
# was just written starts a shell and enumerates the host).
#
# Odd by: path
# (The names are not web-server or Office names, so the comm features stay quiet and the only
# odd thing is the directory.) `/dev/shm` can be mounted `noexec`: the exec then fails and the
# scenario is reported as failed; fine on the lab VM, where it is not.
#
# The binaries are copies of `bash` and `python3` under innocuous names. Their path is one of
# `lineage.py::SUSPICIOUS_PATHS`, which is the only thing that distinguishes them from the
# benign workload's user-installed tools (those run from the user's own directory, not from
# `/dev/shm` or `/var/tmp`; the workload has one job that runs a script from `/tmp`, which is
# ordinary and keeps this feature from being an alarm by itself).
#
# Lab VM only; nothing is attacked or changed. No sidecar `.yaml`.

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../../lib/common.sh"

# Each directory's removal is registered as soon as it exists: a failure of the second
# `mktemp` must not leave the first behind. /var/tmp when /dev/shm cannot hold one.
D1="$(mktemp -d /dev/shm/edr-odd-drop.XXXXXX 2>/dev/null)" && add_cleanup rm -rf "$D1" \
    || make_workdir D1 /var/tmp edr-odd-drop.
make_workdir D2 /var/tmp edr-odd-drop.

cp "$(command -v bash)" "$D1/kworker-update"
cp "$(command -v python3)" "$D2/syslogd-helper"
for _ in 1 2 3; do
    "$D1/kworker-update" -c '(sh -c "id; uname -a; ip -br addr | head -2")'
    "$D2/syslogd-helper" -c 'import subprocess; subprocess.run(["sh", "-c", "ps -ef | head -3; ls /home | head -2"], capture_output=True)'
    sleep 1
done
echo "  dropped binaries done"
