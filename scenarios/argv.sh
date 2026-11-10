#!/usr/bin/env bash
# argv/cmdline fidelity scenario (issue #152).
#
# The eBPF probe no longer reads argv from `mm->arg_start..arg_end` (the last
# per-kernel frozen offset); the userspace loader reads `/proc/<pid>/cmdline` when it
# drains the exec event. This scenario is the assertion for "argv/cmdline is correct
# across the Linux rows of rig/docs/machine-matrix.md": the T1059.004 base64 rule matches on the
# process's `cmdline`, so it fires *only if* the loader captured the argument vector.
#
# Shape: a shell runs a one-liner that contains `base64` and a decode flag. The
# check_base64_decode rule (stateless, cmdline substring) fires iff `cmdline` was
# populated — i.e. iff the `/proc/<pid>/cmdline` read on this kernel worked.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./scenarios/argv.sh
#   3) expected: exactly one alert per iteration —
#        T1059.004 — pid=<sh> comm=sh: command line contains a base64 decode: sh -c ...
#      No alert means argv/cmdline capture is broken on this kernel ($(uname -r)).
#
# Also eyeball the raw exec events (agent run --print-events): every `sh -c` event
# must show the full `argv` (["sh", "-c", "echo ... | base64 -d ..."]) and a
# space-joined `cmdline`, not an empty vector.
#
# Note: a process that exits within the drain latency (a few ms) legitimately shows
# an empty argv — the accepted race of the userspace read. A bare `echo | base64`
# pipeline is gone in ~1-2 ms and loses that race under load (observed on 6.1 in the
# Hyper-V lab), so the `sh -c` here begins with `sleep 0.2` to hold the process open
# well past the drain — this scenario measures capture fidelity, not the race.
#
# Known wrong count, frozen with the sidecar until the next retrain (#207): the
# `base64 -d` child of each `sh -c` matches check_base64_decode as well (its argv is
# `base64 -d`). It exits within ~1 ms, so whether it wins the drain race decides
# between 3 and 6 alerts: the rig's debian12 run of 2026-11-08 counted 6, the
# `base64 -d` children being pids 6503/6508/6513. Not a double report: two processes
# each carry the decode. The fix for the retrain keeps `base64 -d` blocked on its
# stdin past the drain (`(sleep 0.2; echo ...) | base64 -d`) and expects 6.
#
# Scope: this asserts *capture fidelity* for a cooperative process, not tamper
# resistance. `/proc/<pid>/cmdline` is read at drain time, not at execve, so a process
# that rewrites its own argv region before the read can spoof what a cmdline-substring
# rule sees. That is a known gap of the userspace read (see `read_proc_cmdline`), out
# of scope here — `image_path` stays authoritative regardless.

set -euo pipefail

ITERATIONS=3
PAYLOAD='ZWNobyBoZWxsbwo='  # "echo hello\n"

echo "Running $ITERATIONS shell invocations with a base64 decode in argv..."
for i in $(seq 1 "$ITERATIONS"); do
    sh -c "sleep 0.2; echo $PAYLOAD | base64 -d >/dev/null"
    echo "  iteration $i done"
    sleep 1
done

echo "Done. Check the agent terminal: one T1059.004 alert per iteration means argv/"
echo "cmdline capture is correct on this kernel ($(uname -r)); no alerts means #152"
echo "has regressed (the /proc/<pid>/cmdline read returned nothing)."
