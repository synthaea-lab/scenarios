#!/usr/bin/env bash
# argv/cmdline fidelity scenario (issue #152).
#
# The eBPF probe reads argv at execve from `mm->arg_start..arg_end`, with offsets
# resolved from the kernel's BTF at load (agent#48); where BTF does not give them, the
# loader falls back to reading `/proc/<pid>/cmdline` when it drains the exec event.
# This scenario is the assertion for "argv/cmdline is correct across the Linux rows of
# rig/docs/machine-matrix.md": the T1059.004 base64 rule matches on the process's
# `cmdline`, so it fires *only if* the agent captured the argument vector.
#
# Shape: a shell runs a one-liner that contains `base64` and a decode flag. The
# check_base64_decode rule (stateless, cmdline substring) fires iff `cmdline` was
# populated, by the probe or by the `/proc` fallback.
#
# Usage:
#   1) terminal A: sudo target/release/agent run
#   2) terminal B: ./scenarios/argv.sh
#   3) expected: exactly two alerts per iteration, one per process whose argv holds the
#      decode —
#        T1059.004 — pid=<sh> comm=sh: command line contains a base64 decode: sh -c ...
#        T1059.004 — pid=<base64> comm=base64: command line contains a base64 decode: base64 -d
#      No alert means argv/cmdline capture is broken on this kernel ($(uname -r)).
#
# Also eyeball the raw exec events (agent run --print-events): every `sh -c` event
# must show the full `argv` (["sh", "-c", "echo ... | base64 -d ..."]) and a
# space-joined `cmdline`, not an empty vector.
#
# Both processes match: the `sh -c` and its `base64 -d` child, hence two alerts per
# iteration. With the probe's read at execve the count is always 6 (agent#207:
# vm-debian12 6.1.0-17, agent a142f0df, 5/5 runs, with or without the sleeps below).
#
# The sleeps guard the `/proc` fallback only. There a process that exits within the
# drain latency (a few ms) legitimately shows an empty argv; a bare `echo | base64`
# pipeline is gone in ~1-2 ms and loses that race under load (observed on 6.1 in the
# Hyper-V lab, before the probe read argv). The `sh -c` begins with `sleep 0.2`, and
# its pipeline's left side sleeps 0.2 s before the `echo` so `base64 -d` waits on its
# stdin: both stay alive past the drain, and the fallback counts 6 as well. This
# scenario measures capture fidelity, not that race.
#
# Scope: this asserts *capture fidelity* for a cooperative process, not tamper
# resistance. On the `/proc` fallback a process that rewrites its own argv region
# before the drain can spoof what a cmdline-substring rule sees (see
# `read_proc_cmdline`), out of scope here — `image_path` stays authoritative regardless.

set -euo pipefail

ITERATIONS=3
PAYLOAD='ZWNobyBoZWxsbwo='  # "echo hello\n"

echo "Running $ITERATIONS shell invocations with a base64 decode in argv..."
for i in $(seq 1 "$ITERATIONS"); do
    sh -c "sleep 0.2; (sleep 0.2; echo $PAYLOAD) | base64 -d >/dev/null"
    echo "  iteration $i done"
    sleep 1
done

echo "Done. Check the agent terminal: two T1059.004 alerts per iteration means argv/"
echo "cmdline capture is correct on this kernel ($(uname -r)); no alerts means #152"
echo "has regressed (the /proc/<pid>/cmdline read returned nothing)."
