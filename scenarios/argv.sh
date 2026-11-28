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
# Note: a process that exits within the drain latency (a few ms) legitimately shows
# an empty argv — the accepted race of the userspace read. A bare `echo | base64`
# pipeline is gone in ~1-2 ms and loses that race under load (observed on 6.1 in the
# Hyper-V lab), so the `sh -c` here begins with `sleep 0.2` to hold the process open
# well past the drain — this scenario measures capture fidelity, not the race.
#
# Two processes carry the decode, hence two alerts per iteration: the `sh -c` and its
# `base64 -d` child. The exec probe reads argv in the kernel, so both are always seen.
# On the `/proc` fallback the child must outlive the drain as well, so the pipeline's
# left side sleeps 0.2 s before the `echo` and `base64 -d` waits on its stdin.
#
# Scope: this asserts *capture fidelity* for a cooperative process, not tamper
# resistance. `/proc/<pid>/cmdline` is read at drain time, not at execve, so a process
# that rewrites its own argv region before the read can spoof what a cmdline-substring
# rule sees. That is a known gap of the userspace read (see `read_proc_cmdline`), out
# of scope here — `image_path` stays authoritative regardless.

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"

ITERATIONS=3
PAYLOAD='ZWNobyBoZWxsbwo='  # "echo hello\n"

say "Running $ITERATIONS shell invocations with a base64 decode in argv..."
for i in $(seq 1 "$ITERATIONS"); do
    sh -c "sleep 0.2; (sleep 0.2; echo $PAYLOAD) | base64 -d >/dev/null"
    say "  iteration $i done"
    sleep 1
done

done_msg "two T1059.004 alerts per iteration (the shell and its base64 child), which means argv/cmdline capture is correct" \
    "on this kernel ($(uname -r)); no alert means #152 has regressed (the" \
    "/proc/<pid>/cmdline read returned nothing)"
