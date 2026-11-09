# Limits and known gaps

What the scenarios prove, and what they do not.

## What a pass means

- **Counts, not content.** A pass means each expected technique string appeared the expected
  number of times. Neither the rig nor the ML replay reads the alert message, so an alert raised
  for the wrong process or with the wrong detail still counts. Read the alert lines in the rig's
  report when a scenario changes.
- **Enforce and observe look the same in the alert log.** `RESPONSE-KILL` and
  `RESPONSE-QUARANTINE` are written whether or not the response was allowed; only the message
  differs. The scenario's own `EXPECT` self-check is what tells the modes apart, so a response
  scenario judged by its sidecar alone does not prove that anything was killed.
- **One technique per entry.** The judges count by technique only. Two expected entries with the
  same technique in one sidecar would share a count, and the ML replay would credit it to both.
- **Unexpected alerts do not fail.** The rig flags them as `UNEXPECTED` and still exits 0; the ML
  replay ignores them. A new false positive shows up only to someone reading the report.
- **The `rule` field is not checked.** It names the agent function expected to raise the alert,
  for traceability. If a different rule starts producing the same technique string, nothing
  notices.

## What the catalog does not cover

- **Benign shapes, not real tooling.** Each scenario reproduces the observable shape of one
  technique with harmless payloads: no real implant, rootkit, encryptor or exploit. A detection
  that keys on a payload's content (beyond the bundled YARA marker) is not exercised.
- **Cooperative processes.** The command-line and environment scenarios assert capture fidelity
  for a process that does not hide. A process that rewrites its own argv before the sensor reads
  `/proc/<pid>/cmdline`, or exits within the drain latency, is out of scope.
- **One variant per technique.** `log-clear.sh` deletes a file but does not run
  `journalctl --vacuum`; the Windows persistence scenarios use `schtasks.exe`, `sc.exe` and
  `net user` but not the PowerShell cmdlets; `encoded-powershell.ps1` uses the full
  `-EncodedCommand` spelling and not its abbreviations.
- **Windows has no sidecars.** The Windows expectations live in each script's header and in the
  rig's Windows catalog, so they are not hash-bound and not read by the ML pipeline.
- **No macOS scenarios.** Nothing in the catalog targets macOS.
- **Fleet behavior is checked by hand.** `prevalence-lineage.sh` asserts only the local alert; the
  "seen on N hosts" result is read on the control plane.
- **Opt-in scenarios need manual setup.** The log-source scenarios, `ransomware-reflex.sh` and
  `prevalence-lineage.sh` need services, configuration or a second host that the rig does not
  provision, so they are not part of a plain `rig.py run`.

## Environment-dependent results

- **Timing.** Counts that depend on how many events land in one correlation window
  (`T1059/T1071` in `beacon.yaml` and `respawn-beacon.yaml`) are bounded with a wide tolerance,
  which also hides a moderate increase. Slow or heavily loaded machines can make short-lived
  processes lose the drain race and drop an alert.
- **Kernel and userland.** `timestomp-linux.sh` needs the BPF LSM and kernel 6.3 or later;
  `dns-exfil.sh` needs glibc; the `signal.sh` kill replay needs bpffs at `/sys/fs/bpf`. The rig
  skips what it can detect and reports the reason.
- **WSL2 is not a test target.** It reports no parent pids and empty command lines, so lineage
  and command-line scenarios fail there regardless of the agent.
- **Enforce runs can affect the test machine.** With `--enable-kill`, the agent may also kill
  unrelated processes that its verdict judges, such as a network manager or SSH session processes.
  Do not drive an enforce run over an interactive SSH session; start the agent and the scenario
  detached, and collect the files afterwards.

## Freezing and drift

- **Sidecars cannot follow the agent freely.** An existing sidecar changes only with a retrain
  ([sidecar-format.md](sidecar-format.md#hash-binding)). When the agent legitimately changes how
  often a detection fires, the sidecar stays wrong until the next retrain, and the rig reports a
  `FAIL` in the meantime.
- **Header comments can lag.** A script's header describes the expected alert text and
  sometimes the agent internals at the time it was written. The sidecar and the rig's result are
  the reference; report a stale header as a documentation fix.
- **Exit codes differ by platform.** The Linux scripts separate an unmet precondition (2) from a
  failed self-check (1); the Windows scripts exit 1 for both. Not every Linux script checks every
  tool it uses before starting: some (`beacon.sh`, `bind-shell.sh`, `respawn-beacon.sh`, `dropper-chain.sh`) rely on
  the rig's `needs` column to skip a host without `nc` or `curl`, and fail with a shell error when run by
  hand without it.
