# Writing scenarios

A good scenario performs exactly one technique, the way an attacker would, and nothing that
could hurt the machine it runs on. It produces the same detections on every supported kernel, so
that a missing alert means a regression and not a flaky script. This page is the reference for
writing one. The repository's [CONTRIBUTING.md](../CONTRIBUTING.md) has the short version.

## Benign by construction

- Create, modify and delete only files the scenario created, and restore anything it changes (a
  shell profile, a web root) on exit.
- Connect only to listeners the scenario starts on the loopback interface, or to names under
  `.invalid`, which never resolve.
- Use no more privilege than the technique needs, and leave no account, task, service, listener or
  process behind.
- Put scratch files in a fresh `mktemp` directory, not at a fixed path in `/tmp`, unless the path
  itself is the stimulus (the alert names it, a rule or the rig keys on it). Then say so in a
  comment.

## The stimulus is the behavior

The agent judges the process tree, names, arguments, paths and timing that the script produces.
Those are therefore part of what the scenario asserts, and shell conveniences change them:

- **No wrappers around the commands that matter.** A `$(...)`, a pipeline or a `( ... )` adds a
  shell process between the scenario and the command, and changes its parent. The helpers in
  `lib/common.sh` return values through variable names (`make_workdir VAR ...`) instead of
  command substitution for that reason.
- **Mind `sh -c` exec elision.** Bash and dash run a `-c` body that is one simple command by
  executing it in place, without forking. When the parent of the leaf matters, wrap it:
  `sh -c '(/bin/sh -c "id >/dev/null")'`.
- **Keep Python inline.** Use a `<<'PY'` heredoc fed to `python3 -`, or a single-quoted
  `python3 -c '...'`. Moving it to a `.py` file changes the argv the agent sees. Tag every Python
  heredoc `PY`, so [`tools/check-python-snippets.py`](../tools/check-python-snippets.py) finds,
  compiles and lints it.
- **Keep short-lived processes alive past the drain.** The Linux sensor reads a process's command
  line and environment from `/proc` when it drains the exec event, a few milliseconds later. A
  process that is already gone shows an empty command line. If the detection needs it, keep the
  process alive (`sleep 0.2` inside the one-liner, as in `argv.sh`).
- **One process when the rule is per process.** Rules that count per pid (`rule_dns_exfil`, the
  ransomware join, the kill gate) need the whole pattern from one process. A loop of fresh
  processes tests a different rule.
- **Count your side effects.** A cleanup can itself be the technique (restoring `~/.bashrc` is a
  persistence write), and an extra `touch` or `unlink` can add an alert. Make every alert the
  script causes deliberate, and write the expected count in the sidecar.

## Shell helpers: `lib/common.sh`

Every Linux scenario except `argv.sh`, `dns-exfil.sh` and `signal.sh` sources the shared helpers:

```sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
```

Sourcing it installs an `EXIT` trap. Do not install your own: a second `trap ... EXIT` replaces
the first and silently drops every cleanup registered before it.
[`tools/test-cleanup.sh`](../tools/test-cleanup.sh) fails on any script other than `lib/common.sh`
that sets one.

### Cleanup

| Function | Use |
| --- | --- |
| `add_cleanup CMD [ARG...]` | Queue a teardown step. Arguments are captured by value at registration (`printf %q`). All steps run once, at exit, in reverse order of registration, and a failing step does not stop the others |
| `kill_process PID` | A ready-made step: stop one process, tolerating one that already exited |
| `kill_process_group PGID` | Stop a whole process group; registered by `start_loopback_listener` |
| `remove_empty_dirs DIR...` | Remove each directory if it is empty |

Because steps run in reverse, register a removal before the thing that must be undone first. For
a step whose argument is only known at exit, register a small named function (as
`restore_profile` in [`persistence-write.sh`](../scenarios/persistence-write.sh) does).

### Listeners and fake parents

| Function | Use |
| --- | --- |
| `start_loopback_listener BODY [ARG...]` | Run `BODY` with `setsid bash -c BODY bash ARG...` in the background, in its own session, and register the kill of that process group. The group kill matters: killing only the loop leaves an orphaned `nc` holding the port, and the next run's listener then fails and spins |
| `make_fake_webserver PATH [SH]` | Copy the shell `SH` (default `/bin/sh`) to `PATH`, so a process run from it has `comm` equal to `basename PATH`. Copies `$BASH` when `SH` is busybox. It only copies: register the removal yourself, and spawn from `PATH` yourself |
| `spawn_shells_from FAKE ITERATIONS` | The lineage stimulus: `ITERATIONS` times, one second apart, run `FAKE -c '(/bin/sh -c "id >/dev/null")'`. Call it directly, never in `$(...)` or a pipeline |

`BODY` takes its values as `$1`, `$2`... of the inner Bash, so the body is single-quoted. ShellCheck
reports that as SC2016; mark it with a justified directive:

```sh
# shellcheck disable=SC2016  # $1... are the inner bash's positional parameters
start_loopback_listener '
  while true; do
    nc -l -p "$1" >/dev/null 2>&1 || nc -l "$1" >/dev/null 2>&1
  done
' "$PORT"
```

The `nc -l -p PORT || nc -l PORT` pair covers both traditional and OpenBSD/busybox syntax.

### Work directories

| Function | Use |
| --- | --- |
| `make_workdir VAR BASE PREFIX` | Create `BASE/PREFIXxxxxxx` with `mktemp -d`, store its path in the variable named `VAR`, register its removal. Exits 1 if it cannot be created |
| `create_throwaway_files DIR COUNT PATTERN` | Create `COUNT` empty files named by the `printf` format `PATTERN` applied to 0 through `COUNT - 1`. Builtins only, so it adds no process to the tree |

Keep `PREFIX` stable: detection rules and validation may key on the path
(`$HOME/synthaea-scenario-*`).

### Preconditions

| Function | Stops with exit 2 unless |
| --- | --- |
| `require_root REASON` | The script runs as root |
| `require_command COMMAND [HINT]` | `COMMAND` is on `PATH` |
| `require_web_server URL` | A web server answers at `URL` within three seconds |
| `die_precondition MESSAGE` | (always) |

Each prints `ERROR: precondition not met: ...` on stderr. Check every precondition before the
scenario does anything, so that exit 2 always means "nothing was attempted". Exit 1 is only for a
self-check that ran and failed.

### Self-checks

| Function | Use |
| --- | --- |
| `require_expect_mode` | Validate `EXPECT` (`enforce` or `observe`); unset or empty stops with Bash's error (exit 1), another value exits 2 |
| `check_fail MESSAGE` | Print `FAIL: MESSAGE` on stderr and remember the failure; later checks still run, so one run shows every failure |
| `exit_with_checks OK_MESSAGE` | Print `OK_MESSAGE` and exit 0 if nothing failed, else exit 1 |

A self-check verifies only the scenario's own side (was the process killed, is the file still
there). Alert counts belong in the sidecar, judged by the consumer.

## Adding a Linux scenario

1. **Write `scenarios/<name>.sh`.** Start with `#!/usr/bin/env bash`, then a header comment that
   says what the scenario simulates, which agent detection it exercises (function and file), what
   it needs on the host, how to run it and the exact alert text to expect. Then
   `set -euo pipefail` (or `set -uo pipefail` when the script must survive a failing command to
   judge it), source `lib/common.sh`, check preconditions, and perform the technique. Make it
   executable: `chmod +x scenarios/<name>.sh`.
2. **Run it on a test machine** against a live agent, several times, on more than one kernel if
   the detection depends on the sensor. Record what fired and how often.
3. **Write `scenarios/<name>.yaml`** in the [sidecar format](sidecar-format.md), with the
   measured counts and the reasoning in `notes`. Check what the rig reads from it, from a rig
   checkout beside this one:

   ```sh
   bash ../rig/runner/run-scenarios.sh --expectations scenarios/<name>.yaml
   ```

4. **Add the sidecar to the manifest.** The new file must be tracked for `git ls-files` to list
   it:

   ```sh
   git add scenarios/<name>.yaml
   git ls-files 'scenarios/*.yaml' | xargs sha256sum > scenarios/sidecars.sha256
   python3 tools/check-sidecar-bytes.py
   ```

5. **Add a row to the [catalog](../scenarios/README.md)** and a section to
   [linux-scenarios.md](linux-scenarios.md).
6. **Run the [repository checks](testing.md#repository-checks).** If the scenario has a
   precondition, add a case to [`tools/test-preconditions.sh`](../tools/test-preconditions.sh);
   if it uses a work directory unprivileged, to [`tools/test-workdir.sh`](../tools/test-workdir.sh).
7. **Add the scenario to the rig's catalog**, `runner/scenarios.conf` in
   [synthaea-lab/rig](https://github.com/synthaea-lab/rig/blob/main/runner/scenarios.conf), in a
   pull request there: `default` if it is safe and self-contained, `opt-in` with a note if it needs
   setup the rig does not do. Until then, the rig's `--check` fails on the new script. Run it on a
   VM with `python3 rig.py run <machine> <name>`.

Once merged, the sidecar's bytes are frozen: a later change needs a retrain
([sidecar-format.md](sidecar-format.md#hash-binding)). Measure before merging.

## Adding a Windows scenario

1. Write `scenarios/<name>.ps1` in ASCII, with a comment-based help header (`.SYNOPSIS`,
   `.DESCRIPTION`, `.NOTES` with usage and the expected alert, `.LINK` to the ATT&CK page), a
   `[CmdletBinding()]` parameter block, `$ErrorActionPreference = "Stop"`, then dot-source the
   helpers and turn on strict mode:

   ```powershell
   $ErrorActionPreference = "Stop"
   . (Join-Path $PSScriptRoot "common.ps1")
   Set-StrictMode -Version Latest
   ```

2. Run every native tool through `Invoke-Native`, build dates with `Get-FarFutureDate`, and undo
   everything in a `finally` block with `Invoke-NativeCleanup`
   ([windows-scenarios.md](windows-scenarios.md#powershell-51-constraints)).
3. For a self-checking run, accept `-AgentExe` and `-OutDir`, use the harness functions, and put
   the judgment in a `Get-ScenarioVerdict` function that only returns check objects; add fixture
   cases for it to [`tools/test-scenario-verdicts.ps1`](../tools/test-scenario-verdicts.ps1).
4. Run `python3 tools/check-ps1-ascii.py` and `pwsh -NoProfile -File tools/test-common-ps1.ps1`.
5. Add a row to the [catalog](../scenarios/README.md) and to the rig's
   `runner/scenarios-windows.conf`, with the expectation in its `expect` column.

## Pull requests

Keep a pull request to one scenario or one concern, and say in its description where the scenario
was run (distribution and kernel, or Windows build) and what fired. Sign off every commit
(`git commit -s`): the repository requires a Developer Certificate of Origin.
