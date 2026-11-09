# Testing

Two levels of testing apply to this repository. The repository checks run anywhere, unprivileged,
in about a minute, and catch broken scripts and helpers. Whether a scenario still triggers
its detections can only be shown on a real kernel or Windows build against a live agent, which is
the rig's job.

## Repository checks

Run from the repository root. They need Bash, Python 3, [ShellCheck](https://www.shellcheck.net/),
[ruff](https://docs.astral.sh/ruff/) 0.17.0 for the Python lint, [PowerShell 7](https://github.com/PowerShell/PowerShell)
(`pwsh`) for the PowerShell checks, and `gcc` and `rustc` for the compiled stimuli. None needs
root, and none starts an agent.

```sh
# Shell
git ls-files -z '*.sh' | xargs -0 -n 1 bash -n
git ls-files -z '*.sh' | xargs -0 shellcheck --severity=warning
git ls-files -z '*.sh' | xargs -0 shellcheck --include=SC2016
bash tools/test-cleanup.sh
bash tools/test-preconditions.sh
bash tools/test-fake-webserver.sh
bash tools/test-workdir.sh
bash tools/test-self-check.sh
bash tools/test-run-json.sh
bash tools/test-signal-state.sh
bash tools/test-signal-checks.sh

# Inline Python
python3 tools/check-python-snippets.py --ruff ruff
RUFF=ruff bash tools/test-python-snippets.sh

# PowerShell
python3 tools/check-ps1-ascii.py
pwsh -NoProfile -File tools/test-common-ps1.ps1
pwsh -NoProfile -File tools/test-scenario-verdicts.ps1

# Compiled stimuli: syntax and type checks only, no binary is produced
git ls-files -z '*.c' | xargs -0 -r -n 1 gcc -fsyntax-only -Wall -Wextra -Werror -pthread
rustc --edition 2021 --crate-type bin --emit=metadata -D warnings --out-dir "$(mktemp -d)" scenarios/v652-beacon.rs

# Sidecars
python3 tools/check-sidecar-bytes.py
```

These are the same commands as the jobs in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml),
which also refuses a pull request that changes an existing sidecar without the `retrain` label.
Without `--ruff`, `check-python-snippets.py` only compiles the snippets.

| Check | What it guards |
| --- | --- |
| `bash -n`, ShellCheck at warning level | Every shell script parses and has no warning-level finding |
| ShellCheck SC2016 | A `$` inside single quotes is either a bug or deliberate (a body handed to an inner Bash, a PHP payload). The info-level check is run on its own, and every deliberate case carries a `# shellcheck disable=SC2016` with the reason |
| [`test-cleanup.sh`](../tools/test-cleanup.sh) | The cleanup registry runs steps in reverse order, with arguments captured at registration, also when `set -e` or a precondition stops the script, and keeps the script's exit status; no script but `lib/common.sh` installs an `EXIT` trap |
| [`test-preconditions.sh`](../tools/test-preconditions.sh) | The precondition helpers, and that scenarios which cannot run on this host (no root, no web server, no `EXPECT`) stop with exit 2 before doing anything |
| [`test-fake-webserver.sh`](../tools/test-fake-webserver.sh) | `make_fake_webserver` copies the right binary (and `$BASH` for busybox), the copy runs the spawn command, and `spawn_shells_from` spawns from the calling shell |
| [`test-workdir.sh`](../tools/test-workdir.sh) | `make_workdir` and `create_throwaway_files`, and that the unprivileged scenarios using them leave nothing behind |
| [`test-self-check.sh`](../tools/test-self-check.sh) | `require_expect_mode`, `check_fail` and `exit_with_checks`, and how the self-checking scenarios treat a missing or wrong `EXPECT` |
| [`test-run-json.sh`](../tools/test-run-json.sh) | `write_run_json` writes valid JSON for any scenario name (quotes, backslashes, slashes) and refuses a non-numeric pid, an empty timestamp, a bad `RAN_COUNT` or a missing argument |
| [`test-signal-state.sh`](../tools/test-signal-state.sh) | `signal.sh kill` keeps its state file in the private runtime directory, never in `/tmp`, and `verify-kill` finds it. A `sleep` stands in for the agent; takes about 15 seconds |
| [`test-signal-checks.sh`](../tools/test-signal-checks.sh) | `signal.sh` stops with exit 2 before signaling anything when the agent or its files are missing, and its verdict prints `FAIL` lines and exits 1. Takes about 30 seconds |
| [`check-python-snippets.py`](../tools/check-python-snippets.py), [`test-python-snippets.sh`](../tools/test-python-snippets.sh) | The Python inline in the shell scripts compiles and lints clean, and the extractor finds every snippet |
| [`check-ps1-ascii.py`](../tools/check-ps1-ascii.py) | Every PowerShell script is ASCII-only (Windows PowerShell 5.1 would misread it otherwise) |
| [`test-common-ps1.ps1`](../tools/test-common-ps1.ps1) | Every PowerShell script parses, has a `[CmdletBinding()]` parameter block and turns on strict mode; the harness writes the expected lab configuration byte for byte |
| [`test-scenario-verdicts.ps1`](../tools/test-scenario-verdicts.ps1) | The `Get-ScenarioVerdict` functions of `bits-job.ps1` and `windows-container.ps1`, loaded from the parsed scripts and fed recorded events, pass and fail as stated |
| `gcc -fsyntax-only`, `rustc --emit=metadata` | The compiled stimuli, built by hand on test machines, still compile with warnings as errors |
| [`check-sidecar-bytes.py`](../tools/check-sidecar-bytes.py) | Every sidecar matches [`scenarios/sidecars.sha256`](../scenarios/sidecars.sha256), and the manifest lists exactly the tracked sidecars |

The precondition and self-check tests run real scenarios, which is safe because each case stops
at a precondition before the scenario does anything. `test-workdir.sh` runs the unprivileged
file scenarios for real, against a temporary `HOME`.

## Checks from the rig

A rig checkout beside this one checks what the two repositories must agree on, still without a
VM:

```sh
cd ../rig
python3 rig.py check
```

Among its checks: the rig's catalog covers every `scenarios/*.sh` and names existing YARA files,
the Bash and PowerShell runners read every sidecar the same way, and the runner judges each
sidecar correctly at the edges of its count window. Run it after adding or renaming a scenario
or a sidecar.

## On a VM

A scenario is validated only when it has run against a live agent. With the rig
([running.md](running.md#through-the-rig)):

```sh
python3 rig.py run <machine> <name>
python3 rig.py report <machine>
```

Check that the result is `PASS`, and read the alert lines in the report's details: the technique
count can be right for the wrong reason. Run it on more than one row of the rig's
[machine matrix](https://github.com/synthaea-lab/rig/blob/main/docs/machine-matrix.md) when the
detection depends on the sensor (lineage, command lines, LSM hooks, uprobes). A real kernel is
required: WSL2, for one, reports no parent pids and empty command lines, so lineage and command-line
scenarios fail there for reasons unrelated to the agent.

For the self-checking scenarios, run both modes: `EXPECT=observe` against an agent without the
response flags, and `EXPECT=enforce` against one with them. The rig runs only `observe`.
