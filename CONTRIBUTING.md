# Contributing to Synthaea scenarios

This guide covers what is specific to this repository. The rules that hold across the project
(Developer Certificate of Origin, licensing of contributions, code standards, conduct) are in the
[organization contributing guide](https://github.com/synthaea-lab/.github/blob/main/CONTRIBUTING.md)
and the [Code of Conduct](https://github.com/synthaea-lab/.github/blob/main/CODE_OF_CONDUCT.md).

## Adding a scenario

A scenario is one script that performs one technique and leaves the host as it found it.

1. Add `scenarios/<name>.sh` (Linux) or `scenarios/<name>.ps1` (Windows). Open with a header
   comment that says what the scenario simulates, which detection it exercises, what it needs on
   the host and how to run it.
2. For a Linux scenario, add the sidecar `scenarios/<name>.yaml` in the
   [sidecar format](scenarios/README.md#sidecar-format), then add its hash to the manifest (see
   [Sidecars](#sidecars)).
3. Add a row to the [catalog](scenarios/README.md).
4. Add the scenario to the runner catalog in [synthaea-lab/rig](https://github.com/synthaea-lab/rig)
   (`runner/scenarios.conf`, or `runner/scenarios-windows.conf`) in a pull request there, and run
   it on a VM with `python rig.py run <machine> <name>`.

### Benign by construction

- Create, modify and delete only files the scenario created itself, and restore anything it
  changes (a shell profile, a log directory) on exit.
- Connect only to listeners the scenario starts on the loopback interface, or to names that never
  resolve (`.invalid`).
- Never escalate privileges beyond what the technique needs, and never leave an account, task,
  service or listener behind.

### Shell scenarios

Source the shared helpers instead of re-implementing them:

```sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
```

- `add_cleanup CMD [ARG...]` queues a teardown step; all steps run once on exit, in reverse order.
  Do not set your own `trap ... EXIT`, which would replace them (`tools/test-cleanup.sh` fails
  on one). For a step whose argument is only known at exit time, register a small named
  function. `kill_process PID` and `remove_empty_dirs DIR...` are ready-made steps.
- `start_loopback_listener BODY [ARG...]` runs a listener in its own process group and registers
  its teardown.
- `make_fake_webserver PATH [SH]` copies a shell to `PATH` under a web server's name; the
  scenario then spawns from that copy itself, so the parent and arguments stay its own.
- `spawn_shells_from FAKE ITERATIONS` is the lineage stimulus: FAKE runs a shell that runs a
  leaf command, once a second. Call it directly (not in `$(...)`), so FAKE stays a child of the
  scenario.
- `require_root`, `require_command`, `require_web_server` and `die_precondition` stop the
  scenario with exit code 2 when the host is not set up for it. Use exit code 1 only for a
  self-check that ran and failed.

The process tree, names, arguments and paths of a scenario are the behavior under test: do not
add wrapper shells or subshells around the commands that matter.

Keep a scenario's Python inline, as a `<<'PY'` heredoc or a single-quoted `python3 -c '...'`
string: moving it to a `.py` file would change the argv the agent sees. Tag every Python heredoc
`PY`. CI compiles and lints that code with `tools/check-python-snippets.py`; run it locally with
`python3 tools/check-python-snippets.py --ruff ruff`.

### PowerShell scenarios

Windows scenarios must run on a stock Windows PowerShell 5.1 under any locale. Dot-source
`scenarios/common.ps1` and follow its rules:

- ASCII only. PowerShell 5.1 reads a file without a byte order mark in the ANSI code page, so a
  single non-ASCII character can break parsing.
- Build locale-dependent arguments from the current culture (`Get-FarFutureDate`), never from a
  literal.
- Run every native tool through `Invoke-Native`, so a failed step throws instead of reporting
  success.
- Self-checking scenarios use the agent harness in the same file: `Assert-Administrator`,
  `New-LabAgentConfig`, `Start-ScenarioAgent` and `Stop-ScenarioAgent`.

## Sidecars

The [ML pipeline](https://github.com/synthaea-lab/ml) binds each trained model's record to the
SHA-256 of the exact sidecar bytes it was evaluated against. Changing one byte of an existing
sidecar, or checking it out with CRLF line endings, invalidates those records.

- Adding a sidecar is always allowed.
- Editing, renaming or deleting an existing sidecar is allowed only together with a retrain.
  Label the pull request `retrain`; the sidecar check fails without it.
- Sidecars use LF line endings (`.gitattributes` enforces it).
- `scenarios/sidecars.sha256` lists the hash of every sidecar. After adding a sidecar, or after a
  retrain, regenerate it from the repository root:

  ```sh
  git ls-files 'scenarios/*.yaml' | xargs sha256sum > scenarios/sidecars.sha256
  ```

## Checks

Run these from the repository root before opening a pull request. They need Bash, Python 3,
[ShellCheck](https://www.shellcheck.net/) and [PowerShell 7](https://github.com/PowerShell/PowerShell)
(`pwsh`), and run unprivileged.

```sh
git ls-files -z '*.sh' | xargs -0 -n 1 bash -n
git ls-files -z '*.sh' | xargs -0 shellcheck --severity=warning
bash tools/test-preconditions.sh
bash tools/test-fake-webserver.sh
bash tools/test-workdir.sh
python3 tools/check-ps1-ascii.py
pwsh -NoProfile -File tools/test-common-ps1.ps1
python3 tools/check-sidecar-bytes.py
```

| Check | What it verifies |
| --- | --- |
| `bash -n`, ShellCheck | Every shell script parses and has no warning-level findings |
| `test-preconditions.sh` | The precondition helpers, and that scenarios which cannot run on this host exit with code 2 |
| `test-fake-webserver.sh` | `make_fake_webserver` copies the right shell and the copy runs the spawn command; `spawn_shells_from` spawns it with that command from the calling shell |
| `test-workdir.sh` | `make_workdir` and `create_throwaway_files`, and that the unprivileged scenarios using them leave nothing behind |
| `check-ps1-ascii.py` | Every PowerShell script is ASCII-only |
| `test-common-ps1.ps1` | Every PowerShell script parses, and the agent harness writes the expected lab configuration |
| `check-sidecar-bytes.py` | Every sidecar matches `scenarios/sidecars.sha256` |

## Pull requests

Keep a pull request to one scenario or one concern, and say in its description where the
scenario was run (distribution, kernel or Windows build) and what fired. Sign off every commit:

```sh
git commit -s
```
