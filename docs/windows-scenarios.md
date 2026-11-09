# Windows scenarios

The Windows scenarios are PowerShell scripts that run on a stock **Windows PowerShell 5.1**,
under any display language. They have no sidecars yet: each script's header states what must
fire, and the rig's Windows catalog,
[`runner/scenarios-windows.conf`](https://github.com/synthaea-lab/rig/blob/main/runner/scenarios-windows.conf),
carries the same expectations in its `expect` column (`technique:min_count:tolerance`). Once a
scenario gains a sidecar, the runner reads the sidecar instead.

## The scenarios

| Scenario | Stimulus | Expected | Agent source |
| --- | --- | --- | --- |
| [`encoded-powershell.ps1`](../scenarios/encoded-powershell.ps1) | `-Iterations` (default 3) `powershell.exe -EncodedCommand` runs of a payload that decodes to `Write-Host hello` | `T1059.001`, one per iteration | ETW process start, command-line rule |
| [`scheduled-task-persistence.ps1`](../scenarios/scheduled-task-persistence.ps1) | `schtasks.exe /Create` of tasks that run `notepad.exe` 70 years from now, deleted at the end | `T1053.005`, one per task | Security log event 4698 |
| [`service-install-persistence.ps1`](../scenarios/service-install-persistence.ps1) | `sc.exe create` of demand-start services pointing at `notepad.exe`, deleted at the end | `T1543.003`, one per service | System log event 7045 |
| [`create-account-persistence.ps1`](../scenarios/create-account-persistence.ps1) | `net user /add` of local accounts with random passwords, outside any privileged group, deleted at the end | `T1136.001`, one per account | Security log event 4720 |
| [`bits-job.ps1`](../scenarios/bits-job.ps1) | `bitsadmin /transfer` of a `whoami.exe` copy from a loopback HTTP listener into `%TEMP%`, then run | Two `bits_job` events, one `T1197` alert | ETW Bits-Client provider |
| [`windows-container.ps1`](../scenarios/windows-container.ps1) | Processes in a process-isolated container (a long-lived one, and `hostname.exe` through `docker exec`) and one on the host | No alert: container processes carry the container id, the host process none | ETW process start, container attribution |

The three persistence scenarios take `-Iterations` (default 3) and need Administrator: the tools
require it, and the agent needs it to read the Security log. They use the native tools (`schtasks.exe`,
`sc.exe`, `net user`) rather than the PowerShell cmdlets because those are what intrusions use;
Windows writes the same event either way. The agent's
[Windows sensors](https://github.com/synthaea-lab/agent/blob/main/docs/sensors/windows/README.md)
page describes ETW and Event Log collection.

`bits-job.ps1` exists because BITS downloads from its own service: without the Bits-Client
provider nothing ties the file to `bitsadmin.exe`. Its listener answers `HEAD` and ranged `GET`
requests, which is how BITS sizes and fetches a file. With `-MicrosoftJob` (needs internet) a
second job fetches a Microsoft connectivity-check URL, which the sensor must drop.

`windows-container.ps1` needs the Containers feature and Docker in Windows-containers mode
(Windows Server 2025, or Windows 11 22H2 or later Pro or Enterprise), and an image whose build
matches the host (`-Image`, default `mcr.microsoft.com/windows/nanoserver:ltsc2025`). Besides its
checks it prints what attribution rests on (each process's server silo id, `hcsdiag list`, the
Kernel-Process silo records), so a failure can be told apart from a wrong assumption.

## PowerShell 5.1 constraints

Every `.ps1` here must parse and behave the same on a fresh Windows install with any locale. That
rules out four things, and [`common.ps1`](../scenarios/common.ps1) provides the replacement for
each:

| Constraint | Why | Use |
| --- | --- | --- |
| ASCII only | PowerShell 5.1 reads a file without a byte order mark in the ANSI code page; an em dash decodes into a character that breaks parsing | Plain ASCII; enforced by [`tools/check-ps1-ascii.py`](../tools/check-ps1-ascii.py) |
| No locale-formatted literals | `schtasks /SD 12/31/2099` is rejected under a locale whose date order differs | `Get-FarFutureDate`, which formats with the current culture's short date pattern |
| No unchecked native calls | A script that prints "created" after the tool failed validates nothing | `Invoke-Native`, which throws on a non-zero exit code and can redact arguments such as a password |
| No native prompts | A tool waiting for input on a console whose output is discarded hangs forever | `Invoke-Native` feeds one empty line and closes stdin, so a prompt gets Enter and a tool that needs real input fails loudly |

Cleanup uses `Invoke-NativeCleanup`, which warns instead of throwing, so one failed delete in a
`finally` block does not skip the rest. Scripts run with `$ErrorActionPreference = "Stop"` and
`Set-StrictMode -Version Latest`; `Get-OptionalProperty` reads a property that may be absent (the
agent's JSON leaves out unset optional fields) without tripping strict mode.

`.gitattributes` checks out `.ps1` files with CRLF line endings.

## Self-checking runs

`bits-job.ps1` and `windows-container.ps1` can start and judge their own agent. Pass the agent
binary from an elevated prompt with no other agent running:

```powershell
powershell -ExecutionPolicy Bypass -File scenarios\bits-job.ps1 -AgentExe ..\agent\target\release\agent.exe
```

The harness in `common.ps1`:

| Function | Does |
| --- | --- |
| `Assert-Administrator` | Throws unless the session is elevated (the ETW session needs it) |
| `Get-RunDirectory` | `-OutDir` if given, else `%TEMP%\synthaea-lab-validation\<prefix>-<timestamp>` |
| `New-LabAgentConfig` | Writes an offline `agent.toml` into the run directory: control plane `https://cp.lab.invalid` with offline fallback, logs, state and certificates under the run directory, IPC on a named pipe of its own |
| `Start-ScenarioAgent` | Refuses if an `agent.exe` already runs, starts `agent --config <toml> run --alerts ... --events ...`, waits up to 30 seconds for the first event, then two more seconds, and fails if the agent logged that its ETW sensor failed (the Event Log sensor keeps writing events without ETW, so the first event alone proves nothing) |
| `Read-AgentEvents` | The events of one `type` (`exec`, `bits_job`) from `events.jsonl`, as objects |
| `Stop-ScenarioAgent` | Kills the agent and waits up to 10 seconds; a no-op without `-AgentExe` |
| `Write-Verdict`, `Test-VerdictPassed` | Print one `PASS` or `FAIL` line per check, and reduce the checks to the exit code |

Each self-checking scenario implements `Get-ScenarioVerdict`, which takes the recorded events and
returns `{ Check, Pass, Detail }` objects without printing anything. Keeping the verdict a pure
function is what lets [`tools/test-scenario-verdicts.ps1`](../tools/test-scenario-verdicts.ps1)
load it from the parsed script and feed it fixture events on any machine, Linux included.

Without `-AgentExe`, `bits-job.ps1` runs against an agent you started yourself and prints the
Bits-Client operational log records for its jobs as its own evidence.

## Exit codes

A Windows scenario exits 0 when it ran (and, with `-AgentExe`, every check passed) and 1
otherwise. There is no separate precondition code as on Linux: a missing elevation or feature is
a terminating error, exit 1.
