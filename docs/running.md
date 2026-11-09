# Running scenarios

A scenario needs a running agent to be worth anything: on its own it only produces activity.
There are two ways to run one, by hand on a test machine or through the rig, which does the
bookkeeping and judges the result. Both need a disposable machine.

## Through the rig

The [rig](https://github.com/synthaea-lab/rig) is the intended way to run the catalog. It expects
the four checkouts side by side:

```sh
mkdir synthaea && cd synthaea
for r in agent rules scenarios rig; do git clone https://github.com/synthaea-lab/$r.git; done
cd rig
python3 rig.py up debian12
python3 rig.py build debian12 --ort-compat   # Debian 12 needs the ONNX Runtime compatibility build
python3 rig.py run debian12                  # every `default` scenario
python3 rig.py run debian12 lineage argv     # just these, opt-in ones included
python3 rig.py report debian12
```

The rig's [README](https://github.com/synthaea-lab/rig#readme) covers host setup, the machine list
and reports. What it does per Linux scenario, from
[`runner/run-scenarios.sh`](https://github.com/synthaea-lab/rig/blob/main/runner/run-scenarios.sh):

1. Checks the scenario's `needs` (commands, active LSMs) and `min_kernel` from
   [`runner/scenarios.conf`](https://github.com/synthaea-lab/rig/blob/main/runner/scenarios.conf).
   A missing need is a `SKIP` with the reason, not a failure.
2. Builds a content directory from the `rules` checkout plus any YARA file the catalog row names
   (`response-marker.yar` for `response`).
3. Starts a fresh agent: `agent run --standalone --content-dir <run>/content --alerts
   <run>/alerts.ndjson --events <run>/events.jsonl` plus the row's `agent_flags`, and waits up to
   90 seconds for the Linux sensor to log that it is listening.
4. Runs `bash scenarios/<name>.sh` from the run directory, under `sudo` when the row says
   `root yes`, with a 300-second timeout and this environment:

   | Variable | Value |
   | --- | --- |
   | `EVENTS` | The agent's event log for this run |
   | `ALERTS` | The agent's alert log for this run |
   | `AGENT_PID` | The agent's pid |
   | the row's `env` | For example `EXPECT=observe` for `response` and `ransomware-reflex`, `TAG=lab` for `prevalence-lineage` |

5. Waits the row's `settle` seconds (default 3), then until the alert file has not grown for
   two seconds (at most 20 more), copies it, and only then stops the agent.
6. Judges the copy against the sidecar ([sidecar-format.md](sidecar-format.md#how-the-rig-parses-a-sidecar))
   and the script's exit code.

One agent per scenario: a late alert or rule state from one scenario cannot leak into the next.

| Result | Meaning |
| --- | --- |
| `PASS` | Every expected technique fired within `[min_count, min_count + tolerance]` and nothing else fired |
| `UNEXPECTED` | The expectations are met, but other techniques fired too |
| `FAIL` | An expected technique fired too few or too many times |
| `ERROR` | The agent did not start, or the script exited non-zero with the counts otherwise met |
| `SKIP` | The guest lacks a need; the reason is shown |

`RESPONSE-ESCALATE`, a follow-up record the agent adds on top of detections, is listed but not
judged unless a sidecar expects it. `rig.py run` exits 1 when a scenario fails or errors;
`UNEXPECTED` does not fail the run, but each one is either a false positive or a sidecar to
update.

To inspect the catalog and the expectations without a VM, from the rig checkout:

```sh
bash runner/run-scenarios.sh --scenarios ../scenarios/scenarios --list
bash runner/run-scenarios.sh --scenarios ../scenarios/scenarios --check
```

`--check` fails when a `scenarios/*.sh` has no catalog row, a cataloged scenario has no script or
no readable sidecar, or a row names a YARA file that does not exist. A new scenario therefore
needs a pull request in the rig as well ([writing-scenarios.md](writing-scenarios.md#adding-a-linux-scenario)).

On Windows guests the rig uses
[`runner/run-scenarios.ps1`](https://github.com/synthaea-lab/rig/blob/main/runner/run-scenarios.ps1)
and [`runner/scenarios-windows.conf`](https://github.com/synthaea-lab/rig/blob/main/runner/scenarios-windows.conf),
whose `expect` column stands in for the missing sidecars.

## By hand

On a Linux test machine with the agent built from
[synthaea-lab/agent](https://github.com/synthaea-lab/agent) and a configuration at
`/etc/synthaea/agent.toml` (see the agent's
[configuration guide](https://github.com/synthaea-lab/agent/blob/main/docs/configuration.md)), and
the checkouts side by side:

```sh
# Terminal A, in the agent checkout. --content-dir is the directory that holds rules/.
sudo ./target/release/agent run --standalone --content-dir .. \
    --alerts /tmp/alerts.ndjson --events /tmp/events.jsonl

# Terminal B, in this repository.
./scenarios/beacon.sh
```

Then compare `/tmp/alerts.ndjson` with `scenarios/beacon.yaml`. Count lines per technique:

```sh
grep -o '"technique":"[^"]*"' /tmp/alerts.ndjson | sort | uniq -c
```

Start the agent **before** the scenario and wait until it logs that the sensor is listening:
`bind-shell.sh`, for one, alerts on listeners the agent did not see at startup, and every
scenario is lost if the sensor attaches after it ran. Leave the agent running for a few seconds
after the scenario ends; correlation rules and the access-log poll decide after the fact.

Each script's header comment gives its exact usage, the agent flags it needs and the alert text
to expect. The [catalog](linux-scenarios.md) summarizes the requirements. In short:

| Requirement | Scenarios |
| --- | --- |
| Run the scenario as root | `log-clear`, `pid-reuse`, `signal`, `web-webshell-php` |
| An agent flag | `dns-exfil` (`--enable-dns-capture`); `response` (`--enable-kill --enable-quarantine` for `EXPECT=enforce`); `ransomware-reflex` (`--enable-kill` for `EXPECT=enforce`) |
| An `agent.toml` entry | `mysql-failed-login`, `web-webshell`, `web-webshell-php`, `web-custom-logformat` (`[[logs.sources]]`); `ransomware-reflex` (`[deception] canary_dirs`) |
| Extra content | `response` (`response-marker.yar` under `<content-dir>/rules/yara/`) |
| A real service | `mysql-failed-login` (MariaDB or MySQL), `web-*` (nginx or Apache, PHP-FPM for `web-webshell-php`) |
| Kernel or libc | `timestomp-linux` (BPF LSM active, kernel 6.3 or later), `dns-exfil` (glibc) |
| A control plane | `prevalence-lineage` (two enrolled hosts, not `--standalone`) |

`signal.sh` reads the agent's files itself: run it from the directory where the agent writes
`events.jsonl` and `alerts.ndjson`, or set `EVENTS` and `ALERTS`, and set `AGENT_PID` if the
process is not named `agent` or `synthaea-agent`.

On Windows, run the agent from an elevated prompt and the scenario with Windows PowerShell 5.1:

```powershell
powershell -ExecutionPolicy Bypass -File scenarios\encoded-powershell.ps1
```

[windows-scenarios.md](windows-scenarios.md) describes the self-checking `-AgentExe` runs, which
start and stop their own agent.

## Exit codes

The Linux scripts share one convention, implemented in [`lib/common.sh`](../lib/common.sh):

| Code | Meaning | Printed |
| --- | --- | --- |
| 0 | The scenario ran, and its self-check passed where it has one | The script's own summary |
| 1 | The scenario ran and its self-check failed | `FAIL: ...` lines on stderr |
| 2 | A precondition is not met (not root, a tool, service or setting missing); nothing was attempted | `ERROR: precondition not met: ...` on stderr |

The distinction lets a runner tell "this host is not set up for the scenario" from "the scenario
ran and something is wrong". Two exceptions: `signal.sh` prints its own `PASS` and `FAIL` lines
on stdout, and a self-checking scenario started without `EXPECT` stops with Bash's own
`parameter null or not set` error and code 1 (an invalid `EXPECT` value exits 2).

The Windows scripts run with `$ErrorActionPreference = "Stop"`, so any failure, a precondition
included, is a terminating error and exit code 1.

## Environment variables

Variables a scenario reads, all optional unless noted:

| Variable | Scenarios | Meaning |
| --- | --- | --- |
| `EXPECT` | `response`, `ransomware-reflex` (required) | `enforce` or `observe`: how the agent was started |
| `CANARY_DIR` | `ransomware-reflex` (required) | The directory listed in `[deception] canary_dirs`, not under `/tmp`, `/var/tmp` or `/dev/shm` |
| `COUNT`, `MAX_ENCRYPTED`, `PAUSE` | `ransomware-reflex` | Files to create (300), the most renames allowed before the kill (60), seconds between renames (0.04) |
| `PORT`, `CONNECTIONS`, `PAYLOAD` | `response` | Listener port (4444), connections one second apart (30), payload path (`/tmp/synthaea-response-payload.bin`) |
| `TAG` | `prevalence-lineage` (required) | Names the directory the fake web server runs from |
| `FAKE_COMM` | `web-webshell` | The parent's name: `nginx` (default), `apache2`, `httpd`, `php-fpm8.4`, ... |
| `WEB_ROOT` | `web-webshell-php` | The document root the PHP file is dropped under (`/var/www/html`) |
| `EVENTS`, `ALERTS`, `AGENT_PID` | `signal` | The agent's files and pid |
| `TMPDIR` | `ransomware-reflex` | Where the encryptor's script file is written |

Positional arguments select modes or targets: `pid-reuse.sh [recycled|real]`,
`ransomware-rename-burst.sh [single|loop]`, `signal.sh [live|kill|verify-kill]`,
`dns-exfil.sh [PARENT_DOMAIN]`, `mysql-failed-login.sh [USER]`, and a base URL for the `web-*`
scenarios.
