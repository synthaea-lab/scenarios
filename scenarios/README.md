# Scenario catalog

Each scenario is one script that performs one technique, benign by construction. Linux scenarios
come with a `<name>.yaml` sidecar listing the detections they must trigger; the script's header
comment explains the technique, the detection logic it exercises and how to read the result.

Run them only on a disposable test machine. See the [repository README](../README.md) for how to
run a scenario and what its exit code means.

Source paths in the header comments (`crates/rules/src/state.rs`, `apps/agent/src/...`) are
relative to the [agent](https://github.com/synthaea-lab/agent) repository. Usage lines that start
the agent (`target/release/agent run`) run in an agent checkout; the scenario itself runs from the
root of this repository.

## Linux

Unless noted, a scenario runs as an ordinary user against an agent started with
`agent run --standalone`.

### Process and command line

| Scenario | Simulates | Expected detection | Needs |
| --- | --- | --- | --- |
| `lineage.sh` | A process named like a web server spawns a shell | `T1059` | |
| `argv.sh` | A shell one-liner with a base64 decode in its arguments | `T1059.004` | |
| `ld-preload-hijack.sh` | `LD_PRELOAD` pointed at a shared object outside the dynamic linker's trusted paths | `T1574.006` | A C compiler (`cc`) |
| `pid-reuse.sh` | A recycled pid posing as `sed` renames files; `real` mode runs a real `sed -i.bak` as a control | `T1486` (`recycled`), none (`real`) | root, `python3` |

### Network

| Scenario | Simulates | Expected detection | Needs |
| --- | --- | --- | --- |
| `beacon.sh` | Periodic connections to the same local destination | `T1071/T1041`, `T1059/T1071` | `nc` |
| `respawn-beacon.sh` | A beacon that respawns after each connection | `T1071/T1041`, `T1059/T1071` | `nc` |
| `dropper-chain.sh` | One process downloads, writes and executes a payload | `T1105/T1059/T1071` | `nc`, `curl` |
| `bind-shell.sh` | A shell served on a loopback port through a listening `nc` | `T1571`, `T1059/T1071` | `nc` |
| `dns-exfil.sh` | Data chunked into high-entropy DNS subdomains of a domain that never resolves | `T1048.003/T1071.004` | `python3`, glibc, agent flag `--enable-dns-capture` |

### Persistence and defense evasion

| Scenario | Simulates | Expected detection | Needs |
| --- | --- | --- | --- |
| `persistence-write.sh` | A marked comment line appended to `~/.bashrc`, removed on exit | `T1546.004` | |
| `log-clear.sh` | A throwaway file under `/var/log/` deleted | `T1070.002` | root |
| `timestomp-linux.sh` | File times set explicitly three ways, next to a write, a plain `touch` and a `chmod` that must stay silent | `T1070.006` (three alerts) | `bpf` in the active LSM list, kernel 6.3 or later |
| `signal.sh` | Unprivileged `SIGTERM` and `SIGKILL` aimed at the agent, amid unrelated signal traffic | `T1562.001` | root; the `kill` and `verify-kill` modes restart the agent |

### Ransomware and response

| Scenario | Simulates | Expected detection | Needs |
| --- | --- | --- | --- |
| `ransomware-rename-burst.sh` | A burst of renames, each appending a suffix to the original name | `T1486` | `python3` |
| `ransomware-reflex.sh` | A benign encryptor reads planted canaries, then renames files one by one | `T1083`, `T1486`, `RESPONSE-KILL` | `python3`; `[deception] canary_dirs` in `agent.toml` and `CANARY_DIR` set to it; `EXPECT=enforce` or `EXPECT=observe` |
| `response.sh` | A process beacons every second while a YARA-marked payload is written | `BAYES`, `RESPONSE-KILL`, `RESPONSE-QUARANTINE` | `nc`; `response-marker.yar` installed under `<content-dir>/rules/yara/`; `EXPECT=enforce` or `EXPECT=observe` |

`EXPECT` states how the agent was started: `enforce` with `--enable-kill` (and
`--enable-quarantine` for `response.sh`), `observe` without them. The scenario checks its own
side: in `enforce` mode the process was killed, in `observe` mode it ran to completion.

### Log sources

These need a real service and a `[[logs.sources]]` entry in `agent.toml`; the script header shows
the configuration.

| Scenario | Simulates | Expected detection | Needs |
| --- | --- | --- | --- |
| `mysql-failed-login.sh` | Six failed logins against a local MariaDB or MySQL server | `T1110` | MariaDB or MySQL logging to a file; a `mysql_error` source |
| `web-webshell.sh` | One request per web-attack signature, then a shell spawned by a process named `nginx` | `T1505.003`, `T1059` | nginx or Apache on port 80, `curl`; an `access_combined` source |
| `web-webshell-php.sh` | A real PHP web shell dropped under the web root and run through a request | `T1505.003`, `T1059` | root, Apache with PHP-FPM on port 80, `curl`; an `access_combined` source |
| `web-custom-logformat.sh` | Requests to an Apache vhost whose log is not in combined format | `LOG-SOURCE` | Apache vhost with a custom `LogFormat` on port 8081, `curl`; declared as `access_combined` |

### Fleet

| Scenario | Simulates | Expected detection | Needs |
| --- | --- | --- | --- |
| `prevalence-lineage.sh` | The `lineage.sh` chain from a directory named by `TAG`, run on two hosts | `T1059`, with the case showing how many hosts saw the transition | Two hosts with agents uploading to a [control plane](https://github.com/synthaea-lab/server) (not `--standalone`); `TAG` set |

## Windows

The Windows scenarios run on a stock Windows PowerShell 5.1, under any locale. They have no
sidecars yet; each script's header states what must fire.

| Scenario | Simulates | Expected detection | Needs |
| --- | --- | --- | --- |
| `encoded-powershell.ps1` | `powershell.exe -EncodedCommand` with a benign payload | `T1059.001` | |
| `scheduled-task-persistence.ps1` | `schtasks.exe /Create` of a demo task that never runs, then deleted | `T1053.005` | Administrator |
| `service-install-persistence.ps1` | `sc.exe create` of a demo service that never starts, then deleted | `T1543.003` | Administrator |
| `create-account-persistence.ps1` | `net user /add` of a local account outside any privileged group, then deleted | `T1136.001` | Administrator |
| `bits-job.ps1` | `bitsadmin /transfer` of a `whoami.exe` copy from a local listener, then run | `T1197` | Self-checking with `-AgentExe`, which needs Administrator |
| `windows-container.ps1` | Processes in a process-isolated container and on the host | No alert: container attribution on the container's processes only | Administrator; the Containers feature and Docker in Windows-containers mode (Windows Server 2025, or Windows 11 22H2 or later Pro or Enterprise); self-checking with `-AgentExe` |

The self-checking scenarios write a lab agent configuration, start the agent, run, stop it and
print `PASS` or `FAIL` per expectation:

```powershell
powershell -ExecutionPolicy Bypass -File scenarios\bits-job.ps1 -AgentExe ..\agent\target\release\agent.exe
```

`common.ps1` holds the helpers the Windows scenarios share; it is not a scenario.

## Other files

| File | Purpose |
| --- | --- |
| `response-marker.yar` | The YARA rule `response.sh` needs installed in the agent's content directory |
| `pending-syscall-exit-exec.c` | A negative check for the Linux syscall-exit probes: a thread `execve`s while the leader is blocked in `accept(2)`, which must not produce a `SocketAccept` event for that pid |
| `v652-beacon.rs` | A standalone beacon binary for the rig's kill-gate validation, run as a systemd service from a trusted path; build it with `rustc -O` |
| `sidecars.sha256` | The hash of every sidecar, checked by `tools/check-sidecar-bytes.py` |

To run the syscall-exit check on a Linux test machine with the agent capturing events:

```sh
gcc -O2 -Wall -Wextra -pthread scenarios/pending-syscall-exit-exec.c -o /tmp/pending-syscall-exit-exec
sudo /tmp/pending-syscall-exit-exec
```

It prints its pid and exits 0. In the captured events, that pid has an `ExecEvent` for
`/bin/true` and no `SocketAccept`.

## Sidecar format

```yaml
name: <scenario name, without extension>
platform: linux
script: <name>.sh
simulates: >
  What the scenario does, in prose.
expected_detections:
  - technique: "<technique string>"
    rule: <name of the agent function that raises it>
    min_count: 1
    tolerance: 0
notes: <free text, or null>
```

| Field | Meaning |
| --- | --- |
| `technique` | Matched exactly against the `technique` field of each record in the agent's `alerts.ndjson`, which carries both rule and correlation alerts |
| `rule` | The agent function expected to raise it; documentation only, not checked at run time |
| `min_count` | The minimum number of matching alerts, at least 1 |
| `tolerance` | How many alerts above `min_count` are still a pass |
| `notes` | Measurements from live runs and caveats; not read by runners |

A scenario passes when every listed technique fires between `min_count` and
`min_count + tolerance` times. The [rig](https://github.com/synthaea-lab/rig) runner and the
[ML](https://github.com/synthaea-lab/ml) scenario replay read these files. Before editing an
existing sidecar, read the sidecar rules in [CONTRIBUTING.md](../CONTRIBUTING.md#sidecars).
