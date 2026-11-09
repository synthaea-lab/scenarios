# Synthaea scenarios

Benign attack simulations for testing the [Synthaea](https://github.com/synthaea-lab/agent) EDR
agent end to end. Each scenario performs one technique the way an attacker would and states, in
a machine-readable sidecar, which detections it must trigger. A run against a live agent is an
assertion, not a demo.

> **Status: alpha.** The Linux catalog covers process lineage, command lines, network beacons,
> persistence, defense evasion, ransomware behavior, log sources and automated response. The
> Windows catalog is smaller and does not have sidecars yet. Scenarios change as the agent's
> detections change.

## Safety

The scenarios are benign by construction: they create and remove their own files, connect only to
local listeners, and undo what they change on exit. They still behave like attacks (persistence
writes, log deletion, `LD_PRELOAD` hijacking, beaconing, mass renames), which is the point.

**Run them only on a disposable test machine or VM, never on a host that matters.** Expect any
security product on that machine to react.

## What is in the repository

| Path | Contents |
| --- | --- |
| [`scenarios/`](scenarios/README.md) | The catalog: one script per technique (`*.sh` for Linux, `*.ps1` for Windows), and for each Linux script a `*.yaml` sidecar listing the detections it must trigger |
| [`ml-capture/`](ml-capture/README.md) | Workloads for recording the benign and malicious captures the ML models are trained and evaluated on |
| `lib/common.sh` | Helpers shared by the shell scenarios: cleanup on exit, loopback listeners, precondition checks |
| `tools/` | Repository checks, described in [CONTRIBUTING.md](CONTRIBUTING.md#checks) |

The [scenario catalog](scenarios/README.md) lists every scenario, what it simulates, what it must
trigger and what it needs on the host.

## Running scenarios

### With the rig

[synthaea-lab/rig](https://github.com/synthaea-lab/rig) boots a VM from a machine matrix, builds
the agent inside it, runs every safe scenario against it and reports, per scenario, what was
expected and what fired. It is the intended way to run this catalog:

```sh
mkdir synthaea && cd synthaea
for r in agent rules scenarios rig; do git clone https://github.com/synthaea-lab/$r.git; done
cd rig
python3 rig.py up debian12
python3 rig.py build debian12 --ort-compat   # Debian 12 needs the ONNX Runtime compatibility build
python3 rig.py run debian12
python3 rig.py report debian12
```

On Windows, clone the same four repositories into one directory and run the same `rig.py`
commands with `python` from an elevated PowerShell. The rig's README covers host setup on Linux,
Windows and macOS, the machine list and the scenarios that need extra setup.

### By hand

On a test machine with the agent built from
[synthaea-lab/agent](https://github.com/synthaea-lab/agent) and a configuration in place (on
Linux, `/etc/synthaea/agent.toml`; see the agent's
[configuration guide](https://github.com/synthaea-lab/agent/blob/main/docs/configuration.md)),
start the agent standalone in one terminal and run a scenario from this repository in another.
With the checkouts side by side as above:

```sh
# Terminal A, in the agent checkout. --content-dir is the directory that holds rules/.
sudo ./target/release/agent run --standalone --content-dir .. \
    --alerts /tmp/alerts.ndjson --events /tmp/events.ndjson

# Terminal B, in this repository.
./scenarios/beacon.sh
```

The scenario's sidecar (`scenarios/beacon.yaml`) names the alerts to look for in
`/tmp/alerts.ndjson`. Scenarios that need root, a service, an agent flag or a configuration entry
say so in their header comment and in the [catalog](scenarios/README.md).

On Windows, run the agent from an elevated prompt and the scenario with Windows PowerShell 5.1:

```powershell
powershell -ExecutionPolicy Bypass -File scenarios\encoded-powershell.ps1
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The scenario ran, and its self-check passed where it has one |
| 1 | The scenario ran and its self-check failed |
| 2 | A precondition is not met (not root, a tool or service missing, a wrong setting); nothing was attempted |

An unmet precondition also prints a line starting with `ERROR: precondition not met:` on stderr.

## Expected detections

Every Linux scenario has a YAML sidecar next to it that a runner can read without executing
anything:

```yaml
name: beacon
platform: linux
script: beacon.sh
simulates: >
  Periodic same-destination C2 traffic.
expected_detections:
  - technique: "T1071/T1041"
    rule: check_beacon
    min_count: 1
    tolerance: 0
notes: null
```

A run passes when each `technique` appears in the agent's alerts at least `min_count` times and
at most `min_count + tolerance` times. The [catalog](scenarios/README.md#sidecar-format) describes
every field.

The sidecars are also inputs to the [ML pipeline](https://github.com/synthaea-lab/ml): each
trained model's record is bound to the exact bytes of the sidecars it was evaluated against, so an
existing sidecar changes only together with a retrain. [CONTRIBUTING.md](CONTRIBUTING.md)
explains the rule.

## Related projects

| Repository | Role |
| --- | --- |
| [agent](https://github.com/synthaea-lab/agent) | The endpoint agent these scenarios test |
| [rules](https://github.com/synthaea-lab/rules) | Sigma and YARA detection content the agent loads |
| [rig](https://github.com/synthaea-lab/rig) | VM matrix and scenario runner |
| [ml](https://github.com/synthaea-lab/ml) | Model training and evaluation, which replays these scenarios |
| [server](https://github.com/synthaea-lab/server) | The control plane, needed by the fleet scenarios |

Project documentation is at [synthaea.com/en/docs](https://www.synthaea.com/en/docs).

Technical documentation for this repository is in [docs/](docs/README.md).

## Contributing

New scenarios and fixes are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) describes how a scenario
is structured, the checks to run before opening a pull request, and the sidecar rules. Every
commit needs a Developer Certificate of Origin sign-off (`git commit -s`).

Report security issues privately, as described in the
[security policy](https://github.com/synthaea-lab/.github/blob/main/SECURITY.md), not in a public
issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
