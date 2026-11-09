# Technical documentation

This repository holds Synthaea's **attack scenarios**: small scripts that each perform one
technique the way an attacker would, benign by construction, plus a machine-readable statement
of what the agent must detect when they run. They are how the project checks, on real kernels and
real Windows builds, that a detection works end to end: sensor, normalization, rule or
correlation, alert. A scenario run against a live agent is an assertion, not a demo.

The repository is consumed by three things, none of which live here:

- the [rig](https://github.com/synthaea-lab/rig), which boots VMs, runs every safe scenario
  against a fresh agent and reports, per scenario, what was expected and what fired;
- the [ML pipeline](https://github.com/synthaea-lab/ml), which replays scenario results into model
  records and binds each record to the exact bytes of the sidecar it was judged against;
- a person on a test machine, who runs the agent in one terminal and a scenario in another.

The pages below explain the formats these consumers rely on, how the scripts are built and why,
and how to add to them. Each script's header comment covers that script; the design reasons
that span scripts are here.

**Safety.** Every scenario cleans up after itself, talks only to loopback listeners or names
that never resolve, and touches only files it created. It still behaves like an attack
(persistence writes, log deletion, `LD_PRELOAD`, beaconing, mass renames). Run scenarios only on
a disposable test machine or VM.

## Concepts and formats

- [architecture.md](architecture.md): the repository layout, the contract between a scenario and
  its consumers, and how one run flows from script to verdict.
- [sidecar-format.md](sidecar-format.md): the `<name>.yaml` sidecar field by field, how the rig
  and the ML pipeline parse it, the hash manifest and the rule for changing a sidecar.

## Using the scenarios

- [running.md](running.md): running a scenario by hand or through the rig, the environment a
  scenario receives, exit codes and results.
- [linux-scenarios.md](linux-scenarios.md): every Linux scenario, the agent mechanism it
  exercises, why it is shaped the way it is, and its parameters.
- [windows-scenarios.md](windows-scenarios.md): the Windows scenarios, the PowerShell 5.1
  constraints and the self-checking agent harness in `common.ps1`.
- [ml-capture.md](ml-capture.md): the workloads that record benign and malicious event data for
  the behavior model, and the `run.json` record.

## Contributing

- [writing-scenarios.md](writing-scenarios.md): adding a scenario step by step, and the reference
  for the shared shell helpers in [`lib/common.sh`](../lib/common.sh).
- [testing.md](testing.md): the repository checks, what each one guards, and how to validate a
  scenario on a VM.
- [limits.md](limits.md): known gaps and what the scenarios do not prove.

Related reference outside this repository: the agent's
[technical documentation](https://github.com/synthaea-lab/agent/tree/main/docs) (rules,
correlation, response, sensors) and the rig's
[README](https://github.com/synthaea-lab/rig#readme) (machines, commands, reports).
