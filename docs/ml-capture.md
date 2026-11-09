# ML capture workloads

[`ml-capture/`](../ml-capture/) holds the workloads used to record the event data the behavior
model in [synthaea-lab/ml](https://github.com/synthaea-lab/ml) is trained and evaluated on: one
benign workload, and a driver that runs the attack scenarios inside one measured window. The
recorded events are data and are never committed here.

## Why lineage variety matters

The behavior model is an Isolation Forest that scores a process on its command line, its
correlation context and its parents. A forest never splits on a feature that is constant in
training. If every benign process in the training data hangs under one shell, the model can never
learn that some other parent is unusual, because "parent" never varied. The benign workload
therefore runs ordinary commands from many kinds of parent, and the malicious run includes
scenarios whose parent is unusual on purpose.

## The benign workload

[`benign-workload.sh`](../ml-capture/benign-workload.sh) runs harmless jobs in random order for
`DURATION` seconds (default 900): reading, listing, archiving and deleting its own files, and
talking to an HTTP server it starts on `127.0.0.1:$PORT` (default 18080). The jobs come from
different parents: a login-style shell, `sh -c`, `systemd-run` units, `xargs`, `timeout`, `env`,
`setsid`, `nohup`, Python and Perl scripts that spawn children, web-application processes that
run one program with fixed arguments (never a shell), and user-installed tools under
`~/.local/share`.

Two choices keep the benign data honest:

- User tools run from the user's own directory, not from `/tmp`. Running them all from `/tmp` made
  "parent in a temporary directory" more common in benign data than in malicious data, an
  artifact of the workload rather than of real hosts.
- One job does run a script from `/tmp`, as installers and test runners do, so that a temporary
  parent path is not an alarm on its own.

`SEED` (default 1) makes the job order repeatable. Run as root, the workload's `systemd-run`
units get the system manager as parent, which adds another lineage. It cleans up its work
directory and tool directory, and removes `~/.local/share` again if it created it and left it empty.

## The malicious run

[`malicious-run.sh`](../ml-capture/malicious-run.sh) runs, as root, one after another with
`GAP` seconds between them (default 8) and a `TIMEOUT` per scenario (default 120):

- the Linux scenarios `beacon`, `bind-shell`, `dropper-chain`, `lineage`, `persistence-write`,
  `respawn-beacon`, `argv`, `log-clear`, and `ld-preload-hijack` when `cc` is installed;
- the three [`odd-parents/`](../ml-capture/odd-parents/) scenarios.

Left out: scenarios that need a service (web servers, MySQL), `signal.sh` (it targets the agent),
the ransomware and response scenarios (they exercise the response path, not behavior scoring) and
`dns-exfil.sh`.

A scenario that fails is recorded, not fatal; a script that is not executable is skipped with a
message and listed nowhere. The run exits 1 if none ran.

### Odd parents

| Scenario | Odd by | Shape |
| --- | --- | --- |
| [`webapp-spawns-shell.sh`](../ml-capture/odd-parents/webapp-spawns-shell.sh) | `comm` | Interpreter copies named like web servers run `sh -c` with reconnaissance commands (`id`, `uname -a`, the first lines of `/etc/passwd`) |
| [`office-spawns-shell.sh`](../ml-capture/odd-parents/office-spawns-shell.sh) | `comm` | A process named like an Office application runs a shell (the macro shape) |
| [`dropped-binary-spawns-children.sh`](../ml-capture/odd-parents/dropped-binary-spawns-children.sh) | path | Copies of `bash` and `python3` under innocuous names in `/dev/shm` or `/var/tmp` run children (the dropper shape) |

Each declares `# Odd by: comm` or `# Odd by: path`, and is odd by exactly that: the `comm` ones run
from the user's directory so their path is ordinary, and the path one uses names that are neither
web-server nor Office names. A gain measured on a scenario odd by both could not be credited to
either feature. `tests/test_odd_parent_scenarios.py` in the ml repository keeps the declarations
true. The Office one measures how the model treats a value it never saw in training, since no Linux
host runs an Office binary; say so when reporting a number on it. These scenarios have no sidecar:
they exist for this capture, not for the rule suite.

### `run.json`

The run writes `<out-dir>/run.json`, then prints it, through `write_run_json` in
[`ml-capture/run-json.sh`](../ml-capture/run-json.sh):

```json
{
  "root_pid": 12345,
  "start_ns": 1762700000000000000,
  "end_ns": 1762700300000000000,
  "ran": ["beacon", "odd-parents/webapp-spawns-shell"],
  "failed": ["ld-preload-hijack"]
}
```

| Field | Meaning |
| --- | --- |
| `root_pid` | The pid of `malicious-run.sh` itself. Every scenario process is its descendant; anything else in the window (the agent, SSH, cron) is not counted as malicious |
| `start_ns`, `end_ns` | The run's window, in nanoseconds since the epoch |
| `ran` | Scenarios that exited 0 |
| `failed` | Scenarios that exited non-zero or timed out |

The JSON is produced by Python's `json` module, so any scenario name is a valid string, and a
non-numeric pid or timestamp is an error rather than a broken file. `write_run_json` is called
after `end_ns` is taken, so its own `python3` falls outside the window. Check `failed` before
using a run.

## Recording

The events must come from a real kernel. Build the agent (`cargo build --release -p agent` in an
agent checkout), then on the test VM:

```sh
# Benign: terminal A captures, terminal B runs the workload as the user to model.
sudo ./agent capture-events --output events.jsonl
DURATION=1200 ./ml-capture/benign-workload.sh

# Malicious: a fresh capture file, the scenarios run as root.
sudo ./agent capture-events --output events-malicious.jsonl
sudo ./ml-capture/malicious-run.sh out-malicious
```

Keep each run's events in a separate file. The training and evaluation commands that consume
them, including the lineage-gain evaluation that reads `run.json`, are in
[`ml-capture/README.md`](../ml-capture/README.md#training-and-evaluation) and in the ml repository.
When reporting a lineage gain, give the number of distinct benign and malicious vectors next to
every rate, and report it separately for scenarios odd by name, by path, and ordinary lineage: a
gain can only show where the parent is odd.
