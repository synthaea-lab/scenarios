# ml-capture

Workloads for recording the event captures the behavior model in
[synthaea-lab/ml](https://github.com/synthaea-lab/ml) is trained and evaluated on. The captures
themselves are data and are never committed.

| File | Purpose |
| --- | --- |
| `benign-workload.sh` | Ordinary, harmless commands run from many kinds of parent process (login shell, `sh -c`, `systemd-run`, `xargs`, `nohup`, script interpreters, web applications, user-installed tools), so the benign capture varies in its process lineage |
| `malicious-run.sh` | Runs the Linux scenarios from [`../scenarios/`](../scenarios/README.md) plus `odd-parents/` one after another, and writes the runner's pid and the time window to `<out-dir>/run.json` |
| `odd-parents/` | Scenarios whose parent process is unusual: a web application or an Office-named process running a shell, a binary dropped in `/dev/shm` or `/var/tmp` running children. Each declares `# Odd by: comm` or `# Odd by: path`; `tests/test_odd_parent_scenarios.py` in the ml repository keeps that true |

The benign workload only touches files in its own work directory and talks to a server it starts
on `127.0.0.1`. The malicious run inherits the [safety rules](../README.md#safety) of the
scenarios: use an isolated test VM.

## Recording a capture

The capture has to come from a real kernel: WSL2 reports no parent pids. Build the agent with
`cargo build --release -p agent`, then, on the VM:

```sh
# Benign: terminal A captures, terminal B runs the workload as the user to model.
sudo ./agent capture-events --output events.jsonl
DURATION=1200 ./ml-capture/benign-workload.sh

# Malicious: a fresh capture file, the scenarios run as root.
sudo ./agent capture-events --output events-malicious.jsonl
sudo ./ml-capture/malicious-run.sh out-malicious
```

`DURATION` is in seconds (default 900) and `SEED` makes the job order repeatable. Running the
benign workload a second time as root adds `systemd-run` units parented by the system manager.
Keep each run's capture separate, and check `failed` in `out-malicious/run.json` before using a
malicious run.

## Training and evaluation

From an ml checkout, with this repository checked out beside it:

```sh
python -m synthaea_ml.data.manifest write \
    --platform linux --os-version "Fedora 44" --workload-label dev \
    --capture-start <ISO> --capture-end <ISO> --baseline-filename events.jsonl \
    datasets/captures/linux-lab-<date>/

python -m synthaea_ml.training.train_behavior \
    --dataset datasets/captures/linux-lab-<date>/ \
    --output-dir registry/behavior-iforest-linux/0.1.0/ \
    --robustness-scenarios ../scenarios/scenarios/beacon.yaml ../scenarios/scenarios/lineage.yaml \
    --robustness-events datasets/labeled/linux-lab-<date>/events.jsonl

python -m synthaea_ml.evaluation.t1_lineage_gain \
    --benign-dataset datasets/captures/linux-lab-<date>/ \
    --malicious-capture datasets/labeled/linux-lab-<date>/events.jsonl \
    --root-pid <root_pid> --start-ns <start_ns> --end-ns <end_ns> \
    --output registry/behavior-iforest-linux/0.1.0/t1_lineage_gain.json
```

`t1_lineage_gain` measures whether adding parent-process features improves detection at the same
false-positive budget. When reporting its result, give the number of distinct benign and malicious
vectors next to every rate, and report the gain separately for scenarios that are odd by name, odd
by path, both, and ordinary lineage: the gain can only show on scenarios whose parent is odd.
