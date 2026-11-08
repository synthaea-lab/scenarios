# Synthaea scenarios

Benign attack simulations for validating the [Synthaea](https://github.com/synthaea-lab) agent end to
end. Each scenario reproduces one technique the way an attacker would, so the detections it should
trigger can be checked against a live agent, not only against unit tests.

| Path | Contents |
| --- | --- |
| `scenarios/` | One scenario per technique: a script (`*.sh` for Linux/macOS, `*.ps1` for Windows) and a `*.yaml` sidecar stating what must fire (technique, rule, severity) and what was measured live |
| `ml-capture/` | The workloads behind the ML training captures: a benign workload, a malicious run, and odd-parent variants |

## Safety

These scripts are **benign by construction**: they create and remove their own files, connect only to
local listeners, and undo what they change on exit. They still behave like attacks (persistence
writes, log deletion, `LD_PRELOAD`, beaconing), which is the point. **Run them only on a disposable
test machine or VM, never on a host that matters**, and expect any EDR on that machine to react.

## Running one

Build the agent ([synthaea-lab/agent](https://github.com/synthaea-lab/agent)), start it standalone in
one terminal, and run the scenario in another:

```sh
sudo ./target/release/agent run --standalone --content-dir <rules checkout parent> \
     --alerts /tmp/alerts.ndjson --events /tmp/events.ndjson     # terminal A, in the agent repo
./scenarios/beacon.sh                                            # terminal B, in this repo
```

The scenario's `.yaml` sidecar says which alert to expect in `/tmp/alerts.ndjson`. Some scenarios need
root or extra setup; their header comment says so.

## Byte-exact sidecars

The ML pipeline ([synthaea-lab/ml](https://github.com/synthaea-lab/ml)) binds each trained model's record
to the exact bytes of the scenario sidecars it was evaluated against. Editing a `.yaml` file
invalidates those bindings: change one only together with a retrain, and keep its line endings LF
(`.gitattributes` enforces it).
CI holds both lines: `scenarios/sidecars.sha256` lists every sidecar's hash
(`python3 tools/check-sidecar-bytes.py` checks it and says how to regenerate it), and a pull request
that edits, renames or deletes a sidecar fails unless it carries the `retrain` label.

## License

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions need a DCO sign-off
(`git commit -s`), which CI checks on every pull request.
