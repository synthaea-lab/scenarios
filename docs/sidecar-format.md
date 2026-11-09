# Sidecar format

Every Linux scenario `scenarios/<name>.sh` has a sidecar `scenarios/<name>.yaml` that states,
without running anything, which alerts the agent must raise when the scenario runs and how many
times. The Windows scenarios have none yet ([windows-scenarios.md](windows-scenarios.md)).

Three parsers read sidecars, with different strictness. A sidecar is valid only if all three read
it the same way, so this page documents the shape they share, then each parser's rules.

## Shape

```yaml
name: beacon
platform: linux
script: beacon.sh
simulates: >
  Periodic same-destination C2 traffic.
expected_detections:
  - technique: "T1071/T1041"
    rule: check_beacon       # crates/rules/src/network_state.rs
    min_count: 1
    tolerance: 0
  - technique: "T1059/T1071"
    rule: rule_respawn_connect   # crates/correlator/src/rules.rs
    min_count: 1
    tolerance: 20
notes: >
  Live-run measurements and caveats, in prose.
```

## Fields

| Field | Type | Required by | Meaning |
| --- | --- | --- | --- |
| `name` | string | ML | The scenario name: the file stem, without extension. The ML pipeline records it and later finds the sidecar again as `<scenarios dir>/<name>.yaml`, so it must equal the stem |
| `platform` | string | none | `linux` in every current sidecar. Documentation; no parser reads it |
| `script` | string | none | The script's file name (`beacon.sh`). Documentation; runners derive the script from the sidecar's stem |
| `simulates` | string | none | One or two sentences: what the scenario does |
| `expected_detections` | list | rig, ML | One entry per expected alert technique (below). Must be non-empty: the rig's catalog check rejects a cataloged scenario whose sidecar yields no expectation, the ML loader raises on a missing key, and the ML robustness evaluation refuses an empty list |
| `notes` | string or `null` | none | Measurements from live runs, why a count is what it is, known caveats. No parser reads it |

Each entry of `expected_detections`:

| Field | Type | Required by | Meaning |
| --- | --- | --- | --- |
| `technique` | string | rig, ML | Matched by **exact string equality** against the `technique` field of each line of the agent's `alerts.ndjson`. Not decomposed: `T1071/T1041` does not match an alert tagged `T1071` |
| `rule` | string | ML | What raises the alert in the agent, usually a function name with its source file in a trailing comment. Descriptive: the ML replay copies it into its record but never matches it against an alert, and the rig ignores it |
| `min_count` | integer, at least 1 | ML (rig defaults to 1) | Fewest matching alerts for a pass |
| `tolerance` | integer, at least 0 | ML (rig defaults to 0) | How many alerts above `min_count` still pass |

A technique passes when its count `c` satisfies `min_count <= c <= min_count + tolerance`. A
scenario passes when every listed technique passes.

### Technique strings

The `technique` field of an alert is whatever the agent's rule or correlator wrote, so a sidecar
uses the agent's label verbatim. The current sidecars use three kinds:

| Kind | Examples | Raised by |
| --- | --- | --- |
| One ATT&CK technique or sub-technique | `T1059`, `T1059.004`, `T1486`, `T1571` | A rule in the agent's [`rules`](https://github.com/synthaea-lab/agent/blob/main/docs/detection/rules.md) crate, or a Sigma rule (its tags joined with `/`) |
| Several techniques joined with `/` | `T1071/T1041`, `T1105/T1059/T1071`, `T1048.003/T1071.004` | A [correlation](https://github.com/synthaea-lab/agent/blob/main/docs/correlation.md) rule or a stateful rule that names several techniques |
| A non-ATT&CK label | `BAYES`, `RESPONSE-KILL`, `RESPONSE-QUARANTINE`, `LOG-SOURCE` | The Bayesian belief crossing its threshold, the [response](https://github.com/synthaea-lab/agent/blob/main/docs/response.md) audit records, the log-source misparse watch |

Always quote the value (`"T1059"`). YAML would read an unquoted `T1059` as a string anyway, but a
quoted value cannot turn into a number, a date or a boolean if a future label happens to look
like one, and both rig parsers strip the quotes.

### Choosing `min_count` and `tolerance`

`min_count` is what the scenario provably causes; `tolerance` is the noise the detection is
allowed to add on top. Set them from live runs on the rig's machines, and write the measurement
in `notes`:

- **One alert per iteration.** `argv.sh` and `lineage.sh` run three iterations and their rules
  have no windowed deduplication, so `min_count: 3, tolerance: 0`.
- **Side effects that are themselves the technique.** `persistence-write.sh` expects
  `min_count: 2`: the append to `~/.bashrc`, and the restore on exit, which is also a write-intent
  open on a persistence path.
- **Detections without deduplication.** `beacon.yaml` expects `T1059/T1071` with
  `tolerance: 20`. The script's four `nc` clients share the script as parent, which is enough for
  the respawn-and-connect correlation, and that rule fires again on every qualifying spawn past its
  threshold instead of once per window. The count depends on how many connections land in one
  window; only "at least once" is the assertion, and 20 is headroom, not a measured ceiling.
- **Response records.** `response.yaml` allows `tolerance: 5` on `RESPONSE-KILL` and
  `RESPONSE-QUARANTINE`, because the beacon keeps producing qualifying events after the first
  response decision.

`tolerance: 0` is the default and the strongest assertion: it catches a rule that starts
double-firing. Raise it only with a measured reason.

An over-count fails the scenario. That is deliberate: a rule that fires 40 times on one stimulus
is a noisy rule, and a scenario is where it shows.

## How the rig parses a sidecar

Neither rig runner uses a YAML library. The Linux runner extracts expectations with a short `awk`
program ([`expectations` in `run-scenarios.sh`](https://github.com/synthaea-lab/rig/blob/main/runner/run-scenarios.sh)),
and the Windows runner mirrors it line for line in PowerShell (`Get-Expectations` in
[`run-scenarios.ps1`](https://github.com/synthaea-lab/rig/blob/main/runner/run-scenarios.ps1)), so a
guest needs neither Python nor a YAML module. The rules both implement:

1. The block starts at a line beginning with `expected_detections:` in column 0.
2. It ends at the first line that starts with anything other than a space, a tab, `#` or `-`:
   the next top-level key. A list written flush with the key (`- technique: ...` in column 0)
   stays inside the block.
3. On every line of the block, everything from the first `#` on is dropped.
4. A line containing `technique:` starts a new expectation, with `min_count` 1 and `tolerance` 0.
   The value is taken to the end of the line, with one pair of surrounding `"` or `'` removed.
5. A later line containing `min_count:` or `tolerance:` sets that number on the current
   expectation. Any other line (`rule:`, comments, blank lines) is ignored.
6. Keys outside the block are never read. A sidecar with no block yields no expectation, which
   the runners judge as "no alert expected"; the catalog check rejects it for a cataloged
   scenario.

`python3 rig.py check` in a rig checkout runs both parsers on every sidecar of the sibling
scenarios checkout and on the fixtures in its
[`tests/sidecars/`](https://github.com/synthaea-lab/rig/tree/main/tests/sidecars), and fails if they
disagree. To see what the Linux runner reads from one sidecar:

```sh
bash ../rig/runner/run-scenarios.sh --expectations scenarios/beacon.yaml
```

```text
T1071/T1041|1|0
T1059/T1071|1|20
```

## How the ML pipeline parses a sidecar

[`load_expected_detections`](https://github.com/synthaea-lab/ml/blob/main/synthaea_ml/evaluation/scenario_replay.py)
loads the file with `yaml.safe_load` and reads `name` and, for each entry of
`expected_detections`, all four of `technique`, `rule`, `min_count` and `tolerance`. A missing key
raises `KeyError`: a malformed sidecar fails loudly instead of producing an empty result. It is
used by the scenario replay (an `alerts.ndjson` from any run, turned into a recorded pass or fail)
and by the robustness evaluation, which mutates a scenario's events and measures how often the
model still detects them.

The ML judge differs from the rig in two ways:

- It ignores techniques that fired but are not expected. The rig reports them as `UNEXPECTED`.
- It ignores the script's exit code. The rig reports a non-zero exit as `ERROR`.

It also counts by technique only, and copies the expected `rule` onto the observation. Two
entries in one sidecar with the same `technique` would therefore share one count; no current
sidecar does this, and a new one must not.

## The portable subset

Because the rig reads lines and the ML pipeline reads YAML, a sidecar must stay inside the subset
on which they agree:

- Block style only, two-space indentation, `expected_detections:` at column 0 and the keys
  `technique`, `rule`, `min_count`, `tolerance` each on its own line. No flow style
  (`[{technique: ...}]`), no anchors or aliases.
- Write all four keys in every entry, even when `min_count: 1` and `tolerance: 0` are the rig's
  defaults: the ML loader has no defaults.
- Plain decimal integers for `min_count` and `tolerance`, unquoted.
- No `#`, `"` or `'` inside a technique string, and no `technique:`, `min_count:` or
  `tolerance:` text inside the block other than the keys themselves (a `rule:` value or a comment
  containing `min_count: 3` would be read as one).
- Multi-line comments under a key are fine: the rig drops them, YAML ignores them.

The `name` field must match the file stem, and every sidecar is UTF-8 with LF line endings.

## Hash binding

The ML pipeline stores, in each scenario-replay result and robustness card of a trained model's
record, the SHA-256 of the sidecar bytes it was judged against (`scenario_yaml_sha256`). The
pipeline's provenance check recomputes the hash of `<scenarios dir>/<name>.yaml` and rejects a
record whose sidecar no longer matches. One changed byte, including a comment, trailing
whitespace or a CRLF checkout, invalidates every record bound to that sidecar.

Three mechanisms in this repository protect those bytes:

| Mechanism | What it does |
| --- | --- |
| [`.gitattributes`](../.gitattributes) | `scenarios/*.yaml text eol=lf`, so no checkout, Windows included, rewrites line endings |
| [`scenarios/sidecars.sha256`](../scenarios/sidecars.sha256) | The `sha256sum` line of every tracked sidecar. [`tools/check-sidecar-bytes.py`](../tools/check-sidecar-bytes.py) fails on a sidecar whose bytes differ, a sidecar missing from the manifest, or a manifest line for an untracked file |
| The `retrain` label | The CI workflow ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml), job `sidecar-bytes`) fails a pull request that modifies, renames or deletes an existing sidecar unless the pull request carries the `retrain` label |

The rules that follow:

- **Adding** a sidecar is always allowed. Add its line to the manifest.
- **Editing, renaming or deleting** an existing sidecar is allowed only together with a retrain of
  the models bound to it. Label the pull request `retrain`, and regenerate the manifest.
- A wrong count in an existing sidecar is therefore not fixed in place for convenience. Note the
  observation in the scenario's header comment or in the rig's catalog note, and fold the fix
  into the next retrain.

Regenerate the manifest from the repository root:

```sh
git ls-files 'scenarios/*.yaml' | xargs sha256sum > scenarios/sidecars.sha256
python3 tools/check-sidecar-bytes.py
```

```text
21 sidecar(s), all match scenarios/sidecars.sha256
```
