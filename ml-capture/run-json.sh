# shellcheck shell=bash
#
# write_run_json, sourced (never executed) by malicious-run.sh:
#   . "$(dirname "${BASH_SOURCE[0]}")/run-json.sh"
# It lives beside the capture drivers, not in lib/common.sh: only they write a run.json.

# write_run_json FILE ROOT_PID START_NS END_NS SCENARIOS_TSV
#
# Write the run record that t1_lineage_gain and the case labeller (ml#3) read: the runner's
# pid, the window of the run in ns since the epoch, the scenarios that ran and failed, and one
# entry per scenario with its own pid and window. SCENARIOS_TSV holds one line per scenario,
# `name<TAB>pid<TAB>start_ns<TAB>end_ns<TAB>exit_code`, in run order (bash cannot pass a list
# of records). A scenario ran when its exit code is 0 and failed otherwise.
#
# The per-scenario pid and window are what let a case be attributed to the scenario that
# produced it: the runner's pid alone says "some scenario", and a case's techniques can only
# be checked against the sidecar of the one it came from.
#
# The JSON comes from Python's json module, so a name is always a valid string whatever it
# holds, and a non-numeric pid, timestamp or exit code, a line without five fields, or a
# scenario window outside the run's is an error, not a broken file. Call it after the capture
# window closes (END_NS): its python3 must not be counted among the processes of the run.
write_run_json() {
    python3 -c '
import json, sys

if len(sys.argv) != 6:
    sys.exit("usage: write_run_json FILE ROOT_PID START_NS END_NS SCENARIOS_TSV")
path, tsv = sys.argv[1], sys.argv[5]
root_pid, start_ns, end_ns = (int(arg) for arg in sys.argv[2:5])
scenarios = []
with open(tsv, encoding="utf-8", newline="") as lines:
    for number, line in enumerate(lines, 1):
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 5:
            sys.exit(f"{tsv}:{number}: {len(fields)} fields, want name, pid, start_ns, end_ns, exit_code")
        pid, scenario_start, scenario_end, exit_code = (int(field) for field in fields[1:])
        if not start_ns <= scenario_start <= scenario_end <= end_ns:
            sys.exit(f"{tsv}:{number}: window {scenario_start}..{scenario_end} is not inside the run {start_ns}..{end_ns}")
        scenarios.append({
            "name": fields[0],
            "pid": pid,
            "start_ns": scenario_start,
            "end_ns": scenario_end,
            "exit_code": exit_code,
        })
record = {
    "root_pid": root_pid,
    "start_ns": start_ns,
    "end_ns": end_ns,
    "ran": [s["name"] for s in scenarios if s["exit_code"] == 0],
    "failed": [s["name"] for s in scenarios if s["exit_code"] != 0],
    "scenarios": scenarios,
}
with open(path, "w", encoding="utf-8") as out:
    json.dump(record, out, indent=2)
    out.write("\n")
' "$@"
}
