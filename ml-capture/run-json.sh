# shellcheck shell=bash
#
# write_run_json, sourced (never executed) by malicious-run.sh:
#   . "$(dirname "${BASH_SOURCE[0]}")/run-json.sh"
# It lives beside the capture drivers, not in lib/common.sh: only they write a run.json.

# write_run_json FILE ROOT_PID START_NS END_NS RAN_COUNT RAN... FAILED...
#
# Write the run record that t1_lineage_gain reads: the runner's pid, the window of the run
# in ns since the epoch, and the scenarios that ran and failed. The first RAN_COUNT names
# after it are the ones that ran, the rest the ones that failed (bash cannot pass two
# arrays). The JSON comes from Python's json module, so a name is always a valid string
# whatever it holds, and a non-numeric pid or timestamp is an error, not a broken file.
# Call it after the capture window closes (END_NS): its python3 must not be counted among
# the processes of the run.
write_run_json() {
    python3 -c '
import json, sys

path = sys.argv[1]
root_pid, start_ns, end_ns, ran_count = (int(arg) for arg in sys.argv[2:6])
names = sys.argv[6:]
if not 0 <= ran_count <= len(names):
    sys.exit(f"RAN_COUNT {ran_count} is not between 0 and the {len(names)} names given")
record = {
    "root_pid": root_pid,
    "start_ns": start_ns,
    "end_ns": end_ns,
    "ran": names[:ran_count],
    "failed": names[ran_count:],
}
with open(path, "w", encoding="utf-8") as out:
    json.dump(record, out, indent=2)
    out.write("\n")
' "$@"
}
