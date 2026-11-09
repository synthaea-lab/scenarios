# Linux scenarios

This page explains each Linux scenario: the stimulus, the agent mechanism it exercises, why the
script is shaped the way it is, and its expectations. The short table form, with requirements, is
the [catalog](../scenarios/README.md). Agent source paths below link into
[synthaea-lab/agent](https://github.com/synthaea-lab/agent).

Expectations are written `technique ×min_count(+tolerance)`, as the rig prints them. Unless noted,
a scenario runs as an ordinary user against `agent run --standalone`, and the rig runs it in its
`default` set.

Most rules referenced here live in two files of the agent's `rules` crate:
[`stateless.rs`](https://github.com/synthaea-lab/agent/blob/main/crates/rules/src/stateless.rs)
(one event, one verdict) and
[`state.rs`](https://github.com/synthaea-lab/agent/blob/main/crates/rules/src/state.rs)
(`RuleState`: windows, counters, per-pid memory). Correlation rules live in
[`crates/correlator/src/rules.rs`](https://github.com/synthaea-lab/agent/blob/main/crates/correlator/src/rules.rs).
The agent's [rules](https://github.com/synthaea-lab/agent/blob/main/docs/detection/rules.md) and
[correlation](https://github.com/synthaea-lab/agent/blob/main/docs/correlation.md) pages describe
them.

## Process and command line

### `lineage.sh`

[Script](../scenarios/lineage.sh) · [sidecar](../scenarios/lineage.yaml) · `T1059 ×3`

A copy of a real shell binary named `/tmp/nginx` runs a shell that runs `id`, three times, one
second apart. `check_web_server_spawns_shell` fires only if the child's parent pid resolves to the
process named `nginx`, so the alert proves that the sensor's process lineage is right on this
kernel ([process context](https://github.com/synthaea-lab/agent/blob/main/docs/sensors/linux/process-context.md)).
A broken lineage gives no alert at all, not a wrong one.

Shape decisions, all in [`lib/common.sh`](../lib/common.sh):

- The kernel takes a process's `comm` from the name of the executed file, so a copy of `/bin/sh`
  named `nginx` is a process named `nginx` (`make_fake_webserver`).
- On busybox systems `/bin/sh` is the multi-call binary, which dispatches on its own name and
  fails as `nginx`; the helper copies `$BASH` instead.
- Bash and dash execute a `-c` body consisting of one simple command in place instead of forking,
  which would make the leaf a child of the scenario rather than of `nginx`. The inner command is
  therefore wrapped in an explicit subshell, `(/bin/sh -c "id >/dev/null")` (`spawn_shells_from`).
- The path `/tmp/nginx` is fixed because the rig's lineage validation looks for it.

### `argv.sh`

[Script](../scenarios/argv.sh) · [sidecar](../scenarios/argv.yaml) · `T1059.004 ×3`

Three `sh -c` one-liners containing `base64 -d`. `check_base64_decode` matches a substring of the
command line, so it fires only if the agent captured the argument vector. The Linux sensor reads
`/proc/<pid>/cmdline` when it drains the exec event, not at `execve`. A process that exits within
the few milliseconds before the drain legitimately shows an empty command line, so each one-liner
starts with `sleep 0.2` to stay alive past it: the scenario measures capture fidelity, not that
race.

### `ld-preload-hijack.sh`

[Script](../scenarios/ld-preload-hijack.sh) · [sidecar](../scenarios/ld-preload-hijack.yaml) ·
`T1574.006 ×1` · needs `cc`

Compiles a shared object whose only code is a constructor that writes a marker file, then runs
`LD_PRELOAD=/tmp/edr-test-preload.so sleep 0.3`. `check_ld_preload_hijack` fires when the
`LD_PRELOAD` or `LD_AUDIT` value captured from `/proc/<pid>/environ` points outside the dynamic
linker's trust set ([`ld_trust.rs`](https://github.com/synthaea-lab/agent/blob/main/crates/rules/src/ld_trust.rs):
the standard library directories plus what `/etc/ld.so.conf` declares, with `/tmp`, `/var/tmp` and
`/dev/shm` never trusted).

The variable is set on a single `sleep` rather than on a `sh -c` wrapper: a wrapper would carry
`LD_PRELOAD` on two execs and make the count 1 or 2 depending on drain timing. The paths are
fixed because the marker path is compiled into the library and the alert names the library path.
The script warns if the marker is missing, which means the library did not load.

### `pid-reuse.sh`

[Script](../scenarios/pid-reuse.sh) · [sidecar](../scenarios/pid-reuse.yaml) · `T1486 ×1` · root,
`python3`

The mass-rename rule exempts a real `sed -i.bak`, which legitimately renames many files. To do so
the agent remembers which image each pid executed. This scenario checks that the memory does not
outlive the process: it runs a real `/bin/sed`, then writes `pid - 1` to
`/proc/sys/kernel/ns_last_pid` so the next fork receives the same pid, and that child sets its
`comm` to `sed` with `prctl` and renames 22 throwaway files with a `.bak` suffix. The agent must
treat it as a new process and raise `T1486`.

The child touches nothing unless it really received the recycled pid; otherwise a failed attempt
would consume the files and could raise `T1486` anyway, making a failure look like a pass. It
retries up to 50 times, since any other fork on the machine can take the number.

`pid-reuse.sh real` is the control: a real `sed -i.bak` over the same files, which must raise
nothing. The sidecar covers the default `recycled` mode.

## Network

### `beacon.sh`

[Script](../scenarios/beacon.sh) · [sidecar](../scenarios/beacon.yaml) ·
`T1071/T1041 ×1`, `T1059/T1071 ×1(+20)` · needs `nc`

Four `nc` connections to a loopback listener on port 4444, two seconds apart. `check_beacon`
fires once the same `(comm, destination, port)` reaches three connections in 60 seconds on a
non-standard port, and is deduplicated per window, hence exactly one. The four clients share the
script as parent and each connects, which also satisfies the correlator's `rule_respawn_connect`
(grouped by parent and `comm`); that rule is not deduplicated, so its count varies with timing.

### `respawn-beacon.sh`

[Script](../scenarios/respawn-beacon.sh) · [sidecar](../scenarios/respawn-beacon.yaml) ·
`T1071/T1041 ×1`, `T1059/T1071 ×1(+20)` · needs `nc`

A listener on port 4445 that restarts after every accepted connection, each time as a new pid,
and four client connections one second apart. It is the shape of an implant that respawns after
each beacon. Both alerts fire, for the same reasons as in `beacon.sh`: `check_beacon` keys on the
client's destination, not on any pid, and `rule_respawn_connect` groups by parent and `comm`, so
a new pid per respawn does not hide the pattern.

### `dropper-chain.sh`

[Script](../scenarios/dropper-chain.sh) · [sidecar](../scenarios/dropper-chain.yaml) ·
`T1105/T1059/T1071 ×1` · needs `nc`, `curl`

`curl -o` downloads from a loopback HTTP responder into a fresh `mktemp` file under `/tmp`. One
process executes, connects and writes a file within the window, which is what
`rule_spawn_connect_filewrite` correlates. `curl` is chosen because it does all three under one
pid; `wget ... && ./payload` would be two processes, a different rule. The output file is created
by `mktemp` (`O_EXCL`), so the write cannot follow a planted symlink; the rule keys on the pid,
not the path.

### `bind-shell.sh`

[Script](../scenarios/bind-shell.sh) · [sidecar](../scenarios/bind-shell.yaml) ·
`T1571 ×1`, `T1059/T1071 ×1` · needs `nc`

An interactive `sh` wired to a listening `nc` on `127.0.0.1:4445` through a FIFO (portable across
busybox, traditional and OpenBSD `nc`, unlike `nc -e`). `check_listen_port_drift` alerts on a
listener absent from the agent's startup snapshot. It reads the netlink `sock_diag` poll, every 10
seconds ([netlink](https://github.com/synthaea-lab/agent/blob/main/docs/sensors/linux/netlink.md)),
so the script holds the listener for 12 seconds before connecting. Then it sends `id` through the
shell and fails with exit 1 if no `uid=` comes back: a scenario that passes without a working
shell behind the port proves nothing. The client `nc`, spawned and then connecting, raises
`T1059/T1071` from `rule_spawn_connect`.

Start the agent before this scenario: a listener present at startup is baseline and never alerts.

### `dns-exfil.sh`

[Script](../scenarios/dns-exfil.sh) · [sidecar](../scenarios/dns-exfil.yaml) ·
`T1048.003/T1071.004 ×1` · needs `python3`, glibc, agent flag `--enable-dns-capture`

Sixteen lookups of 36-character random labels under `tunnel.example.invalid` (never resolves), 0.3
seconds apart, from one Python process calling `socket.getaddrinfo`. The correlator's
`rule_dns_exfil` counts distinct high-entropy subdomains per process. Two constraints dictate the
single Python process:

- The rule aggregates per process, so sixteen `dig` invocations would be sixteen processes with
  one query each, never reaching the threshold.
- On Linux the agent sees DNS through a uprobe on glibc's `getaddrinfo`
  ([uprobes](https://github.com/synthaea-lab/agent/blob/main/docs/sensors/linux/uprobes.md)).
  `dig` and `nslookup` build packets themselves and `getent hosts` uses a different NSS entry
  point, so none of them reach the probe. CPython's `getaddrinfo` calls the libc symbol.

On musl systems the uprobe has nothing to attach to; the rig's catalog notes the scenario as
glibc only.

## Persistence and defense evasion

### `persistence-write.sh`

[Script](../scenarios/persistence-write.sh) · [sidecar](../scenarios/persistence-write.yaml) ·
`T1546.004 ×2`

Appends a marked comment line to `~/.bashrc` and restores the file on exit.
`check_persistence_write` fires on a write-intent open of a path containing a known persistence
location. Two alerts: the append, and the restore, which is also a write-intent open of
`.bashrc`.

The restore copies the backup's content back into the original file instead of replacing it, so
the inode, permissions and a dotfile manager's symlink survive. The backup's name does not
contain `.bashrc`, so it never matches the rule. There is no `touch` before the append: GNU
`touch` opens an existing file for writing, which would be a third alert on GNU systems and not on
busybox ones.

### `log-clear.sh`

[Script](../scenarios/log-clear.sh) · [sidecar](../scenarios/log-clear.yaml) · `T1070.002 ×1` ·
root

Creates `/var/log/synthaea-scenario-test.log` and deletes it. `check_log_file_delete` fires on a
delete under a known log location. The safety-net cleanup checks that the file exists before
removing it: the probe fires at syscall entry, before the kernel knows whether the file exists, so
a second `unlink` would be a second alert. The exec-side sibling (`journalctl --vacuum` and the
like) is not exercised.

### `timestomp-linux.sh`

[Script](../scenarios/timestomp-linux.sh) · [sidecar](../scenarios/timestomp-linux.yaml) ·
`T1070.006 ×3` · needs the BPF LSM active and kernel 6.3 or later

Sets file times explicitly three ways (`touch -d`, Python `os.utime`, `touch -m -d`), then makes
three changes that must stay silent: a write (the kernel sets the mtime), a plain `touch`
(`UTIME_NOW`) and a `chmod`. The agent's BPF-LSM `inode_setattr` hook
([lsm](https://github.com/synthaea-lab/agent/blob/main/docs/sensors/linux/lsm.md)) reports explicit
time sets, and `evaluate_file_set_time` turns them into alerts. `tolerance: 0` makes the three
silent operations part of the assertion. The hook needs the `inode_setattr` signature introduced
in kernel 6.3, which is why the rig skips older kernels.

### `signal.sh`

[Script](../scenarios/signal.sh) · [sidecar](../scenarios/signal.yaml) · `T1562.001 ×2` · root

Tests the signal probe's kernel-side filter and the tamper rule on top of it
([signals](https://github.com/synthaea-lab/agent/blob/main/docs/sensors/linux/signals.md)). The
default `live` mode, which the sidecar covers:

1. 62 signals between two unrelated `sleep` processes must produce zero signal events.
2. `kill -0` to the agent must produce one signal event and no alert.
3. `SIGTERM` and `SIGKILL` to the agent from `nobody` (both fail with `EPERM`; the agent survives)
   must produce two events and two `T1562.001` alerts from `check_security_process_signal`. The
   probe fires at syscall entry, before the permission check, which is what makes a failed attempt
   visible.

The script counts events and alerts in the agent's own files before and after each step and
prints `PASS` or `FAIL` per check, because "zero events from unrelated traffic" is not an alert
count. `kill` mode then really kills the agent and records the sender pid in a state file in the
caller's private runtime directory (`$XDG_RUNTIME_DIR`, `/run/user/<uid>` or, for root, `/run`;
never `/tmp`, where a planted symlink could redirect a root write). After the agent restarts,
`verify-kill` waits up to 30 seconds for the replayed `T1562.001` alert naming that sender. The
replay depends on bpffs at `/sys/fs/bpf`. The rig runs only `live`, since the other two modes
restart the agent.

## Ransomware and response

### `ransomware-rename-burst.sh`

[Script](../scenarios/ransomware-rename-burst.sh) · [sidecar](../scenarios/ransomware-rename-burst.yaml) ·
`T1486 ×1` · needs `python3`

Renames 22 empty files from `file<n>.docx` to `file<n>.docx.locked` in a fresh directory under
`$HOME`. `check_mass_rename_pattern` fires at 20 renames in 5 seconds where the old name is a
strict prefix of the new one, whatever the extension. 22 gives a margin over the threshold.

- `single` (default, covered by the sidecar): one Python process does every rename; the per-pid
  counter fires.
- `loop`: one `mv` per file. Each `mv` is a new pid, so only the per-parent counter can see the
  burst.

The directory is under `$HOME` because ransomware targets documents, and to stay independent of
the sensor's special handling of `/tmp`.

### `ransomware-reflex.sh`

[Script](../scenarios/ransomware-reflex.sh) · [sidecar](../scenarios/ransomware-reflex.yaml) ·
`T1083 ×1(+2)`, `T1486 ×1(+3)`, `RESPONSE-KILL ×1(+2)` · `python3`; `[deception] canary_dirs`
and `CANARY_DIR`; `EXPECT`; opt-in in the rig

The ransomware reflex
([`ransomware_join.rs`](https://github.com/synthaea-lab/agent/blob/main/apps/agent/src/ransomware_join.rs))
kills a process that both raised the rename burst and touched a planted canary file
([deception](https://github.com/synthaea-lab/agent/blob/main/docs/detection/deception.md)) within
60 seconds. The scenario finds the canaries the agent planted in `CANARY_DIR` (files starting with
`# SYNTHAEA DECOY`), creates 300 throwaway `doc_<n>.docx` files beside them, then starts one Python
"encryptor" that reads every canary and renames the files one by one, 0.04 seconds apart.

It checks its own side: with `EXPECT=enforce` (agent started with `--enable-kill`) the encryptor
must exit 137 (`SIGKILL`) with at most `MAX_ENCRYPTED` (60) files renamed; with `EXPECT=observe`
it must finish all 300. The earliest the reflex can act is the 20th rename, and 60 leaves room for
sensor and drain latency at 25 renames per second.

`CANARY_DIR` must not be under `/tmp`, `/var/tmp` or `/dev/shm`, where the sensor does not report
read-only opens: the canary read would never be seen. The script stops with exit 2 when it is,
or when no canary is present. The encryptor is a single process because the join is per process.

### `response.sh`

[Script](../scenarios/response.sh) · [sidecar](../scenarios/response.yaml) ·
`BAYES ×1(+2)`, `RESPONSE-KILL ×1(+5)`, `RESPONSE-QUARANTINE ×1(+5)` · `nc`;
[`response-marker.yar`](../scenarios/response-marker.yar) in the content; `EXPECT`

Writes `/tmp/synthaea-response-payload.bin` containing the marker string
`SYNTHAEA-RESPONSE-SCENARIO-MARKER`, which the bundled YARA rule matches, then starts one Bash
process that connects to a loopback listener every second, 30 times. The correlator's Bayesian
belief crosses its threshold (`BAYES`) and the agent's
[response](https://github.com/synthaea-lab/agent/blob/main/docs/response.md) kills the process
and quarantines the payload, or, without `--enable-kill --enable-quarantine`, records that it
would have.

The implant is one long-lived process on purpose: a kill lands on the pid whose event crossed
the threshold, and `beacon.sh`'s four separate `nc` processes never accumulate enough belief. The
self-check mirrors `ransomware-reflex.sh`: killed (exit 137) and payload gone for
`EXPECT=enforce`, ran to completion and payload present for `EXPECT=observe`. The rig runs it in
`observe` mode with the YARA file added to the run's content.

The `RESPONSE-*` techniques fire in both modes; only the message ("killed pid N" against
"... (observe-only)") differs. The sidecar cannot tell the modes apart, the self-check can.
After an enforce run, the agent's `quarantine` command lists and restores the payload.

## Log sources

These scenarios need a real service writing a log file and a `[[logs.sources]]` entry in
`agent.toml` pointing at it ([service logs](https://github.com/synthaea-lab/agent/blob/main/docs/sensors/linux/service-logs.md)).
Each script's header gives the configuration. They are opt-in in the rig, which does not set up
the services.

### `mysql-failed-login.sh`

[Script](../scenarios/mysql-failed-login.sh) · [sidecar](../scenarios/mysql-failed-login.yaml) ·
`T1110 ×1`

Six failed logins to `127.0.0.1:3306` as a made-up user (`edr_lab_victim` by default). The agent
turns each `Access denied` line of the MariaDB or MySQL error log (a `mysql_error` source) into a
failed authentication, and the brute-force rule (`on_auth`, five failures in 60 seconds per user
and source) fires once. The error log must be a file: Debian and Ubuntu MariaDB log to the journal
by default, and MySQL 8 needs `log_error_verbosity = 3` to log the denials.

### `web-webshell.sh`

[Script](../scenarios/web-webshell.sh) · [sidecar](../scenarios/web-webshell.yaml) ·
`T1505.003 ×1`, `T1059 ×1` · nginx or Apache on port 80, `curl`; an `access_combined` source

Sends one request per access-log signature (SQL injection, path traversal, scanner user agent)
plus an ordinary one, waits three seconds, spawns a shell from a fake web server (`/tmp/nginx`,
as in `lineage.sh`), then sends a web-shell-like request (`/uploads/c99.php?cmd=id`). The
correlator's `rule_web_request_shell` pairs a shell spawned by a web server with a signature
request read from the shell's time through three seconds after it, which is why the decisive
request comes after the shell: the access log line is written after the response. The earlier
requests are read first and do not pair. The fake parent raises `T1059` through
`check_web_server_spawns_shell`.

### `web-webshell-php.sh`

[Script](../scenarios/web-webshell-php.sh) · [sidecar](../scenarios/web-webshell-php.yaml) ·
`T1505.003 ×1`, `T1059 ×1` · root, Apache with PHP-FPM on port 80, `curl`; an `access_combined`
source

The real version of the previous scenario: it drops a one-line PHP web shell under
`$WEB_ROOT/uploads/` (default `/var/www/html`) and requests it with `cmd=id`, so a real `php-fpm`
worker spawns the shell. It exits 1 if the server does not execute PHP.

### `web-custom-logformat.sh`

[Script](../scenarios/web-custom-logformat.sh) · [sidecar](../scenarios/web-custom-logformat.yaml) ·
`LOG-SOURCE ×1` · an Apache vhost on port 8081 with a custom `LogFormat`, declared as
`access_combined`

Sends 21 requests to a vhost whose log is not in combined format and waits 65 seconds. The agent
reports a source whose lines mostly fail to parse (at least 10 lines in 60 seconds, at least half
rejected) once, as `LOG-SOURCE`, instead of staying silently blind. The extra request after the
wait makes sure a poll runs after the window closes.

## Fleet

### `prevalence-lineage.sh`

[Script](../scenarios/prevalence-lineage.sh) · [sidecar](../scenarios/prevalence-lineage.yaml) ·
`T1059 ×3` · `TAG`; agents enrolled with a [control plane](https://github.com/synthaea-lab/server)

The `lineage.sh` chain, from `/tmp/prevalence-<TAG>/nginx`. The agent alerts locally as in
`lineage.sh`; the point is on the server, which records the transition
`/tmp/prevalence-<TAG>/nginx -> <shell>` as a prevalence key. Running the same `TAG` on two hosts
must show "seen on 2 hosts" on the case's transition line, and a `TAG` run on one host "seen on 1
host". The sidecar asserts only the local alert; the fleet half is read on the server.

## Other stimuli

| File | What it checks | How to run |
| --- | --- | --- |
| [`pending-syscall-exit-exec.c`](../scenarios/pending-syscall-exit-exec.c) | A negative case for the syscall-exit probes: a thread calls `execve` while the leader is blocked in `accept(2)`. The captured events must show an `ExecEvent` for `/bin/true` under the printed pid and no `SocketAccept` for it | `gcc -O2 -Wall -Wextra -pthread scenarios/pending-syscall-exit-exec.c -o pending-syscall-exit-exec`, then run it as root with the agent capturing events |
| [`v652-beacon.rs`](../scenarios/v652-beacon.rs) | The kill gate's exemption for service binaries: a dependency-free binary that tries a TCP connection to `127.0.0.1:4444` every second, 90 times. Installed under a trusted path (`/usr/libexec/v652-beacon`) and run as a systemd unit's `ExecStart`, its main process has parent pid 1, the case the [kill gate](https://github.com/synthaea-lab/agent/blob/main/docs/response.md#the-kill-gate) protects, unlike a shell or interpreter | `rustc -O scenarios/v652-beacon.rs`, then install it and a unit on the test machine |

Neither has a sidecar or a rig catalog row; both are judged by reading the agent's output.
