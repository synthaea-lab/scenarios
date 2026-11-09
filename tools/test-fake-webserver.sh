#!/usr/bin/env bash
# Checks make_fake_webserver in lib/common.sh: which binary it copies (the shell, or
# $BASH when the shell is busybox), that the copy can run the lineage scenarios'
# spawn command, and spawn_shells_from's argv and parent. Runs unprivileged and writes only to a temporary directory.
#
#   tools/test-fake-webserver.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$REPO/lib/common.sh"

failures=0
work=$(mktemp -d)
add_cleanup rm -rf "$work"

# expect_copy_of SOURCE COPY DESCRIPTION — COPY must be an executable, byte-identical
# copy of SOURCE.
expect_copy_of() {
    if [ -x "$2" ] && cmp -s "$1" "$2"; then
        echo "ok: $3"
    else
        echo "FAIL: $3: $2 is not an executable copy of $1"
        failures=$((failures + 1))
    fi
}

make_fake_webserver "$work/nginx"
expect_copy_of /bin/sh "$work/nginx" "copies /bin/sh by default"

if "$work/nginx" -c '(/bin/sh -c "id >/dev/null")'; then
    echo "ok: the copy runs the scenarios' spawn command"
else
    echo "FAIL: the copy could not run the scenarios' spawn command"
    failures=$((failures + 1))
fi

# A shell that resolves to busybox: copying it would break its argv[0] dispatch.
cp /bin/sh "$work/busybox"
ln -s "$work/busybox" "$work/sh"
make_fake_webserver "$work/httpd" "$work/sh"
expect_copy_of "$BASH" "$work/httpd" "copies \$BASH when the shell resolves to busybox"

# Any other shell is copied itself, following symlinks.
ln -s /bin/sh "$work/dash-link"
make_fake_webserver "$work/apache2" "$work/dash-link"
expect_copy_of /bin/sh "$work/apache2" "copies a non-busybox shell through its symlink"

# spawn_shells_from: FAKE is run ITERATIONS times with the documented argv, as a
# direct child of the calling shell (the loop must not run in a subshell).
cat > "$work/recorder" <<'SH'
#!/bin/sh
printf '%s|%s|%s\n' "$PPID" "$1" "$2" >> "${0%/*}/spawn.log"
SH
chmod +x "$work/recorder"
progress=$(spawn_shells_from "$work/recorder" 2 | tr '\n' ';')
if [ "$progress" = "  iteration 1 done;  iteration 2 done;" ]; then
    echo "ok: spawn_shells_from prints one progress line per iteration"
else
    echo "FAIL: spawn_shells_from progress was: $progress"
    failures=$((failures + 1))
fi
rm -f "$work/spawn.log"
spawn_shells_from "$work/recorder" 2 >/dev/null
expected="$$|-c|(/bin/sh -c \"id >/dev/null\")"
if [ "$(sort -u "$work/spawn.log")" = "$expected" ] && [ "$(wc -l < "$work/spawn.log")" -eq 2 ]; then
    echo "ok: spawn_shells_from runs FAKE -c '(/bin/sh -c ...)' from the calling shell"
else
    echo "FAIL: spawn_shells_from spawned: $(cat "$work/spawn.log"); expected twice: $expected"
    failures=$((failures + 1))
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed."
    exit 1
fi
echo "All checks passed."
