#!/usr/bin/env bash
# Checks make_fake_webserver in lib/common.sh: which binary it copies (the shell, or
# $BASH when the shell is busybox), and that the copy can run the lineage scenarios'
# spawn command. Runs unprivileged and writes only to a temporary directory.
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

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed."
    exit 1
fi
echo "All checks passed."
