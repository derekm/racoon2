#!/bin/sh
# Exercise actual automake install rules without touching system directories.
set -eu
stage=$(mktemp -d "${TMPDIR:-/tmp}/r2-systemd-install.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
"${MAKE:-make}" install DESTDIR="$stage"
unit="$stage$UNITDIR"
sbin="$stage$SBINDIR"
test -f "$unit/iked.service"
grep -q '^NoNewPrivileges=true$' "$unit/iked.service"
grep -q '^ProtectSystem=strict$' "$unit/iked.service"
grep -q '^LimitCORE=0$' "$unit/iked.service"
if grep -q '@racoon_' "$unit/iked.service"; then
    echo 'unexpanded service paths' >&2; exit 1
fi
case "$DEBUG_CORES" in
yes)
    test -f "$unit/iked.service.d/core.conf"
    test -f "$unit/spmd.service.d/core.conf"
    test -x "$sbin/iked-core-bt"
    grep -q '^LimitCORE=infinity$' "$unit/iked.service.d/core.conf"
    ;;
no)
    test ! -e "$unit/iked.service.d/core.conf"
    test ! -e "$unit/spmd.service.d/core.conf"
    test ! -e "$sbin/iked-core-bt"
    ;;
*) echo 'missing/invalid DEBUG_CORES test mode' >&2; exit 1 ;;
esac
printf 'systemd staged install: debug-cores=%s PASS\n' "$DEBUG_CORES"
