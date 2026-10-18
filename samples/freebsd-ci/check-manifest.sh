#!/bin/sh
# check-manifest.sh — dispatcher rows == lanes/all.rows, both directions.
#
# Fast static gate.  Run it on the Ubuntu runner BEFORE the FreeBSD VM:
# a drift here must not burn a 30-minute boot.  The numeric `-eq 103`
# invariant is gone (f42a2e0 -> 9f77115 -> d69a148); this equality is
# the gate.  Do not replace it with a count literal.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
SCRIPT=$HERE/freebsd-vnet-matrix.sh
MAN=$HERE/lanes/all.rows
T=$(mktemp -d "${TMPDIR:-/tmp}/r2-manifest.XXXXXX")
trap 'rm -rf "$T"' EXIT
awk '/^case "\$ROW" in/{f=1} f&&/^\t\t;;/{exit} f' "$SCRIPT" |
	grep -E '^[[:space:]]*run ' | awk '{print $2}' | sort > "$T/script"
# Strip CR so a CRLF manifest compares equal under BSD awk too.
awk '{ gsub(/\r/, ""); if ($0 ~ /^[[:space:]]*(#|$)/) next; print $1 }' "$MAN" |
	sort > "$T/man"
ns=$(wc -l < "$T/script" | tr -d ' ')
nm=$(wc -l < "$T/man" | tr -d ' ')
if cmp -s "$T/script" "$T/man"; then
	echo "MANIFEST: dispatcher=$ns manifest=$nm equal"
	exit 0
fi
echo "MANIFEST: FAIL dispatcher=$ns manifest=$nm (not equal)"
diff "$T/script" "$T/man" | sed 's/^/    /'
exit 1
