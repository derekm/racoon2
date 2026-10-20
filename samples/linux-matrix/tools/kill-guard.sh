#!/bin/sh
# tools/kill-guard.sh [file|dir ...] -- refuse netns-unsafe daemon kills.
#
# `ip netns exec` only changes the NETWORK namespace; pkill/killall still
# scan every process in the PID namespace.  A kind that kills daemons by
# the shared install prefix or by bare daemon name therefore SIGKILLs the
# daemons of every concurrently running shard.  Kills must be scoped to the
# row's own per-row paths (pkill -f "$C/", the row's pid files, ...).
#
# Flags, on any non-comment line that is not a message (echo/log/printf):
#   - killall (by-name kill: never row-scoped)
#   - pkill whose arguments reference SBIN in any form ($SBIN, ${SBIN},
#     quoted or not)
#   - pkill whose pattern is a bare daemon name (iked, spmd, kinkd,
#     charon, starter), optionally with a path prefix
#   - pkill/killall wrapped in `ip netns exec`
# Exit 0 clean, 1 on any violation (each printed as file:line: text).
# Default target: the kinds/ directory and lib.sh next to this tool.
TOOLS=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
[ $# -gt 0 ] || set -- "$TOOLS/../kinds" "$TOOLS/../lib.sh"
rc=0
for t in "$@"; do
	if [ -d "$t" ]; then find "$t" -type f -name '*.sh'; else printf '%s\n' "$t"; fi
done | sort | while read -r f; do
	awk -v f="$f" '
	{
		line = $0
		if (line ~ /^[ \t]*#/) next
		# drop a trailing comment (" # ..."), keep "#" inside quotes rare enough
		code = line; sub(/[ \t]+#.*$/, "", code)
		bad = ""
		# message text (echo/log/printf ...) only DESCRIBES a kill
		if (code ~ /^[ \t]*(echo|log|printf)[ \t]/) next
		if (code ~ /(^|[^A-Za-z0-9_])killall([ \t]|$)/) bad = "killall"
		else if (code ~ /ip[ \t]+netns[ \t]+exec.*(^|[^A-Za-z0-9_])pkill([ \t]|$)/) bad = "ip netns exec ... pkill"
		else if (code ~ /(^|[^A-Za-z0-9_])pkill([ \t]|$)/) {
			args = code; sub(/^.*(^|[^A-Za-z0-9_])pkill[ \t]+/, "", args)
			sub(/[;|&].*$/, "", args)
			if (args ~ /\$\{?SBIN([^A-Za-z0-9_]|$)/) bad = "pkill by $SBIN"
			else if (args ~ /(^|[ \t"'"'"'\/])(iked|spmd|kinkd|charon|starter)(["'"'"' \t]|$)/) bad = "pkill by bare daemon name"
		}
		if (bad != "") { printf "%s:%d: %s: %s\n", f, NR, bad, line; found = 1 }
	}
	END { exit found ? 1 : 0 }' "$f" || echo FAIL
done | {
	out=$(cat)
	printf '%s' "$out" | grep -v '^FAIL$' | sed '/^$/d' >&2
	case "$out" in *FAIL*) exit 1 ;; esac
	exit 0
}
