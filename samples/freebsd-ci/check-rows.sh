#!/bin/sh
# check-rows.sh <merged-log> <rows-manifest> <min-pass>
#
# Gate for the merged FreeBSD shard log, replacing the hard-coded TOTAL=106:
#   - every manifest row has exactly ONE verdict line
#     ("PASS|FAIL|XFAIL|XPASS freebsd-vnet <row>"),
#   - no verdict for a row that is not in the manifest (a new row must be
#     added to lanes/all.rows in the same commit),
#   - zero FAIL and zero XPASS; an XFAIL is accepted only for a row the
#     manifest marks "xfail",
#   - PASS + XFAIL >= <min-pass> ("all" = every manifest row; a matrix that aborted early or ran an
#     empty shard can never look green).
set -u
LOG=${1:?log}; MAN=${2:?manifest}; MIN=${3:?min-pass}
[ -s "$LOG" ] || { echo "ROWS: FAIL empty log $LOG"; exit 1; }
awk -v min="$MIN" '
	FNR == NR {
		if ($0 ~ /^[[:space:]]*(#|$)/) next
		want[$1] = 1; nwant++
		if ($2 == "xfail") xf[$1] = 1
		next
	}
	$2 == "freebsd-vnet" && $1 ~ /^(PASS|FAIL|XFAIL|XPASS)$/ {
		v[$3]++; verd[$3] = $1
		if (!($3 in want)) { printf "ROWS: FAIL verdict for unlisted row %s (add it to the manifest)\n", $3; bad++ }
		if ($1 == "FAIL") { printf "ROWS: FAIL row %s\n", $3; bad++ }
		if ($1 == "XPASS") { printf "ROWS: FAIL XPASS %s (defect fixed: drop its xfail mark)\n", $3; bad++ }
		if ($1 == "XFAIL" && !($3 in xf)) { printf "ROWS: FAIL XFAIL for %s which is not marked xfail\n", $3; bad++ }
		if ($1 == "PASS" || $1 == "XFAIL") ok++
	}
	END {
		for (r in want) {
			if (!(r in v)) { printf "ROWS: FAIL no verdict for %s\n", r; bad++ }
			else if (v[r] > 1) { printf "ROWS: FAIL %d verdicts for %s\n", v[r], r; bad++ }
		}
		if (min == "all") min = nwant
		if (ok + 0 < min + 0) { printf "ROWS: FAIL only %d rows passed, minimum %d\n", ok, min; bad++ }
		printf "ROWS: expected=%d passed=%d problems=%d\n", nwant, ok, bad
		exit (bad > 0)
	}' "$MAN" "$LOG"
