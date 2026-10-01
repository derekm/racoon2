#!/bin/sh
# run-shards.sh — run the cases.tsv matrix in N parallel shards on ONE host,
# then merge the per-shard logs and sum the tallies.
#
# The matrix's expensive rows are netem/timer-bound (i2ike-silence DPD
# ladder, rekey waits, netem replay windows), so wall-time is dominated by
# idle sleeps, not CPU.  Splitting the rows across N parallel run.sh
# instances (each in its own shard) with the SAME installed prefix — but
# resource-disjoint — cuts wall-time ~N-fold.
#
# SAME-HOST SAFETY:
#   Every two-netns kind calls lib.sh row_ns "$name", which names netns,
#   veth, unix sockets, log dirs and resume dirs FROM THE ROW NAME.  Two
#   rows of the SAME kind therefore use disjoint resources on one host, so
#   we round-robin ALL non-charon rows across shards (row-ordered; shard k
#   gets the k-th, (k+M)-th, ... row).  Charon-seat rows are host-global
#   (/var/run/charon.ctl + killall -9 charon) and stay pinned to shard 0,
#   running serially there.
#
# usage: bash run-shards.sh <M> <cases-regex> <merged-log> [--src DIR] [--prefix DIR]
#   M           number of parallel shards (>= 1; 1 = plain run.sh)
#   cases-regex run.sh --cases filter; pass '' or '.*' for all rows
#   merged-log  file receiving the concatenated per-shard logs (shard logs
#               sit alongside as <merged-log>.<K> until merged)
#   env: R2_ADDKE/R2_DPD/R2_BOX pass through to run.sh
#   exit       0 iff every shard PASSed (fail counts summed)
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
M=${1:-1}
CASES=${2:-.*}
MERGED=${3:-/tmp/r2-shards.log}
shift 3
SRC=
PREFIX=
while [ $# -gt 0 ]; do
	case $1 in
	--src) SRC=$2; shift 2 ;;
	--prefix) PREFIX=$2; shift 2 ;;
	*) echo "unknown arg: $1" >&2; exit 2 ;;
	esac
done
[ -n "$SRC" ] || SRC=${R2_SRC:-/home/derek/src/racoon2}
export R2_SRC=$SRC

# sanity: M must be a positive integer
case "$M" in ''|*[!0-9]*) echo "bad shards '$M'" >&2; exit 2 ;; esac
[ "$M" -ge 1 ] || { echo "shards must be >= 1" >&2; exit 2; }

if [ "$M" -eq 1 ]; then
	if [ -n "$PREFIX" ]; then
		bash "$HERE/run.sh" --src "$SRC" --prefix "$PREFIX" --cases "$CASES" >"$MERGED" 2>&1
	else
		bash "$HERE/run.sh" --src "$SRC" --cases "$CASES" >"$MERGED" 2>&1
	fi
	exit $?
fi

# ---- build a kind-partitioned plan -------------------------------------
# Every row's (name, kind) that survives the CASES filter; group by kind.
# kind families are assigned to shards greedily by row-count (heaviest
# family first, into the currently-lightest shard), EXCEPT that charon
# rows are pinned to shard 0 (host-global charon.ctl / killall).
rows=""                 # "name kind" lines (space-split, safe names)
while IFS="$(printf '\t')" read -r name kind rest || [ -n "$name" ]; do
	name=$(printf '%s' "$name" | tr -d '\r')
	kind=$(printf '%s' "$kind" | tr -d '\r')
	case $name in ''|\#*) continue ;; esac
	printf '%s %s' "$name" "$kind" | grep -Eq "$CASES" || continue
	rows="$rows
$name $kind"
done <"$HERE/cases.tsv"

# assigned[shard] = "name1 name2 ..." ; weight per shard
i=0
for shard in $(seq 1 1 "$M"); do
	eval "A$shard="
done

# 1) charon rows -> shard 0 (index 1)
if printf '%s' "$rows" | grep -q 'charon'; then
	# keep relative order: assign each charon row, in order, to shard 0
	for r in $(printf '%s' "$rows" | grep ' charon$'); do
		eval "A1=\"\${A1:-} $r\""
	done
fi

# 2) round-robin the remaining (non-charon) rows across all shards IN ORDER.
#    row_ns() names every resource from the row NAME (netns/sockets/D/C/
#    resume dirs are per-row), so two concurrent same-kind rows now use
#    disjoint resources on one host — no kind-family packing needed.
#    NOTE: build $non via command substitution and loop with `for`, NOT
#    `printf | while` — a pipeline's while runs in a subshell and the
#    A$shard=  assignment would be lost here.
non=$(printf '%s' "$rows" | grep -v ' charon$' | sed '/^[[:space:]]*$/d' | awk '{print $1}')
ii=0
for n in $non; do
	[ -n "$n" ] || continue
	shard=$(( (ii % M) + 1 )); ii=$((ii + 1))
	eval "A$shard=\"\${A$shard:-} $n\""
done

# ---- launch one run.sh per shard with a family-scoped --cases regex -----
pids=
rc_file=$(mktemp /tmp/r2-shards.XXXXXX)
s=1
while [ "$s" -le "$M" ]; do
	shard_log="$MERGED.$((s-1))"
	: >"$shard_log"
	eval "names=\${A$s:-}"
	if [ -n "$names" ]; then
		# anchored alternation of this shard's names
		SEL='^('; first=1
		for n in $names; do
			if [ "$first" = 1 ]; then SEL="$SEL$n"; first=0; else SEL="$SEL|$n"; fi
		done
		SEL="$SEL)([[:space:]]|$)"
		if [ -n "$PREFIX" ]; then
			bash "$HERE/run.sh" --src "$SRC" --prefix "$PREFIX" --cases "$SEL" >>"$shard_log" 2>&1 &
		else
			bash "$HERE/run.sh" --src "$SRC" --cases "$SEL" >>"$shard_log" 2>&1 &
		fi
		echo "$! $shard_log" >>"$rc_file"
	fi
	s=$((s + 1))
done

# wait for all lanes; collect rc per lane
total_pass=0; total_fail=0; total_skip=0; any_fail=0
while read -r pid shard_log; do
	if wait "$pid"; then
		:
	else
		any_fail=1
	fi
	pass=$(grep -E '^pass=[0-9]+ fail=[0-9]+ skip=[0-9]+$' "$shard_log" | tail -1 | sed -E 's/^pass=([0-9]+) fail=([0-9]+) skip=([0-9]+)$/\1 \2 \3/')
	[ -z "$pass" ] && pass="0 0 0"
	set -- $pass
	total_pass=$((total_pass + $1)); total_fail=$((total_fail + $2)); total_skip=$((total_skip + $3))
	echo "== shard $(basename "$shard_log") pass=$1 fail=$2 skip=$3"
done <"$rc_file"
rm -f "$rc_file"

# merge lane logs (lane header lines remain inside each lane's own log)
: >"$MERGED"
k=0
while [ "$k" -lt "$M" ]; do
	cat "$MERGED.$k" >>"$MERGED"
	rm -f "$MERGED.$k"
	k=$((k + 1))
done

echo "pass=$total_pass fail=$total_fail skip=$total_skip (summed over $M shards)" >>"$MERGED"
echo "pass=$total_pass fail=$total_fail skip=$total_skip (summed over $M shards)"
[ "$any_fail" -eq 0 ] && [ "$total_fail" -eq 0 ]
