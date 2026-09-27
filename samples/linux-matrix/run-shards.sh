#!/bin/sh
# run-shards.sh — run the cases.tsv matrix in N parallel shards on ONE host,
# then merge the per-shard logs and sum the tallies.
#
# The matrix's expensive rows are netem/timer-bound (i2ike-silence DPD
# ladder, rekey waits, netem replay windows), so wall-time is dominated by
# idle sleeps, not CPU.  Splitting the rows round-robin across N parallel
# run.sh instances (each in its own shard) with the SAME installed prefix —
# but disjoint rows, so no two lanes touch the same host :500 or SPD — cuts
# wall-time ~N-fold.  Each lane runs a separate `run.sh --shard K M`; the
# rows' own netns isolation (lib.sh R2_NS/R2_VETH_H/R2_VETH_C) keeps every
# lane disjoint even on the same host.
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
	# no fan-out: identical to a plain run.sh invocation (used by CI/box
	# upgrade paths that keep a single-lane default)
	if [ -n "$PREFIX" ]; then
		bash "$HERE/run.sh" --src "$SRC" --prefix "$PREFIX" --cases "$CASES" >"$MERGED" 2>&1
	else
		bash "$HERE/run.sh" --src "$SRC" --cases "$CASES" >"$MERGED" 2>&1
	fi
	exit $?
fi

pids=
rc_file=$(mktemp /tmp/r2-shards.XXXXXX)
k=0
while [ "$k" -lt "$M" ]; do
	shard_log="$MERGED.$k"
	: >"$shard_log"
	# each lane runs the shared prefix; gate env comes from the caller.
	if [ -n "$PREFIX" ]; then
		bash "$HERE/run.sh" --src "$SRC" --prefix "$PREFIX" \
			--cases "$CASES" --shard "$k" "$M" >>"$shard_log" 2>&1 &
	else
		bash "$HERE/run.sh" --src "$SRC" --cases "$CASES" \
			--shard "$k" "$M" >>"$shard_log" 2>&1 &
	fi
	echo "$! $shard_log" >>"$rc_file"
	k=$((k + 1))
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
	echo "== shard $(basename "$shard_log") pass=$1 fail=$2 skip=$3 rc=$?" 
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
