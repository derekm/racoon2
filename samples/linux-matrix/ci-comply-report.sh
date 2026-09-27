#!/bin/sh
# samples/linux-matrix/ci-comply-report.sh — GH Actions compliance report
# step.  Collects the real CPL/KAT evidence lines a workflow produced, runs
# mk_report.sh, and FAILS the job (gating PRs) when any compliance cell
# FAILed or no evidence at all was found.
#
# Usage (run inside the checkout, after the unit/matrix steps):
#   ci-comply-report.sh <report.md> <evidence file/dir>...
# Each arg is grepped recursively (-a) for `CPL <cell>:` / `KAT <cell>:`
# lines; the deduplicated set is fed verbatim to mk_report.sh.  Nothing is
# invented and no cell is asserted from a path the run did not exercise —
# an unobserved cell simply has no line and shows as NO EVIDENCE.
#
# Exit: 0 report generated without any FAIL cell; 1 a cell FAILed
# (nonconformance — this job must stay red); 2 no evidence / usage error.
set -u

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# deduped evidence staging under the report's directory
rept=${1:-}
[ -n "$rept" ] || { echo "usage: ci-comply-report.sh <report.md> <evidence>..."; exit 2; }
shift
[ "$#" -ge 1 ] || { echo "ci-comply-report: no evidence sources given"; exit 2; }

ev=$(mktemp "$(dirname "$rept")/comply-ev.XXXXXX") || exit 2
raw="$ev.raw"
trap 'rm -f "$ev" "$raw"' 0

for src in "$@"; do
	if [ -f "$src" ]; then
		grep -ahE '^(CPL |KAT )[A-Za-z0-9]+: (PASS|FAIL|INFO) ' "$src" >> "$raw" || true
	elif [ -d "$src" ]; then
		grep -ahrE '^(CPL |KAT )[A-Za-z0-9]+: (PASS|FAIL|INFO) ' "$src" >> "$raw" || true
	fi
done

sort -u "$raw" > "$ev"

if [ ! -s "$ev" ]; then
	echo "ci-comply-report: no CPL/KAT evidence found in the given sources" >&2
	exit 2
fi

sh "$HERE/mk_report.sh" "$ev" "$rept"
rc=$?
sed -n '1,8p' "$rept" 2>/dev/null
echo "ci-comply-report: $rept generated (rc=$rc)"
exit $rc
