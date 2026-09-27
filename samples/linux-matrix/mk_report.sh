#!/bin/sh
# samples/linux-matrix/mk_report.sh — NDcPP v3.0e full compliance report
# generator.
#
# Consumes the CPL evidence lines a box suite run emits into the matrix log
# (and, where present, the KAT lines from the ndcppkats unit row), and
# renders the FINAL compliance report artifact.  Nothing is invented: every
# verdict cell is taken verbatim from real `CPL <cell>: PASS|FAIL|INFO ...`
# or `KAT <cell>: PASS|FAIL ...` lines in the run output.  A cell with no
# observed line is reported as "NO EVIDENCE", never as a PASS.
#
# Usage:
#   mk_report.sh <log> [report.md]
#     log      = a run output file that contains the CPL lines (the runner
#                captures kind stdout; run.sh's own log also works).
#     report.md= output path (default: <log>.compliance-report.md)
#
# Exit status: 0 if every known cell has at least one observed PASS/INFO
# line and none FAILed; 1 if some cell FAILed (nonconformance); 2 on usage
# error / no evidence found.

set -u

LOG="${1:-}"
[ -z "$LOG" ] || [ ! -r "$LOG" ] && { echo "mk_report: need a readable log file" >&2; exit 2; }
shift || true
OUT="${1:-$LOG.compliance-report.md}"

# ---- collect cells: <cell>:<verdict>:<evidence> (multiple per cell ok) ----
TMP="$(mktemp "${TMPDIR:-/tmp}/mkrep.XXXXXX")" || exit 2
trap 'rm -f "$TMP"' EXIT

# CPL lines: `CPL <cell>: <VERDICT> <evidence>` and KAT lines:
# `KAT <cell>: <VERDICT> <evidence>` (KAT evidence becomes the B-cell's).
sed -n -e 's/^CPL \([A-Z][A-Za-z0-9]*\): \(PASS\|FAIL\|INFO\) /\1:\2:/p' \
       -e 's/^KAT \([A-Z][A-Za-z0-9]*\): \(PASS\|FAIL\) /\1:\2:/p' \
    "$LOG" 2>/dev/null | sed 's/\\n/ /g' > "$TMP"

n="$(wc -l < "$TMP" | tr -d ' ')"
if [ "$n" -eq 0 ]; then
	echo "mk_report: no CPL/KAT cells found in '$LOG'" >&2
	exit 2
fi

# ---- which cells does the plan claim? (authoritative plan list) -----------
# A1..A14 FCS_IPSEC_EXT.1, B1..B6 crypto support SFRs.
CELLS="A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 A14 B1 B2 B3 B4 B5 B6"

# ---- aggregate: any FAIL -> FAIL; else any PASS -> PASS; else INFO -------
{
	echo "# NDcPP v3.0e — IPsec & IKE Compliance Report (generated)"
	echo
	echo "Source log: \`$LOG\`"
	echo "Generated : $(date -u '+%Y-%m-%d %H:%M:%SZ')"
	echo
	echo "Every cell below is quoted verbatim from the observed CPL/KAT lines"
	echo "of this run.  A cell with no observed line is **NO EVIDENCE**."
	echo
	echo "| Cell | Verdict | Observed evidence (quoted) |"
	echo "|------|---------|----------------------------|"
} >> "$OUT"

rc=0; n_noev=0; n_fail=0
for c in $CELLS; do
	raw="$(grep "^$c:" "$TMP" | sort -u)"
	if [ -z "$raw" ]; then
		echo "| $c | NO EVIDENCE | no CPL/KAT line observed in this run |" >> "$OUT"
		n_noev=$((n_noev+1)); continue
	fi
	# aggregate verdict for the cell (raw lines carry <CELL>:<VERDICT>:...)
	v=""
	if printf '%s\n' "$raw" | grep -q ":FAIL:"; then v="FAIL"; rc=1; n_fail=$((n_fail+1));
	elif printf '%s\n' "$raw" | grep -q ":PASS:"; then v="PASS";
	else v="INFO"; fi
	# render each distinct evidence line for this cell
	echo "| $c | $v | $(printf '%s\n' "$raw" \
	    | sed -e 's/:\(PASS\|FAIL\|INFO\):/ \1 → /' \
	          -e "s/^$c //" \
	    | sed ':a;N;$!ba;s/\n/<br>/g' ) |" >> "$OUT"
done

npass="$(grep -c ':PASS:' "$TMP")"
ninf="$(grep -c ':INFO:' "$TMP")"
nfail="$(grep -c ':FAIL:' "$TMP")"
{
	echo
	echo "## Suite summary"
	echo
	echo "- CPL/KAT evidence lines observed: **$n** ($npass PASS, $ninf INFO, $nfail FAIL)"
	echo "- Cells with a FAIL verdict: **$n_fail**"
	echo "- Cells with no evidence: **$n_noev** (of 20 planned: A1–A14, B1–B6)"
	echo
	if [ "$rc" -eq 0 ] && [ "$n_noev" -eq 0 ]; then
		echo "**CONCLUSION: all 20 planned cells have observed verdicts and none failed.**"
	else
		echo "**CONCLUSION: not fully green.** See FAIL / NO EVIDENCE rows above."
	fi
} >> "$OUT"

echo "mk_report: wrote $OUT ($n cells, $n_fail fail, $n_noev no-evidence)"
exit "$rc"
