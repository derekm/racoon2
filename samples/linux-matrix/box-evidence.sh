#!/bin/sh
# box-evidence.sh — CI-visible proof the private box ran the box/dpd rows.
#
# Those rows never run in GitHub CI (R2_BOX / R2_DPD unset).  Greenness
# is not assumed.  The box posts a summary; a nightly job fails if the
# last accepted post is older than 36h.
#
# On the box, after a matrix run with R2_BOX=yes and R2_DPD=yes:
#   sh samples/linux-matrix/box-evidence.sh emit /path/to/matrix.log \
#     > /tmp/box-evidence.txt
#   gh workflow run box-evidence.yml --ref int/gsoc2026 \
#     -f summary="$(cat /tmp/box-evidence.txt)"
# Authenticity is the repo token that dispatches the workflow (no secret
# in the workflow file).  The sha256 line detects a truncated payload.
#
# check FILE [SHA] exits 0 only when the summary lists every gate=box and
# gate=dpd row exactly once as PASS, fail=0, the sha256 matches, the
# timestamp is within R2_BOX_EVIDENCE_MAX_AGE hours (default 36), and
# (REVIEW_2026-10-18 M5) its "commit:" line names exactly SHA (default:
# R2_BOX_EVIDENCE_COMMIT, else `git rev-parse HEAD` of this checkout), so
# evidence from older code never vouches for a newer tip.  emit records
# the commit of R2_SRC (default: this checkout) and refuses a dirty tree.
#
# These rows need root, netns and charon: they run on Derek's private box
# (or any host provisioned like it), never on GitHub runners.  Every
# failure prints the reason and what to do next.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
CASES=${R2_CASES:-$HERE/cases.tsv}
MAX_AGE=${R2_BOX_EVIDENCE_MAX_AGE:-36}

digest() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum | awk '{print $1}'
	else
		openssl dgst -sha256 | awk '{print $NF}'
	fi
}

box_rows() {
	awk -F '\t' '
		{ gsub(/\r/, "") }
		$0 ~ /^[[:space:]]*(#|$)/ { next }
		$6 == "box" || $6 == "dpd" { print $1 }
	' "$CASES" | sort
}

src_commit() {	# src_commit DIR: HEAD sha, empty if not a git tree
	git -C "$1" rev-parse --verify -q HEAD 2>/dev/null
}

emit() {
	log=$1
	[ -f "$log" ] || { echo "box-evidence: no log $log" >&2; exit 2; }
	src=${R2_SRC:-$HERE/../..}
	commit=$(src_commit "$src")
	[ -n "$commit" ] || { echo "box-evidence: cannot resolve the commit of $src (set R2_SRC to the tested checkout)" >&2; exit 2; }
	if [ -n "$(git -C "$src" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
		echo "box-evidence: $src has uncommitted changes; evidence must name the exact tested commit" >&2
		exit 2
	fi
	ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	host=$(hostname 2>/dev/null || echo unknown)
	rows=$(box_rows)
	[ -n "$rows" ] || { echo "box-evidence: no box/dpd rows in $CASES" >&2; exit 2; }
	body=$(mktemp "${TMPDIR:-/tmp}/r2-boxev.XXXXXX")
	: > "$body"
	fail=0 pass=0
	for name in $rows; do
		if grep -qE "^PASS ${name}( |$)" "$log"; then
			echo "$name PASS" >> "$body"
			pass=$((pass + 1))
		else
			echo "$name FAIL" >> "$body"
			fail=$((fail + 1))
		fi
	done
	# the digest covers the commit too, so it cannot be edited alone
	sum=$( { echo "commit: $commit"; cat "$body"; } | digest)
	n=$(wc -l < "$body" | tr -d ' ')
	printf 'timestamp: %s\nhost: %s\ncommit: %s\nrows: %s\npass: %s\nfail: %s\nsha256: %s\n---\n' \
		"$ts" "$host" "$commit" "$n" "$pass" "$fail" "$sum"
	cat "$body"
	rm -f "$body"
	[ "$fail" -eq 0 ]
}

check() {
	file=$1
	wantsha=${2:-${R2_BOX_EVIDENCE_COMMIT:-$(src_commit "$HERE/../..")}}
	[ -f "$file" ] || { echo "box-evidence: no file $file" >&2; exit 2; }
	[ -n "$wantsha" ] || { echo "box-evidence: FAIL: no commit to check against (pass SHA or set R2_BOX_EVIDENCE_COMMIT)" >&2; exit 1; }
	commit=$(awk -F ': ' '$1=="commit"{print $2; exit}' "$file")
	if [ -z "$commit" ]; then
		echo "box-evidence: FAIL: summary has no 'commit:' line (emitted by an older box-evidence.sh); re-run the box rows at $wantsha and emit again" >&2
		exit 1
	fi
	if [ "$commit" != "$wantsha" ]; then
		echo "box-evidence: FAIL: evidence is for commit $commit but the ref under test is $wantsha; re-run the gate=box/dpd rows on the private box at $wantsha and dispatch box-evidence.yml" >&2
		exit 1
	fi
	ts=$(awk -F ': ' '$1=="timestamp"{print $2; exit}' "$file")
	fail=$(awk -F ': ' '$1=="fail"{print $2; exit}' "$file")
	want=$(awk -F ': ' '$1=="sha256"{print $2; exit}' "$file")
	[ -n "$ts" ] && [ -n "$want" ] || { echo "box-evidence: FAIL: summary lacks a timestamp or sha256 line (truncated or not emit output)" >&2; exit 1; }
	[ "$fail" = 0 ] || { echo "box-evidence: FAIL: the box run had fail=$fail gate=box/dpd rows (listed as FAIL below the ---); fix them and re-run" >&2; exit 1; }
	body=$(mktemp "${TMPDIR:-/tmp}/r2-boxev.XXXXXX")
	awk 'f && $2 ~ /^(PASS|FAIL)$/ { print } /^---$/ { f = 1 }' "$file" > "$body"
	got=$( { echo "commit: $commit"; cat "$body"; } | digest)
	if [ "$got" != "$want" ]; then
		echo "box-evidence: sha256 mismatch want=$want got=$got" >&2
		rm -f "$body"
		exit 1
	fi
	exp=$(mktemp "${TMPDIR:-/tmp}/r2-boxev.XXXXXX")
	act=$(mktemp "${TMPDIR:-/tmp}/r2-boxev.XXXXXX")
	box_rows > "$exp"
	awk '{ print $1 }' "$body" | sort > "$act"
	if ! cmp -s "$exp" "$act"; then
		echo "box-evidence: row set does not match gate=box|dpd in $CASES" >&2
		diff "$exp" "$act" | sed 's/^/    /' >&2
		rm -f "$body" "$exp" "$act"
		exit 1
	fi
	rm -f "$body" "$exp" "$act"
	# age: GNU date.  A missing -d is a hard fail, not a skip.
	now=$(date -u +%s)
	then=$(date -u -d "$ts" +%s 2>/dev/null) || {
		echo "box-evidence: cannot parse timestamp $ts" >&2; exit 1; }
	age=$(( (now - then) / 3600 ))
	if [ "$age" -gt "$MAX_AGE" ] || [ "$age" -lt 0 ]; then
		echo "box-evidence: timestamp $ts is ${age}h old (max ${MAX_AGE}h)" >&2
		exit 1
	fi
	echo "box-evidence: ok commit=$commit $ts age=${age}h"
}

case ${1:-} in
emit) emit "${2:?log}" ;;
check) check "${2:?file}" "${3:-}" ;;
*) echo "usage: box-evidence.sh emit LOG | check FILE [SHA]" >&2; exit 2 ;;
esac
