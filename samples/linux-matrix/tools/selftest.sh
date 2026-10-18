#!/bin/sh
# tools/selftest.sh -- root-free self-test of the matrix harness (run.sh).
#
# Drives run.sh with a throw-away cases file and a fake "st" kind, no
# netns, no daemons, no root, and asserts the verdict logic itself:
#   XFAIL at the exact defect value, XPASS -> FAIL, xfail failing for a
#   different reason -> FAIL, xfail without a defect regex -> FAIL,
#   R2_REQUIRE_LIVE (unexpected skip fails, manifest-listed skip passes,
#   empty run fails), R2_MIN_PASS, and the xfrm_audit analyser on canned
#   `ip -s xfrm state` samples (96-bit sha256 ICV, flat counters).
# Run by ci (ubuntu.yml "harness self-test") and locally: sh tools/selftest.sh
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
T=$(mktemp -d "${TMPDIR:-/tmp}/r2-selftest.XXXXXX")
trap 'rm -rf "$T"' EXIT
bad=0

cat > "$T/kind.sh" <<'K'
kind_st() {
	case $1 in
	*-ok)     log "st: all good"; return 0 ;;
	*-icv96)  log "XA ns icv FAIL spi 0x1 a->b: hmac(sha256) 96 (want 128)"; return 1 ;;
	*-other)  log "st: something else broke"; return 1 ;;
	*-noise)  log "debug: error in a passing note"; log "FAIL $1 (socket timeout)"; return 1 ;;
	esac
}
K
T_TAB=$(printf '\t')
mkcases() { printf '%s\n' "$@" | sed "s/|/$T_TAB/g" > "$T/cases.tsv"; }
run() {	# run <expect-rc> <label> [env...] -- runs run.sh, checks rc + output
	_want=$1 _lbl=$2; shift 2
	env R2_CASES="$T/cases.tsv" R2_EXTRA_KINDS="$T/kind.sh" R2_XFRM_AUDIT=0 \
		R2_SRC="$T" "$@" bash "$HERE/run.sh" > "$T/out" 2>&1
	_rc=$?
	if [ "$_rc" != "$_want" ]; then
		echo "SELFTEST FAIL $_lbl: rc=$_rc want $_want"; sed 's/^/    /' "$T/out"; bad=1
	else
		echo "SELFTEST PASS $_lbl (rc=$_rc)"
	fi
}
want() {	# want <label> <ERE>: last run output must match
	grep -Eq -- "$2" "$T/out" || { echo "SELFTEST FAIL $1: no /$2/"; sed 's/^/    /' "$T/out"; bad=1; }
}

D='hmac\(sha256\) 96 \(want 128\)'
mkcases "a-ok|st|pass|-|n|" "b-icv96|st|xfail|-|n|-|$D"
run 0 "xfail at exact value is not a failure"
want xfail-line '^XFAIL b-icv96 .*96 \(want 128\)'
want xfail-sum 'pass=1 fail=0 skip=0 xfail=1 xpass=0'

mkcases "c-ok|st|xfail|-|n|-|$D"
run 1 "fixed defect is XPASS and fails"
want xpass-line '^XPASS c-ok'

mkcases "d-other|st|xfail|-|n|-|$D"
run 1 "xfail row failing for another reason fails"
want other-line 'WITHOUT its declared defect'

mkcases "n-noise|st|xfail|-|n|-|error"
run 1 "broad defect regex on a debug line is not an XFAIL"
want noise-line 'WITHOUT its declared defect'

mkcases "e-icv96|st|xfail|-|n|"
run 1 "xfail without a defect regex fails"

mkcases "f-ok|st|pass|-|n|box" "g-ok|st|pass|-|n|"
run 0 "box-gated skip is fine without R2_REQUIRE_LIVE"
run 1 "R2_REQUIRE_LIVE fails an unexpected skip" R2_REQUIRE_LIVE=1 R2_LANE=selftest-none
want uskip 'unexpected SKIP'
run 0 "R2_REQUIRE_LIVE accepts a manifest-listed gate" R2_REQUIRE_LIVE=1 R2_LANE=ubuntu

mkcases "h-ok|st|pass|-|n|"
run 0 "empty run without R2_REQUIRE_LIVE (legacy)"
env R2_CASES="$T/cases.tsv" R2_EXTRA_KINDS="$T/kind.sh" R2_XFRM_AUDIT=0 R2_REQUIRE_LIVE=1 \
	bash "$HERE/run.sh" --cases '^no-such-row$' > "$T/out" 2>&1
if [ $? = 1 ] && grep -q 'empty run' "$T/out"; then echo "SELFTEST PASS empty run fails under R2_REQUIRE_LIVE"
else echo "SELFTEST FAIL empty run not caught"; cat "$T/out"; bad=1; fi
env R2_CASES="$T/cases.tsv" R2_EXTRA_KINDS="$T/kind.sh" R2_XFRM_AUDIT=0 R2_REQUIRE_LIVE=1 \
	bash "$HERE/run.sh" --cases 'no-such-row' > "$T/out" 2>&1
if [ $? = 2 ] && grep -q 'must be anchored' "$T/out"; then echo "SELFTEST PASS unanchored --cases rejected under R2_REQUIRE_LIVE"
else echo "SELFTEST FAIL unanchored --cases not rejected"; cat "$T/out"; bad=1; fi
env R2_CASES="$T/cases.tsv" R2_EXTRA_KINDS="$T/kind.sh" R2_XFRM_AUDIT=0 R2_REQUIRE_LIVE=1 \
	bash "$HERE/run.sh" --cases '.*' > "$T/out" 2>&1
if [ $? = 0 ]; then echo "SELFTEST PASS '.*' all-rows filter allowed under R2_REQUIRE_LIVE"
else echo "SELFTEST FAIL '.*' rejected"; cat "$T/out"; bad=1; fi
run 1 "R2_MIN_PASS" R2_MIN_PASS=2
run 0 "R2_MIN_PASS met" R2_MIN_PASS=1

# xfrm_audit analyser on canned samples
cat > "$T/s.log" <<'S'
@@ SAMPLE
src 10.0.0.1 dst 10.0.0.2
	proto esp spi 0x00000101(257) reqid 1(0x00000001) mode tunnel
	auth-trunc hmac(sha256) 0x00 (256 bits) 96
	enc cbc(aes) 0x00 (128 bits)
	lifetime current:
	  840(bytes), 10(packets)
	stats:
	  replay-window 0 replay 0 failed 0
src 10.0.0.2 dst 10.0.0.1
	proto esp spi 0x00000102(258) reqid 1(0x00000001) mode tunnel
	auth-trunc hmac(sha256) 0x00 (256 bits) 128
	enc cbc(aes) 0x00 (128 bits)
	lifetime current:
	  0(bytes), 0(packets)
	stats:
	  replay-window 0 replay 0 failed 3
@@ STAT
XfrmInStateProtoError   	3
@@ ADDR
2: v0    inet 10.0.0.1/24 scope global v0
S
awk -v ns=t -v allow_icv=0 -v allow_traffic=0 -v allow_safail=0 -v statallow= \
	-f "$HERE/tools/xfrm_audit.awk" "$T/s.log" > "$T/out"
r=$?
for p in 'icv FAIL .*hmac\(sha256\) 96 \(want 128\)' 'traffic FAIL' 'safail FAIL .*failed=3' 'xfrm_stat FAIL .*XfrmInStateProtoError\+3'; do
	grep -Eq -- "$p" "$T/out" || { echo "SELFTEST FAIL audit: no /$p/"; cat "$T/out"; bad=1; }
done
[ "$r" = 1 ] && echo "SELFTEST PASS audit flags 96-bit ICV, flat counter, integrity failures" || { echo "SELFTEST FAIL audit rc=$r"; bad=1; }
awk -v ns=t -v allow_icv=1 -v allow_traffic=0 -v allow_safail=1 -v statallow=XfrmInStateProtoError=3 \
	-f "$HERE/tools/xfrm_audit.awk" "$T/s.log" > "$T/out"
grep -q 'icv XFAIL' "$T/out" && echo "SELFTEST PASS audit XFAIL when declared" || { echo "SELFTEST FAIL audit XFAIL"; cat "$T/out"; bad=1; }

# FreeBSD manifest must list exactly the rows ROW=all runs, and the
# checker must not depend on GNU awk's CR tolerance.
FB=$HERE/../freebsd-ci
if [ -f "$FB/lanes/all.rows" ]; then
	if sh "$FB/check-manifest.sh"; then
		echo "SELFTEST PASS freebsd manifest equals dispatcher"
	else
		echo "SELFTEST FAIL freebsd manifest drifted"; bad=1
	fi
	printf 'PASS freebsd-vnet r1 (x)\nPASS freebsd-vnet r2 (x)\n' > "$T/fb.log"
	printf 'r1\nr2\n' > "$T/fb.rows"
	sh "$FB/check-rows.sh" "$T/fb.log" "$T/fb.rows" all > /dev/null &&
		echo "SELFTEST PASS check-rows accepts a complete log" || { echo "SELFTEST FAIL check-rows complete"; bad=1; }
	printf 'r1\nr2\nr3\n' > "$T/fb.rows"
	sh "$FB/check-rows.sh" "$T/fb.log" "$T/fb.rows" all > /dev/null &&
		{ echo "SELFTEST FAIL check-rows missed a missing row"; bad=1; } || echo "SELFTEST PASS check-rows fails a missing row"
	: > "$T/fb.empty"
	sh "$FB/check-rows.sh" "$T/fb.empty" "$T/fb.rows" all > /dev/null &&
		{ echo "SELFTEST FAIL check-rows passed an empty log"; bad=1; } || echo "SELFTEST PASS check-rows fails an empty log"
	printf 'r1\r\nr2\r\n' > "$T/fb.crlf"
	sh "$FB/check-rows.sh" "$T/fb.log" "$T/fb.crlf" all > /dev/null &&
		echo "SELFTEST PASS check-rows accepts a CRLF manifest" ||
		{ echo "SELFTEST FAIL check-rows rejected a CRLF manifest"; bad=1; }
fi

# Box-tier evidence: a complete PASS summary checks, a missing row does not,
# and the evidence is bound to one commit SHA.
BE=$HERE/box-evidence.sh
printf 'a	k	pass	0	n	box\nb	k	pass	0	n	dpd\n' > "$T/be.cases"
printf 'PASS a (ok)\nPASS b (ok)\n' > "$T/be.log"
BR=$T/be.repo
mkdir -p "$BR" && git -C "$BR" init -q && echo x > "$BR/f" && git -C "$BR" add f &&
	git -C "$BR" -c user.name=t -c user.email=t@t commit -qm t
BSHA=$(git -C "$BR" rev-parse HEAD)
R2_SRC="$BR" R2_CASES="$T/be.cases" sh "$BE" emit "$T/be.log" > "$T/be.ev"
if R2_CASES="$T/be.cases" sh "$BE" check "$T/be.ev" "$BSHA" >/dev/null; then
	echo "SELFTEST PASS box-evidence accepts a complete summary for its commit"
else
	echo "SELFTEST FAIL box-evidence rejected a complete summary"; bad=1
fi
if R2_CASES="$T/be.cases" sh "$BE" check "$T/be.ev" 0000000000000000000000000000000000000000 2>"$T/be.err" >/dev/null; then
	echo "SELFTEST FAIL box-evidence accepted evidence for another commit"; bad=1
elif grep -q 'evidence is for commit' "$T/be.err"; then
	echo "SELFTEST PASS box-evidence rejects another commit with a reason"
else
	echo "SELFTEST FAIL box-evidence commit mismatch gave no reason"; bad=1
fi
sed "s/^commit: .*/commit: 0000000000000000000000000000000000000000/" "$T/be.ev" > "$T/be.ev2"
if R2_CASES="$T/be.cases" sh "$BE" check "$T/be.ev2" 0000000000000000000000000000000000000000 >/dev/null 2>&1; then
	echo "SELFTEST FAIL box-evidence accepted an edited commit line"; bad=1
else
	echo "SELFTEST PASS box-evidence rejects an edited commit line (sha256)"
fi
grep -v '^commit: ' "$T/be.ev" > "$T/be.ev3"
if R2_CASES="$T/be.cases" sh "$BE" check "$T/be.ev3" "$BSHA" 2>"$T/be.err" >/dev/null; then
	echo "SELFTEST FAIL box-evidence accepted a summary without commit"; bad=1
elif grep -q "no 'commit:' line" "$T/be.err"; then
	echo "SELFTEST PASS box-evidence rejects a summary without commit"
else
	echo "SELFTEST FAIL box-evidence missing commit gave no reason"; bad=1
fi
echo y >> "$BR/f"
if R2_SRC="$BR" R2_CASES="$T/be.cases" sh "$BE" emit "$T/be.log" >/dev/null 2>&1; then
	echo "SELFTEST FAIL box-evidence emitted for a dirty tree"; bad=1
else
	echo "SELFTEST PASS box-evidence refuses to emit for a dirty tree"
fi
git -C "$BR" checkout -q f
printf 'PASS a (ok)\n' > "$T/be.log"
R2_SRC="$BR" R2_CASES="$T/be.cases" sh "$BE" emit "$T/be.log" > "$T/be.ev" || true
if R2_CASES="$T/be.cases" sh "$BE" check "$T/be.ev" "$BSHA" >/dev/null 2>&1; then
	echo "SELFTEST FAIL box-evidence accepted a missing row"; bad=1
else
	echo "SELFTEST PASS box-evidence rejects a missing row"
fi

[ "$bad" = 0 ] && echo "SELFTEST: all passed" || echo "SELFTEST: FAILURES"
exit "$bad"
