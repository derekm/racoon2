#!/bin/sh
# Reproducible WSL Linux matrix. Cases are rows in cases.tsv.
#   wsl.exe -d Ubuntu -u root -- bash samples/linux-matrix/run.sh
#   ./run.sh --cases 'unit|admin-empty'
# IKE rows with a numeric workers cell stop racoon2-iked, flush leftover
# SPD, restart racoon2-spmd (IKE-bypass cache), spawn iked -F with
# RACOON2_CRYPTO_WORKERS, restore after the case.
# Does not enable racoon2.target.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
# R2_CASES: alternate cases file (harness self-test); R2_EXTRA_KINDS: extra
# kind files to source (same).  Neither is set in CI matrix runs.
CASES_FILE=${R2_CASES:-$HERE/cases.tsv}
. "$HERE/lib.sh"
. "$HERE/xfrm_audit.sh"
. "$HERE/kinds/unit.sh"
. "$HERE/kinds/admin.sh"
. "$HERE/kinds/ikev2.sh"
. "$HERE/kinds/ikev1.sh"
. "$HERE/kinds/i2ike.sh"
. "$HERE/kinds/i2ixfrm.sh"
. "$HERE/kinds/i2i_peer.sh"
. "$HERE/kinds/i2ike_drop.sh"
. "$HERE/kinds/i2ike_drop576.sh"
. "$HERE/kinds/i2ike_dup.sh"
. "$HERE/kinds/i2ike_skfreplay.sh"
. "$HERE/kinds/i2ike_reqdrop.sh"
. "$HERE/kinds/i2ike_silence.sh"
. "$HERE/kinds/i2ike_collide.sh"
. "$HERE/kinds/i2ike_drain.sh"
. "$HERE/kinds/i2ike_redirect2.sh"
. "$HERE/kinds/i2ikesa.sh"
. "$HERE/kinds/i2i_rekey.sh"
. "$HERE/kinds/i2iinit.sh"
. "$HERE/kinds/i2ipubkey.sh"
. "$HERE/kinds/i2ieap.sh"
. "$HERE/kinds/i2inatt.sh"
. "$HERE/kinds/i2i_compliance.sh"
. "$HERE/kinds/i2i_neg.sh"
. "$HERE/kinds/i2iconf_life.sh"
. "$HERE/kinds/i2iconf_addrpool.sh"
. "$HERE/kinds/i2iinit_drop.sh"
. "$HERE/kinds/i2iinit_drop576.sh"
. "$HERE/kinds/i2i_nsawarn.sh"
. "$HERE/kinds/i2idh.sh"
. "$HERE/kinds/i2iv6.sh"
. "$HERE/kinds/i2io4.sh"
. "$HERE/kinds/i2ilw.sh"
. "$HERE/kinds/i2iresume.sh"
. "$HERE/kinds/i2iinit_nointermediate.sh"
. "$HERE/kinds/icvaudit.sh"
. "$HERE/kinds/pfkeyicv.sh"
for _xk in ${R2_EXTRA_KINDS:-}; do . "$_xk"; done

FILTER=
REBUILD=
R2_SRC=${R2_SRC:-/home/derek/src/racoon2}

crstrip() { printf '%s' "$1" | tr -d '\r'; }

usage() {
	cat <<EOF
usage: run.sh [--cases REGEX] [--rebuild BUILD] [--src DIR] [--prefix DIR]
              [--shard K M]
builds.tsv names: xfrm (Linux default), pfkey, xfrm-addke (RFC 9370 PQC)
cases.tsv kinds: unit admin ikev2 ikev1 i2ike
cases.tsv gates: gate=addke rows run ONLY when ADDKE is available (see
                 R2_ADDKE below); gate=dpd rows run ONLY when R2_DPD=yes;
                 gate=box rows run ONLY when R2_BOX=yes (new-row staging:
                 box-verified before a container run admits them to CI).
--shard K M    run only rows whose (filter-passing index) %% M == K.  Run M
                 disjoint shards in parallel (different shells/hosts) to cut
                 wall-time; sum the per-shard "pass=" lines for the total.
env: R2_ADDKE=yes|auto  force the ADDKE gate (default auto: detect WITH_ADDKE
     in the installed iked).  CI sets it explicitly per target: yes for
     Fedora 44 (OpenSSL 3.5), unset/auto for Ubuntu (OpenSSL 3.0).
     R2_DPD=yes / R2_BOX=yes: box-only rows (never set in CI).
     R2_REQUIRE_LIVE=1  every SKIP is a FAILURE unless the lane manifest
     (lanes/$R2_LANE.skip) expects it; also fails a run with zero PASS
     rows (an empty or fully-filtered run can never look green).
     R2_LANE=NAME       lane manifest name (ubuntu, fedora, pfkey, ...).
     R2_MIN_PASS=N      fail unless at least N rows PASS (or XFAIL).
cases.tsv expect: pass | skip | xfail.  An xfail row names its KNOWN
     defect in column 7 as an ERE that must match the row's output at the
     exact wrong value.  Row fails + regex matches -> XFAIL (ok); row passes
     -> XPASS -> FAIL (the defect is fixed: make the row "pass"); row fails
     without the regex -> FAIL (a different breakage).
EOF
}

while [ $# -gt 0 ]; do
	case $1 in
	--cases) FILTER=$2; shift 2 ;;
	--rebuild) REBUILD=$2; shift 2 ;;
	--src) R2_SRC=$2; shift 2 ;;
	--prefix) PREFIX=$2; ETC=$PREFIX/etc/racoon2; SBIN=$PREFIX/sbin; shift 2 ;;
	--shard) SHARD_K=$2; SHARD_M=$3; shift 3 ;;
	-h|--help) usage; exit 0 ;;
	*) usage; exit 2 ;;
	esac
done
# 0-based shard contract: a K >= M can never match `idx % M == K`, which
# would silently dispatch zero rows and exit 0 (a vacuous PASS/PASS summary).
# Reject it up front so a mistyped --shard 1 1 cannot fake a green full run.
if [ -n "${SHARD_M:-}" ] && [ "${SHARD_K:-0}" -ge "$SHARD_M" ]; then
	echo "error: --shard $SHARD_K $SHARD_M is an EMPTY shard (0 <= K < M required); use --shard 0 1 for a single full run" >&2
	exit 2
fi
# An unanchored --cases can match a typo'd subset and still look green.
# The warmup 'a^' is the one intentional unanchored pattern, and it does
# not set R2_REQUIRE_LIVE.  '.*' is the documented all-rows filter
# (run-shards.sh).  Any other live-lane filter must be anchored.
if [ -n "$FILTER" ] && [ "$FILTER" != '.*' ] && [ "${R2_REQUIRE_LIVE:-0}" = 1 ]; then
	case $FILTER in
	^*) ;;
	*) echo "error: --cases must be anchored (^...) when R2_REQUIRE_LIVE=1 (got: $FILTER)" >&2
	   exit 2 ;;
	esac
fi
export R2_SRC PREFIX ETC SBIN

# RFC 9370 ADDKE availability gate (env/configure-specific).
# R2_ADDKE=yes|no forces; 'auto'/unset detects WITH_ADDKE in the installed iked
# (the followup symbol is compiled in only under WITH_ADDKE, i.e. OpenSSL 3.5 /
# Fedora 44).  This is what keeps the PQC matrix off the OpenSSL 3.0 Ubuntu
# build and on Fedora.
addke_ok() {
	case ${R2_ADDKE:-auto} in
	yes) return 0 ;;
	no)  return 1 ;;
	esac
	[ -x "$SBIN/iked" ] && grep -q ikev2_followup_ke_recv "$SBIN/iked" 2>/dev/null && return 0
	# Autoconf writes `/* #undef WITH_ADDKE */` when the feature is off.
	# A bare grep of the token is a false-positive on Ubuntu OpenSSL 3.0
	# and lets i2ikesa-addke / i2iinit-addke run (and fail) in CI.
	[ -f "$R2_SRC/iked/config.h" ] &&
		grep -qE '^[[:space:]]*#define[[:space:]]+WITH_ADDKE([[:space:]]|$)' \
			"$R2_SRC/iked/config.h" 2>/dev/null
}


rebuild() {
	b=$1
	args=
	while IFS="$(printf '\t')" read -r name cargs; do
		name=$(crstrip "$name")
		cargs=$(crstrip "$cargs")
		case $name in ''|\#*) continue ;; esac
		if [ "$name" = "$b" ]; then
			args=$cargs
			break
		fi
	done < "$HERE/builds.tsv"
	[ -d "$R2_SRC" ] || die "no src $R2_SRC" || return 1
	(
		cd "$R2_SRC" || exit 1
		if [ ! -f Makefile ]; then
			autoreconf -fi
			# shellcheck disable=SC2086
			./configure --prefix="$PREFIX" $args
		fi
		make -j2
		make install
	)
}

if [ -n "$REBUILD" ]; then
	rebuild "$REBUILD" || exit 1
fi

pass=0
fail=0
skip=0
xfail=0
xpass=0
uskip=0
LANE_SKIP=$HERE/lanes/${R2_LANE:-none}.skip
# Structured results: one TSV line per row (verdict, gate class, seconds,
# structured GATE counts from r2_gate) so CI and reports parse verdicts
# instead of grepping log text.  Swept up with the /tmp/r2-* row logs.
# Default: a fresh per-run file (parallel shards/lanes on one host must not
# truncate each other's results); an explicit R2_RESULTS is used as given.
if [ -z "${R2_RESULTS:-}" ]; then
	R2_RESULTS=$(mktemp /tmp/r2-results.XXXXXX) || { echo "mktemp failed" >&2; exit 1; }
fi
log "results file: $R2_RESULTS"
printf '# row\tkind\texpect\tverdict\tgate\tseconds\tgates_pass\tgates_fail\tdetail\n' >"$R2_RESULTS"
r2_result() {	# r2_result <row> <kind> <expect> <verdict> <gate> <secs> <detail>
	_gp=0; _gf=0
	if [ -n "${ROW_OUT:-}" ] && [ -f "$ROW_OUT" ] && [ "$4" != SKIP ]; then
		_gp=$(grep -c "^GATE $1 [^ ]* PASS" "$ROW_OUT")
		_gf=$(grep -c "^GATE $1 [^ ]* FAIL" "$ROW_OUT")
	fi
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" \
	    "${5:--}" "$6" "$_gp" "$_gf" "$(printf '%s' "$7" | tr '\t\n' '  ')" >>"$R2_RESULTS"
}
# charon_ikev1_absent: succeed (printing the proof) only when the installed
# strongSwan libcharon demonstrably has no IKEv1 (no main_mode/quick_mode
# task strings).  Fails when charon is missing or still speaks IKEv1.
charon_ikev1_absent() {
	for _l in /usr/lib/ipsec/libcharon.so.0 /usr/libexec/ipsec/libcharon.so.0 \
	    /usr/lib64/strongswan/libcharon.so.0 /usr/lib/strongswan/libcharon.so.0 \
	    /usr/lib/x86_64-linux-gnu/strongswan/libcharon.so.0; do
		[ -f "$_l" ] || continue
		grep -qa 'main_mode' "$_l" && return 1
		grep -qa 'quick_mode' "$_l" && return 1
		_v=$(dpkg-query -W -f '${Version}' strongswan-charon 2>/dev/null || rpm -q --qf '%{VERSION}' strongswan 2>/dev/null || echo '?')
		echo "$_l (strongSwan $_v) has no main_mode/quick_mode task"
		return 0
	done
	return 1
}
# lane_expects_skip <name> <reason-class>: is this skip in the manifest?
# Manifest lines: "row <name> <why>" or "gate <gate> <why>".
lane_expects_skip() {
	[ -f "$LANE_SKIP" ] || return 1
	awk -v n="$1" -v g="$2" '$1 == "row" && $2 == n { f = 1 }
		$1 == "gate" && $2 == g { f = 1 } END { exit !f }' "$LANE_SKIP"
}
# row_skip <name> <gate-class> <message>
row_skip() {
	if [ "${R2_REQUIRE_LIVE:-0}" = 1 ] && ! lane_expects_skip "$1" "$2"; then
		log "FAIL $1 (R2_REQUIRE_LIVE=1: unexpected SKIP: $3; not in ${LANE_SKIP#$HERE/})"
		fail=$((fail + 1)); uskip=$((uskip + 1))
		r2_result "$1" "${kind:-?}" "${expect:-?}" FAIL "$2" 0 "unexpected skip: $3"
		return
	fi
	log "SKIP $1 ($3)"
	skip=$((skip + 1))
	r2_result "$1" "${kind:-?}" "${expect:-?}" SKIP "$2" 0 "$3"
}
SHARD_IDX=0
trap iked_restore EXIT
while IFS="$(printf '	')" read -r name kind expect workers note gate defect || [ -n "$name" ]; do
	name=$(crstrip "$name")
	kind=$(crstrip "$kind")
	expect=$(crstrip "$expect")
	workers=$(crstrip "$workers")
	note=$(crstrip "$note")
	gate=$(crstrip "$gate")
	defect=$(crstrip "${defect:-}")
	# read(1) collapses empty tab fields, so a row with a defect column
	# spells "no gate" as "-" (cases.tsv header)
	[ "$gate" = - ] && gate=
	case $name in ''|\#*) continue ;; esac
	if [ -n "$FILTER" ]; then
		echo "$name $kind" | grep -Eq "$FILTER" || continue
	fi
	# Shard partition (round-robin over filter-passing rows).  A shared
	# global row index gives every shard the SAME partition only if the
	# counter is incremented before any per-shard continue.  skip the
	# row iff K != (index %% M).
	SHARD_IDX=$((SHARD_IDX + 1))
	if [ -n "${SHARD_M:-}" ]; then
		if [ $((SHARD_IDX % SHARD_M)) -ne "${SHARD_K:-0}" ]; then
			log "SKIP $name (shard $SHARD_K/$SHARD_M, idx $SHARD_IDX)"
			skip=$((skip + 1))
			r2_result "$name" "$kind" "$expect" SKIP shard 0 "shard $SHARD_K/$SHARD_M"
			continue
		fi
	fi
	if [ "$expect" = skip ]; then
		row_skip "$name" expect "$note"
		continue
	fi
	if [ "$gate" = addke ] && ! addke_ok; then
		row_skip "$name" addke "ADDKE gate off: R2_ADDKE=${R2_ADDKE:-auto}"
		continue
	fi
	# DPD gate: rows that need the full retransmit ladder (11 timers,
	# ~383s at dpd_delay 60) only run when the runner opts in.  The
	# box sets R2_DPD=yes; CI does not, so i2ike-silence stays off the
	# Ubuntu/NetBSD full matrix (a 16-minute ladder on every push).
	if [ "$gate" = dpd ] && [ "${R2_DPD:-no}" != "yes" ]; then
		row_skip "$name" dpd "DPD gate off: R2_DPD=${R2_DPD:-no}"
		continue
	fi
	# BOX gate: new rows (i2ike-dup, i2ike-reqdrop) run
	# ONLY on the box until a counted-gate PASS exists there AND a
	# container run admits them (i2ike-drop576 rule).  The box sets
	# R2_BOX=yes; CI does not, so unverified rows cannot leak into the
	# Ubuntu/NetBSD full matrix or the Fedora container default.
	# PFKEY gate: rows about the Linux pfkey backend itself run only in
	# the pfkey lane (R2_KM=pfkey); xfrm lanes list the gate as expected.
	if [ "$gate" = pfkey ] && [ "${R2_KM:-xfrm}" != pfkey ]; then
		row_skip "$name" pfkey "PFKEY gate off: R2_KM=${R2_KM:-xfrm}"
		continue
	fi
	# CHARON-IKEv1 capability: strongSwan 6.1 removed IKEv1 upstream
	# (Debian sid 6.1.0-2: "the IKEv1 protocol has been disabled"), so the
	# rows that put charon on the IKEv1 initiator seat cannot run against
	# it.  Skip only on PROOF: the installed libcharon carries none of the
	# IKEv1 phase tasks (main_mode / quick_mode).  Lanes list the class
	# (gate charonv1) so R2_REQUIRE_LIVE accepts it; anywhere charon still
	# has IKEv1 the rows run and must pass.
	case $name in
	ikev1-strongswan|ikev1-depr-clean|ikev1-depr-3des)
		if _cv1=$(charon_ikev1_absent); then
			row_skip "$name" charonv1 "charon has no IKEv1: $_cv1"
			continue
		fi
		;;
	esac
	# NSIM capability: crypto offload rows need netdevsim + ESP offload.
	# Skip only on PROOF (a hand-installed offload SA is refused or the
	# module is absent), printed in the SKIP line; lanes list the class
	# (gate nsim) so R2_REQUIRE_LIVE accepts it.  Where the kernel accepts
	# offload the row runs and must pass.
	if [ "$gate" = nsim ]; then
		if ! _np=$(nsim_offload_probe); then
			row_skip "$name" nsim "no netdevsim ESP offload: $_np"
			continue
		fi
		log "nsim probe: $_np"
	fi
	if [ "$gate" = box ] && [ "${R2_BOX:-no}" != "yes" ]; then
		row_skip "$name" box "BOX gate off: R2_BOX=${R2_BOX:-no}"
		continue
	fi
	if [ "$expect" = xfail ] && [ -z "$defect" ]; then
		log "FAIL $name (expect=xfail needs the exact defect regex in column 7)"
		fail=$((fail + 1))
		continue
	fi
	case $workers in -|'') R2_WORKERS= ;; *) R2_WORKERS=$workers ;; esac
	export R2_WORKERS
	log "=== $name ($kind) workers=${R2_WORKERS:-live} ==="
	R2_CASE_FAIL=0
	ROW_OUT=/tmp/r2-row-$name.out
	ROW_T0=$(date +%s)
	xa_start "$name"
	# Brace group, not a pipe: the kind runs in THIS shell so its globals
	# (R2_CASE_FAIL, R2_IKED_*) survive; the output is replayed below and
	# kept for the xfail defect match.
	{
		if kind_$kind "$name"; then
			st=0
		else
			st=$?
		fi
		if ! xa_check "$name"; then
			log "XA $name: data-plane audit FAILED (see XA lines; xfrm_audit.sh)"
			R2_CASE_FAIL=1
		fi
	} > "$ROW_OUT" 2>&1
	cat "$ROW_OUT"
	ROW_SECS=$(( $(date +%s) - ROW_T0 ))
	if [ "$R2_CASE_FAIL" != 0 ] || [ "$st" -ne 0 ]; then
		row_ok=0
	else
		row_ok=1
	fi
	if [ "$expect" = xfail ]; then
		if [ "$row_ok" = 1 ]; then
			log "XPASS $name (declared defect /$defect/ is gone: change expect to pass)"
			log "FAIL $name"
			fail=$((fail + 1)); xpass=$((xpass + 1))
			r2_result "$name" "$kind" "$expect" XPASS "$gate" "$ROW_SECS" "declared defect gone: $defect"
		elif grep -E -- "$defect" "$ROW_OUT" | grep -Eq ' FAIL |^FAIL '; then
			log "XFAIL $name (known defect at its exact value: $(grep -E -- "$defect" "$ROW_OUT" | grep -E ' FAIL |^FAIL ' | head -1))"
			xfail=$((xfail + 1))
			r2_result "$name" "$kind" "$expect" XFAIL "$gate" "$ROW_SECS" "$defect"
		else
			log "FAIL $name (xfail row failed WITHOUT its declared defect /$defect/)"
			fail=$((fail + 1))
			r2_result "$name" "$kind" "$expect" FAIL "$gate" "$ROW_SECS" "xfail without its declared defect"
		fi
	elif [ "$row_ok" = 0 ]; then
		log "FAIL $name"
		fail=$((fail + 1))
		r2_result "$name" "$kind" "$expect" FAIL "$gate" "$ROW_SECS" "$(grep -E '^FAIL|^GATE .* FAIL' "$ROW_OUT" | head -1)"
	elif [ "$(grep -c "^GATE $name [^ ]* FAIL" "$ROW_OUT")" -ne 0 ]; then
		# a structured FAIL cannot be outvoted by a zero exit status
		log "FAIL $name (structured GATE FAIL with a zero kind status)"
		fail=$((fail + 1))
		r2_result "$name" "$kind" "$expect" FAIL "$gate" "$ROW_SECS" "GATE FAIL"
	else
		log "PASS $name"
		pass=$((pass + 1))
		r2_result "$name" "$kind" "$expect" PASS "$gate" "$ROW_SECS" ""
	fi
	iked_restore
	name=
done < "$CASES_FILE"

log "pass=$pass fail=$fail skip=$skip xfail=$xfail xpass=$xpass unexpected_skip=$uskip"
log "results: $R2_RESULTS ($(grep -vc '^#' "$R2_RESULTS") rows)"
rc=0
[ "$fail" -eq 0 ] || rc=1
# empty-run guards: a filter/shard/gate that selects nothing, or a matrix
# that aborted early, must not report green.
if [ "${R2_REQUIRE_LIVE:-0}" = 1 ] && [ $((pass + xfail)) -eq 0 ]; then
	log "FAIL: R2_REQUIRE_LIVE=1 and no row passed (empty run)"
	rc=1
fi
if [ -n "${R2_MIN_PASS:-}" ] && [ $((pass + xfail)) -lt "$R2_MIN_PASS" ]; then
	log "FAIL: only $((pass + xfail)) rows passed, R2_MIN_PASS=$R2_MIN_PASS"
	rc=1
fi
exit $rc
