#!/bin/sh
# samples/freebsd-ci/freebsd-vnet-matrix.sh - FreeBSD vnet conformance MATRIX
# (renamed from ...-smoke.sh: this is a matrix runner, not a smoke test).
# Runs real iked<->iked tunnels across TWO vnet jails on ONE epair(4) per
# row (FreeBSD's analogues of Linux netns + veth), driven through the pfkey
# KM (if_pfkeyv2.c - auto-selected on FreeBSD; *linux*->xfrm, *->pfkey).
#
# First BSD leg that runs an actual tunnel matrix (the NetBSD legs are
# build+rc.d smoke only: "npf/pf/ipf is packet filter, not SAD/SPD").
# Rows mirror linux-matrix kinds with IDENTICAL algorithm tokens so pfkey
# parity can be asserted against xfrm on the same iked config:
#   i2iinit-*     initial IKE_SA + ESP child (mirrors kinds/i2iinit.sh rows)
#   i2idh-*       DH group rows (mirrors kinds/i2idh.sh non-charon rows)
#   i2ike-rekey   CREATE_CHILD child-SA rekey, new ESP SPI BOTH seats
#                 (mirrors i2ike.sh SPI gate; pfkey SADB UPDATE)
#   i2ineg-*      NEG rows: wrongpsk / idmismatch / a12strict / a12permit
#                 (mirrors kinds/i2i_neg.sh): a NEG(refuse) row PASSES when
#                 NO child SA appears in the window AND the refusal reason
#                 is in the responder log where expected.
#   expected-reject rows (neg=x): XCBC/CMAC ESP transforms that the FreeBSD
#                 15.1 kernel supported_aalgs[] does NOT ship.  racoon2 must
#                 refuse them at config-check ("not supported by kernel"),
#                 and the verdict requires that marker - so a future kernel
#                 that ADDS them turns the row red (child appears) and tells
#                 us to flip it to a positive accept test.  Never a SKIP.
#   i2iv6-esp     same tunnel over AF_INET6 (mirrors kinds/i2iv6.sh)
# Rows that are Linux-BOUND are deliberately NOT replicated: charon/
# strongSwan interop (no strongSwan in this testbed), netem drop/dup rows
# (Linux 'tc' only), mobike/cookie2 multi-address rows (need 2 SA endpoints),
# xfrm-only cells.  Every row PASSes only on a real per-jail SADB + a
# post-establishment data-plane ping through the tunnel (in/out `require`).
#
# PF_KEY SAD/SPD on stock FreeBSD is VIMAGE-virtualized PER-VNET JAIL
# (sys/netipsec/key.c): the ESP child is only visible from INSIDE each jail
# (host `setkey -D` is the host vnet and stays empty).  The two jails give
# each seat its own stack+port-500, matching the Linux matrix's netns.
#
# On blind CI runs every seat logs to /tmp/freeb-*; SADB+SPD dumps are
# retained per row.  Any row failing makes the run exit non-zero (a green
# first row must not mask a later failure).
set -eu
PREFIX="${PREFIX:-/usr/local/racoon2}"
SBIN="${PREFIX}/sbin"
export PATH="$PATH:/usr/local/sbin"
ROW="${ROW:-all}"

# Shard support, mirroring samples/linux-matrix/run.sh --shard K M: run only
# the rows whose dispatcher index % SHARD_M == SHARD_K.  Each shard is its own
# GitHub job / VM (jail+epair+/tmp/freeb names never collide across jobs), and
# a report job merges the per-shard logs and sums the PASS/FAIL lines.  An
# isolated row is a disjoint slice, so `pass=` totals add back to the full
# matrix run.
SHARD_K="${SHARD_K:-0}"
SHARD_M="${SHARD_M:-1}"
# Guard the 0-based shard contract: K must be < M, else `x % M == K` never
# matches and the run silently dispatches ZERO rows (a vacuous PASS).  The
# freebsd CI matrix and ssh users must use --shard 0 1 for a full run.
if [ "$SHARD_K" -ge "$SHARD_M" ]; then
	echo "FAIL: --shard K M requires 0 <= K < M (got $SHARD_K/$SHARD_M) - shard would dispatch no rows"
	exit 2
fi
_shard_idx=0
while [ $# -gt 0 ]; do
	case $1 in
		--shard) SHARD_K=$2; SHARD_M=$3; shift 3 ;;
		*) echo "unknown arg: $1"; exit 2 ;;
	esac
done
# re-validate after CLI override
if [ "$SHARD_K" -ge "$SHARD_M" ]; then
	echo "FAIL: --shard K M requires 0 <= K < M (got $SHARD_K/$SHARD_M) - shard would dispatch no rows"
	exit 2
fi


jr=r2vr   # responder vnet jail
ji=r2vi   # initiator vnet jail
SEP="======================================================"

for S in "$SBIN/iked" "$SBIN/spmd" "$SBIN/ikedctl"; do
	[ -x "$S" ] || { echo "FAIL: missing $S"; exit 1; }
done
command -v setkey >/dev/null 2>&1 || { echo "FAIL: setkey not found (install ipsec-tools)"; exit 1; }

# netipsec is NOT compiled into the base kernel on the vmactions CI image:
# it is ipsec.ko, auto-loaded only by the first PF_KEY socket open.  Our rows
# run entirely INSIDE vnet jails, and a jail can never kldload - so on a
# fresh CI VM the module stays unloaded and every SADB_ADD/UPDATE is answered
# EINVAL ("kernel rejected SADB ADD/UPDATE").  Explicitly load it here, in
# HOST context (idempotent; -n is a no-op when already loaded), before any
# jail exists.  Locally this is normally already loaded by a prior setkey;
# CI has no such history, hence the divergence.
if ! kldstat -q -n ipsec 2>/dev/null; then
	kldload -n ipsec || { echo "FAIL: cannot load ipsec.ko (netipsec)"; exit 1; }
fi
# Backstop for the 16.0 seed, which kldloads if_epair before the base
# upgrade can replace the .ko.  If that did not run (15.1, or a local
# boot), load it here.  A kldload failure is not fatal: 15.1 may have the
# cloner built-in, and a mismatched .ko must surface on the ifconfig
# line below with its stderr kept.
if ! kldstat -q -n if_epair 2>/dev/null; then
	kldload -n if_epair 2>/tmp/freeb-epair-kld.err || \
		echo "WARN: kldload if_epair failed (built-in, or see /tmp/freeb-epair-kld.err)"
fi

spi() { # spi $JAIL : sorted SPI set in that jail's per-vnet SADB
	jexec "$1" /usr/local/sbin/setkey -D 2>/dev/null | grep -oE 'spi=[0-9]+' | sort -u
}
esp_up() { # esp_up $JAIL : count of *mature* esp tunnel SAs in that jail's SADB
	# A refused exchange leaves a `state=larval` SAD entry on the initiator
	# (no SADB_DELETE on abort) - that is expected, not an established child,
	# so count only entries whose state line says `mature`.
	# CRITICAL (F2): pfkey_sadump() prints E:/A: key lines BETWEEN the
	# `esp mode=tunnel` header and the `seq=... state=...` line (state is at
	# +3 for an established SA whose keys fit one line).  A -A1 window can
	# therefore never match `state=mature` and every positive row times out.
	# Use awk: remember a pending esp tunnel header across the key-dump
	# lines.  A 384/512-bit auth key wraps to a SECOND key line (E: / A: on
	# one line, continuation on the next), so the state line sits at +4, not
	# +3 - the window must span the longest possible key dump (E one line +
	# A up to two lines = state at +4).  `mature` at +1..+4 all count.
	jexec "$1" /usr/local/sbin/setkey -D 2>/dev/null | awk '
		/esp mode=tunnel/ { pend=5; next }
		pend && /state=mature/ { c++ }
		pend { pend-- }
		END { print c+0 }' || true
}

# ---------------------------------------------------------------------------
# fbsd_comply — NDcPP v3.0e compliance cells from THIS row's retained
# artifacts (mirror of linux-matrix/kinds/i2i_compliance.sh, reading the
# FreeBSD jails' setkey -D/-DP dumps + iked logs + confs instead of
# ip xfrm pol/state).  Called on each PASSING row so the merged matrix log
# carries real CPL lines; UNOBSERVABLE cells are INFO, never a blind PASS.
#
# Cell mapping (FreeBSD evidence):
#   A1  SPD PROTECT(esp/tunnel) rows in BOTH jails' setkey -DP dump
#   A2  no cleartext path: the ONLY SPD rows are the esp/tunnel ipsec rows
#   A3  esp mode=tunnel state=mature SAs in both jails' SADB
#   A4  ESP cipher in claimed set (iked log 'child ENCR transform_id=N')
#   A5  IKEv2 -> ESTABLISHED both seats + NAT-T 4500 encap socket claimed
#   A6  IKE payload cipher in claimed set (conf kmp_enc_alg)
#   A7  IKE_SA 24h default honored (resume ike_remain=86400)
#   A8  CHILD_SA soft/hard lifetime honored (iked SADB log)
#   A9/A10/B1..B6  unit/KAT-covered (ndcppkats.log); INFO cross-ref here
#   A11 DH group in claimed set (conf kmp_dh_group)
#   A12 IKE_SA >= CHILD_SA strength (conf keylens; strict=INFO w/ refusal)
#   A13 peer auth DECLARED on both seat confs (psk or pubkey)
#   A14 peer id pinned (peers_id fqdn in confs)
# NEG rows (wrongpsk/idmismatch): the refusal IS the evidence; childless
# cells (A3/A4/A5/A8) waive to INFO like linux i2i_compliance *-cfgneg*.
# ---------------------------------------------------------------------------
fbsd_comply() {
	_name=$1 _neg=$2
	_plog() { printf 'CPL %s: %s %s\n' "$1" "$2" "$3"; }
	# A-file for grep -vE: strip hex dumps so they never match transforms
	AF() { grep -avE '^[0-9a-f]{8}( |$)' "$1" 2>/dev/null || true; }

	# ---- A1  SPD PROTECT architecture (setkey -DP across both jails) ----
	_a1=1
	for _sp in resp-spd.txt init-spd.txt; do
		if ! grep -qE 'esp/tunnel/.*/require|esp/tunnel' "/tmp/freeb/$_sp" 2>/dev/null; then
			_a1=0
		fi
	done
	[ "$_a1" -eq 1 ] && _plog A1 PASS "SPD has PROTECT(esp/tunnel require) rows in both jails (setkey -DP resp/init)"
	[ "$_a1" -eq 0 ] && _plog A1 FAIL "SPD missing PROTECT(esp/tunnel require) row in a jail (resp-spd.txt/init-spd.txt)" || true

	# ---- A2  no cleartext path: only esp/tunnel rows may exist -----------
	_a2=1
	for _sp in resp-spd.txt init-spd.txt; do
		# any policy row that is NOT an in/out ipsec esp/tunnel row = risk
		if grep -avE 'esp/tunnel|^[[:space:]]*(in|out) ipsec|^[0-9a-f:./]+\[any\] [0-9a-f:./]+\[any\]|spid=|[[:space:]]*$' "/tmp/freeb/$_sp" 2>/dev/null | grep -qE 'bypass|pass |discard|proto (udp|tcp)'; then
			_a2=0
		fi
	done
	[ "$_a2" -eq 1 ] && _plog A2 PASS "SPD shape: only esp/tunnel ipsec rows (no cleartext bypass/pass/catch-all) in resp/init SPD"
	[ "$_a2" -eq 0 ] && _plog A2 FAIL "SPD cleartext-path risk (non-esp/tunnel policy row present)" || true

	# ---- A3  tunnel-mode ESP SAs both jails (SADB dump) ------------------
	_a3=1
	for _sa in resp-sadb.txt init-sadb.txt; do
		if ! grep -qE 'esp mode=tunnel .*state=mature' "/tmp/freeb/$_sa" 2>/dev/null; then _a3=0; fi
	done
	[ "$_a3" -eq 1 ] && _plog A3 PASS "esp mode=tunnel state=mature SAs in both jails (setkey -D)"
	[ "$_a3" -eq 0 ] && _plog A3 INFO "no mature tunnel ESP SA on a jail (NEG-refusal or dump timing); not a FAIL"

	# ---- A4  ESP cipher in claimed set (iked child ENCR line) ------------
	# claimed set {AES-CBC (RFC 4868), AES-GCM}; AES-CTR/others -> INFO.
	_a4=0
	case "$_name" in
	*-esp-ctr*)   : ;;
	esac
	for _lg in resp-iked.log init-iked.log; do
		AF "/tmp/freeb/$_lg" | grep -qE 'child ENCR transform_id=(12|13|20|7|8 |9)|AES-GCM' && _a4=1 || true
	done
	if [ "$_a4" -eq 1 ]; then
		case "$_name" in
		*-esp-ctr*) _plog A4 INFO "ESP cipher AES-CTR established but outside v3.0e claimed set ($_name)" ;;
		*)          _plog A4 PASS "ESP cipher in claimed set (iked child ENCR: AES-GCM/AES-CBC, row $_name)" ;;
		esac
	else
		_plog A4 INFO "no ESP cipher transform observed for $_name (NEG-refusal expected)"
	fi

	# ---- A5  IKEv2 ESTABLISHED + NAT-T encap socket (iked logs) ----------
	_a5=1
	for _lg in resp-iked.log init-iked.log; do
		AF "/tmp/freeb/$_lg" | grep -qE -- '-> ESTABLISHED' || _a5=0
	done
	_a5nat=0
	for _lg in resp-iked.log init-iked.log; do
		AF "/tmp/freeb/$_lg" | grep -q 'used for NAT-T' && _a5nat=1 || true
	done
	if [ "$_a5" -eq 1 ]; then
		_plog A5 PASS "IKEv2 ESTABLISHED both seats ($_name); NAT-T 4500 socket claimed=$_a5nat (iked log)"
	else
		_plog A5 INFO "no IKEv2 ESTABLISHED on a seat ($_name) — expected on NEG-refusal"
	fi

	# ---- A6  IKE payload cipher in claimed set (conf kmp_enc_alg) --------
	_a6=0
	for _c in r2vr.conf r2vi.conf; do
		grep -qE 'kmp_enc_alg \{ (aes128_cbc|aes256_cbc|aes_gcm)' "/tmp/freeb/$_c" 2>/dev/null && _a6=1 || true
	done
	[ "$_a6" -eq 1 ] && _plog A6 PASS "IKE payload cipher in claimed set (kmp_enc_alg in confs)"
	[ "$_a6" -eq 0 ] && _plog A6 INFO "IKE payload cipher not in claimed set for $_name (interop vector)"

	# ---- A7  IKE_SA 24h default honored (resume ike_remain) --------------
	_a7=0
	for _lg in resp-iked.log init-iked.log; do
		AF "/tmp/freeb/$_lg" | grep -qE 'ike_remain=86400' && _a7=1 || true
	done
	[ "$_a7" -eq 1 ] && _plog A7 PASS "IKE_SA default 24h honored (resume ike_remain=86400, row $_name)"
	[ "$_a7" -eq 0 ] && _plog A7 INFO "no ike_remain=86400 in a log for $_name (rc.d/NEG seat)"

	# ---- A8  CHILD_SA soft/hard lifetime from config (iked SADB log) -----
	_a8=0
	for _lg in resp-iked.log init-iked.log; do
		AF "/tmp/freeb/$_lg" | grep -qE 'lifetime soft time=[0-9]+ .*hard time=[0-9]+' && _a8=1 || true
	done
	[ "$_a8" -eq 1 ] && _plog A8 PASS "CHILD_SA soft/hard lifetime from config honored (iked SADB add, row $_name)"
	[ "$_a8" -eq 0 ] && _plog A8 INFO "no CHILD_SA soft/hard lifetime line for $_name"

	# ---- A9/A10/B-cells: unit/KAT covered (INFO cross-ref, never FAIL) --
	_plog A9 INFO "DH secret length enforced in DH/ECDH keygen (KAT unit rows)"
	_plog A10 INFO "IKEv2 nonce >=128bit / half-PRF (KAT unit rows)"
	_plog B1 INFO "FCS_CKM.1 keygen covered by KAT unit rows"
	_plog B2 INFO "key-establishment keymat SHA-256 cross-check: WITH_KEYMAT_ORACLE build (g_ir line emitted per child; oracle is a debug cross-check, not a v3.0e-required function)"
	_plog B3 INFO "FCS_CKM.4 zeroization covered by unit OPENSSL_cleanse checks"
	_plog B4 INFO "FCS_COP.1 AES ciphers covered by KAT unit rows"
	_plog B5 INFO "FCS_COP.1 siggen covered by KAT unit rows"
	_plog B6 INFO "FCS_RBG_EXT.1 DRBG covered by KAT unit rows"

	# ---- A11  DH group in claimed set (conf kmp_dh_group) ----------------
	_a11=0
	for _c in r2vr.conf r2vi.conf; do
		grep -qE 'kmp_dh_group \{ (modp2048|modp3072|modp4096|modp6144|modp8192|ecp256|ecp384|ecp521)' "/tmp/freeb/$_c" 2>/dev/null && _a11=1 || true
	done
	[ "$_a11" -eq 1 ] && _plog A11 PASS "DH group in claimed set (kmp_dh_group in confs, row $_name)"
	[ "$_a11" -eq 0 ] && _plog A11 INFO "no claimed DH group in confs for $_name"

	# ---- A12  IKE_SA strength >= CHILD_SA strength (conf keylens) --------
	_ikesz=0 _childsz=0
	for _c in r2vr.conf r2vi.conf; do
		[ -f "/tmp/freeb/$_c" ] || continue
		grep -q 'kmp_enc_alg { aes256_cbc' "/tmp/freeb/$_c" && _ikesz=256 || true
		grep -q 'kmp_enc_alg { aes_gcm, 256' "/tmp/freeb/$_c" && _ikesz=256 || true
		grep -q 'kmp_enc_alg { aes128_cbc' "/tmp/freeb/$_c" && [ "$_ikesz" -eq 0 ] && _ikesz=128 || true
		grep -q 'kmp_enc_alg { aes_gcm' "/tmp/freeb/$_c" && [ "$_ikesz" -eq 0 ] && _ikesz=128 || true
		grep -q 'esp_enc_alg { aes_gcm, 256' "/tmp/freeb/$_c" && _childsz=256 || true
		grep -q 'esp_enc_alg { aes256_cbc' "/tmp/freeb/$_c" && _childsz=256 || true
		grep -q 'esp_enc_alg { aes128_cbc' "/tmp/freeb/$_c" && _childsz=128 || true
		grep -q 'esp_enc_alg { aes_ctr' "/tmp/freeb/$_c" && _childsz=128 || true
		[ "$_childsz" -eq 0 ] && grep -q 'esp_enc_alg { aes_gcm' "/tmp/freeb/$_c" && _childsz=128 || true
	done
	if [ "$_ikesz" -eq 0 ] || [ "$_childsz" -eq 0 ]; then
		_plog A12 INFO "key strengths not fully determined (ikesz=$_ikesz childsz=$_childsz)"
	elif [ "$_ikesz" -ge "$_childsz" ]; then
		_plog A12 PASS "IKE_SA $_ikesz-bit >= CHILD_SA $_childsz-bit"
	else
		_plog A12 INFO "CHILD_SA $_childsz-bit exceeds IKE_SA $_ikesz-bit under RFC 7296 permissive default (strict refusal is i2ineg-a12strict)"
	fi

	# ---- A13  peer auth declared on both seat confs ----------------------
	_a13=1
	for _c in r2vr.conf r2vi.conf; do
		grep -q 'pre_shared_key\|my_public_key' "/tmp/freeb/$_c" 2>/dev/null || _a13=0
	done
	[ "$_a13" -eq 1 ] && _plog A13 PASS "peer auth declared on both seat confs (psk or public key, row $_name)"
	[ "$_a13" -eq 0 ] && _plog A13 FAIL "no peer-auth declaration in a seat conf" || true

	# ---- A14  peer id pinned (peers_id fqdn in confs) --------------------
	_a14=1
	for _c in r2vr.conf r2vi.conf; do
		grep -q 'peers_id fqdn' "/tmp/freeb/$_c" 2>/dev/null || _a14=0
	done
	[ "$_a14" -eq 1 ] && _plog A14 PASS "peer id pinned (peers_id fqdn in confs, row $_name)"
	[ "$_a14" -eq 0 ] && _plog A14 FAIL "no peers_id fqdn in a seat conf" || true
	# Evidence-only: cells feed mk_report (which fails on any FAIL cell);
	# the ROW's own SADB/data-plane/NEG gate decides the matrix verdict.
	return 0
}

jails_teardown() {
	jexec $jr /bin/sh -c 'killall iked spmd 2>/dev/null' || true
	jexec $ji /bin/sh -c 'killall iked spmd 2>/dev/null' || true
	jail -r $jr 2>/dev/null || true
	jail -r $ji 2>/dev/null || true
	# stale admin/spmif sockets would block the NEXT row's daemons from binding
	rm -f /tmp/freeb/*-ctl* /tmp/freeb/*-spmif*
	rm -f /tmp/freeb-epair.txt
	# Per-row isolation: iked's resume dir (RACOON2_RESUME_DIR) is a
	# persistent host/shared path.  Left alone, EVERY row's iked restores the
	# PREVIOUS row's already-established IKE_SA (children=8 in the logs) and
	# rides resume/rekey instead of running a fresh IKE_AUTH - so NEG rows
	# (wrongpsk / idmismatch / strength) can never produce their refusal
	# marker because no authentication ever runs.  Clear the dumps per row so
	# every row is a virgin daemon with a clean SADB.
	rm -rf /tmp/freeb/init-resume /tmp/freeb/resp-resume
	# Truncate per-seat iked logs so diag()'s full-log greps only ever see
	# the CURRENT row's lines, never a previous row's pskey/ESTABLISHED/etc.
	rm -f /tmp/freeb/resp-iked.log /tmp/freeb/init-iked.log \
	      /tmp/freeb/resp-spmd.log /tmp/freeb/init-spmd.log
}

# gen_conf $SEAT $NAME $FAM $MY $PEER $IKE_ENC $IKE_PRF $IKE_DH \
#          $ESP_ENC $ESP_AUTH $MYID $PEERID $LFT $PSK_FILE $STRENGTH(on|"") \
#          [S6R S6I] [ADDKE_ALG(mlkem768|"")] [AUTH(psk|rsasig|ecdsa)] [CERTDIR]
# Seat-specific: MY=my IP, PEER=peer IP.  Everything else is mirrored on
# both seats, matching the Linux matrix's identical-both-sides model.
# ADDKE_ALG non-empty adds `esp_addke_alg { <alg>; }` to the sa block (RFC
# 9370 type-06 offer) - SAME token as the linux i2ike/i2iinit kinds.
# AUTH != psk switches to X.509 public-key auth (NDcPP A13 .1.11): the sa
# seats reference per-seat leaf certs under CERTDIR, no pre_shared_key.
gen_conf() {
	_seat=$1 _name=$2 _fam=$3 _my=$4 _peer=$5 _ienc=$6 _iprf=$7 _idh=$8 \
	_eesp=$9 _eaut=${10} _myid=${11} _peerid=${12} _lft=${13} _pskf=${14} _str=${15}
	# i2io4 rows: $_my/$_peer are the IPv4 IKE + outer SA endpoints, and
	# $_smy/$_speer are the IPv6 inner selectors (v6-inside-v4 tunnel).
	# For every other row $_smy=$_my / $_speer=$_peer (same family).
	# NOTE: defaulting must happen AFTER the assignment line — in POSIX sh
	# every expansion in a simple command runs before the assignments land,
	# so "${16:-$_my}" would see an unset $_my (breaks set -u when arg16 is
	# the empty string from a non-i2io4 row).
	_smy=${16:-}; _speer=${17:-}
	[ -n "$_smy" ] || _smy=$_my
	[ -n "$_speer" ] || _speer=$_peer
	_addke=${18:-}; _auth=${19:-psk}; _cdir=${20:-}
	# responder (jr) is passive: only the initiator's establish-sa triggers
	# the exchange, matching the proven matrix topology.
	_passive="off"; [ "$_seat" = "$jr" ] && _passive="on"
	[ "$_fam" = inet6 ] && _sfx=v6 || _sfx=""
	if [ "$_auth" = psk ]; then
		_auth_lines="		kmp_auth_method { psk; };\n		pre_shared_key \"$_pskf\";"
	else
		# X.509 public-key auth: my_public_key/peers_public_key point at the
		# per-seat leaf certs; SSL_CERT_FILE (set per-daemon) anchors the CA.
		# peers_public_key is the OTHER seat's leaf (init<->resp pair).
		case "$_seat" in
		$jr) _my_cert=resp _peer_cert=init ;;
		*)   _my_cert=init _peer_cert=resp ;;
		esac
		_auth_lines="		kmp_auth_method { $_auth; };\n		my_public_key x509pem \"$_cdir/$_my_cert.crt\" \"$_cdir/$_my_cert.key\";\n		peers_public_key x509pem \"$_cdir/$_peer_cert.crt\";"
	fi
	_addke_line=""
	[ -z "$_addke" ] || _addke_line="	esp_addke_alg { $_addke; };"
	_eesp_emit=$(printf '%b\n' "$_addke_line")
	cat > /tmp/freeb/$_seat.conf <<EOF
interface {
	ike { $_my; };
	spmd { unix "/tmp/freeb/$_seat-spmif$_sfx"; };
	spmd_password "/tmp/freeb/spmd.pwd";
};
resolver { resolver off; };
remote matrix_$_seat {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive $_passive;
		my_id fqdn "$_myid";
		peers_id fqdn "$_peerid";
		peers_ipaddr $_peer;
		kmp_enc_alg { $_ienc; };
		kmp_prf_alg { $_iprf; };
		kmp_hash_alg { $_iprf; };
		kmp_dh_group { $_idh; };
$(printf '%b\n' "$_auth_lines")
		$_str
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src $_smy; dst $_speer;
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst $_smy; src $_speer;
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_$_seat;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr $_peer;
	my_sa_ipaddr $_my;
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time $_lft sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $_eesp; };
	esp_auth_alg { $_eaut; };
	$_eesp_emit
};
EOF
	echo "wrote /tmp/freeb/$_seat.conf"
}

# run_row NAME FAM HI HR IKE_ENC IKE_PRF IKE_DH ESP_ENC ESP_AUTH \
#          LFT_INIT LFT_RESP REKEY(0|1) NEG(a|r|p) STRENGTH_LINE
#   NEG=a : positive (child must come up + data-plane ping)
#   NEG=r : refuse   (child must NOT come up)
#   NEG=p : a12permit (stronger child with strength knob OFF -> must come up)
# STRENGTH_LINE e.g. 'parent_child_strength on;' (a12strict) or '' (default).
run_row() {
	_name=$1 _fam=$2 _hi=$3 _hr=$4 _ienc=$5 _iprf=$6 _idh=$7 \
	_eesp=$8 _eaut=$9 _lfti=${10} _lftr=${11} _rekey=${12} _neg=${13} _str=${14}
	# i2io4* rows set s6r/s6i as v6 selector overrides; reset per row so a
	# v4 row dispatched after an i2io4 row never inherits stale v6 selectors.
	s6r=""; s6i=""
	echo "$SEP"
	echo "=== ROW $_name (fam=$_fam ike=$_ienc/$_iprf/$_idh esp=$_eesp/$_eaut neg=$_neg) ==="
	# kernel PF_KEY DPRINTFs (esp_init keylen/AEAD rejects) go to the console
	# when net.key.debug is set; set it BEFORE any SADB_ADD so a kernel
	# refusal on GCM/CTR/etc is visible in `dmesg` - never guess the reason.
	key_debug_on() {
		jexec $jr sysctl net.key.debug=7 >/dev/null 2>&1 || true
		jexec $ji sysctl net.key.debug=7 >/dev/null 2>&1 || true
		sleep 1
	}
	diag() {
		echo "--- raw responder SADB ---"; sed -n '1,30p' /tmp/freeb/resp-sadb.txt 2>/dev/null || true
		echo "--- raw initiator SADB ---"; sed -n '1,30p' /tmp/freeb/init-sadb.txt 2>/dev/null || true
		echo "--- responder SPD ---"; sed -n '1,20p' /tmp/freeb/resp-spd.txt 2>/dev/null || true
		# Instrument markers (proposal emit / wire transform / psk verify)
		# can sit far from the tail even on pos rows; grep FULL logs always.
		echo "--- iked instrument lines (full logs) ---"
		grep -E 'alg_to_proppair|child ENCR|pskey path|psk verify|keylen|transform_id' \
			/tmp/freeb/resp-iked.log 2>/dev/null | grep -vE '^[0-9a-f]{8}( |$)' | tail -25 || true
		grep -E 'alg_to_proppair|child ENCR|pskey path|psk verify|keylen|transform_id' \
			/tmp/freeb/init-iked.log 2>/dev/null | grep -vE '^[0-9a-f]{8}( |$)' | tail -25 || true
		# NEG rows: FULL iked logs matter (IKE_AUTH / ID-refusal lines are far
		# from the tail); the 25-line tail hid exactly that for wrongpsk.
		if [ "$_neg" = r ] || [ "$_neg" = x ]; then
			echo "--- responder iked (FULL) ---"; cat /tmp/freeb/resp-iked.log 2>/dev/null || true
			echo "--- initiator iked (FULL) ---"; cat /tmp/freeb/init-iked.log 2>/dev/null || true
		else
			echo "--- responder iked (tail) ---"; tail -25 /tmp/freeb/resp-iked.log 2>/dev/null || true
			echo "--- initiator iked (tail) ---"; tail -25 /tmp/freeb/init-iked.log 2>/dev/null || true
		fi
		echo "--- spmd logs ---"; cat /tmp/freeb/resp-spmd.log /tmp/freeb/init-spmd.log 2>/dev/null || true
		echo "--- host dmesg PF_KEY/ESP (net.key.debug=7, host buffer sees both vnets) ---"
		dmesg 2>/dev/null | grep -iE 'esp|ipsec|sadb|pfkey|gcm|keylen|auth' | tail -20 || true
		echo "--- per-jail dmesg (may be empty in a vnet jail; host reads above) ---"
		jexec $jr dmesg 2>/dev/null | grep -iE 'esp|ipsec|sadb|pfkey|gcm|keylen|auth' | tail -10 || true
		jexec $ji dmesg 2>/dev/null | grep -iE 'esp|ipsec|sadb|pfkey|gcm|keylen|auth' | tail -10 || true
	}
	# seed the endpoint locals from args; the inet6 branch overrides them.
	hr=$_hr; hi=$_hi
	# per row: keep a seat-local admin-sock suffix so the two seats never
	# collide; both seats use the same sock suffix (init vs resp).
	[ "$_fam" = inet6 ] && _sfx=v6 || _sfx=""
	jails_teardown

	echo "=== ONE epair, both ends into the two vnet jails ==="
	set +e; ifconfig epair create > /tmp/freeb-epair.txt 2>/tmp/freeb-epair.err; r=$?; set -e
	[ "$r" -eq 0 ] || {
		echo "FAIL: ifconfig epair create"
		echo "--- kldstat if_epair ---"; kldstat -n if_epair 2>&1 || true
		echo "--- kldload ---"; cat /tmp/freeb-epair-kld.err 2>/dev/null || true
		echo "--- ifconfig stderr ---"; cat /tmp/freeb-epair.err 2>/dev/null || true
		echo "--- ifconfig stdout ---"; cat /tmp/freeb-epair.txt 2>/dev/null || true
		exit 1
	}
	ea=$(head -1 /tmp/freeb-epair.txt | awk '{print $1}' | tr -d ':')
	case "$ea" in
		*a) eb="${ea%a}b" ;;
		*b) eb="${ea%b}a" ;;
		*) echo "FAIL: unexpected epair '$ea'"; exit 1 ;;
	esac
	echo "epair ends: $ea (resp) / $eb (init)"
	jail -c name=$jr persist vnet vnet.interface="$ea" || { echo "FAIL: jail -c $jr"; exit 1; }
	jail -c name=$ji persist vnet vnet.interface="$eb" || { echo "FAIL: jail -c $ji"; exit 1; }

	case "$_name" in
	i2io4*)
		# IPv6-over-IPv4: the epair carries BOTH a v4 pair (IKE + outer SA
		# endpoints, 192.0.5.x) and a v6 /64 (inner selectors,
		# 2001:db8:1::x).  The inner v6 packet is wrapped before output, so
		# only the v4 outer needs link resolution (ARP, L2) — no ND6 gate
		# at all, unlike i2iv6.  Racoan2 separates selector from sa_ipaddr,
		# so this is config-only (no daemon code).
		jexec $jr ifconfig "$ea" inet 192.0.5.1/24 up || { echo "FAIL: $jr v4"; exit 1; }
		jexec $ji ifconfig "$eb" inet 192.0.5.2/24 up || { echo "FAIL: $ji v4"; exit 1; }
		jexec $jr ifconfig "$ea" inet6 2001:db8:1::1/64 up || { echo "FAIL: $jr v6"; exit 1; }
		jexec $ji ifconfig "$eb" inet6 2001:db8:1::2/64 up || { echo "FAIL: $ji v6"; exit 1; }
		hr=192.0.5.1; hi=192.0.5.2
		s6r=2001:db8:1::1; s6i=2001:db8:1::2
		# _fam stays inet (IKE/SA family); the selector family is v6 via s6*.
		;;
	*)
	if [ "$_fam" = inet6 ]; then
		# IPv6 row: assign v4 (for tooling) + a v6 /64 on each epair end; the
		# addresses ARE the IKE endpoints (2001:db8:1::1 / ::2).
		jexec $jr ifconfig "$ea" inet6 "2001:db8:1::1/64" up || { echo "FAIL: $jr v6"; exit 1; }
		jexec $ji ifconfig "$eb" inet6 "2001:db8:1::2/64" up || { echo "FAIL: $ji v6"; exit 1; }
		hi="2001:db8:1::2"; hr="2001:db8:1::1"
		# FreeBSD ND6 fix (mirrors linux-matrix i2iv6.sh static-neigh): the
		# responder's kernel-generated ICMPv6 NA is swallowed by its OWN
		# outbound `[any] require esp/tunnel` SPD (netipsec inspects ICMPv6 at
		# L3; v4 ARP is L2 so v4 IKE is never ND-gated). Result: the initiator
		# can't resolve the peer, IKE_SA_INIT never leaves — verified via
		# `keydbg1/snd` + tcpdump (NS-only, no NA, no UDP/500 wire). Program
		# BOTH peers' MACs statically (FreeBSD: ndp -n -s addr mac), so no
		# NS/NA ever needs to traverse the SPD (same fix as Linux).
		vr_mac=$(jexec $jr ifconfig "$ea" 2>/dev/null | awk '/ether/{print $2}')
		vi_mac=$(jexec $ji ifconfig "$eb" 2>/dev/null | awk '/ether/{print $2}')
		echo "ND6: $hr <-> $hi static neigh ($vr_mac / $vi_mac)"
		jexec $ji ndp -n -s "$hr" "$vr_mac" 2>/dev/null || true
		jexec $jr ndp -n -s "$hi" "$vi_mac" 2>/dev/null || true
	else
		jexec $jr ifconfig "$ea" inet "$hr/24" up || { echo "FAIL: $jr addr"; exit 1; }
		jexec $ji ifconfig "$eb" inet "$hi/24" up || { echo "FAIL: $ji addr"; exit 1; }
	fi
	;;
	esac
	jexec $jr ifconfig lo0 inet 127.0.0.1/8 up 2>/dev/null || true
	jexec $ji ifconfig lo0 inet 127.0.0.1/8 up 2>/dev/null || true

	echo "=== throwaway CI PSK (random raw bytes, never the box PSK) + configs ==="
	install -d -m 0755 /tmp/freeb
	dd if=/dev/urandom of=/tmp/freeb/test.psk bs=32 count=1 2>/dev/null
	chmod 600 /tmp/freeb/test.psk
	printf 'ci-spmd-pw\n' > /tmp/freeb/spmd.pwd
	chmod 600 /tmp/freeb/spmd.pwd

	# NEG rows perturb ONE seat (differing key / id / strength).
	PSK_FI="/tmp/freeb/test.psk"   # initiator psk (overridden for wrongpsk)
	MYID_FI="r2init-matrix"        # initiator my_id (overridden for idmismatch)
	case "$_name" in
		*i2ineg-wrongpsk*)  PSK_FI="/tmp/freeb/neg.psk";
			dd if=/dev/urandom of=$PSK_FI bs=32 count=1 2>/dev/null; chmod 600 $PSK_FI ;;
		*i2ineg-idmismatch*) MYID_FI="racoon2-foreign" ;;
	esac
	# Both seats share the matrix ids; the responder always expects the
	# normal initiator id "r2init-matrix" — a NEG row mutates ONLY the
	# initiator's presented my_id (or its PSK file), never the responder's
	# expectation, else the refusal could not fire.
	# --- row-kind extras (parity rows) ---
	#   i2ipubkey-*  X.509 public-key auth (A13 .1.11): build a per-row test
	#                CA + leaf certs with the `openssl` CLI (FreeBSD 16 base
	#                ships OpenSSL 3.5.9), conf switches to rsasig/ecdsa.
	#   i2iinit-addke/i2ike-addke  RFC 9370 ADDKE (WITH_ADDKE on this
	#                OpenSSL 3.5 build): sa block gains esp_addke_alg.
	#   i2iconf-life  A7/A8 admin-config lifetimes (kmp_sa_lifetime_time
	#                37s + ipsec_sa_lifetime_time 53s: DISTINCT knobs in
	#                gen_conf via the LFT arg pairing).
	AUTH=psk; ADDKE=""; CERTDIR=""
	case "$_name" in
	i2ipubkey-*)
		AUTH=$(case "$_name" in *-rsa*) echo rsasig;; *-ecdsa*) echo ecdsa;; esac)
		ADDKE=""; if [ -z "$AUTH" ]; then echo "FAIL: unknown i2ipubkey row $_name"; exit 1; fi
		;;
	*i2ike-addke-512*) ADDKE="mlkem512" ;;
	*i2ike-addke-1024*) ADDKE="mlkem1024" ;;
	*i2iinit-addke*|*i2ike-addke*|*i2iinit-ike-gcm*|*nointermediate*|*pfsrekey*) ADDKE="mlkem768" ;;
	esac
	# generated only when a pubkey row needs it (skip for PSK rows = no
	# openssl dependency on the classic matrix)
	if [ "$AUTH" != psk ]; then
		CERTDIR=/tmp/freeb/certs
		rm -rf "$CERTDIR"; mkdir -p -m 700 "$CERTDIR"
		case "$AUTH" in
		ecdsa)  openssl ecparam -name P-384 -genkey -noout -out "$CERTDIR/ca.key" 2>/dev/null || { echo "FAIL: ecparam ca"; exit 1; }
			openssl req -new -x509 -key "$CERTDIR/ca.key" -out "$CERTDIR/ca.crt" -days 3650 -subj "/CN=racoon2-test-CA" 2>/dev/null || { echo "FAIL: ca req"; exit 1; } ;;
		*)      openssl genrsa -out "$CERTDIR/ca.key" 2048 2>/dev/null || { echo "FAIL: genrsa ca"; exit 1; }
			openssl req -new -x509 -key "$CERTDIR/ca.key" -out "$CERTDIR/ca.crt" -days 3650 -subj "/CN=racoon2-test-CA" 2>/dev/null || { echo "FAIL: ca req"; exit 1; } ;;
		esac
		for s in resp init; do
			case "$AUTH" in
			ecdsa)  openssl ecparam -name P-384 -genkey -noout -out "$CERTDIR/$s.key" 2>/dev/null || { echo "FAIL: ecparam $s"; exit 1; } ;;
			*)      openssl genrsa -out "$CERTDIR/$s.key" 2048 2>/dev/null || { echo "FAIL: genrsa $s"; exit 1; } ;;
			esac
			openssl req -new -key "$CERTDIR/$s.key" -out "$CERTDIR/$s.csr" -subj "/CN=matrix-$s" 2>/dev/null || { echo "FAIL: req $s"; exit 1; }
			openssl x509 -req -in "$CERTDIR/$s.csr" -CA "$CERTDIR/ca.crt" -CAkey "$CERTDIR/ca.key" -CAcreateserial -out "$CERTDIR/$s.crt" -days 3650 2>/dev/null || { echo "FAIL: x509 $s"; exit 1; }
			rm -f "$CERTDIR/$s.csr"
		done
		echo "i2ipubkey PKI ready ($AUTH): CA + resp/init leaf certs in $CERTDIR"
	fi
	gen_conf $jr "$_name" "$_fam" "$hr" "$hi" "$_ienc" "$_iprf" "$_idh" \
		"$_eesp" "$_eaut" "racoon2-matrix" "r2init-matrix" "$_lftr" "/tmp/freeb/test.psk" "$_str" \
		"${s6r:-}" "${s6i:-}" "$ADDKE" "$AUTH" "$CERTDIR"
	gen_conf $ji "$_name" "$_fam" "$hi" "$hr" "$_ienc" "$_iprf" "$_idh" \
		"$_eesp" "$_eaut" "$MYID_FI" "racoon2-matrix" "$_lfti" "$PSK_FI" "$_str" \
		"${s6i:-}" "${s6r:-}" "$ADDKE" "$AUTH" "$CERTDIR"
	# Conf-echo: prove the perturbed config is what iked loads (NEG rows
	# mutate only the initiator seat).  On a surprise child-appears this
	# shows whether the daemon really got the wrong PSK / foreign id.
	if [ "$_neg" = r ]; then
		echo "NEG conf-echo $_name: responder psk=$(ls -l /tmp/freeb/test.psk 2>/dev/null | awk '{print $5}')B initiator psk=$(ls -l "$PSK_FI" 2>/dev/null | awk '{print $5}')B"
		echo "NEG conf-echo $_name: responder expects peers_id=r2init-matrix; initiator my_id=$MYID_FI"
		grep -E 'pre_shared_key|my_id fqdn|peers_id fqdn' /tmp/freeb/r2vi.conf 2>/dev/null | sed 's/^/  init conf: /' || true
	fi
	# NB: ipsec lifetime for the initiator is short on rekey rows (below we
	# pass LFT_INIT < LFT_RESP so the initiator fires the CREATE_CHILD).

	# haul in kernel PF_KEY DPRINTFs (esp_init etc) BEFORE any SADB_ADD
	key_debug_on

	echo "=== start spmd + iked per seat (inside their vnet jails) ==="
	# For pubkey rows the daemons must trust the per-run test CA: pass
	# SSL_CERT_FILE to BOTH spmd and iked (iked does the peer-cert chain
	# verify via X509_STORE_set_default_paths, so it is the one that must
	# see it; same mechanism as linux i2ipubkey).
	_sslenv=""
	[ "$AUTH" = psk ] || _sslenv=" SSL_CERT_FILE=$CERTDIR/ca.crt"
	jexec $jr /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/resp-ctl$_sfx RACOON2_RESUME_DIR=/tmp/freeb/resp-resume $_sslenv $SBIN/spmd -F -f /tmp/freeb/$jr.conf > /tmp/freeb/resp-spmd.log 2>&1 &" || true
	jexec $ji /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/init-ctl$_sfx RACOON2_RESUME_DIR=/tmp/freeb/init-resume $_sslenv $SBIN/spmd -F -f /tmp/freeb/$ji.conf > /tmp/freeb/init-spmd.log 2>&1 &" || true
	i=0
	while [ "$i" -lt 15 ]; do
		[ -S "/tmp/freeb/resp-spmif$_sfx" ] && [ -S "/tmp/freeb/init-spmif$_sfx" ] && break
		i=$((i+1)); sleep 1
	done
	[ -S "/tmp/freeb/resp-spmif$_sfx" ] && [ -S "/tmp/freeb/init-spmif$_sfx" ] || echo "note: spmif sockets slow"
	sleep 1
	# Debug level: 0x0001 = DEBUG (A4/A5/A8 cells, ADDKE g_ir_present) for
	# every row; 0x0003 adds DEBUG_FLAG_TRACE=0x0002 so the pubkey rows can
	# prove the peer-auth METHOD ('auth method 1/10' is a TRACE line), same
	# as linux i2ipubkey's I2I_DBG override.
	_dbg=0x0001
	[ "$AUTH" = psk ] || _dbg=0x0003
	jexec $jr /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/resp-ctl$_sfx RACOON2_RESUME_DIR=/tmp/freeb/resp-resume $_sslenv $SBIN/iked -F -f /tmp/freeb/$jr.conf -D $_dbg > /tmp/freeb/resp-iked.log 2>&1 &" || true
	jexec $ji /bin/sh -c "env RACOON2_ADMIN_SOCK=/tmp/freeb/init-ctl$_sfx RACOON2_RESUME_DIR=/tmp/freeb/init-resume $_sslenv $SBIN/iked -F -f /tmp/freeb/$ji.conf -D $_dbg > /tmp/freeb/init-iked.log 2>&1 &" || true
	sleep 3

	echo "=== establish IKE/ESP from the initiator seat ==="
	jexec $ji $SBIN/ikedctl -s "/tmp/freeb/init-ctl$_sfx" establish-sa isakmp $_fam "$hi" "$hr" sel_out > /tmp/freeb/ctl.out 2>&1 || true

	up=0
	i=0
	if [ "$_neg" = r ] || [ "$_neg" = x ]; then
		# NEG(refuse) / expected-reject gate: child must NOT appear.
		# `r` = auth/id NEG (wrongpsk, idmismatch).  `x` = expected kernel
		# -gap rejection (XCBC/CMAC absent from supported_aalgs[]): refusal
		# must ALSO be proven by the config-check marker below, else a bare
		# timeout would fake a pass.
		rn=0; in=0
		while [ "$i" -lt 20 ]; do
			rn=$(esp_up $jr); in=$(esp_up $ji)
			if [ "$rn" -ge 1 ] || [ "$in" -ge 1 ]; then break; fi
			i=$((i+1)); sleep 1
		done
		if [ "$rn" -ge 1 ] || [ "$in" -ge 1 ]; then
			echo "FAIL (NEG): child SA appeared; refused exchange must stay empty"
		else
			grep -q "does not match peers id" /tmp/freeb/resp-iked.log 2>/dev/null && echo "row $_name: refusal reason in responder log (id/cert/psk)" || true
			grep -q "not supported by kernel" /tmp/freeb/resp-iked.log 2>/dev/null && echo "row $_name: kernel-gap refusal (config-check) confirmed" || true
			up=1
		fi
	else
		# positive / a12permit gate: child must come up.
		while [ "$i" -lt 45 ]; do
			rn=$(esp_up $jr); in=$(esp_up $ji)
			if [ "$rn" -ge 1 ] && [ "$in" -ge 1 ]; then up=1; break; fi
			i=$((i+1)); sleep 1
		done
	fi

	# DATA-PLANE gate (positive rows only): post-establishment ping THROUGH
	# the tunnel.  Under in/out `require` SPD a successful echo proves both
	# directions' SAs decrypt+encrypt — the real parity bar.
	TUN_OK=0
	if [ "$up" -eq 1 ] && [ "$_neg" != r ] && [ "$_neg" != x ]; then
		# FreeBSD /sbin/ping is IPv4-only; v6 rows (and i2io4's inner v6)
		# must use ping6.  For i2io4 the ping target is the INNER v6
		# selector (s6r), not the v4 hr — the whole point is that the v6
		# packet transits inside the v4 ESP tunnel.
		ping6_needed=0
		if [ "$_fam" = inet6 ] || [ "${_name#i2io4}" != "$_name" ]; then ping6_needed=1; fi
		if [ "$ping6_needed" -eq 1 ] && command -v ping6 >/dev/null 2>&1; then
			jexec $ji ping6 -c 1 -t 5 "${s6r:-$hr}" > /tmp/freeb/ping-tun.txt 2>&1 || true
		else
			jexec $ji ping -c 1 -t 5 "$hr" > /tmp/freeb/ping-tun.txt 2>&1 || true
		fi
		if grep -qE '[1-9][0-9]* (packets )?received' /tmp/freeb/ping-tun.txt 2>/dev/null \
			&& ! grep -qE '0 packets received|100[.]0% packet loss|100% packet loss' /tmp/freeb/ping-tun.txt 2>/dev/null; then
			echo "row $_name: data-plane OK (post-establishment $ji->${s6r:-$hr} ping through tunnel)"
			TUN_OK=1
		else
			echo "row $_name: FAIL data-plane (post-establishment ping did not transit)"
			cat /tmp/freeb/ping-tun.txt 2>/dev/null || true
		fi
	fi

	if [ "$up" -eq 1 ] && [ "$_neg" != r ] && [ "$_neg" != x ] && [ "$_rekey" -eq 1 ]; then
		echo "=== row $_name: child UP; assert CREATE_CHILD rekey (new ESP SPI both seats) ==="
		R0=$(spi $jr); I0=$(spi $ji)
		echo "initial SPIs R=[$(echo $R0 | tr '\n' ' ')] I=[$(echo $I0 | tr '\n' ' ')]"
		printf '%s\n' "$R0" > /tmp/freeb/R0.txt
		printf '%s\n' "$I0" > /tmp/freeb/I0.txt
		rekeyed=0
		i=0
		while [ "$i" -lt 90 ]; do
			spi $jr > /tmp/freeb/Rn.txt
			spi $ji > /tmp/freeb/In.txt
			nr=$(comm -13 /tmp/freeb/R0.txt /tmp/freeb/Rn.txt | grep -c spi || true)
			ni=$(comm -13 /tmp/freeb/I0.txt /tmp/freeb/In.txt | grep -c spi || true)
			if [ "$nr" -ge 1 ] && [ "$ni" -ge 1 ]; then
				echo "row $_name: CREATE_CHILD rekey new SPI both seats at ${i}s"
				rekeyed=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$rekeyed" -eq 1 ] || { echo "FAIL row $_name: no new ESP SPI in 90s"; up=0; }
		if [ "$rekeyed" -eq 1 ]; then
			# Rekey swaps the new SA over the old one; the SPI poll breaks the
			# instant a new SPI appears, so the very first ping can race the
			# old-SA delete.  Retry briefly instead of failing on that race.
			dplane=0; pt=0
			while [ "$pt" -lt 5 ]; do
				jexec $ji ping -c 1 -t 5 "$hr" > /tmp/freeb/ping-rekey.txt 2>&1 || true
				if grep -qE '[1-9][0-9]* (packets )?received' /tmp/freeb/ping-rekey.txt 2>/dev/null \
					&& ! grep -qE '0 packets received|100[.]0% packet loss|100% packet loss' /tmp/freeb/ping-rekey.txt 2>/dev/null; then
					dplane=1; break
				fi
				pt=$((pt+1)); sleep 1
			done
			if [ "$dplane" -eq 1 ]; then
				echo "row $_name: post-rekey data-plane OK (still transiting)"
			else
				echo "FAIL row $_name: post-rekey data-plane did not transit (ping raced SPI swap, ${pt} tries)"
				up=0
			fi
		fi
	fi

	# --- X.509 PK-auth gate (i2ipubkey-* rows only) ---
# Child-up + tunnel ping prove AUTH succeeded (there is NO PSK anywhere in
# these confs), but the NDcPP evidence cell needs the METHOD: the iked TRACE
# 'auth method N' line on BOTH seats (1 = RSASIG, 10 = ECDSA).  Same latch
# string as linux i2ipubkey.sh.
case "$_name" in
i2ipubkey-*)
	_exp="auth method 1([^0-9]|$)"
	case "$_name" in *-ecdsa*) _exp="auth method 10" ;; esac
	ai=$(grep -cE "$_exp" /tmp/freeb/init-iked.log 2>/dev/null || true)
	ar=$(grep -cE "$_exp" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	if [ "$ai" -ge 1 ] && [ "$ar" -ge 1 ]; then
		echo "row $_name: X.509 PK auth verified on BOTH seats ($_exp)"
	else
		echo "FAIL row $_name: PK auth gate (init=$ai resp=$ar; need '$_exp' on both seats)"
		up=0
	fi
	;;
esac

# --- classical IKE fallback (AEAD not met) ---
# CBC/CTR IKE cannot echo 16438.  Child-up is the successful fallback.
# A round-complete line means the row accidentally took the AEAD path.
case "$_name" in
*i2iinit-ike-cbc*|*i2iinit-ike-ctr*)
	ri=$(grep -c "IKE_INTERMEDIATE ADDKE round complete" /tmp/freeb/init-iked.log 2>/dev/null || true)
	rr=$(grep -c "IKE_INTERMEDIATE ADDKE round complete" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	if [ "${ri:-0}" -eq 0 ] && [ "${rr:-0}" -eq 0 ]; then
		echo "row $_name: classical fallback OK (no IKE_INTERMEDIATE; AEAD not met)"
	else
		echo "FAIL row $_name: classical row ran IKE_INTERMEDIATE (init=$ri resp=$rr)"
		up=0
	fi
	;;
esac

# --- offer_intermediate off: ADDKE is offered, 16438 is not ---
# Linux i2iinit-nointermediate.  Type-6 must be on the wire (the proposal
# still carries ML-KEM) and 00004036 / round-complete must be absent, or
# the knob did not apply.
case "$_name" in
*nointermediate*)
	t6i=$(grep -c "06000024" /tmp/freeb/init-iked.log 2>/dev/null || true)
	t6r=$(grep -c "06000024" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	n164i=$(grep -c "00004036" /tmp/freeb/init-iked.log 2>/dev/null || true)
	n164r=$(grep -c "00004036" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	ri=$(grep -c "IKE_INTERMEDIATE ADDKE round complete" /tmp/freeb/init-iked.log 2>/dev/null || true)
	rr=$(grep -c "IKE_INTERMEDIATE ADDKE round complete" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	if [ "$((${t6i:-0} + ${t6r:-0}))" -ge 1 ] \
	   && [ "$((${n164i:-0} + ${n164r:-0}))" -eq 0 ] \
	   && [ "${ri:-0}" -eq 0 ] && [ "${rr:-0}" -eq 0 ]; then
		echo "row $_name: offer_intermediate off OK - type-6 offered, no 16438, no IKE_INTERMEDIATE"
	else
		echo "FAIL row $_name: nointermediate gate (t6i=$t6i t6r=$t6r n164i=$n164i n164r=$n164r round_init=$ri round_resp=$rr)"
		up=0
	fi
	;;
esac

# --- need_pfs child rekey (both seats) ---
# IKE is AEAD and the sa block has ADDKE.  SPI change is the REKEY=1
# poll above.  Linux latches g_ir_present=Y, not SA_hex: ecp384 rekeys,
# pings, and logs a matching Y-hash on both seats with no SA_hex type-6
# line.  Either proof is enough.  Do not zero up when the SAs are mature.
case "$_name" in
*pfsrekey*)
	npc_i=$(grep -c "NO_PROPOSAL_CHOSEN" /tmp/freeb/init-iked.log 2>/dev/null || true)
	npc_r=$(grep -c "NO_PROPOSAL_CHOSEN" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	t6r=$(grep -cE "SA_hex=.*06000024" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	ri=$(grep -c "IKE_INTERMEDIATE ADDKE round complete" /tmp/freeb/init-iked.log 2>/dev/null || true)
	rr=$(grep -c "IKE_INTERMEDIATE ADDKE round complete" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	ky_i=$(grep -oE "sha256=[0-9a-f]+ g_ir_present=Y" /tmp/freeb/init-iked.log 2>/dev/null | grep -oE "sha256=[0-9a-f]+" | tail -1)
	ky_r=$(grep -oE "sha256=[0-9a-f]+ g_ir_present=Y" /tmp/freeb/resp-iked.log 2>/dev/null | grep -oE "sha256=[0-9a-f]+" | tail -1)
	pfs_ok=0
	if [ "${npc_i:-0}" -eq 0 ] && [ "${npc_r:-0}" -eq 0 ] \
	   && [ "${ri:-0}" -ge 1 ] && [ "${rr:-0}" -ge 1 ]; then
		if [ -n "$ky_i" ] && [ "$ky_i" = "$ky_r" ]; then
			pfs_ok=1
		elif [ "${t6r:-0}" -ge 1 ]; then
			pfs_ok=1
		fi
	fi
	if [ "$pfs_ok" -eq 1 ]; then
		echo "row $_name: need_pfs rekey OK - no NO_PROPOSAL_CHOSEN, g_ir_present=Y ${ky_i:-none} (t6=$t6r), initial IKE_INTERMEDIATE both seats"
	else
		echo "FAIL row $_name: pfsrekey gate (npc_i=$npc_i npc_r=$npc_r t6=$t6r ky_i=${ky_i:-none} ky_r=${ky_r:-none} round_init=$ri round_resp=$rr)"
		gate_why="pfsrekey latch (t6=${t6r:-0} ky=${ky_i:-none})"
		up=0
	fi
	;;
esac

# --- ADDKE/PQC gate (i2i*addke rows only) ---
# A bare child-up is NOT ML-KEM (a plain PSK row passes that).  PQC proof
# needs BOTH, latched exactly like the linux i2ike/i2iinit kinds:
#   (a) type-06 ADDKE transform on the wire (06000024 = MLKEM768).
#       i2iinit-addke: the IKE_SA_INIT proposal hex dump (no CREATE_CHILD,
#       so there is no SA_hex= line).  i2ike-addke: the CREATE_CHILD
#       request's SA_hex= line.
#   (b) the KEM keymat actually used, proven differently per row:
#       - i2iinit-addke: the initial IKE_SA ran the RFC 9370 round ->
#         'IKE_INTERMEDIATE ADDKE round complete' on BOTH seats (PLOG_INFO),
#         with the ESP child up (AUTH+IntAuth verified -> SKEYSEED(1) match);
#       - i2ike-addke: the CREATE_CHILD ADDKE rekey installed a fresh KEM
#         keymat -> matching `CHILD_RESP keymat ... g_ir_present=Y` sha256 on
#         BOTH seats (g_ir=Y = real IKE_FOLLOWUP_KE keymat, vs the n-polarity
#         plain rekey installs);
#   (c) no `ADDKE followup timeout; abort`.
case "$_name" in
*i2iinit-addke*|*i2iinit-ike-gcm*)
	# IKE_SA_INIT dumps the proposal as a raw hex block, not SA_hex=.
	# SA_hex= is CREATE_CHILD only; this row does not rekey.
	t6r=$(grep -c "06000024" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	ri=$(grep -c "IKE_INTERMEDIATE ADDKE round complete" /tmp/freeb/init-iked.log 2>/dev/null || true)
	rr=$(grep -c "IKE_INTERMEDIATE ADDKE round complete" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	abt=$(grep -cE "ADDKE followup timeout; abort" /tmp/freeb/resp-iked.log 2>/dev/null || true)
	if [ "${t6r:-0}" -ge 1 ] && [ "$ri" -ge 1 ] && [ "$rr" -ge 1 ] \
	   && [ "${abt:-0}" -eq 0 ]; then
		echo "row $_name: PQC INITIAL IKE_SA ADDKE OK - type-6 offer (x$t6r), IKE_INTERMEDIATE ADDKE round complete on BOTH seats, no followup abort"
	else
		echo "FAIL row $_name: ADDKE/PQC gate (t6=$t6r round_init=$ri round_resp=$rr abt=${abt:-0}); need wire type-6 + round-complete both seats + no abort"
		up=0
	fi
	;;
*i2ike-addke*)
	# CBC IKE cannot echo 16438, and the soft rekey has no DH, so ADDKE
	# is not re-offered.  The row's pass is the CREATE_CHILD rekey already
	# asserted above (new SPI both seats + post-rekey ping).  Demanding
	# SA_hex type-6 and a new g_ir_present=Y here zeros up after the SAs
	# exist, and the verdict then lies that there were no ESP SAs.
	# Type-6 + Y stays the proof on the AEAD rows (i2iinit-addke, pfsrekey).
	if grep -qE 'kmp_enc_alg \{ aes(128|192|256)_cbc' /tmp/freeb/r2vr.conf 2>/dev/null; then
		if [ "$up" -eq 1 ]; then
			echo "row $_name: CBC IKE rekey OK (ADDKE not re-offered without DH; AEAD not met)"
		fi
	else
		pqc=0
		i=0
		t6id=06000024
		case "$_name" in
		*-512*) t6id=06000023 ;;
		*-1024*) t6id=06000025 ;;
		esac
		t6r=$(grep -cE "SA_hex=.*$t6id" /tmp/freeb/resp-iked.log 2>/dev/null || true)
		YI0=$(grep -oE "sha256=[0-9a-f]+ g_ir_present=Y" /tmp/freeb/init-iked.log 2>/dev/null | grep -oE "sha256=[0-9a-f]+" | tail -1 || true)
		while [ "$i" -lt 90 ]; do
			ky_i=$(grep -oE "sha256=[0-9a-f]+ g_ir_present=Y" /tmp/freeb/init-iked.log 2>/dev/null | grep -oE "sha256=[0-9a-f]+" | tail -1)
			ky_r=$(grep -oE "sha256=[0-9a-f]+ g_ir_present=Y" /tmp/freeb/resp-iked.log 2>/dev/null | grep -oE "sha256=[0-9a-f]+" | tail -1)
			abt=$(grep -cE "ADDKE followup timeout; abort" /tmp/freeb/resp-iked.log 2>/dev/null || true)
			if [ -n "$ky_i" ] && [ -n "$ky_r" ] && [ "$ky_i" = "$ky_r" ] \
			   && { [ -z "$YI0" ] || [ "$ky_i" != "$YI0" ]; } \
			   && [ "$abt" -eq 0 ]; then
				pqc=1; break
			fi
			i=$((i+1)); sleep 1
		done
		if [ "${t6r:-0}" -ge 1 ] && [ "$pqc" -eq 1 ]; then
			echo "row $_name: PQC ADDKE rekey OK - type-6 offer (x$t6r), KEM keymat sha256=$ky_i matches both seats (new, != baseline ${YI0:-none}), no followup abort (at ${i}s)"
		else
			echo "FAIL row $_name: ADDKE/PQC gate (t6=$t6r ky_i=${ky_i:-none} ky_r=${ky_r:-none} abt=${abt:-0} base=${YI0:-none}); need wire type-6 + NEW matching Y-keymat + no abort"
			gate_why="ADDKE/PQC latch (t6=${t6r:-0})"
			up=0
		fi
	fi
	;;
esac

echo "=== SAD/SPD dump from INSIDE each vnet jail (retained for diagnosis) ==="
	jexec $jr /usr/local/sbin/setkey -D > /tmp/freeb/resp-sadb.txt 2>&1 || true
	jexec $ji /usr/local/sbin/setkey -D > /tmp/freeb/init-sadb.txt 2>&1 || true
	jexec $jr /usr/local/sbin/setkey -DP > /tmp/freeb/resp-spd.txt 2>&1 || true
	jexec $ji /usr/local/sbin/setkey -DP > /tmp/freeb/init-spd.txt 2>&1 || true
	echo "responder jail ESP tunnel SAs: $(grep -cE 'esp mode=tunnel' /tmp/freeb/resp-sadb.txt 2>/dev/null || true)"
	echo "initiator jail ESP tunnel SAs: $(grep -cE 'esp mode=tunnel' /tmp/freeb/init-sadb.txt 2>/dev/null || true)"

	echo "=== verdict (row $_name) ==="
	# SA count is INFORMATIONAL ONLY (a healthy bidir tunnel can show 1
	# esp line per jail).  The authoritative gate is the data-plane ping /
	# NEG refusal, never the SA count.
	# On any FAILURE diag() (defined at top of run_row) dumps raw SADB,
	# both iked logs, and the kernel's netipsec dmesg reason - never guess
	# from the SA count alone.
	if [ "$_neg" = r ]; then
		# NEG(auth/id/strength) rows: refusal must be PROVEN, not just
		# inferred from an empty SADB.  A bare "no child" is coexistence
		# with the refusal (could be a timeout or an unrelated kernel
		# rejection, e.g. a12strict whose GCM child cannot install).  The
		# PASS requires the row's own refusal marker in the responder log.
		refusal=0
		case "$_name" in
			*i2ineg-wrongpsk*)   grep -q "authentication failure" /tmp/freeb/resp-iked.log 2>/dev/null && refusal=1 || true ;;
			*i2ineg-idmismatch*) grep -q "does not match peers id" /tmp/freeb/resp-iked.log 2>/dev/null && refusal=1 || true ;;
			*i2ineg-a12strict*)  grep -q "parent_child_strength on" /tmp/freeb/resp-iked.log 2>/dev/null && refusal=1 || true ;;
		esac
		if [ "$up" -eq 1 ] && [ "$refusal" -eq 1 ]; then
			echo "PASS freebsd-vnet $_name (NEG: refusal proven by responder log marker)"
			echo "CPL-ND : PASS $_name (pfkey KM, per-jail setkey -D empty + refusal marker)"
			fbsd_comply "$_name" r
			jails_teardown
			return 0
		fi
		echo "FAIL freebsd-vnet $_name (NEG: refusal NOT proven)"
		echo "  up=$up refusal_marker=$refusal (expected: up=1 AND responder-log marker)"
		if [ "$up" -eq 0 ]; then
			echo "  child SA appeared - refusal did not fire (see resp-iked.log tail in diag)"
		else
			echo "  no child but the expected refusal marker is absent - refusal came from another cause (e.g. kernel), not this gate"
		fi
		cat /tmp/freeb/ctl.out 2>/dev/null || true
		diag
		echo "$SEP"
		jails_teardown
		return 1
	fi
	if [ "$_neg" = x ]; then
		# expected-reject (kernel gap): the transform is absent from the
		# FreeBSD kernel supported_aalgs[], so racoon2 MUST refuse at
		# config-check (ike_conf.c:4636 "not supported by kernel").  A PASS
		# requires BOTH no child AND that marker — a bare timeout must not
		# count as rejection.  When FreeBSD later ships XCBC/CMAC, the
		# config-check passes, a child appears and this FAILs: that red is
		# the signal to flip the row to a positive accept test (run ... a).
		if [ "$up" -eq 1 ] && grep -q "not supported by kernel" /tmp/freeb/resp-iked.log 2>/dev/null; then
			echo "PASS freebsd-vnet $_name (expected reject: kernel-gap refusal confirmed by config-check)"
			echo "CPL-XR : PASS $_name (expected kernel-gap rejection, non-vacuous: 'not supported by kernel' in responder log)"
			fbsd_comply "$_name" x
			jails_teardown
			return 0
		fi
		echo "FAIL freebsd-vnet $_name (expected reject: kernel-gap refusal NOT confirmed)"
		if [ "$up" -eq 1 ]; then
			echo "WARN: no child SA but 'not supported by kernel' absent — refusal may be from a different cause; see diag"
		else
			echo "ALERT: child SA appeared — this transform is now accepted (FreeBSD kernel added support?); convert row from expected-reject to a positive accept test"
		fi
		diag
		echo "$SEP"
		jails_teardown
		return 1
	fi
	if [ "$up" -eq 1 ] && [ "$TUN_OK" -eq 1 ]; then
		lines=$(grep -cE 'esp mode=tunnel' /tmp/freeb/resp-sadb.txt /tmp/freeb/init-sadb.txt 2>/dev/null | awk -F: '{s+=$2} END{print s}')
		echo "PASS freebsd-vnet $_name (pfkey KM: $lines ESP tunnel SAs + data-plane $ji->${s6r:-$hr})"
		echo "CPL B1: PASS $_name (pfkey KM ESP child up AND transiting, per-jail setkey -D + tunnel ping)"
		fbsd_comply "$_name" a
		jails_teardown
		return 0
	fi
	# Distinguish kernel-rejected SADB writes from a plain timeout: when the
	# kernel rejects spmd's SADB_ADD/UPDATE (ike_pfkey.c:217 sadb_poll
	# "error at the kernel on ADD/UPDATE, Invalid argument"), the row is not
	# "no SAs after timeout" - it is a kernel refusal, and that needs its own
	# verdict so the EINVAL mechanism is visible at a glance without grepping.
	if [ "$up" -eq 0 ] && grep -q 'Invalid argument' /tmp/freeb/resp-iked.log /tmp/freeb/init-iked.log 2>/dev/null; then
		echo "FAIL freebsd-vnet $_name (kernel rejected SADB ADD/UPDATE: EINVAL - see diag for the first sadb_poll error)"
	elif [ "$up" -eq 0 ] && grep -q 'malformed payload format' /tmp/freeb/resp-iked.log /tmp/freeb/init-iked.log 2>/dev/null; then
		echo "FAIL freebsd-vnet $_name (IKE payload malformed after decrypt, not a SADB timeout)"
	elif [ "$up" -eq 0 ] && grep -q 'state=mature' /tmp/freeb/resp-sadb.txt /tmp/freeb/init-sadb.txt 2>/dev/null; then
		echo "FAIL freebsd-vnet $_name (${gate_why:-later latch cleared up}; ESP SAs were mature)"
	else
		echo "FAIL freebsd-vnet $_name: no ESP tunnel SAs in either per-vnet SADB after timeout"
	fi
	echo "--- initiator ikedctl output ---"; cat /tmp/freeb/ctl.out 2>/dev/null || true
	diag
	echo "$SEP"
	jails_teardown
	return 1
}

fail=0
run() {
	# 0-based dispatcher index, matching linux run.sh --shard K M
	if [ $((_shard_idx % SHARD_M)) -eq "$SHARD_K" ]; then
		run_row "$@" || fail=1
	fi
	_shard_idx=$((_shard_idx + 1))
}

# Matrix rows.  Tokens match the Linux kinds verbatim so pfkey/xfrm parity
# is asserted on identical config.  REKEY rows: initiator lifetime short.
# 47 rows.  Still Linux-only (not replicated): charon/strongSwan, netem
# drop/dup, mobike/cookie2, xfrm-only cells, PPK, childless, ESN,
# IKE-SA rekey (i2ikesa-addke), DPD silence, NSA-warn.  Those need a
# peer or a conf knob this harness does not emit.
case "$ROW" in
	all)
		# --- i2iinit esp alg vectors (mirror linux i2iinit-esp-*) ---
		run i2iinit-esp-cbc128 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-esp-cbc192 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes192_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-esp-cbc256 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-esp-gcm256 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a ""
		run i2iinit-esp-sha384 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_384 300 300 0 a ""
		run i2iinit-esp-sha512 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_512 300 300 0 a ""
		# xcbc/cmac rows are EXPECTED-REJECT: FreeBSD 15.1 supported_aalgs[]
		# (sys/netipsec/key.c) lacks AES-XCBC-MAC/AES-CMAC, so racoon2 must
		# refuse at config-check.  The verdict gates on that marker, so when a
		# future FreeBSD kernel ships these transforms the row goes red (child
		# appears) and must be converted to a positive accept run.
		run i2iinit-esp-xcbc   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc "aes_xcbc" 300 300 0 x ""
		run i2iinit-esp-cmac   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc "aes_cmac" 300 300 0 x ""
		run i2iinit-esp-ctr    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_ctr" "non_auth" 300 300 0 a ""
		# --- i2iinit ike/prf vectors (mirror linux i2iinit-ike-*/prf-*) ---
		run i2iinit-ike-cbc192 inet 192.0.5.2 192.0.5.1 aes192_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-ike-cbc256 inet 192.0.5.2 192.0.5.1 aes256_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-ike-cbc128 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-ike-ctr    inet 192.0.5.2 192.0.5.1 "aes_ctr, 128" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
	run i2iinit-ike-ctr192 inet 192.0.5.2 192.0.5.1 "aes_ctr, 192" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
	run i2iinit-ike-ctr256 inet 192.0.5.2 192.0.5.1 "aes_ctr, 256" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-ike-gcm256 inet 192.0.5.2 192.0.5.1 "aes_gcm, 256" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-prfsha384  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_384 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-prfsha512  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_512 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-prfxcbc    inet 192.0.5.2 192.0.5.1 aes128_cbc aes_xcbc modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2iinit-prfcmac    inet 192.0.5.2 192.0.5.1 aes128_cbc aes_cmac modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		# --- i2idh DH groups (mirror linux i2idh non-charon rows) ---
		run i2idh-modp2048  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-modp3072  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp3072 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-modp4096  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp4096 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-modp6144  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp6144 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-modp8192  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp8192 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-ecp256    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp256  aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-ecp384    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp384  aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2idh-ecp521    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp521  aes128_cbc hmac_sha2_256 300 300 0 a ""
		# --- rekey rows (CREATE_CHILD on short initiator lifetime) ---
		run i2ike-rekey     inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 60 3600 1 a ""
		run i2ike-addke     inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes_gcm non_auth 60 3600 1 a ""
		run i2ike-addke-512  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes_gcm non_auth 60 3600 1 a ""
		run i2ike-addke-1024 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes_gcm non_auth 60 3600 1 a ""
		# --- PQC rows (OpenSSL 3.5 build = WITH_ADDKE: RATOON2 out-of-band
		#      RFC 9370, not netbsd-style kernel ESP).  i2iinit-addke proves
		#      ML-KEM-768 on the INITIAL IKE_SA (type-06 offer + matching
		#      Y-keymat both seats + no followup abort); i2ike-addke proves the
		#      CREATE_CHILD ADDKE rekey installs a fresh KEM keymat.  Same
		#      latches as the linux i2ike/i2iinit kinds. ---
		# PQC INITIAL IKE_SA: IKE cipher MUST be AEAD (aes_gcm) or the
		# responder won't echo 16438 (ikev2.c:1953: IntAuth_A is only
		# deterministic for AEAD; a CBC peer falls back to classical
		# IKE_AUTH).  ESP child stays CBC - the ADDKE constraint is on the
		# IKE SA only.
		run i2iinit-addke   inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 60 60 0 a ""
		# offer_intermediate off: ADDKE still in the proposal, no 16438.
		run i2iinit-nointermediate inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "offer_intermediate off;"
		# need_pfs on both seats.  IKE AEAD so the initial ADDKE round runs;
		# short child lifetime so the CREATE_CHILD rekey carries KE.
		run i2iinit-pfsrekey        inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 ecp256 aes_gcm non_auth 60 60 1 a "need_pfs on;"
		run i2iinit-dh384-pfsrekey  inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 ecp384 aes_gcm non_auth 60 60 1 a "need_pfs on;"
		run i2iinit-dh521-pfsrekey  inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 ecp521 aes_gcm non_auth 60 60 1 a "need_pfs on;"
		# --- X.509 public-key auth (NDcPP A13 .1.11 requires >=1 PK method;
		#      PSK-only FreeBSD matrix fails that).  Same openssl PKI build +
		#      SSL_CERT_FILE mechanism as linux i2ipubkey; conf declares
		#      kmp_auth_method rsasig/ecdsa + my/peers_public_key x509pem. ---
		run i2ipubkey-rsa   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2ipubkey-ecdsa inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		# --- NEG rows (mirror linux i2i_neg.sh) ---
		run i2ineg-wrongpsk   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 r ""
		run i2ineg-idmismatch inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 r ""
		run i2ineg-a12strict  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 r "parent_child_strength on;"
		run i2ineg-a12permit  inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a ""
		# --- IPv6 row (mirror linux i2iv6-esp) ---
		# Linux i2iv6-esp is AES-GCM.  The CBC shape is i2iv6-esp-cbc128.
		run i2iv6-esp          inet6 :: :: aes128_cbc hmac_sha2_256 modp2048 aes_gcm non_auth 300 300 0 a ""
		run i2iv6-esp-cbc128   inet6 :: :: aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		# --- IPv6-over-IPv4 rows: v4 IKE + outer SA pair (192.0.5.x),
		#     v6 inner selectors (2001:db8:1::x).  The inner v6 rides inside
		#     the v4 ESP tunnel; only v4 ARP (L2) is needed, so no ND6 gate.
		run i2io4-cbc128        inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a ""
		run i2io4-gcm256        inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a ""
		;;
	i2iinit-esp-cbc128) run_row i2iinit-esp-cbc128 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-esp-cbc192) run_row i2iinit-esp-cbc192 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes192_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-esp-cbc256) run_row i2iinit-esp-cbc256 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-esp-gcm256) run_row i2iinit-esp-gcm256 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a "" ;;
	i2iinit-esp-sha384) run_row i2iinit-esp-sha384 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_384 300 300 0 a "" ;;
	i2iinit-esp-sha512) run_row i2iinit-esp-sha512 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc hmac_sha2_512 300 300 0 a "" ;;
	i2iinit-esp-xcbc)  run_row i2iinit-esp-xcbc   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc "aes_xcbc" 300 300 0 x "" ;;
	i2iinit-esp-cmac)  run_row i2iinit-esp-cmac   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes256_cbc "aes_cmac" 300 300 0 x "" ;;
	i2io4-cbc128)      run_row i2io4-cbc128       inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2io4-gcm256)      run_row i2io4-gcm256       inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a "" ;;
	i2ike-addke)       run_row i2ike-addke        inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes_gcm non_auth 60 3600 1 a "" ;;
	i2ike-addke-512)   run_row i2ike-addke-512    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes_gcm non_auth 60 3600 1 a "" ;;
	i2ike-addke-1024)  run_row i2ike-addke-1024   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes_gcm non_auth 60 3600 1 a "" ;;
	i2iinit-addke)     run_row i2iinit-addke      inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 60 60 0 a "" ;;
	i2iinit-ike-cbc128) run_row i2iinit-ike-cbc128 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-ike-ctr)   run_row i2iinit-ike-ctr    inet 192.0.5.2 192.0.5.1 "aes_ctr, 128" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-ike-ctr192) run_row i2iinit-ike-ctr192 inet 192.0.5.2 192.0.5.1 "aes_ctr, 192" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-ike-ctr256) run_row i2iinit-ike-ctr256 inet 192.0.5.2 192.0.5.1 "aes_ctr, 256" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-nointermediate) run_row i2iinit-nointermediate inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "offer_intermediate off;" ;;
	i2iinit-pfsrekey)  run_row i2iinit-pfsrekey   inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 ecp256 aes_gcm non_auth 60 60 1 a "need_pfs on;" ;;
	i2iinit-dh384-pfsrekey) run_row i2iinit-dh384-pfsrekey inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 ecp384 aes_gcm non_auth 60 60 1 a "need_pfs on;" ;;
	i2iinit-dh521-pfsrekey) run_row i2iinit-dh521-pfsrekey inet 192.0.5.2 192.0.5.1 aes_gcm hmac_sha2_256 ecp521 aes_gcm non_auth 60 60 1 a "need_pfs on;" ;;
	i2iv6-esp)         run_row i2iv6-esp         inet6 :: :: aes128_cbc hmac_sha2_256 modp2048 aes_gcm non_auth 300 300 0 a "" ;;
	i2iv6-esp-cbc128)  run_row i2iv6-esp-cbc128  inet6 :: :: aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2ipubkey-rsa)     run_row i2ipubkey-rsa      inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2ipubkey-ecdsa)   run_row i2ipubkey-ecdsa    inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2ineg-wrongpsk)   run_row i2ineg-wrongpsk   inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 r "" ;;
	i2ineg-idmismatch) run_row i2ineg-idmismatch inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 r "" ;;
	i2iinit-esp-ctr) run_row i2iinit-esp-ctr inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_ctr" "non_auth" 300 300 0 a "" ;;
	i2iinit-ike-cbc192) run_row i2iinit-ike-cbc192 inet 192.0.5.2 192.0.5.1 aes192_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-ike-cbc256) run_row i2iinit-ike-cbc256 inet 192.0.5.2 192.0.5.1 aes256_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-ike-gcm256) run_row i2iinit-ike-gcm256 inet 192.0.5.2 192.0.5.1 "aes_gcm, 256" hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-prfsha384) run_row i2iinit-prfsha384 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_384 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-prfsha512) run_row i2iinit-prfsha512 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_512 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-prfxcbc) run_row i2iinit-prfxcbc inet 192.0.5.2 192.0.5.1 aes128_cbc aes_xcbc modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2iinit-prfcmac) run_row i2iinit-prfcmac inet 192.0.5.2 192.0.5.1 aes128_cbc aes_cmac modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2idh-modp2048) run_row i2idh-modp2048 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2idh-modp3072) run_row i2idh-modp3072 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp3072 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2idh-modp4096) run_row i2idh-modp4096 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp4096 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2idh-modp6144) run_row i2idh-modp6144 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp6144 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2idh-modp8192) run_row i2idh-modp8192 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp8192 aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2idh-ecp256) run_row i2idh-ecp256 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp256  aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2idh-ecp384) run_row i2idh-ecp384 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp384  aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2idh-ecp521) run_row i2idh-ecp521 inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 ecp521  aes128_cbc hmac_sha2_256 300 300 0 a "" ;;
	i2ike-rekey) run_row i2ike-rekey inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 aes128_cbc hmac_sha2_256 60 3600 1 a "" ;;
	i2ineg-a12strict) run_row i2ineg-a12strict inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 r "parent_child_strength on;" ;;
	i2ineg-a12permit) run_row i2ineg-a12permit inet 192.0.5.2 192.0.5.1 aes128_cbc hmac_sha2_256 modp2048 "aes_gcm, 256" non_auth 300 300 0 a "" ;;
	*) echo "unknown ROW=$ROW"; exit 2 ;;
esac
echo "$SEP"
if [ "$fail" -eq 0 ]; then
	echo "FREEBSD-VNET-OK (matrix: $ROW, shard $SHARD_K/$SHARD_M, rows iterated=$_shard_idx)"
	exit 0
fi
echo "FREEBSD-VNET-FAIL (matrix: $ROW, shard $SHARD_K/$SHARD_M, rows iterated=$_shard_idx)"
exit 1
