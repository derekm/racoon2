#!/bin/sh
# kinds/i2i_rekey.sh — gates for the i2iinit rekey-family rows: policy
# initial_child_ke (immediate | childless), RFC 6023 childless first child
# and its fallback, multi-generation ADDKE child rekeys, IKE_SA ADDKE
# rekeys, and zero-child IKE_SA rekeys.  Each row runs iked<->iked or with a
# strongSwan charon seat (-charon: charon initiates the IKE_SA, -charonr:
# charon responds), and every gate checks BOTH seats: the iked log on an
# iked seat, charon's own log plus `swanctl --list-sas` on a charon seat.
# Called from kind_i2iinit while the netns pair and daemons are live; the
# caller has set NSR/NSI, D, PEER/PEER_R, I2I_RK* (see i2iinit.sh).

# rk_log <seat i|r> — the iked log of a seat ("" when that seat is charon).
rk_log() {
	case "$1" in
	i) [ "$PEER" = charon ] && echo "" || echo "$D/init-iked.log" ;;
	r) [ "$PEER_R" = charon ] && echo "" || echo "$D/resp-iked.log" ;;
	esac
}
# rk_clog — the charon log of this row ("" for iked<->iked).
rk_clog() {
	if [ "$PEER" = charon ]; then echo "$D/charon-init.log"
	elif [ "$PEER_R" = charon ]; then echo "$D/charon-resp.log"
	else echo ""; fi
}
rk_cns() { [ "$PEER" = charon ] && echo "$NSI" || echo "$NSR"; }
# rk_ys <log> — distinct g_ir_present=Y (KE/ML-KEM-derived) child keymat
# hashes, in install order.
rk_ys() {
	[ -n "$1" ] || return 0
	grep -oE 'sha256=[0-9a-f]+ g_ir_present=Y' "$1" 2>/dev/null \
		| grep -oE '[0-9a-f]{64}' | awk '!s[$0]++'
}
rk_cnt() { _n=$(grep -cE "$1" "$2" 2>/dev/null); echo "${_n:-0}"; }
rk_esp() { _n=$(ip netns exec "$1" ip xfrm state 2>/dev/null | grep -c 'proto esp'); echo "${_n:-0}"; }
rk_spis() { ip netns exec "$1" ip xfrm state 2>/dev/null | grep 'proto esp' | grep -oE 'spi 0x[0-9a-f]+' | awk '{print $2}' | sort -u; }

# rk_charon_child_ke — number of CHILD_SAs charon negotiated with a KE and
# ML-KEM-768 (its 'selected proposal: ESP:...KE1_ML_KEM_768' lines; an
# IKE_AUTH child never carries KE, RFC 7296 s1.2).
rk_charon_child_ke() {
	_cl=$(rk_clog); [ -n "$_cl" ] || { echo 0; return; }
	rk_cnt 'selected proposal: ESP:[^ ]*ECP_256[^ ]*KE1_ML_KEM_768' "$_cl"
}

# rk_common_bad — strings that fail every rekey-family row on any iked seat.
rk_common_bad() {
	for _l in "$(rk_log i)" "$(rk_log r)"; do
		[ -n "$_l" ] || continue
		if grep -qE 'ADDKE followup timeout; abort|NO_PROPOSAL_CHOSEN|state 3 skipped' "$_l" 2>/dev/null; then
			log "FAIL: $(basename "$_l") has an ADDKE abort / NO_PROPOSAL_CHOSEN / skipped rekey"
			return 1
		fi
	done
	_cl=$(rk_clog)
	if [ -n "$_cl" ] && grep -qE 'NO_PROPOSAL_CHOSEN|no acceptable proposal found|INVALID_KE_PAYLOAD' "$_cl" 2>/dev/null; then
		log "FAIL: charon refused a proposal ($(grep -m1 -E 'NO_PROPOSAL_CHOSEN|no acceptable proposal found|INVALID_KE_PAYLOAD' "$_cl"))"
		return 1
	fi
	return 0
}

# rk_wait_ys <n> <secs> <log>... — wait until every listed iked log has >= n
# distinct Y keymats (and, iked<->iked, the two lists are identical).
rk_wait_ys() {
	_need=$1 _secs=$2; shift 2
	_t=0
	while [ "$_t" -lt "$_secs" ]; do
		_ok=1; _ref=""
		for _l in "$@"; do
			_ys=$(rk_ys "$_l" | tr '\n' ' ')
			[ "$(echo $_ys | wc -w)" -ge "$_need" ] || _ok=0
			if [ -n "$_ref" ] && [ "$_ys" != "$_ref" ]; then _ok=0; fi
			_ref=$_ys
		done
		[ "$_ok" = 1 ] && return 0
		_t=$((_t+1)); sleep 1
	done
	return 1
}

# rk_iked_logs — the iked logs of this row (one or two).
rk_iked_logs() { for _s in i r; do _l=$(rk_log $_s); [ -n "$_l" ] && echo "$_l"; done; }

# --- initial_child_ke immediate (and the fallback of 'childless') --------
# The IKE_AUTH child is keyed from SKEYSEED only (g_ir_present=n, RFC 7296
# s1.2; RFC 9370 s2.2.2 forbids additional key exchanges in IKE_AUTH).  The
# iked seat with the knob must rekey it right away with CREATE_CHILD_SA
# carrying KE + the type-6 ML-KEM transform, both seats must install the
# same fresh KEM keymat, and the IKE_AUTH child must be gone.
rk_gate_immediate() {
	_seat=$1 _why=$2
	_kl=$(rk_log "$_seat")
	[ -n "$_kl" ] || { log "FAIL: immediate gate: seat $_seat is not iked"; return 1; }
	if ! grep -q "initial_child_ke $_why: rekeying the IKE_AUTH child" "$_kl"; then
		log "FAIL: no 'initial_child_ke $_why: rekeying the IKE_AUTH child' on seat $_seat"; return 1
	fi
	# the first child installed on every iked seat is the plain IKE_AUTH child
	for _l in $(rk_iked_logs); do
		_p=$(grep -oE 'g_ir_present=[Yn]' "$_l" | head -1)
		[ "$_p" = "g_ir_present=n" ] || { log "FAIL: first keymat on $(basename "$_l") is '$_p', expected the plain IKE_AUTH child (n)"; return 1; }
	done
	# fresh KEM keymat (matching on iked<->iked), within 30 s of child-up:
	# with 300 s lifetimes this cannot be a lifetime rekey.
	if ! rk_wait_ys 1 30 $(rk_iked_logs); then
		log "FAIL: no matching g_ir_present=Y keymat after the immediate rekey ($(for l in $(rk_iked_logs); do printf '%s=[%s] ' "$(basename "$l")" "$(rk_ys "$l" | tr '\n' ' ')"; done))"
		return 1
	fi
	_y=$(rk_ys "$_kl" | head -1)
	_nrk=$(rk_cnt 'initiating CREATE_CHILD_SA rekey' "$_kl")
	[ "$_nrk" -eq 1 ] || { log "FAIL: expected exactly one child rekey from seat $_seat, saw $_nrk"; return 1; }
	_old=$(grep -oE 'initiating CREATE_CHILD_SA rekey child=[^ ]+ spi=0x[0-9a-f]+' "$_kl" | head -1 | grep -oE '0x[0-9a-f]+$')
	# the rekey must have offered type-6 ML-KEM-768: on the peer seat, the
	# iked CREATE_CHILD request SA dump or charon's selected ESP proposal
	_peer=$([ "$_seat" = i ] && echo r || echo i)
	_pl=$(rk_log "$_peer")
	if [ -n "$_pl" ]; then
		_t6=$(rk_cnt 'CREATE_CHILD_SA request SA_hex=.*06000024' "$_pl")
		[ "$_t6" -ge 1 ] || { log "FAIL: peer iked saw no type-6 06000024 in the rekey request"; return 1; }
	else
		sleep 2
		_ck=$(rk_charon_child_ke)
		[ "$_ck" -ge 1 ] || { log "FAIL: charon never selected an ESP proposal with ECP_256 + KE1_ML_KEM_768"; return 1; }
	fi
	# the IKE_AUTH child (its SPI from the rekey line) is gone from the
	# knob seat's SAD, and one child (2 ESP states) remains per side
	_t=0
	while [ "$_t" -lt 20 ]; do
		_ns=$([ "$_seat" = i ] && echo "$NSI" || echo "$NSR")
		if ! rk_spis "$_ns" | grep -qx "$(printf '0x%08x' "$_old" 2>/dev/null)" \
		   && [ "$(rk_esp "$NSR")" -eq 2 ] && [ "$(rk_esp "$NSI")" -eq 2 ]; then
			break
		fi
		_t=$((_t+1)); sleep 1
	done
	[ "$_t" -lt 20 ] || { log "FAIL: IKE_AUTH child spi $_old still installed or ESP count != 2 (resp=$(rk_esp "$NSR") init=$(rk_esp "$NSI"))"; return 1; }
	log "initial_child_ke $_why OK: seat $_seat rekeyed the IKE_AUTH child (spi $_old) at once; KE+ML-KEM keymat sha256=$_y on $(rk_iked_logs | xargs -n1 basename | tr '\n' ' ')$( [ -n "$(rk_clog)" ] && echo "+ charon ESP KE1_ML_KEM_768 x$(rk_charon_child_ke)")"
	return 0
}

# --- RFC 6023 childless first child ---------------------------------------
# The IKE_AUTH carried no SA/TS, so the first (and only) child came from a
# CREATE_CHILD_SA with KE + type-6: its keymat is already g_ir_present=Y on
# every iked seat, no seat ever installed a plain child, and nobody ran an
# initial_child_ke rekey (the child was not negotiated in IKE_AUTH).
rk_gate_childless_first() {
	for _l in $(rk_iked_logs); do
		_p=$(grep -oE 'g_ir_present=[Yn]' "$_l" | head -1)
		[ "$_p" = "g_ir_present=Y" ] || { log "FAIL: first child keymat on $(basename "$_l") is '$_p', expected a KE child (Y)"; return 1; }
		if grep -q 'initial_child_ke [a-z]*: rekeying the IKE_AUTH child' "$_l"; then
			log "FAIL: $(basename "$_l") ran an initial_child_ke rekey although the IKE_SA was childless"; return 1
		fi
		if grep -q 'initiating CREATE_CHILD_SA rekey' "$_l"; then
			log "FAIL: $(basename "$_l") rekeyed the first child; a childless first child needs no rekey"; return 1
		fi
	done
	rk_wait_ys 1 20 $(rk_iked_logs) || { log "FAIL: childless first child: Y keymat missing/mismatched"; return 1; }
	_cl=$(rk_clog)
	if [ -n "$_cl" ]; then
		[ "$(rk_charon_child_ke)" -ge 1 ] || { log "FAIL: charon's first child has no ECP_256+KE1_ML_KEM_768 proposal"; return 1; }
	else
		# iked<->iked: the responder saw a NEW-child CREATE_CHILD (not a rekey)
		# with type-6
		grep -qE 'CREATE_CHILD_SA request: .*proto=ESP rekey_proto=0 ' "$D/resp-iked.log" || { log "FAIL: responder saw no new-child CREATE_CHILD_SA"; return 1; }
		[ "$(rk_cnt 'CREATE_CHILD_SA request SA_hex=.*06000024' "$D/resp-iked.log")" -ge 1 ] || { log "FAIL: first-child CREATE_CHILD had no type-6"; return 1; }
	fi
	[ "$(rk_esp "$NSR")" -eq 2 ] && [ "$(rk_esp "$NSI")" -eq 2 ] || { log "FAIL: expected exactly one child (2 ESP states per side): resp=$(rk_esp "$NSR") init=$(rk_esp "$NSI")"; return 1; }
	log "RFC 6023 childless first child OK: CREATE_CHILD with KE+ML-KEM, Y keymat $(rk_ys "$(rk_iked_logs | head -1)" | head -1) on every seat, no IKE_AUTH child, no rekey"
	return 0
}

# --- multi-generation ADDKE child rekeys ----------------------------------
# >= 2 consecutive child rekeys, each with a NEW KE+ML-KEM keymat (distinct
# g_ir_present=Y hashes, equal on both iked seats), SPIs replaced each time,
# the child still installed at the end.
rk_gate_gens() {
	_s0=$(rk_spis "$NSR" | tr '\n' ' ')
	if ! rk_wait_ys 2 150 $(rk_iked_logs); then
		log "FAIL: < 2 ADDKE child-rekey generations ($(for l in $(rk_iked_logs); do printf '%s=[%s] ' "$(basename "$l")" "$(rk_ys "$l" | tr '\n' ' ')"; done))"
		return 1
	fi
	sleep 3
	_ng=$(rk_ys "$(rk_iked_logs | head -1)" | wc -l)
	_cl=$(rk_clog)
	if [ -n "$_cl" ]; then
		_ck=$(rk_charon_child_ke)
		[ "$_ck" -ge 2 ] || { log "FAIL: charon logged $_ck KE+ML-KEM child negotiations, expected >= 2"; return 1; }
	fi
	_s1=$(rk_spis "$NSR" | tr '\n' ' ')
	[ "$_s0" != "$_s1" ] || { log "FAIL: responder SPIs unchanged across the rekeys ($_s0)"; return 1; }
	[ "$(rk_esp "$NSR")" -ge 2 ] && [ "$(rk_esp "$NSI")" -ge 2 ] || { log "FAIL: child gone after rekeys"; return 1; }
	log "multi-generation ADDKE child rekeys OK: $_ng distinct KE+ML-KEM keymats [$(rk_ys "$(rk_iked_logs | head -1)" | cut -c1-12 | tr '\n' ' ')] on $(rk_iked_logs | xargs -n1 basename | tr '\n' ' ')$( [ -n "$_cl" ] && echo "charon KE1 children x$_ck"); SPIs $_s0-> $_s1"
	return 0
}

# --- IKE_SA ADDKE rekeys (with or without children) -----------------------
# >= 2 consecutive IKE_SA rekeys, each running the RFC 9370 ADDKE round
# (iked: 'IKE_SA rekey ADDKE SK(1)' on every iked seat), with the IKE_SA
# still established afterwards; charon's own view must show a new IKE_SA
# generation with KE1_ML_KEM_768.  <children> = expected ESP states per side
# (2, or 0 for a zero-child IKE_SA).
rk_gate_ikerekey() {
	_drv=$1 _children=$2
	_t=0
	while [ "$_t" -lt 150 ]; do
		_ok=1
		for _l in $(rk_iked_logs); do
			[ "$(rk_cnt 'IKE_SA rekey ADDKE SK\(1\)' "$_l")" -ge 2 ] || _ok=0
		done
		[ "$_ok" = 1 ] && break
		_t=$((_t+1)); sleep 1
	done
	if [ "$_ok" != 1 ]; then
		log "FAIL: < 2 IKE_SA ADDKE rekeys ($(for l in $(rk_iked_logs); do printf '%s=%s ' "$(basename "$l")" "$(rk_cnt 'IKE_SA rekey ADDKE SK\(1\)' "$l")"; done))"
		return 1
	fi
	_dl=$(rk_log "$_drv")
	if [ -n "$_dl" ]; then
		[ "$(rk_cnt 'initiating IKE_SA rekey' "$_dl")" -ge 2 ] || { log "FAIL: seat $_drv did not initiate the IKE_SA rekeys"; return 1; }
	fi
	for _l in $(rk_iked_logs); do
		if grep -qE 'grace period expired|failed processing IKE_SA rekey' "$_l"; then
			log "FAIL: $(basename "$_l"): grace expiry / failed IKE_SA rekey"; return 1
		fi
	done
	sleep 3
	_cl=$(rk_clog)
	if [ -n "$_cl" ]; then
		i2i_charon_list_sas "$D" "$(rk_cns)" ikerekey
		_sas="$D/charon-sas-ikerekey.txt"
		grep -qE 'ESTABLISHED' "$_sas" || { log "FAIL: charon --list-sas: no ESTABLISHED IKE_SA after the rekeys"; return 1; }
		grep -qE 'KE1_ML_KEM_768' "$_sas" || { log "FAIL: charon --list-sas: IKE_SA proposal lacks KE1_ML_KEM_768"; return 1; }
		_uid=$(grep -oE '^[^ ]+: #[0-9]+' "$_sas" | head -1 | grep -oE '[0-9]+$')
		[ "${_uid:-0}" -ge 3 ] || { log "FAIL: charon IKE_SA unique id ${_uid:-none} < 3 (expected >= 2 rekeys)"; return 1; }
		_cch=$(grep -cE 'INSTALLED' "$_sas")
		[ "$_children" -eq 0 ] && [ "$_cch" -ne 0 ] && { log "FAIL: charon lists $_cch CHILD_SAs on a zero-child IKE_SA"; return 1; }
		[ "$_children" -gt 0 ] && [ "$_cch" -lt 1 ] && { log "FAIL: charon lists no INSTALLED CHILD_SA after the IKE_SA rekeys"; return 1; }
	fi
	_er=$(rk_esp "$NSR"); _ei=$(rk_esp "$NSI")
	if [ "$_children" -eq 0 ]; then
		[ "$_er" -eq 0 ] && [ "$_ei" -eq 0 ] || { log "FAIL: zero-child IKE_SA has ESP states (resp=$_er init=$_ei)"; return 1; }
	else
		[ "$_er" -ge 2 ] && [ "$_ei" -ge 2 ] || { log "FAIL: child lost across IKE_SA rekeys (resp=$_er init=$_ei)"; return 1; }
	fi
	log "IKE_SA ADDKE rekeys OK: driver=$_drv, $(for l in $(rk_iked_logs); do printf '%s SK(1) x%s ' "$(basename "$l")" "$(rk_cnt 'IKE_SA rekey ADDKE SK\(1\)' "$l")"; done)$( [ -n "$_cl" ] && echo "charon IKE_SA #$_uid ESTABLISHED with KE1_ML_KEM_768, $_cch children"); ESP resp=$_er init=$_ei"
	return 0
}

# i2i_rekey_gates — dispatch on I2I_RK; sets rk_ok (1 pass / 0 fail).
i2i_rekey_gates() {
	rk_ok=1
	[ -n "$I2I_RK" ] || return 0
	rk_ok=0
	_iseat=$([ "$PEER" = charon ] && echo r || echo i)   # an iked seat
	case "$I2I_RK" in
	immediate)
		rk_gate_immediate "$I2I_RK_SEAT" immediate || return 0 ;;
	firstchild)
		if [ "$I2I_RK_NOCL" = 1 ]; then
			grep -q 'childless requested but the responder did not send CHILDLESS_IKEV2_SUPPORTED' "$D/init-iked.log" \
				|| { log "FAIL: no RFC 6023 fallback line on the iked initiator"; return 0; }
			if grep -q 'sending modified (SA-less) IKE_AUTH' "$D/init-iked.log"; then
				log "FAIL: iked sent a childless IKE_AUTH to a responder without 16418"; return 0
			fi
			rk_gate_immediate i childless || return 0
		else
			grep -q 'sending modified (SA-less) IKE_AUTH' "$D/init-iked.log" \
				|| { log "FAIL: iked initiator did not send the childless IKE_AUTH"; return 0; }
			rk_gate_childless_first || return 0
		fi ;;
	clresp)
		if [ "$I2I_RK_NOCL" = 1 ]; then
			if grep -q 'received childless (SA-less) IKE_AUTH' "$D/resp-iked.log"; then
				log "FAIL: legacy initiator but the responder saw a childless IKE_AUTH"; return 0
			fi
			rk_gate_immediate r immediate || return 0
		else
			grep -q 'received childless (SA-less) IKE_AUTH' "$D/resp-iked.log" \
				|| { log "FAIL: supporting initiator, but the responder never saw a childless IKE_AUTH"; return 0; }
			rk_gate_childless_first || return 0
		fi ;;
	gens)
		rk_gate_gens || return 0 ;;
	ikerekey)
		_drv=$_iseat; [ "$I2I_RK_CR" = 1 ] && _drv=c
		rk_gate_ikerekey "$_drv" 2 || return 0 ;;
	zerochild)
		grep -q 'received childless (SA-less) IKE_AUTH, establishing IKE_SA with zero children' "$D/resp-iked.log" \
			|| { log "FAIL: iked responder did not establish a zero-child IKE_SA"; return 0; }
		_drv=r; [ "$I2I_RK_CR" = 1 ] && _drv=c
		rk_gate_ikerekey "$_drv" 0 || return 0 ;;
	*)
		log "FAIL: unknown rekey-family token '$I2I_RK'"; return 0 ;;
	esac
	rk_common_bad || return 0
	rk_ok=1
	return 0
}

# i2i_onechild_gate — Linux spurious-ACQUIRE regression (b8c7ce8).  Before
# the per-socket XFRM bypass, iked's getlocaladdr() probe hit the host
# `require` policy, the kernel sent an ACQUIRE during IKE_SA_INIT, and iked
# queued a SECOND child that went out as a new-child CREATE_CHILD_SA right
# after ESTABLISHED.  For every row whose IKE_AUTH carries the child, the
# responder must see NO new-child CREATE_CHILD_SA (only rekeys, rekey_proto
# != 0).  Sets onechild_ok.
i2i_onechild_gate() {
	onechild_ok=1
	if [ "$PEER_R" = charon ]; then
		# charon logs the payload list; a new child has TSi but no N(REKEY_SA)
		_nc=$(grep -E 'parsed CREATE_CHILD_SA request [0-9]+ \[' "$D/charon-resp.log" 2>/dev/null | grep 'TSi' | grep -vc 'N(REKEY_SA)')
	else
		_nc=$(grep -cE 'CREATE_CHILD_SA request: .*proto=ESP rekey_proto=0 ' "$D/resp-iked.log" 2>/dev/null)
	fi
	if [ "${_nc:-0}" -ne 0 ]; then
		onechild_ok=0
		log "FAIL: responder saw ${_nc} new-child CREATE_CHILD_SA on a row whose child is negotiated in IKE_AUTH (spurious ACQUIRE child?)"
	fi
	if [ "$PEER" != charon ] && [ "$I2I_DBG" = 0x0003 ]; then
		_aq=$(rk_cnt 'sadb_acquire_callback:' "$D/init-iked.log")
		if [ "$_aq" -ne 0 ]; then
			onechild_ok=0
			log "FAIL: iked initiator received $_aq kernel ACQUIRE(s) with no data traffic (IKE socket/probe not exempt from the SPD)"
		fi
	fi
	for _l in $(rk_iked_logs); do
		if grep -q 'IPSEC_POLICY bypass unsupported' "$_l"; then
			onechild_ok=0
			log "FAIL: $(basename "$_l"): per-socket IPsec bypass unsupported (IKE sockets not exempt)"
		fi
	done
	return 0
}
