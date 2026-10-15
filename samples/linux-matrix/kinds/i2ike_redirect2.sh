#!/bin/sh
# kinds/i2ike_redirect2.sh — RFC 5685 redirect to a LIVE sibling gateway:
# the two-gateway "fresh session" flow, concentrator-shaped.
#
# THREE seats (three netns) on ONE bridge hub /24, so the initiator has a
# SINGLE interface and reaches both gateways:
#
#          bridge hub (192.0.11.0/24)
#        /      |        \
#   A (192.0.11.1)     C (192.0.11.3)
#          \     I (192.0.11.2)   /     protected address 192.0.30.0 served by BOTH A and C
#
# Concentrator model (the key fix, ICS research finding):
#   - The CHILD's TRAFFIC SELECTOR targets the protected ADDRESS 192.0.30.0
#     (its name $PTC32, a BARE address — rcs_getaddrlist parses a bare IPv4
#     with no "/N" as /32, NOT /24), which every pool gateway serves
#     identically.  ikev2_construct_ts_i/r build TSi/TSr from selector->src/dst
#     (NOT the SA remote), so a client whose sel_out dst is the protected
#     address presents the SAME TSr to A and to C — a redirected child's TS
#     matches on the sibling with no code change.  Responder outbound selector
#     mirrors the mapping the TS matcher enforces:
#     responder sel_out src = initiator's TSr (protected addr),
#                      dst = initiator's TSi (the client $HI).
#   - The tunnel ENDPOINT is NOT pinned by peers_sa_ipaddr: ike_determine_sa_endpoint
#     returns the IKE_SA's (redirected) remote when peers_sa_ipaddr is absent, so
#     after redirect-follow retargets parent->remote to C the child lands on C.
#   (The earlier failed attempts either pinned each gateway's OWN address as the
#    child dst — C rejected TSr==A — or used the wrong responder src/dst sense.)
#
# DATA PLANE / xfrm audit note: the child has SAs keyed to C but NO SPD policy
# row — spmd_pfkey.c refuses a tunnel-policy install when my_sa_ipaddr is absent
# ("No my_sa_ipaddr"), and that same unpin is what lets ike_determine_sa_endpoint
# follow the redirect.  So no data-plane traffic is moved and the harness's
# xa_probe never fires; xfrm_audit.tsv declares the traffic check for exactly
# this reason.  The row's proof is the failover LANDING (wire re-target + keyed
# child on the sibling), not data-plane traversal.
#
# Flow:
#   1. I establishes a child to A (TS: I <-> 192.0.30.0 protected addr).
#   2. 'drain-sa <I-peer> <C>' on A: A SILENTLY closes the peer's established
#      IKE_SA (ikev2_abort, 'aborting ike_sa', A esp 2->0).
#   3. I re-initiates; A answers N(REDIRECT, C=192.0.11.3); I verifies Ni and
#      reretargets + re-drives IKE_SA_INIT against the REAL C, which completes a
#      FULL IKE_AUTH + installs the child (C esp>=2 AND I esp>=2) while A stays 0.
#
# Gate:
#  - I->A up (A esp>=2 AND I esp>=2).
#  - drain-sa SET: 'aborting ike_sa' + A esp 2->0.
#  - I re-drives IKE_SA_INIT to C — wire '192.0.11.3[500]...INI_IKE_SA_INIT_SENT'.
#  - C completes full IKE_AUTH + child (C esp>=2 AND I esp>=2) AND A esp==0.
#
# Honest: redirect+resume mutually exclusive at IKE_SA_INIT, so C does a full
# IKE_AUTH; ike_msg_resume_store_migrate is a documented no-op.
# gate=box.
kind_i2ike_redirect2() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	HR=192.0.11.1; HI=192.0.11.2; CID=192.0.11.3
	PTC32=192.0.30.0           # protected ADDRESS served by BOTH A and C (bare -> /32)
	NSR="n${name}-a"; NSI="n${name}-i"; NSC="n${name}-c"
	NBH="n${name}-hub"
	rst_long_tag=$(printf '%s' "$name" | cksum | awk '{printf "%06x", $1}')
	VBA="v${rst_long_tag}a"; VBI="v${rst_long_tag}i"; VBC="v${rst_long_tag}c" # hub ends
	VLA="v${rst_long_tag}A"; VLI="v${rst_long_tag}I"; VLC="v${rst_long_tag}C" # seat ends
	SPMIF_A="/tmp/spmif-${name}-a"; SPMIF_I="/tmp/spmif-${name}-i"; SPMIF_C="/tmp/spmif-${name}-c"
	SOCK_A="/tmp/iked.sock-${name}-a"; SOCK_I="/tmp/iked.sock-${name}-i"; SOCK_C="/tmp/iked.sock-${name}-c"
	PRIVRES_A="/tmp/r2-${name}-resume-a"; PRIVRES_I="/tmp/r2-${name}-resume-i"; PRIVRES_C="/tmp/r2-${name}-resume-c"
	D="/tmp/r2-${name}"; C="/tmp/r2-${name}-conf"
	DGW=$CID

	rm -rf "$PRIVRES_A" "$PRIVRES_I" "$PRIVRES_C" "$D" "$C"
	mkdir -p "$PRIVRES_A" "$PRIVRES_I" "$PRIVRES_C" "$D" "$C/psk"
	cp "$ETC/psk/macos.psk" "$C/psk/macos.psk"

	# Child TS = PROTECTED SUBNET (service any gateway); NO peers_sa_ipaddr /
	# my_sa_ipaddr pin so the tunnel endpoint auto-follows the redirect.
	cat > "$C/a.conf" <<EOF
interface { ike { "$HR"; }; spmd { unix "$SPMIF_A"; }; spmd_password "$ETC/spmd.pwd"; };
resolver { resolver off; };
remote a_resp {
acceptable_kmp { ikev2; };
ikev2 { passive on; my_id fqdn "afront"; peers_id fqdn "ic2"; peers_ipaddr "$HI";
	kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; }; kmp_hash_alg { hmac_sha2_256; };
	kmp_dh_group { ecp256; }; kmp_auth_method { psk; }; pre_shared_key "$C/psk/macos.psk"; dpd_delay 300 sec; };
selector_index sel_in; };
selector sel_out { direction outbound; src "$PTC32"; dst "$HI"; policy_index pol; };
selector sel_in { direction inbound; dst "$PTC32"; src "$HI"; policy_index pol; };
policy pol { action auto_ipsec; remote_index a_resp; ipsec_mode tunnel; ipsec_index { ipsec_e; };
	ipsec_level require; };
ipsec ipsec_e { ipsec_sa_lifetime_time 3600 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }; };
EOF
	cat > "$C/c.conf" <<EOF
interface { ike { "$CID"; }; spmd { unix "$SPMIF_C"; }; spmd_password "$ETC/spmd.pwd"; };
resolver { resolver off; };
remote c_resp {
	acceptable_kmp { ikev2; };
	ikev2 { passive on; my_id fqdn "afront"; peers_id fqdn "ic2"; peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; }; kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; }; kmp_auth_method { psk; }; pre_shared_key "$C/psk/macos.psk"; dpd_delay 300 sec; };
	selector_index sel_in; };
selector sel_out { direction outbound; src "$PTC32"; dst "$HI"; policy_index pol; };
selector sel_in { direction inbound; dst "$PTC32"; src "$HI"; policy_index pol; };
policy pol { action auto_ipsec; remote_index c_resp; ipsec_mode tunnel; ipsec_index { ipsec_e; };
	ipsec_level require; };
ipsec ipsec_e { ipsec_sa_lifetime_time 3600 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }; };
EOF
	cat > "$C/i.conf" <<EOF
interface { ike { "$HI"; }; spmd { unix "$SPMIF_I"; }; spmd_password "$ETC/spmd.pwd"; };
resolver { resolver off; };
remote i_init {
	acceptable_kmp { ikev2; };
	ikev2 { passive off; my_id fqdn "ic2"; peers_id fqdn "afront"; peers_ipaddr "$HR";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; }; kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; }; kmp_auth_method { psk; }; pre_shared_key "$C/psk/macos.psk"; dpd_delay 300 sec; };
	selector_index sel_in; };
selector sel_out { direction outbound; src "$HI"; dst "$PTC32"; policy_index pol; };
selector sel_in { direction inbound; dst "$HI"; src "$PTC32"; policy_index pol; };
policy pol { action auto_ipsec; remote_index i_init; ipsec_mode tunnel; ipsec_index { ipsec_e; };
	ipsec_level require; };
ipsec ipsec_e { ipsec_sa_lifetime_time 3600 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }; };
EOF

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_A" "$SPMIF_I" "$SPMIF_C" "$SOCK_A" "$SOCK_I" "$SOCK_C"

	for NS in "$NSR" "$NSI" "$NSC" "$NBH"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
		ip netns exec "$NS" ip xfrm state flush 2>/dev/null || true
		ip netns exec "$NS" ip xfrm policy flush 2>/dev/null || true
	done
	ip netns exec "$NBH" ip link add br0 type bridge
	ip netns exec "$NBH" ip link set br0 up
	for spec in "$NSR:$VBA:$VLA:$HR" "$NSI:$VBI:$VLI:$HI" "$NSC:$VBC:$VLC:$CID"; do
		_NS=${spec%%:*}; rest=${spec#*:}; _HUB=${rest%%:*}; rest=${rest#*:}
		_SEAT=${rest%%:*}; _ADDR=${rest#*:}
		ip link add "$_HUB" type veth peer name "$_SEAT"
		ip link set "$_HUB" netns "$NBH"
		ip netns exec "$NBH" ip link set "$_HUB" master br0
		ip netns exec "$NBH" ip link set "$_HUB" up
		ip link set "$_SEAT" netns "$_NS"
		ip netns exec "$_NS" ip link set "$_SEAT" up
		ip netns exec "$_NS" ip addr add "$_ADDR/24" dev "$_SEAT"
	done
	# (No protected-net lo/route scaffolding: the /32 child selector below
	# needs no backing interface, and this row does not move data.)

	# IKE/UDP-XFRM allow per seat (each seat reaches every other on /24).
	for ns in "$NSR:$HR" "$NSI:$HI" "$NSC:$CID"; do
		NSX=${ns%%:*}; LX=${ns#*:}
		for p in 500 4500; do
			for x in "$HR" "$HI" "$CID"; do
				[ "$x" = "$LX" ] && continue
				ip netns exec "$NSX" ip xfrm policy add src "$x"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
				ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$x"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
			done
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/a.conf" ) >"$D/a-spmd.log" 2>&1 &
	ASPMD=$!
	i=0; until [ -S "$SPMIF_A" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_A" RACOON2_RESUME_DIR="$PRIVRES_A" \
	    "$SBIN/iked" -F -f "$C/a.conf" -D 0x0001 -l "$D/a-iked.log" ) >"$D/a-iked.out" 2>&1 &
	( ip netns exec "$NSC" "$SBIN/spmd" -F -f "$C/c.conf" ) >"$D/c-spmd.log" 2>&1 &
	CSPMD=$!
	i=0; until [ -S "$SPMIF_C" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSC" env RACOON2_ADMIN_SOCK="$SOCK_C" RACOON2_RESUME_DIR="$PRIVRES_C" \
	    "$SBIN/iked" -F -f "$C/c.conf" -D 0x0001 -l "$D/c-iked.log" ) >"$D/c-iked.out" 2>&1 &
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/i.conf" ) >"$D/i-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/i.conf" -D 0x0001 -l "$D/i-iked.log" ) >"$D/i-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0; i=0
	while [ "$i" -lt 45 ]; do
		ae=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${ae:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "redirect2 I->A up: A esp=$ae I esp=$ie after ${i}s"
			up=1; break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$up" -eq 1 ] || { log "FAIL: I->A not established (A esp=${ae:-0} I esp=${ie:-0})"; return 1; }

	A_BEFORE=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	"$SBIN/ikedctl" -s "$SOCK_A" drain-sa "$HI" "$DGW" >"$D/drain.out" 2>&1
	log "drain-sa exit=$? (out: $(cat "$D/drain.out" 2>/dev/null | tr '\n' ' '))"
	i=0; closed=0
	[ -f "$D/a-iked.log" ] || touch "$D/a-iked.log"
	while [ "$i" -lt 15 ]; do
		if grep -q "aborting ike_sa" "$D/a-iked.log" 2>/dev/null; then closed=1; break; fi
		i=$((i+1)); sleep 1
	done
	sleep 2
	A_AFTER=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	[ "$A_BEFORE" -ge 2 ] || { log "FAIL: pre-drain A esp=$A_BEFORE"; return 1; }
	[ "$A_AFTER" -eq 0 ] || { log "FAIL: drain did not close established SA (A esp $A_BEFORE -> $A_AFTER)"; return 1; }
	[ "$closed" -eq 1 ] || { log "FAIL: drain did not abort the established IKE_SA ('aborting ike_sa' missing)"; return 1; }
	log "drain-sa SET: A established SA silently closed (abort) + A esp $A_BEFORE -> $A_AFTER"

	"$SBIN/ikedctl" -s "$SOCK_I" flush-sa isakmp >/dev/null 2>&1 || true
	sleep 1
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	i=0; followed=0
	[ -f "$D/i-iked.log" ] || touch "$D/i-iked.log"
	while [ "$i" -lt 20 ]; do
		if grep -E "${DGW}\[500\].*INI_IKE_SA_INIT_SENT" "$D/i-iked.log" 2>/dev/null; then
			followed=1; break
		fi
		i=$((i+1)); sleep 1
	done

	cup=0; i=0
	while [ "$i" -lt 45 ]; do
		ce=$(ip netns exec "$NSC" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		# the initiator's child SA must point at the LIVE sibling (dst C),
		# not back at the draining A — esp-count alone would pass a stale
		# initiator SAD if a flush-sa had failed to prune it.  `ip xfrm
		# state` is one line per direction: outbound `src $HI dst $CID`
		# proves the child lands on C; assert that AND that no `dst $HR`
		# (A) pair remains.
		idstC=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c "dst $CID")
		idstA=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c "dst $HR")
		if [ "${ce:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ] && [ "${idstC:-0}" -ge 1 ] && [ "${idstA:-0}" -eq 0 ]; then
			log "redirect2 child UP on sibling C: C esp=$ce I esp=$ie (I child dst=$CID, no dst=$HR) after ${i}s"
			cup=1; break
		fi
		i=$((i+1)); sleep 1
	done
	A_FINAL=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')

	[ "$followed" -eq 1 ] || { log "FAIL: I never re-drove IKE_SA_INIT to the redirect target C ($DGW)"; return 1; }
	[ "$cup" -eq 1 ] || { log "FAIL: sibling C did not complete the redirected session (C esp=${ce:-0} I esp=${ie:-0})"; return 1; }
	[ "$A_FINAL" -eq 0 ] || { log "FAIL: client re-established against the draining A (A esp=$A_FINAL)"; return 1; }

	# Data plane: the child SAs are keyed (C esp>=2, I esp>=2) and the
	# initiator's wire re-target to C is asserted above.  There is NO SPD
	# policy row for this child (spmd_pfkey refuses a tunnel install without
	# my_sa_ipaddr — the same unpin that follows the redirect), so no
	# data-plane traversal is possible, which is out of scope for this
	# failover-landing proof — the xfrm audit's traffic check is
	# XFAIL-declared for this row for exactly that reason.  Landing + wire
	# re-target are the gates.

	log "redirect2 live proof OK: A drained+closed, I's new IKE_SA_INIT redirected to LIVE sibling C, C completed full IKE_AUTH + child up, A stayed at 0"
	echo ok > "$D/redirect2.gate"

	kill "$ASPMD" "$ISPMD" "$CSPMD" 2>/dev/null || true
	pkill -9 -f "$C/" 2>/dev/null || true
	for NS in "$NSR" "$NSI" "$NSC" "$NBH"; do ip netns del "$NS" 2>/dev/null || true; done

	[ -f "$D/redirect2.gate" ] || { log "FAIL: redirect2 proof incomplete"; return 1; }
	return 0
}
