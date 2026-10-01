#!/bin/sh
# kinds/i2i_neg.sh — NDcPP NEG rows for FCS_IPSEC_EXT.1 on the i2i topology
# (two netnss, P2P veth, iked<->iked).  A NEG row PASSES when the TOE
# CORRECTLY REFUSES the mis-configured exchange, and FAILS when it accepts
# it (fail-closed violation):
#
#   i2ineg-wrongpsk    A13 NEG (peer auth): responder holds the matrix PSK,
#                      initiator is pointed at a DIFFERENT existing psk file
#                      (l2tp.psk) — same fqdn ids, wrong key.  Refusal =
#                      no ESP child AND iked logs 'authentication failure'
#                      / AUTHENTICATION_FAILED on the responder.
#   i2ineg-idmismatch  A14 NEG (identifier): responder expects peers_id
#                      'r2init-matrix' but the initiator presents a foreign
#                      my_id.  Refusal = no ESP child AND 'received ID_I
#                      ... does not match peers id' on the responder.
#   i2ineg-a12strict   A12 STRICT (NDcPP FCS_IPSEC_EXT.1.12): same PSK and
#                      ids, but the child offers 256-bit AES-GCM under a
#                      128-bit IKE_SA and parent_child_strength is ON.
#                      Refusal = no ESP child AND 'CHILD_SA encr strength
#                      256 bits exceeds parent IKE_SA strength 128 bits'.
#   i2ineg-a12permit   A12 RFC-PERMISSIVE (knob OFF): same stronger-child
#                      offer; RFC 7296 allows it, so the exchange MUST
#                      establish a child.  PASS = ESP child present in both
#                      netnss AND no parent_child_strength refusal logged.
#
# The gate is inverted from the positive kinds ONLY for reject-expecting
# rows: this kind returns 0 for i2ineg-* when the exchange was REFUSED,
# and for i2ineg-a12permit when it was ACCEPTED.  Setup/cleanup mirror
# i2iinit.sh but with distinct netns/socket/resume names (copied-kind rule).
kind_i2i_neg() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }

	# per-case knobs: EXPECT (refuse|accept), PSK_I, MYID_I,
	# CHILD_K (child enc keylen, BITS — conf keylen grammar is `alg, bits`),
	# STRENGTH_ON (bool)
	case "$name" in
	i2ineg-wrongpsk)
		EXPECT=refuse
		PSK_I="$ETC/psk/l2tp.psk"   # DIFFERENT key than the responder's
		MYID_I='fqdn "r2init-matrix"'
		CHILD_K=16; STRENGTH_ON=no ;;
	i2ineg-idmismatch)
		EXPECT=refuse
		PSK_I="$ETC/psk/macos.psk"  # same key, foreign identity
		MYID_I='fqdn "neg-intruder"'
		CHILD_K=16; STRENGTH_ON=no ;;
	i2ineg-a12strict)
		EXPECT=refuse
		PSK_I="$ETC/psk/macos.psk"  # same key, same ids — strength is the probe
		MYID_I='fqdn "r2init-matrix"'
		CHILD_K=256; STRENGTH_ON=yes ;;
	i2ineg-a12permit)
		EXPECT=accept
		PSK_I="$ETC/psk/macos.psk"
		MYID_I='fqdn "r2init-matrix"'
		CHILD_K=256; STRENGTH_ON=no ;;
	*)
		log "FAIL: unknown NEG case $name"
		return 1 ;;
	esac
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	[ -f "$PSK_I" ] || { log "FAIL: no $PSK_I for case $name"; return 1; }
	[ "$CHILD_K" = 16 ] || [ "$CHILD_K" = 256 ] || { log "FAIL: bad CHILD_K=$CHILD_K"; return 1; }

	# parent_child_strength line for the ikev2 blocks (empty when off)
	if [ "$STRENGTH_ON" = yes ]; then
		STRENGTH_LINE="parent_child_strength on;"   # → NO_PROPOSAL_CHOSEN for a stronger child
	else
		STRENGTH_LINE=""                             # RFC 7296 permissive default
	fi

	row_ns "$name"
	HR=192.0.7.1; HI=192.0.7.2
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "$SPMIF_R"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_resp {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "racoon2-matrix";
		peers_id fqdn "r2init-matrix";
		peers_ipaddr "$HI";
		$STRENGTH_LINE
		kmp_enc_alg { aes_gcm; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "$HR"; dst "$HI";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "$HR"; src "$HI";
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_resp;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$HI";
	my_sa_ipaddr "$HR";
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 300 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm, $CHILD_K; };
	esp_auth_alg { non_auth; };
};
EOF

cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "$SPMIF_I"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_init {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive off;
		my_id $MYID_I;
		peers_id fqdn "racoon2-matrix";
		peers_ipaddr "$HR";
		$STRENGTH_LINE
		kmp_enc_alg { aes_gcm; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$PSK_I";
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "$HI"; dst "$HR";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "$HI"; src "$HR";
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_init;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$HR";
	my_sa_ipaddr "$HI";
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 300 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm, $CHILD_K; };
	esp_auth_alg { non_auth; };
};
EOF

	# kill daemons by the unique per-run conf dir (it IS in their argv)
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"

	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"
	ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
	ip link set "$VI" netns "$NSI"
	ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"

	# UDP-allow rows BEFORE any spmd so IKE is not captured by the tunnel
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	# Refusals surface fast (IKE_AUTH round-trip); acceptance too.  Wait
	# up to ~30 s for the outcome to settle, then measure the gate.
	up=0
	i=0
	while [ "$i" -lt 30 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then up=1; break; fi
		i=$((i+1)); sleep 1
	done
	sleep 2

	re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	nochild=0
	[ "${re:-0}" -eq 0 ] && [ "${ie:-0}" -eq 0 ] && nochild=1

	# Refusal markers quoted from the real iked log (checked in order;
	# they are mutually exclusive across the cases above).
	marker=0
	marker_line=
	# A12 refuses pin the RESOLVED numbers (cbits=256 > pbits=128): a
	# mis-scaled strength (e.g. 32-vs-128) must NOT satisfy the strict
	# row.  The full log line is "CHILD_SA encr strength 256 bits
	# exceeds parent IKE_SA strength 128 bits; refusing".
	if grep -q "CHILD_SA encr strength" "$D/resp-iked.log" 2>/dev/null; then
		if [ "$STRENGTH_ON" = yes ]; then
			grep -q "CHILD_SA encr strength 256 bits exceeds parent IKE_SA strength 128 bits" "$D/resp-iked.log" 2>/dev/null && { marker=1; marker_line="CHILD_SA encr strength 256 bits exceeds parent IKE_SA strength 128 bits"; }
		else
			marker=1; marker_line="CHILD_SA encr strength"
		fi
	elif grep -q "authentication failure" "$D/resp-iked.log" 2>/dev/null; then
		marker=1; marker_line="authentication failure"
	elif grep -q "does not match peers id" "$D/resp-iked.log" 2>/dev/null; then
		marker=1; marker_line="does not match peers id"
	fi

	gote=0
	if [ "$EXPECT" = refuse ]; then
		[ "$nochild" -eq 1 ] && [ "$marker" -eq 1 ] && gote=1
	else
		# EXPECT=accept: child established AND no strength refusal
		[ "$up" -eq 1 ] && [ "$marker" -eq 0 ] && gote=1
	fi

	if [ "$gote" -eq 1 ]; then
		# the TOE behaved exactly as this row requires
		case "$name" in
		i2ineg-wrongpsk)
			printf 'CPL A13: PASS NEG wrong-psk: exchange refused (resp esp=%s init esp=%s); observed "%s" — TOE fails closed\\n' "${re:-0}" "${ie:-0}" "$marker_line" ;;
		i2ineg-idmismatch)
			printf 'CPL A14: PASS NEG id-mismatch: exchange refused (resp esp=%s init esp=%s); observed "%s" — TOE fails closed\\n' "${re:-0}" "${ie:-0}" "$marker_line" ;;
			i2ineg-a12strict)
				printf 'CPL A12: PASS STRICT parent>=child: 256-bit CHILD_SA under 128-bit IKE_SA refused (resp esp=%s init esp=%s); observed "%s" — TOE fails closed (parent_child_strength on, as the evaluated configuration enables per NDcPP app note 93)\\n' "${re:-0}" "${ie:-0}" "$marker_line" ;;
		i2ineg-a12permit)
			printf 'CPL A12: PASS RFC-permissive: 256-bit CHILD_SA under 128-bit IKE_SA ACCEPTED (resp esp=%s init esp=%s) as RFC 7296 allows when parent_child_strength is off\\n' "${re:-0}" "${ie:-0}" ;;
		esac
		log "PASS $name: TOE behaved as required ($EXPECT; nochild=$nochild marker=$marker up=$up '$marker_line')"
	else
		if [ "$EXPECT" = refuse ]; then
			if [ "$up" -eq 1 ]; then
				log "FAIL $name: TOE ACCEPTED the mis-config (esp up resp=${re} init=${ie}) — fail-closed violation"
			else
				log "FAIL $name: neither child nor refusal marker (nochild=$nochild marker=$marker) — inconclusive/hung"
			fi
		else
			if [ "$marker" -eq 1 ]; then
				log "FAIL $name: TOE refused a legal stronger child (marker='$marker_line') — RFC-permissive broken (false veto)"
			else
				log "FAIL $name: child did not establish under the legal offer (up=$up esp resp=${re} init=${ie})"
			fi
		fi
		log "--- resp-iked.log ---"
		grep -E 'IKE_SA_INIT|IKE_AUTH|authentication|peers id|AUTHENTICATION_FAILED|encr strength|abort|err=|ESTABLISHED|NO_PROPOSAL' \
			"$D/resp-iked.log" 2>/dev/null | tail -10
		log "--- init-iked.log ---"
		grep -E 'IKE_SA_INIT|IKE_AUTH|authentication|peers id|AUTHENTICATION_FAILED|encr strength|abort|err=|ESTABLISHED|NO_PROPOSAL' \
			"$D/init-iked.log" 2>/dev/null | tail -10
	fi

	# cleanup, mirroring i2iinit.sh
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	[ "$gote" -eq 1 ]
	return $?
}

