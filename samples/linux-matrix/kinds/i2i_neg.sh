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
#
# The gate is inverted from the positive kinds: this kind returns 0 only
# when the exchange was REFUSED.  Setup/cleanup mirror i2iinit.sh but with
# distinct netns/socket/resume names (copied-kind rule).
kind_i2i_neg() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	case "$name" in
	i2ineg-wrongpsk)
		PSK_I="$ETC/psk/l2tp.psk"   # DIFFERENT key than the responder's
		MYID_I='fqdn "r2init-matrix"' ;;
	i2ineg-idmismatch)
		PSK_I="$ETC/psk/macos.psk"  # same key, foreign identity
		MYID_I='fqdn "neg-intruder"' ;;
	*)
		log "FAIL: unknown NEG case $name"
		return 1 ;;
	esac
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	[ -f "$PSK_I" ] || { log "FAIL: no $PSK_I for case $name"; return 1; }

	NSR=i2neg-r; NSI=i2neg-i; VR=i2negr; VI=i2negi
	HR=192.0.7.1; HI=192.0.7.2
	PRIVRES_R=/tmp/r2-i2ineg-resume-r; PRIVRES_I=/tmp/r2-i2ineg-resume-i
	D=/tmp/r2-i2ineg; C=/tmp/r2-i2ineg-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2ineg-r"; };
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
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF

cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "/tmp/spmif-i2ineg-i"; };
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
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF

	# kill daemons by the unique per-run conf dir (it IS in their argv)
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2ineg-r /tmp/spmif-i2ineg-i /tmp/iked.sock-i2ineg-r /tmp/iked.sock-i2ineg-i

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
	i=0; until [ -S /tmp/spmif-i2ineg-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ineg-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2ineg-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ineg-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2ineg-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	# A refusal surfaces fast (IKE_AUTH round-trip).  Wait up to ~30 s for
	# the outcome to settle, then measure: NO ESP child may be left in
	# either netns (a child means the TOE accepted the bad config).
	up=0
	i=0
	while [ "$i" -lt 30 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then up=1; break; fi
		i=$((i+1)); sleep 1
	done
	sleep 2

	# NEG gate: refused == (no child) AND (refusal marker in the logs).
	re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	nochild=0
	[ "${re:-0}" -eq 0 ] && [ "${ie:-0}" -eq 0 ] && nochild=1

	marker=0
	marker_line=
	if grep -q "authentication failure" "$D/resp-iked.log" 2>/dev/null; then
		marker=1; marker_line="authentication failure"
	elif grep -q "does not match peers id" "$D/resp-iked.log" 2>/dev/null; then
		marker=1; marker_line="does not match peers id"
	fi

	refused=0
	[ "$nochild" -eq 1 ] && [ "$marker" -eq 1 ] && refused=1

	if [ "$refused" -eq 1 ]; then
		# refused exactly as failed-closed requires -> the NEG row PASSES
		if [ "$name" = i2ineg-wrongpsk ]; then
			printf 'CPL A13: PASS NEG wrong-psk: exchange refused (resp esp=%s init esp=%s); observed "%s" — TOE fails closed\n' "${re:-0}" "${ie:-0}" "$marker_line"
		else
			printf 'CPL A14: PASS NEG id-mismatch: exchange refused (resp esp=%s init esp=%s); observed "%s" — TOE fails closed\n' "${re:-0}" "${ie:-0}" "$marker_line"
		fi
		log "PASS $name: TOE refused the mis-configured exchange (nochild=$nochild marker=$marker '$marker_line')"
	else
		if [ "$up" -eq 1 ]; then
			log "FAIL $name: TOE ACCEPTED the mis-configured exchange (esp up resp=${re} init=${ie}) — fail-closed violation"
		else
			log "FAIL $name: no child AND no refusal marker (nochild=$nochild marker=$marker) — inconclusive/hung"
		fi
		log "--- resp-iked.log ---"
		grep -E 'IKE_SA_INIT|IKE_AUTH|authentication|peers id|AUTHENTICATION_FAILED|abort|err=|ESTABLISHED' \
			"$D/resp-iked.log" 2>/dev/null | tail -10
		log "--- init-iked.log ---"
		grep -E 'IKE_SA_INIT|IKE_AUTH|authentication|peers id|AUTHENTICATION_FAILED|abort|err=|ESTABLISHED' \
			"$D/init-iked.log" 2>/dev/null | tail -10
	fi

	# cleanup, mirroring i2iinit.sh
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	[ "$refused" -eq 1 ]
	return $?
}
