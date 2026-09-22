#!/bin/sh
# kinds/i2iinit-drop.sh — H1 kill-test: netem LOSS on the responder->initiator
# veth during the IKE_INTERMEDIATE exchange.  With 100% loss for a bounded
# window, the responder advanced to gen-1 keys when it answered the
# intermediate request, so the READER's retransmitted gen-0 intermediate
# request fails ICV against the CURRENT (gen-1) keys.  The SA must recover by
# the responder replaying its cached response against the RETAINED gen-0 keys
# (ikev2_check_icv_prev_gen / H1) instead of dropping the retransmit and
# dying on one lost reply.  Gate: only the child comes up (up+round marker);
# the responder log "replayed: ICV ok against PREVIOUS gen" is the H1 proof
# target, logged as diagnostic.
kind_i2iinit_drop() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2idrop-r; NSI=i2idrop-i; VR=i2iv-r; VI=i2iv-i
	HR=192.0.6.1; HI=192.0.6.2
	PRIVRES_R=/tmp/r2-i2idrop-resume-r; PRIVRES_I=/tmp/r2-i2idrop-resume-i
	D=/tmp/r2-i2idrop; C=/tmp/r2-i2idrop-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2idrop-r"; };
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
	esp_addke_alg { mlkem768; };
};
EOF
	cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "/tmp/spmif-i2idrop-i"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_init {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive off;
		my_id fqdn "r2init-matrix";
		peers_id fqdn "racoon2-matrix";
		peers_ipaddr "$HR";
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
	esp_addke_alg { mlkem768; };
};
EOF

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2idrop-r /tmp/spmif-i2idrop-i /tmp/iked.sock-i2idrop-r /tmp/iked.sock-i2idrop-i

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

	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S /tmp/spmif-i2idrop-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2idrop-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2idrop-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2idrop-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2

	# netem LOSS window on responder->initiator (egress of responder veth):
	# drop ALL replies for the first ~1.2s of the exchange.  IkED retransmits
	# its requests; the responder already advanced to gen-1 when it answered
	# the intermediate request, so the retransmitted gen-0 intermediate
	# request must be replayed from cache via the retained gen-0 keys (H1).
	if ! ip netns exec "$NSR" tc qdisc add dev "$VR" root netem loss 100% 2>/dev/null; then
		log "FAIL: cannot add netem loss on $NSR/$VR (no tc?); abort"
		pkill -9 -f "$C/" 2>/dev/null || true
		return 1
	fi

	"$SBIN/ikedctl" -s /tmp/iked.sock-i2idrop-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	# hold the loss exactly one IKE retransmit period, then restore
	sleep 1.2
	ip netns exec "$NSR" tc qdisc del dev "$VR" root 2>/dev/null || true

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "H1 KILL-TEST: child UP after responder->initiator loss window (responder esp=$re initiator esp=$ie after ${i}s)"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done

	# H1 proof target (diagnostic): the retransmitted gen-0 intermediate
	# request was ICV-validated against the retained gen-0 keys and the
	# cached response replayed, instead of the SA dying.
	nint=0; nprev=0
	n_i=$(grep -c 'IKE_INTERMEDIATE ADDKE round complete' "$D/init-iked.log" 2>/dev/null || true)
	n_r=$(grep -c 'IKE_INTERMEDIATE ADDKE round complete' "$D/resp-iked.log" 2>/dev/null || true)
	nprev=$(grep -c 'ICV ok against PREVIOUS gen' "$D/resp-iked.log" 2>/dev/null || true)
	if [ "${n_i:-0}" -ge 1 ] && [ "${n_r:-0}" -ge 1 ]; then
		nint=1
		log "IKE_INTERMEDIATE round completed on BOTH sides (init=$n_i resp=$n_r); H1 prev-gen replay marker=$nprev"
	else
		log "FAIL: no IKE_INTERMEDIATE round on both sides (init=$n_i resp=$n_r)"
	fi

	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$up" -ne 1 ] || [ "${nint:-0}" -ne 1 ]; then
		log "FAIL: H1 kill-test did not recover (up=${up:-0} nint=${nint:-0})"
		log "--- init-iked.log ---"
		grep -E 'IKE_INTERMEDIATE|IKE_SA_INIT|IKE_AUTH|abort|err=|FOLLOWUP' \
			"$D/init-iked.log" 2>/dev/null | tail -10
		log "--- resp-iked.log ---"
		grep -E 'IKE_INTERMEDIATE|IKE_SA_INIT|IKE_AUTH|abort|err=|FOLLOWUP|PREVIOUS gen' \
			"$D/resp-iked.log" 2>/dev/null | tail -10
		return 1
	fi
	return 0
}
