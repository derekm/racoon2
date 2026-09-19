#!/bin/sh
# kinds/i2ike.sh — PQC ADDKE case: iked<->iked on 192.0.4.x, each in its OWN
# netns on a P2P veth (separate socket+XFRM stack), so the case is fully
# self-contained and systemd-free — the only kind that runs the RFC 9370
# ADDKE path end-to-end (strongSwan charon has no ML-KEM to peer with).
# Gate: run.sh only dispatches this case when ADDKE is available (gate=addke,
# R2_ADDKE=yes / xfrm-addke build), so it runs on Fedora 44 (OpenSSL 3.5) and
# skips on an OpenSSL 3.0 Ubuntu build.
kind_i2ikesa() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2ike-r; NSI=i2ike-i; VR=i2v-r; VI=i2v-i
	HR=192.0.4.1; HI=192.0.4.2
	PRIVRES_R=/tmp/r2-i2ike-resume-r; PRIVRES_I=/tmp/r2-i2ike-resume-i
	D=/tmp/r2-i2ike; C=/tmp/r2-i2ike-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2ike-r"; };
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
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		dpd_delay 60 sec;
		addke_unrequested on;
		kmp_sa_lifetime_time 30 sec;
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
	spmd { unix "/tmp/spmif-i2ike-i"; };
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
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		dpd_delay 60 sec;
		addke_unrequested on;
		kmp_sa_lifetime_time 30 sec;
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

	# kill daemons by the unique per-run conf dir (it IS in their argv);
	# a pkill on the conf-internal remote name matches nothing and leaks
	# up to 4 daemons holding the netns.
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2ike-r /tmp/spmif-i2ike-i /tmp/iked.sock-i2ike-r /tmp/iked.sock-i2ike-i

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

	# UDP-allow rows BEFORE any spmd (first-in-bucket at prio 0) so IKE is
	# not captured by the auto_ipsec tunnel input policy (XfrmInNoStates).
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S /tmp/spmif-i2ike-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ike-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2ike-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ike-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2ike-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "PQC ADDKE child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done

	# INIT SA is up.  Now the IKE_SA rekey: kmp_sa_lifetime_time 30s fires
	# ikev2_rekey_ikesa_initiate on the initiator, which offers type-6 ADDKE
	# on its IKE_SA-rekey CREATE_CHILD; the responder parks and both sides
	# complete SK(1) via IKE_FOLLOWUP_KE.  rekey_skeyseed logs
	#   IKE_SA rekey ADDKE SK(1) N bytes: SKEYSEED=<hex>
	# IDENTICALLY on both sides (they share old SK_d, g_ir, Ni, Nr, SK(1)).
	# Assert the ADDKE IKE_SA rekey completed and both derived the same
	# SKEYSEED; a plain (non-ADDKE) IKE_SA rekey logs no such line -> fail.
	ikesa=0; i=0
	while [ "$i" -lt 110 ]; do
		s_i=$(grep -c 'IKE_SA rekey ADDKE SK(1)' "$D/init-iked.log" 2>/dev/null || true)
		s_r=$(grep -c 'IKE_SA rekey ADDKE SK(1)' "$D/resp-iked.log" 2>/dev/null || true)
		if [ "${s_i:-0}" -ge 1 ] && [ "${s_r:-0}" -ge 1 ]; then
			log "IKE_SA rekey ADDKE completed on BOTH sides at ${i}s"
			ikesa=1; break
		fi
		i=$((i+1)); sleep 1
	done
	sk_i=$(grep -oE 'IKE_SA rekey ADDKE SK\(1\) [0-9]+ bytes: SKEYSEED=[0-9a-f]+' \
		"$D/init-iked.log" 2>/dev/null | grep -oE 'SKEYSEED=[0-9a-f]+' | tail -1)
	sk_r=$(grep -oE 'IKE_SA rekey ADDKE SK\(1\) [0-9]+ bytes: SKEYSEED=[0-9a-f]+' \
		"$D/resp-iked.log" 2>/dev/null | grep -oE 'SKEYSEED=[0-9a-f]+' | tail -1)
	pqc=0
	if [ "${ikesa:-0}" -eq 1 ] && [ -n "$sk_i" ] && [ "$sk_i" = "$sk_r" ]; then
		pqc=1
		log "IKE_SA rekey ADDKE: SK(1) fed, SKEYSEED=$sk_i matches BOTH sides"
	else
		log "FAIL: IKE_SA rekey not ADDKE/ML-KEM (ikesa=${ikesa:-0} sk_i=${sk_i:-none} sk_r=${sk_r:-none})"
	fi

	# kill daemons by the unique per-run conf dir (it IS in their argv);
	# a pkill on the conf-internal remote name matches nothing and leaks
	# up to 4 daemons holding the netns.
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$up" -ne 1 ] || [ "${ikesa:-0}" -ne 1 ] || [ "${pqc:-0}" -ne 1 ]; then
		log "FAIL: PQC init-SA + IKE_SA rekey ADDKE incomplete (up=${up:-0} ikesa=${ikesa:-0} pqc=${pqc:-0})"
		log "--- init-iked.log (IKE_SA rekey ADDKE) ---"
		grep -E 'IKE_SA rekey ADDKE|FOLLOWUP|PQC|abort|err=' \
			"$D/init-iked.log" 2>/dev/null | tail -6
		log "--- resp-iked.log (IKE_SA rekey ADDKE) ---"
		grep -E 'IKE_SA rekey ADDKE|FOLLOWUP|ADDKE|abort|err=' \
			"$D/resp-iked.log" 2>/dev/null | tail -6
		return 1
	fi
	return 0
}
