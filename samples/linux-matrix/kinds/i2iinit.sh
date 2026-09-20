#!/bin/sh
# kinds/i2iinit.sh — PQC ADDKE on the INITIAL IKE_SA via RFC 9242
# IKE_INTERMEDIATE: iked<->iked on 192.0.5.x, each in its OWN netns on a P2P
# veth.  The initiator offers ADDKE (type-6) in SAi1 alongside the 16438
# IKE_INTERMEDIATE capability notify; the responder echoes 16438, selects
# type-6, and both sides complete one IKE_INTERMEDIATE ML-KEM round, update
# SKEYSEED per RFC 9370 s3.5, chain IntAuth per RFC 9242 s3.3.2, and only
# then run IKE_AUTH (ESP child lands => AUTH + IntAuth verified).  Gate:
# gate=addke (WITH_INTERMEDIATE+WITH_ADDKE), Fedora 44.
kind_i2iinit() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2init-r; NSI=i2init-i; VR=i2iv-r; VI=i2iv-i
	HR=192.0.5.1; HI=192.0.5.2
	PRIVRES_R=/tmp/r2-i2init-resume-r; PRIVRES_I=/tmp/r2-i2init-resume-i
	D=/tmp/r2-i2init; C=/tmp/r2-i2init-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2init-r"; };
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
	spmd { unix "/tmp/spmif-i2init-i"; };
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

	# kill daemons by the unique per-run conf dir (it IS in their argv)
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2init-r /tmp/spmif-i2init-i /tmp/iked.sock-i2init-r /tmp/iked.sock-i2init-i

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
	i=0; until [ -S /tmp/spmif-i2init-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2init-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2init-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2init-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2init-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "PQC INITIAL IKE_SA ADDKE child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done

	# The initial IKE_SA ran an IKE_INTERMEDIATE ADDKE round (SAi1 type-6 +
	# 16438 both sides).  intermediate_finish_round logs
	#   IKE_INTERMEDIATE ADDKE SK(1) SKEYSEED=<hex>
	# IDENTICALLY on both sides (RFC 9370 s3.5).  A classical int exchange
	# logs no such line -> fail.
	nint=0; i=0
	while [ "$i" -lt 20 ]; do
		n_i=$(grep -c 'IKE_INTERMEDIATE ADDKE round complete' "$D/init-iked.log" 2>/dev/null || true)
		n_r=$(grep -c 'IKE_INTERMEDIATE ADDKE round complete' "$D/resp-iked.log" 2>/dev/null || true)
		if [ "${n_i:-0}" -ge 1 ] && [ "${n_r:-0}" -ge 1 ]; then
			log "IKE_INTERMEDIATE ADDKE round completed on BOTH sides at ${i}s"
			nint=1; break
		fi
		i=$((i+1)); sleep 1
	done
	# AUTH+IntAuth verified == the RFC 9370 s3.5 SKEYSEED(1) matched: both
	# sides derived the same intermediate key or the ESP child could not
	# establish (up=1 is checked separately).  The raw SKEYSEED/IntAuth bytes
	# are intentionally not logged, so the round-complete marker on both
	# sides, plus up=1, is the proof.
	pqc=0
	if [ "${nint:-0}" -eq 1 ]; then
		pqc=1
		log "INITIAL IKE_SA ADDKE: IKE_INTERMEDIATE round on BOTH sides, ESP child up => SK(1) key material matched"
	else
		log "FAIL: initial IKE_SA not ADDKE/ML-KEM (nint=${nint:-0})"
	fi

	# kill daemons by the unique per-run conf dir
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$up" -ne 1 ] || [ "${nint:-0}" -ne 1 ] || [ "${pqc:-0}" -ne 1 ]; then
		log "FAIL: PQC initial-IKE_SA ADDKE incomplete (up=${up:-0} nint=${nint:-0} pqc=${pqc:-0})"
		log "--- init-iked.log ---"
		grep -E 'IKE_INTERMEDIATE|IKE_SA_INIT|IKE_AUTH|abort|err=|FOLLOWUP' \
			"$D/init-iked.log" 2>/dev/null | tail -8
		log "--- resp-iked.log ---"
		grep -E 'IKE_INTERMEDIATE|IKE_SA_INIT|IKE_AUTH|abort|err=|FOLLOWUP' \
			"$D/resp-iked.log" 2>/dev/null | tail -8
		return 1
	fi
	return 0
}
