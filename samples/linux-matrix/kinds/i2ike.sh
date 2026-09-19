#!/bin/sh
# kinds/i2ike.sh — PQC ADDKE case: iked<->iked on 192.0.4.x, each in its OWN
# netns on a P2P veth (separate socket+XFRM stack), so the case is fully
# self-contained and systemd-free — the only kind that runs the RFC 9370
# ADDKE path end-to-end (strongSwan charon has no ML-KEM to peer with).
# Gate: run.sh only dispatches this case when ADDKE is available (gate=addke,
# R2_ADDKE=yes / xfrm-addke build), so it runs on Fedora 44 (OpenSSL 3.5) and
# skips on an OpenSSL 3.0 Ubuntu build.
kind_i2ike() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2ike-r; NSI=i2ike-i; VR=i2v-r; VI=i2v-i
	HR=192.0.4.1; HI=192.0.4.2
	PRIVRES=/tmp/r2-i2ike-resume
	D=/tmp/r2-i2ike; C=/tmp/r2-i2ike-conf
	rm -rf "$PRIVRES" "$D" "$C"; mkdir -p "$PRIVRES" "$D" "$C"

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
	ipsec_sa_lifetime_time 60 sec;
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
	ipsec_sa_lifetime_time 60 sec;
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
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ike-r RACOON2_RESUME_DIR="$PRIVRES" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2ike-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ike-i RACOON2_RESUME_DIR="$PRIVRES" \
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

	# INIT SA is up.  Now exercise the CREATE_CHILD child-SA rekey (ADDKE):
	# the 60s ipsec lifetime soft boundary fires a child rekey shortly after
	# init, so assert a NEW ESP SPI (init-child SPI replaced) on BOTH netnss.
	spi(){ ip netns exec "$1" ip xfrm state 2>/dev/null | grep -oE 'spi 0x[0-9a-f]+' | sort; }
	SR0=$(spi "$NSR"); SI0=$(spi "$NSI")
	rekeyed=0; i=0
	while [ "$i" -lt 120 ]; do
		SRn=$(spi "$NSR"); SIn=$(spi "$NSI")
		nr=$(comm -13 <(printf '%s\n' "$SR0") <(printf '%s\n' "$SRn") | grep -c spi)
		ni=$(comm -13 <(printf '%s\n' "$SI0") <(printf '%s\n' "$SIn") | grep -c spi)
		if [ "${nr:-0}" -ge 1 ] && [ "${ni:-0}" -ge 1 ]; then
			log "INIT SA -> child-SA rekey: new SPI both sides at ${i}s (old: $(echo $SR0 | tr '\n' ' '))"
			rekeyed=1; break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$rekeyed" -eq 1 ] || log "FAIL: child-SA rekey not seen in 120s; resp SPIs now: $(spi "$NSR" | tr '\n' ' ')"

	# PQC proof — a NEW SPI alone is not ML-KEM (a plain rekey passes that).
	# The initiator-side rekey must have (a) offered type-06 ADDKE (0x24 =
	# mlkem768) in its CREATE_CHILD SA, (b) started an IKE_FOLLOWUP_KE, and
	# (c) NOT aborted the pending rekey child to a followup timeout.  The
	# first (classical) child's expected responder-driven 'installing plain
	# child' downgrade is NOT a failure; only the peer-offered-ADDKE rekey
	# abort means the ML-KEM completion was not achieved.
	t6=$(grep -c '06000024' "$D/init-iked.log" 2>/dev/null || true)
	fup=$(grep -ciE 'IKE_FOLLOWUP_KE' "$D/init-iked.log" 2>/dev/null || true)
	abt=$(grep -cE 'ADDKE followup timeout; abort' "$D/resp-iked.log" 2>/dev/null || true)
	pqc=0
	if [ "${t6:-0}" -ge 1 ] && [ "${fup:-0}" -ge 1 ] && [ "${abt:-0}" -eq 0 ]; then
		pqc=1
		log "PQC rekey: type-6 offered (x$t6), FOLLOWUP_KE started (x$fup), no followup abort"
	else
		log "FAIL: rekey not ADDKE/ML-KEM (type6=$t6 followup=$fup abort=$abt)"
	fi

	# kill daemons by the unique per-run conf dir (it IS in their argv);
	# a pkill on the conf-internal remote name matches nothing and leaks
	# up to 4 daemons holding the netns.
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES"

	if [ "$up" -ne 1 ] || [ "${rekeyed:-0}" -ne 1 ] || [ "${pqc:-0}" -ne 1 ]; then
		log "FAIL: PQC init-SA + child-SA rekey incomplete (up=${up:-0} rekeyed=${rekeyed:-0} pqc=${pqc:-0})"
		log "--- init-iked.log (followup/ESTABLISHED) ---"
		sed -n 's/.*\(ESTABLISHED\|FOLLOWUP\|ADDKE\|abort\|err=\|GETSPI\).*/\1: &/p' \
			"$D/init-iked.log" 2>/dev/null | tail -6
		log "--- resp-iked.log (fragment/reassemble/install) ---"
		sed -n 's/.*\(ESTABLISHED\|FOLLOWUP\|ADDKE\|install\|abort\|err=\).*/\1: &/p' \
			"$D/resp-iked.log" 2>/dev/null | tail -6
		return 1
	fi
	return 0
}
