#!/bin/sh
# kinds/i2ikesa.sh — PQC ADDKE IKE_SA-rekey case: iked<->iked on 192.0.4.x,
# each in its OWN netns on a P2P veth (separate socket+XFRM stack), so the
# case is fully self-contained and systemd-free — the only kind that runs the
# RFC 9370 ADDKE path end-to-end (strongSwan charon has no ML-KEM to peer
# with).  NOTE: every resource name here (netns, veth, sockets, resume dirs,
# conf dir) is UNIQUE to this kind — i2ike.sh must never share them, or a
# lingering i2ike daemon/netns in the same runner (e.g. a container after the
# previous case's pkill -9) leaks xfrm state into this case and IKE_SA rekey
# silently never fires (route through the stale SAs instead).
# Gate: run.sh only dispatches this case when ADDKE is available (gate=addke,
# R2_ADDKE=yes / xfrm-addke build), so it runs on Fedora 44 (OpenSSL 3.5) and
# skips on an OpenSSL 3.0 Ubuntu build.
kind_i2ikesa() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2ikesa-r; NSI=i2ikesa-i; VR=i2kesa-v-r; VI=i2kesa-v-i
	HR=192.0.4.1; HI=192.0.4.2
	PRIVRES_R=/tmp/r2-i2ikesa-resume-r; PRIVRES_I=/tmp/r2-i2ikesa-resume-i
	D=/tmp/r2-i2ikesa; C=/tmp/r2-i2ikesa-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2ikesa-r"; };
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
	spmd { unix "/tmp/spmif-i2ikesa-i"; };
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
	rm -f /tmp/spmif-i2ikesa-r /tmp/spmif-i2ikesa-i /tmp/iked.sock-i2ikesa-r /tmp/iked.sock-i2ikesa-i

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
	i=0; until [ -S /tmp/spmif-i2ikesa-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ikesa-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2ikesa-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ikesa-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2ikesa-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

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
	# complete SK(1) (via IKE_INTERMEDIATE on the fresh rekeyed SA, or the
	# older IKE_FOLLOWUP_KE).  The actual key match is proven by AUTH+IntAuth
	# verifying (the child stays up); the raw SKEYSEED/IntAuth bytes are
	# deliberately NOT logged.  A plain (non-ADDKE) IKE_SA rekey logs no
	# round-complete marker -> fail.
	ikesa=0; i=0
	while [ "$i" -lt 110 ]; do
		s_i=$(grep -cE 'IKE_INTERMEDIATE ADDKE round complete|IKE_SA rekey ADDKE SK\(1\)' "$D/init-iked.log" 2>/dev/null || true)
		s_r=$(grep -cE 'IKE_INTERMEDIATE ADDKE round complete|IKE_SA rekey ADDKE SK\(1\)' "$D/resp-iked.log" 2>/dev/null || true)
		if [ "${s_i:-0}" -ge 1 ] && [ "${s_r:-0}" -ge 1 ]; then
			log "IKE_SA rekey ADDKE completed on BOTH sides at ${i}s"
			ikesa=1; break
		fi
		i=$((i+1)); sleep 1
	done
	# The rekeyed IKE_SA's SK(1) matched because AUTH+IntAuth verified and the
	# child stayed up (up=1 is checked separately).  Raw SKEYSEED/IntAuth bytes
	# are intentionally not logged; the round marker on both sides is the proof.
	pqc=0
	if [ "${ikesa:-0}" -eq 1 ]; then
		pqc=1
		log "IKE_SA rekey ADDKE: round on BOTH sides, child stays up => SK(1) key material matched"
	else
		log "FAIL: IKE_SA rekey not ADDKE/ML-KEM (ikesa=${ikesa:-0})"
	fi

	# Rekey teardown — MUST actually run the old-SA dispose path, or the
	# test proves nothing.  The initiator's rekey-done tail starts a wire
	# DELETE IKE_SA for the old SA (ikev2_rekey.c rekey_done ->
	# ikev2_sa_delete); the responder's ikev2_process_delete then aborts
	# the old SA (DYING -> DEAD) and the periodic reaper disposes it.
	# Regression: the responder ADDKE completion used to leave
	# old_sa->new_sa pointing at the LIVE rekeyed SA, so that dispose
	# recursed (ike_sa.c:1058) into an SA that owns children and
	# asserted -> SIGABRT -> data plane died mid-session (seen with iOS
	# at the IKE_SA rekey).  So: first prove the DELETE actually reached
	# the responder (path exercised), then settle past the exchange +
	# reaper ticks and prove both daemons are still alive, no assertion
	# in stderr files either, and the adopted child SA is still up.
	sleep 20
	crash=0
	akill=0
	del=0
	for L in "$D/resp-iked.log" "$D/init-iked.log"; do
		for F in "$L" "${L%.log}.out"; do
			if grep -q 'Assertion.*failed' "$F" 2>/dev/null; then
				log "FAIL: assertion crash in $F: $(grep -m1 'Assertion.*failed' "$F")"
				crash=1
			fi
		done
	done
	grep -q 'received DELETE IKE_SA' "$D/resp-iked.log" 2>/dev/null || {
		log "FAIL: responder never received DELETE IKE_SA (old-SA dispose path not exercised)"
		del=1
	}
	alive_r=0
	if ! command -v pgrep >/dev/null 2>&1 || ! command -v pkill >/dev/null 2>&1; then
		# fedora:44 container images do not ship procps-ng; without pgrep
		# the alive gate below would silently read 0 (command-not-found
		# swallowed by 2>/dev/null) and FAIL a live teardown, and the
		# case-end pkill would no-op, leaking daemons into the next case.
		# Fail loudly instead of mistaking a missing tool for dead daemons.
		log "FAIL: pgrep/pkill not installed (procps-ng) — teardown-alive gate cannot run"
		akill=1
	else
	alive_r=$(pgrep -f "$C/" 2>/dev/null | wc -l)
	[ "${alive_r:-0}" -ge 4 ] || { log "FAIL: daemons died after IKE_SA rekey teardown (alive=$alive_r)"; akill=1; }
	# ESP state count is on the REKEYED IKE_SA now: if the responder
	# seeded its child only to the old (deleted) IKE_SA, the states
	# vanish and the data plane is dead even though IKE is up.
	re2=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	ie2=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	if [ "${re2:-0}" -lt 2 ] || [ "${ie2:-0}" -lt 2 ]; then
		log "FAIL: ESP states lost after IKE_SA rekey teardown (resp=$re2 init=$ie2)"
		akill=1
	fi
	fi
	if [ "${crash:-0}" -eq 0 ] && [ "${akill:-0}" -eq 0 ] && [ "${del:-0}" -eq 0 ]; then
		log "IKE_SA rekey teardown clean: DELETE received, old SA disposed, daemons alive, ESP resp=$re2 init=$ie2"
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

	if [ "$up" -ne 1 ] || [ "${ikesa:-0}" -ne 1 ] || [ "${pqc:-0}" -ne 1 ] \
	   || [ "${crash:-0}" -ne 0 ] || [ "${akill:-0}" -ne 0 ] || [ "${del:-0}" -ne 0 ]; then
		log "FAIL: PQC init-SA + IKE_SA rekey ADDKE incomplete (up=${up:-0} ikesa=${ikesa:-0} pqc=${pqc:-0} crash=${crash:-0} akill=${akill:-0} del=${del:-0})"
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
