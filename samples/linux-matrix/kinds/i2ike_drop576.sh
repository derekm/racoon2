#!/bin/sh
# kinds/i2ike_drop576.sh — PQC CREATE_CHILD fragment-replay kill-test.
# iked<->iked on 192.0.9.x, own netns, veth MTU 576.  i2iinit-drop576 proves
# the IKE_INTERMEDIATE fragment path only.  This row is the CREATE_CHILD /
# IKE_FOLLOWUP_KE path: ML-KEM KEr is 1184B, so the response is RFC 7383
# SKF (3 datagrams).  Responder child lifetime is 3600s so only the
# initiator rekeys.  Loss is 80% on responder->initiator from just before
# the 60s soft rekey until the responder logs the fragmented FOLLOWUP
# path (response just went out under that loss), then 5% so the replayed
# fragments can land.  Holding 80% until the rekey completes cannot deliver
# 3 fragments (0.8% per send).  PASS requires R2 replay >= 1, netem-dropped
# >= 1, the fragmented-path log, matching ML-KEM keymat, and a new SPI.
kind_i2ike_drop576() {
	name=$1
	require_root || return 1
	require_procps || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2iked576-r; NSI=i2iked576-i; VR=i2v576r; VI=i2v576i
	HR=192.0.9.1; HI=192.0.9.2
	PRIVRES_R=/tmp/r2-i2iked576-resume-r; PRIVRES_I=/tmp/r2-i2iked576-resume-i
	D=/tmp/r2-i2iked576; C=/tmp/r2-i2iked576-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2iked576-r"; };
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
	# responder must NOT initiate its own rekey inside the loss window:
	# a simultaneous both-sides rekey steps on the initiator's retransmit
	# (recv window consumed, response_info overwritten -> "dropping
	# unordered" instead of replay).  Only the initiator rekeys (60s).
	ipsec_sa_lifetime_time 3600 sec;
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
	spmd { unix "/tmp/spmif-i2iked576-i"; };
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

	attempts=3
	pass_ok=0
	for attempt in $(seq 1 "$attempts"); do
		# kill daemons by the unique per-run conf dir (it IS in their argv);
		# a pkill on the conf-internal remote name matches nothing and leaks
		# up to 4 daemons holding the netns.
		pkill -9 -f "$C/" 2>/dev/null || true
		rm -f /tmp/spmif-i2iked576-r /tmp/spmif-i2iked576-i \
		      /tmp/iked.sock-i2iked576-r /tmp/iked.sock-i2iked576-i
		# Fresh IKE_SA and empty logs: a leftover 'fragmented path' or
		# 'R2 replay' line from the previous attempt would pass the gate
		# without exercising this attempt.
		rm -rf "$PRIVRES_R" "$PRIVRES_I"
		mkdir -p "$PRIVRES_R" "$PRIVRES_I"
		: >"$D/resp-iked.log"
		: >"$D/init-iked.log"

		for NS in "$NSR" "$NSI"; do
			ip netns del "$NS" 2>/dev/null || true
			ip netns add "$NS"
			ip netns exec "$NS" ip link set lo up
		done
		ip link del "$VR" 2>/dev/null || true
		ip link del "$VI" 2>/dev/null || true
		ip link add "$VR" type veth peer name "$VI"
		# 576 MTU BEFORE addresses: forces RFC 7383 fragmenting of the
		# CREATE_CHILD rekey + FOLLOWUP_KE ML-KEM exchange.
		ip link set "$VR" mtu 576
		ip link set "$VI" mtu 576
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
		i=0; until [ -S /tmp/spmif-i2iked576-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
		( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2iked576-r RACOON2_RESUME_DIR="$PRIVRES_R" \
		    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

		( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
		i=0; until [ -S /tmp/spmif-i2iked576-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
		( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2iked576-i RACOON2_RESUME_DIR="$PRIVRES_I" \
		    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

		sleep 2
		"$SBIN/ikedctl" -s /tmp/iked.sock-i2iked576-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

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
		[ "$up" -eq 1 ] || log "FAIL: child not up after 45s (attempt $attempt)"
		[ "$up" -eq 1 ] || continue

		# Soft rekey is ~48-54s after child install.  Hold no loss until
		# just before that, then 80% so the FOLLOWUP_KE response (3 SKF
		# datagrams at 576) is sent into loss.  Do NOT hold 80% until the
		# rekey completes: P(all 3 fragments survive one send) is 0.8%, so
		# the replayed fragments never land and the row fails even when
		# replay works.  Ease to 5% once the responder has logged the
		# fragmented FOLLOWUP path (response just went out under 80%).
		sleep 30
		if ! ip netns exec "$NSR" tc qdisc replace dev "$VR" root netem loss 80% 2>/dev/null; then
			log "FAIL: cannot apply netem loss on $NSR/$VR (no tc?); abort"
			break
		fi
		d0=$(tc_dropped "$NSR" "$VR" || true)
		ndrop=0
		frag_seen=0
		i=0
		while [ "$i" -lt 70 ]; do
			if grep -F -q 'not advancing (fragmented path)' "$D/resp-iked.log" 2>/dev/null; then
				frag_seen=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		# The fragmented-path log is written before the FOLLOWUP response
		# is transmitted.  Two seconds lets that send hit the qdisc.
		sleep 2
		d1=$(tc_dropped "$NSR" "$VR" || true)
		ndrop=$(( ${d1:-0} - ${d0:-0} ))
		log "drop-count window: netem dropped $ndrop datagrams (d0=${d0:-0} d1=${d1:-0}) frag_path=$frag_seen"
		ip netns exec "$NSR" tc qdisc replace dev "$VR" root netem loss 5% 2>/dev/null || true

		rekeyed=0; i=0
		while [ "$i" -lt 90 ]; do
			re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			# a rekeyed child shows 3 esp rows; expect >= 3 (old + new)
			if [ "${re:-0}" -ge 3 ] && [ "${ie:-0}" -ge 3 ]; then
				nreplay=$(grep -c 'R2 replay' "$D/resp-iked.log" 2>/dev/null || true)
				log "rekey: new SPI rows both sides at ${i}s (resp=$re init=$ie) R2 replay=$nreplay (attempt $attempt)"
				rekeyed=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$rekeyed" -eq 1 ] || \
			log "FAIL: child-SA rekey not seen in 90s after easing loss (attempt $attempt; resp esp rows: $(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp') frag_path=$frag_seen)"

		# PQC proof — identical to i2ike: the rekey must offer type-06 ADDKE
		# (0x24 = mlkem768) in its CREATE_CHILD SA, derive ML-KEM keymat on
		# BOTH sides (install logs 'sha256=<hash> g_ir_present=n'; the LAST
		# such line on each side must MATCH), and not abort the pending rekey.
		t6=$(grep -c '06000024' "$D/init-iked.log" 2>/dev/null || true)
		abt=$(grep -cE 'ADDKE followup timeout; abort' "$D/resp-iked.log" 2>/dev/null || true)
		kh_i=$(grep -oE 'sha256=[0-9a-f]+ g_ir_present=n' "$D/init-iked.log" 2>/dev/null \
			| grep -oE 'sha256=[0-9a-f]+' | tail -1)
		kh_r=$(grep -oE 'sha256=[0-9a-f]+ g_ir_present=n' "$D/resp-iked.log" 2>/dev/null \
			| grep -oE 'sha256=[0-9a-f]+' | tail -1)
		nreplay=$(grep -c 'R2 replay' "$D/resp-iked.log" 2>/dev/null || true)
		pqc=0
		if [ "${t6:-0}" -ge 1 ] && [ -n "$kh_i" ] && [ "$kh_i" = "$kh_r" ] \
		   && [ "${abt:-0}" -eq 0 ]; then
			pqc=1
			log "PQC rekey: type-6 offered (x$t6), last KEM keymat sha256=$kh_i matches both sides, no followup abort"
		else
			log "FAIL: rekey not ADDKE/ML-KEM (type6=$t6 kh_i=${kh_i:-none} kh_r=${kh_r:-none} abort=$abt)"
		fi

		if [ "$rekeyed" -eq 1 ] && [ "$pqc" -eq 1 ] && [ "${nreplay:-0}" -ge 1 ] && [ "${ndrop:-0}" -ge 1 ] && [ "${frag_seen:-0}" -eq 1 ]; then
			log "DROP-KILL-TEST: rekey survived a lost fragmented FOLLOWUP response via armed-response replay (R2 replay x$nreplay, netem-dropped=$ndrop, frag_path=1, attempt $attempt)"
			pass_ok=1
			break
		fi
		log "attempt $attempt: rekeyed=$rekeyed pqc=$pqc nreplay=${nreplay:-0} drop=${ndrop:-0} frag_path=${frag_seen:-0} (need replay >= 1 AND measured drop >= 1 AND fragmented FOLLOWUP path)"
	done

	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$pass_ok" -ne 1 ]; then
		log "FAIL: PQC CREATE_CHILD response-drop rekey did not recover via armed-response replay (pass_ok=0)"
		log "--- resp-iked.log (replay/followup/install) ---"
		sed -n 's/.*\(R2 replay\|ESTABLISHED\|FOLLOWUP\|ADDKE\|install\|abort\|err=\).*/\1: &/p' \
			"$D/resp-iked.log" 2>/dev/null | tail -8
		return 1
	fi
	return 0
}
