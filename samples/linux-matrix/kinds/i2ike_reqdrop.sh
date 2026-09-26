#!/bin/sh
# kinds/i2ike_reqdrop.sh — PQC CREATE_CHILD REQUEST-direction loss kill-test.
#
# Review #4: every existing loss row (i2ike-drop, i2iinit-drop, both
# *drop576) nets the RESPONDER egress veth, i.e. only the
# RESPONDER->INITIATOR direction (response / intermediate reply) is ever
# lost.  This row nets the INITIATOR egress veth instead: the CREATE_CHILD
# rekey REQUEST itself is lost on the wire.  Recovery must be the
# INITIATOR's own retransmit ladder (isakmp_retransmit: 1,2,4,8,16,32,
# 64s doubling ladder, retry_limit 10) — the responder never saw
# the first copy, so there is no armed response to replay: each surviving
# retransmit arrives as a FRESH request (recv_message_id was never
# consumed) and is processed normally.  No R2 replay is expected or
# required here (nothing was answered and then lost); the counted gate is
# proof that a request-direction drop did not stop the rekey.
#
# Shape (tightened per review #4): 100% loss armed on the initiator
# egress AFTER child-up; KEPT until the netem drop counter ticks (the
# first request copy is counted lost), held ~4s longer so the 1s/3s
# ladder rungs are also counted dropped, THEN the qdisc is REMOVED and
# the next ladder rung (t+7s) arrives inside the 10s ADDKE arm timer.
# Keeping loss on across the FOLLOWUP would reproduce CI 36204006963
# (y_arm=1, followup timeout) for the wrong reason — loss ends before
# the FOLLOWUP starts.
# WHY 100% (review #4: "netem-dropped >= 1 is any datagram on initiator
# egress between arm and the request log, not a lost CREATE_CHILD"):
# the window opens at child-up (~t0) and closes within ~5s of the first
# tick, which the 60s child lifetime fires at ~t0+60.  The last
# inbound packet lands at ~t0+12 (FOLLOWUP), so with dpd_delay 60 the
# earliest initiator-side DPD datagram leaves at ~t0+72 — after the
# qdisc is gone — and responder probes ride the responder egress, which
# this qdisc never sees.  Every counted drop in the window is therefore
# a copy of the CREATE_CHILD rekey request, and 100% makes the proof
# deterministic: the first send cannot pass, so any arrival logged AFTER
# qdisc removal is a ladder copy — the initiator's own ladder recovered
# a counted-lost request.
#
# Gate (counted): netem-dropped >= 1 on the INITIATOR egress while ONLY
# request-direction traffic can flow AND the request arrives strictly
# after the qdisc came off (fresh msgid, req counter increments) AND
# the rekey completes (new SPI both sides) AND the new CHILD keymat on
# both sides carries g_ir_present=Y with matching sha256 (the new
# CREATE_CHILD request was KE-bearing: ML-KEM installed after the loss)
# AND no followup timeout.  A rekey completion with zero counted
# request-direction loss proves nothing; a counted drop with no rekey
# proves nothing.
kind_i2ike_reqdrop() {
	name=$1
	require_root || return 1
	require_procps || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2ikereq-r; NSI=i2ikereq-i; VR=i2vreq-r; VI=i2vreq-i
	HR=192.0.11.1; HI=192.0.11.2
	PRIVRES_R=/tmp/r2-i2ikereq-resume-r; PRIVRES_I=/tmp/r2-i2ikereq-resume-i
	D=/tmp/r2-i2ikereq; C=/tmp/r2-i2ikereq-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2ikereq-r"; };
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
	# only the initiator rekeys (60s), so the retransmitted request is
	# the only CREATE_CHILD on the SA.
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
	spmd { unix "/tmp/spmif-i2ikereq-i"; };
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
		# kill daemons by the unique per-run conf dir (it IS in their argv).
		pkill -9 -f "$C/" 2>/dev/null || true
		rm -f /tmp/spmif-i2ikereq-r /tmp/spmif-i2ikereq-i \
		      /tmp/iked.sock-i2ikereq-r /tmp/iked.sock-i2ikereq-i
		# Fresh SAs and empty logs: a leftover 'CREATE_CHILD_SA request'
		# or 'R2 replay' line from a previous attempt would fool the gate.
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
		i=0; until [ -S /tmp/spmif-i2ikereq-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
		( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ikereq-r RACOON2_RESUME_DIR="$PRIVRES_R" \
		    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

		( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
		i=0; until [ -S /tmp/spmif-i2ikereq-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
		( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ikereq-i RACOON2_RESUME_DIR="$PRIVRES_I" \
		    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

		sleep 2
		"$SBIN/ikedctl" -s /tmp/iked.sock-i2ikereq-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

		up=0
		i=0
		while [ "$i" -lt 45 ]; do
			re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
				log "PQC ADDKE child UP: responder esp=$re initiator esp=$ie after ${i}s (attempt $attempt)"
				up=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$up" -eq 1 ] || log "FAIL: child not up after 45s (attempt $attempt)"
		[ "$up" -eq 1 ] || continue

		# INIT SA is up.  Drop 100% of INITIATOR->RESPONDER packets (the
		# REQUEST direction) from just before the 60s-soft rekey until
		# the request is logged by the responder.  100%: the first copy
		# CANNOT arrive, so any logged arrival must be a retransmit-
		# ladder copy (the review #4 proof).  The window is only the
		# request exchange — the qdisc goes away the moment arrival is
		# observed, before FOLLOWUP starts.  The instigator of recovery
		# is the INITIATOR's own retransmit ladder.
		if ! ip netns exec "$NSI" tc qdisc replace dev "$VI" root netem loss 100% 2>/dev/null; then
			log "FAIL: cannot apply netem loss on $NSI/$VI (no tc?); abort"
			break
		fi
		d0=$(tc_dropped "$NSI" "$VI" || true)
		req0=$(grep -c 'CREATE_CHILD_SA request: msgid=' "$D/resp-iked.log" 2>/dev/null || true)

		# While 100% is up, NOTHING arrives.  Watch the netem drop
		# counter for up to 100s: the first tick is the counted loss of a
		# rekey-request copy (soft lifetime 60s fires the rekey inside
		# the window).  Hold 4s longer so the 1s/3s ladder rungs are also
		# counted dropped, THEN remove the qdisc; the 7s rung arrives with
		# the link clean, before FOLLOWUP even starts.
		ticked=0
		i=0
		while [ "$i" -lt 100 ]; do
			d1=$(tc_dropped "$NSI" "$VI" || true)
			if [ $(( ${d1:-0} - ${d0:-0} )) -ge 1 ]; then
				ticked=1
				log "request copy counted lost after ${i}s at 100% request-direction loss (attempt $attempt)"
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$ticked" -eq 1 ] || \
			log "FAIL: no counted loss of the rekey request in 100s at 100% (attempt $attempt)"
		sleep 4
		d1=$(tc_dropped "$NSI" "$VI" || true)
		ndrop=$(( ${d1:-0} - ${d0:-0} ))
		ip netns exec "$NSI" tc qdisc del dev "$VI" root 2>/dev/null || true
		log "drop-count window (REQUEST direction): netem dropped $ndrop datagrams (d0=${d0:-0} d1=${d1:-0}) req ${req0:-0}->(polling)"

		# The qdisc is OFF and the next ladder rung lands within ~10s.
		# Require a FRESH request entry (req > req0) after removal —
		# at 100% nothing could have arrived earlier, so the increment is
		# the initiator's own retransmit ladder completing delivery.
		req=0
		i=0
		while [ "$i" -lt 40 ]; do
			req=$(grep -c 'CREATE_CHILD_SA request: msgid=' "$D/resp-iked.log" 2>/dev/null || true)
			if [ "${req:-0}" -gt "${req0:-0}" ]; then
				log "rekey request arrived at responder ${i}s after qdisc removal (attempt $attempt)"
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "${req:-0}" -gt "${req0:-0}" ] || \
			log "FAIL: rekey CREATE_CHILD request never arrived at responder after counted loss (attempt $attempt)"

		# With loss off, the response + FOLLOWUP finish; watch for the new
		# SPI (rekey install) for up to 30s.
		spi(){ ip netns exec "$1" ip xfrm state 2>/dev/null | grep -oE 'spi 0x[0-9a-f]+' | sort; }
		SR0=$(spi "$NSR"); SI0=$(spi "$NSI")
		rekeyed=0; i=0
		while [ "$i" -lt 30 ]; do
			SRn=$(spi "$NSR"); SIn=$(spi "$NSI")
			nr=$(comm -13 <(printf '%s\n' "$SR0") <(printf '%s\n' "$SRn") | grep -c spi)
			ni=$(comm -13 <(printf '%s\n' "$SI0") <(printf '%s\n' "$SIn") | grep -c spi)
			if [ "${nr:-0}" -ge 1 ] && [ "${ni:-0}" -ge 1 ]; then
				log "rekey: new SPI both sides at ${i}s after request arrival (attempt $attempt)"
				rekeyed=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$rekeyed" -eq 1 ] || \
			log "FAIL: child-SA rekey not seen in 30s after request arrived under REQUEST-direction loss (attempt $attempt; resp SPIs now: $(spi "$NSR" | tr '\n' ' '))"

		# PQC proof — same as i2ike drop576: type-06 ADDKE offer, matching
		# KEM keymat on both sides, no followup timeout.
		t6=$(grep -c '06000024' "$D/init-iked.log" 2>/dev/null || true)
		abt=$(grep -c 'ADDKE followup timeout' "$D/resp-iked.log" 2>/dev/null || true)
		# Review #4 gate: the NEW (rekey) CHILD keymat on BOTH sides must
		# carry g_ir_present=Y — proof the KE-bearing request survived
		# and ML-KEM actually installed after the counted loss.  The
		# AUTH child logs g_ir_present=n, so a Y line can only be the
		# rekey.  Matching sha256 across peers proves the same KEM secret.
		y_i=$(grep -c 'g_ir_present=Y' "$D/init-iked.log" 2>/dev/null || true)
		y_r=$(grep -c 'g_ir_present=Y' "$D/resp-iked.log" 2>/dev/null || true)
		kh_i=$(grep -oE 'sha256=[0-9a-f]+ g_ir_present=Y' "$D/init-iked.log" 2>/dev/null \
			| grep -oE 'sha256=[0-9a-f]+' | tail -1)
		kh_r=$(grep -oE 'sha256=[0-9a-f]+ g_ir_present=Y' "$D/resp-iked.log" 2>/dev/null \
			| grep -oE 'sha256=[0-9a-f]+' | tail -1)
		nreplay=$(grep -c 'R2 replay' "$D/resp-iked.log" 2>/dev/null || true)
		pqc=0
		if [ "${t6:-0}" -ge 1 ] && [ "${y_i:-0}" -ge 1 ] && [ "${y_r:-0}" -ge 1 ] \
		   && [ -n "$kh_i" ] && [ "$kh_i" = "$kh_r" ] \
		   && [ "${abt:-0}" -eq 0 ]; then
			pqc=1
			log "PQC rekey: type-6 offered (x$t6), new KEM keymat g_ir_present=Y both sides, $kh_i matches, no followup timeout"
		else
			log "FAIL: rekey not ADDKE/ML-KEM on the NEW keymat (type6=$t6 y_i=${y_i:-0} y_r=${y_r:-0} kh_i=${kh_i:-none} kh_r=${kh_r:-none} abort=$abt)"
		fi

		if [ "$rekeyed" -eq 1 ] && [ "$pqc" -eq 1 ] && [ "${ndrop:-0}" -ge 1 ]; then
			log "REQDIR-LOSS: request-direction drop recovered via INITIATOR retransmit ladder (netem-dropped=$ndrop, R2 replay=$nreplay (not expected on this row), attempt $attempt)"
			pass_ok=1
			break
		fi
		log "attempt $attempt: rekeyed=$rekeyed pqc=$pqc drop=${ndrop:-0} replay=${nreplay:-0} (need rekeyed AND pqc AND netem-dropped >= 1 on the REQUEST direction; a completion with zero counted request loss proves nothing)"
	done

	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$pass_ok" -ne 1 ]; then
		log "FAIL: PQC CREATE_CHILD REQUEST-direction drop did not recover via the initiator retransmit ladder (pass_ok=0)"
		log "--- init-iked.log (request/retransmit/install) ---"
		sed -n 's/.*\(CREATE_CHILD\|retransmit\|ESTABLISHED\|FOLLOWUP\|ADDKE\|install\|abort\|err=\).*/\1: &/p' \
			"$D/init-iked.log" 2>/dev/null | tail -8
		log "--- resp-iked.log (receive/install) ---"
		sed -n 's/.*\(CREATE_CHILD_SA request\|ESTABLISHED\|FOLLOWUP\|ADDKE\|install\|abort\|err=\).*/\1: &/p' \
			"$D/resp-iked.log" 2>/dev/null | tail -8
		return 1
	fi
	return 0
}
