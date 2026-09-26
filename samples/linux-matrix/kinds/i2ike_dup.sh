#!/bin/sh
# kinds/i2ike_dup.sh — CREATE_CHILD mid-handler duplicate-injection unit.
#
# Review #5 pin ("window-before-arm"): on CREATE_CHILD, the responder
# advances recv_message_id (ikev2.c:4429, ikev2_update_message_id) and
# THEN yields to the event loop at ikev2_child_getspi (XFRM_GETSPI
# netlink round trip); the response is armed later in
# ikev2_create_child_responder_cont.  A wire duplicate of the request
# can land in that window.  Dispatch (ikev2.c:538-547) must
# short-circuit it BEFORE the handler:
#   - response not armed -> ikev2_retransmit_forced returns 0 ->
#     ikev2_check_message_ordering sees recv already advanced ->
#     "dropping unordered message (id N)", handler NOT re-entered.
#   - response already armed -> "R2 replay".
# Either marker is correct; the sharp gate is that the handler runs
# EXACTLY ONCE: the resp log carries exactly one "CREATE_CHILD_SA
# request:" line (ikev2.c:4514) for the rekey.  Two lines = handler
# re-entered = the window hole is real (FAIL).
#
# Injector: netem `duplicate 100%` on the INITIATOR egress veth, armed
# AFTER the initial child is up so establishment is untouched.  Every
# initiator->responder datagram arrives twice, back-to-back, while the
# CREATE_CHILD response window is open.
#
# WHY CLASSICAL ESP (NOT ADDKE): the ADDKE FOLLOWUP goes out as 3 SKF
# fragments (frag_threshold 576, MTU-independent), and the reassembler
# stores fragments UNCONDITIONALLY (ikev2_frag.c:765) with a COUNT-based
# completion check (:778) and NO duplicate-fragment-number guard.  A
# duplicated mid-list fragment inflates num_received, trips a
# premature "missing part" failure, and livelocks the assembly until
# the 10s ADDKE arm aborts — the row would fail for that reason, not
# the window.  Classical ESP has no followup and no fragments: the
# CREATE_CHILD request and response are single datagrams, so
# `duplicate 100%` exercises only the msgid-advance/GETSPI/arm window.
# The DPD/NAT-D reply path is NOT covered here: informational_responder
# has no yield between advance and arm, so that path is unreachable by
# a wire retransmit (documented, not unit-tested).
#
# Gate (counted, same philosophy as i2ike-drop): rekey completes (new
# SPI pair both sides via comm), exactly ONE handler entry, and at
# least one unordered/replay marker (evidence a duplicate actually
# arrived — a clean rekey with duplicates never landing proves
# nothing).  No weakening of iked gates; no daemon patch.
kind_i2ike_dup() {
	name=$1
	require_root || return 1
	require_procps || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NSR=i2ikedup-r; NSI=i2ikedup-i; VR=i2vdup-r; VI=i2vdup-i
	HR=192.0.10.1; HI=192.0.10.2
	PRIVRES_R=/tmp/r2-i2ikedup-resume-r; PRIVRES_I=/tmp/r2-i2ikedup-resume-i
	D=/tmp/r2-i2ikedup; C=/tmp/r2-i2ikedup-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2ikedup-r"; };
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
	# responder must NOT initiate its own rekey inside the dup window:
	# only the initiator rekeys (60s), so the duplicated exchange is the
	# sole CREATE_CHILD on the SA.
	ipsec_sa_lifetime_time 3600 sec;
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
	spmd { unix "/tmp/spmif-i2ikedup-i"; };
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
};
EOF

	attempts=3
	pass_ok=0
	for attempt in $(seq 1 "$attempts"); do
		# kill daemons by the unique per-run conf dir (it IS in their argv).
		pkill -9 -f "$C/" 2>/dev/null || true
		rm -f /tmp/spmif-i2ikedup-r /tmp/spmif-i2ikedup-i \
		      /tmp/iked.sock-i2ikedup-r /tmp/iked.sock-i2ikedup-i
		# Fresh SAs and empty logs: a leftover 'dropping unordered',
		# 'R2 replay' or 'CREATE_CHILD_SA request' line from a previous
		# attempt would pass the gate without exercising this attempt.
		rm -rf "$PRIVRES_R" "$PRIVRES_I"
		mkdir -p "$PRIVRES_R" "$PRIVRES_I"
		: >"$D/resp-iked.log"
		: >"$D/init-iked.log"

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
		i=0; until [ -S /tmp/spmif-i2ikedup-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
		( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ikedup-r RACOON2_RESUME_DIR="$PRIVRES_R" \
		    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

		( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
		i=0; until [ -S /tmp/spmif-i2ikedup-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
		( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2ikedup-i RACOON2_RESUME_DIR="$PRIVRES_I" \
		    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

		sleep 2
		"$SBIN/ikedctl" -s /tmp/iked.sock-i2ikedup-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

		up=0
		i=0
		while [ "$i" -lt 45 ]; do
			re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
			if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
				log "child UP: responder esp=$re initiator esp=$ie after ${i}s (attempt $attempt)"
				up=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$up" -eq 1 ] || log "FAIL: child not up after 45s (attempt $attempt)"
		[ "$up" -eq 1 ] || continue

		# INIT SA is up.  Arm `duplicate 100%` on the INITIATOR egress veth
		# BEFORE the 60s-soft rekey fires: every CREATE_CHILD rekey request
		# arrives at the responder twice, the second copy landing in the
		# GETSPI window (response not yet armed) or right after it (armed).
		# It must be short-circuited, never re-processed.
		if ! ip netns exec "$NSI" tc qdisc replace dev "$VI" root netem duplicate 100% 2>/dev/null; then
			log "FAIL: cannot apply netem duplicate on $NSI/$VI (no tc?); abort"
			break
		fi

		spi(){ ip netns exec "$1" ip xfrm state 2>/dev/null | grep -oE 'spi 0x[0-9a-f]+' | sort; }
		SR0=$(spi "$NSR"); SI0=$(spi "$NSI")
		rekeyed=0; i=0
		while [ "$i" -lt 120 ]; do
			SRn=$(spi "$NSR"); SIn=$(spi "$NSI")
			nr=$(comm -13 <(printf '%s\n' "$SR0") <(printf '%s\n' "$SRn") | grep -c spi)
			ni=$(comm -13 <(printf '%s\n' "$SI0") <(printf '%s\n' "$SIn") | grep -c spi)
			if [ "${nr:-0}" -ge 1 ] && [ "${ni:-0}" -ge 1 ]; then
				log "rekey: new SPI both sides at ${i}s (old R: $(echo $SR0 | tr '\n' ' ')) (attempt $attempt)"
				rekeyed=1
				break
			fi
			i=$((i+1)); sleep 1
		done
		[ "$rekeyed" -eq 1 ] || \
			log "FAIL: child-SA rekey not seen in 120s under dup (attempt $attempt; resp SPIs now: $(spi "$NSR" | tr '\n' ' '))"

		# ease off so the exchange completes cleanly once the response WAS
		# handled (the short-circuit path is what we are proving).
		ip netns exec "$NSI" tc qdisc replace dev "$VI" root netem duplicate 0% 2>/dev/null || true
		sleep 4

		# WINDOW evidence MUST be tied to THIS exchange's msgid.  The
		# handler-entry line (ikev2.c:4514) carries the request msgid M;
		# a short-circuited duplicate is logged for the SAME M:
		# "dropping unordered message (id M)" pre-arm, or
		# "R2 replay: re-sent armed response (message_id M)" post-arm.
		# Bare markers would let an unrelated DPD/informational replay
		# (dpd_delay 60 runs on this same SA) satisfy the gate without
		# any CREATE_CHILD duplicate ever landing, so the marker greps
		# only accept lines carrying M.
		# Sharp no-re-entry assertion scoped to THIS exchange: the
		# initial child also logs the :4514 line, so the rekey is the
		# LAST handler entry; count entries carrying that msgid only.
		MID=$(grep -oE 'CREATE_CHILD_SA request: msgid=[0-9]+' "$D/resp-iked.log" 2>/dev/null \
			| tail -n1 | cut -d= -f2)
		if [ -n "$MID" ]; then
			ncc=$(grep -c "CREATE_CHILD_SA request: msgid=${MID} " "$D/resp-iked.log" 2>/dev/null || true)
			nunord=$(grep -cF "dropping unordered message (id $MID)" "$D/resp-iked.log" 2>/dev/null || true)
			nreplay=$(grep -cF "R2 replay: re-sent armed response (message_id $MID)" "$D/resp-iked.log" 2>/dev/null || true)
		else
			ncc=0
			nunord=0
			nreplay=0
		fi
		abt=$(grep -cE 'abort' "$D/resp-iked.log" 2>/dev/null || true)

		if [ "$rekeyed" -eq 1 ] && [ "${ncc:-0}" -eq 1 ] \
		   && [ $(( ${nunord:-0} + ${nreplay:-0} )) -ge 1 ] && [ "${abt:-0}" -eq 0 ]; then
			log "DUP-WINDOW-UNIT: mid-window duplicate short-circuited (handler entries=$ncc, unordered=$nunord, R2 replay=$nreplay, attempt $attempt)"
			pass_ok=1
			break
		fi
		log "attempt $attempt: rekeyed=$rekeyed cc_entries=${ncc:-0} unordered=${nunord:-0} replay=${nreplay:-0} abort=${abt:-0} (need exactly 1 handler entry AND unordered+replay >= 1 AND no abort; two entries = the window hole is real)"
	done

	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$pass_ok" -ne 1 ]; then
		log "FAIL: CREATE_CHILD mid-window duplicate was not cleanly short-circuited (pass_ok=0)"
		log "--- resp-iked.log (window markers/handler) ---"
		sed -n 's/.*\(dropping unordered\|R2 replay\|CREATE_CHILD_SA request\|ESTABLISHED\|abort\|err=\).*/\1: &/p' \
			"$D/resp-iked.log" 2>/dev/null | tail -10
		return 1
	fi
	return 0
}
