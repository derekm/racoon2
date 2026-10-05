#!/bin/sh
# kinds/i2ike_skfreplay.sh — RFC 7383 replay of an old fragmented request.
#
# F10 (review): a reassembled SKF message skipped the Message ID window.
# ikev2_input() ran ikev2_retransmit_forced() on it (which only matches
# the response currently armed) but never ikev2_check_message_ordering(),
# so a captured, authentic set of SKF fragments for an OLD request was
# dispatched to its handler again once the window had moved on (RFC 7296
# s2.2, RFC 7383 s2.6: "processed as if it was received, verified, and
# decrypted as a regular IKE message").
#
# Setup: i2ike-addke with initiator initial_child_ke immediate, so the
# IKE_AUTH child is rekeyed at once: CREATE_CHILD_SA (KE + type 6), then
# IKE_FOLLOWUP_KE (ML-KEM-768 public key -> several SKF fragments), then
# the INFORMATIONAL DELETE of the old child (7a6f930) at the next id.
# An AF_PACKET tap on the responder veth (tools/ikeframes.py) records the
# initiator's frames.  Once the DELETE (id F+1) has been answered, the
# followup's fragments (id F) are re-sent (IKE bytes unchanged) from the
# initiator veth, below IP/XFRM.
#
# Gate: the fragments reach iked (SKF recv lines for id F grow by the
# number sent), the reassembled request is dropped by the window
# ("dropping unordered message (id F)"), the followup handler is NOT
# re-entered (no new "IKE_FOLLOWUP_KE msgid F (window at" line and no new
# STATE_NOT_FOUND "no pending ADDKE state" answer), and the SA survives.
kind_i2ike_skfreplay() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	PY=$(command -v python3 || true)
	[ -n "$PY" ] || { log "FAIL: python3 required (tools/ikeframes.py)"; return 1; }
	TOOL="$HERE/tools/ikeframes.py"
	MLKEM=mlkem768

	row_ns "$name"
	HR=192.0.11.1; HI=192.0.11.2
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
	ipsec_sa_lifetime_time 3600 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
	esp_addke_alg { $MLKEM; };
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
	initial_child_ke immediate;
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 60 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
	esp_addke_alg { $MLKEM; };
};
EOF

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
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	# tap both directions on the responder veth
	FR="$D/init-frames.txt"; : >"$FR"
	ip netns exec "$NSR" "$PY" "$TOOL" capture "$VR" "$FR" >"$D/tap.err" 2>&1 &
	TAP=$!

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &
	sleep 2
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	# the immediate ADDKE rekey: matching first Y keymat on both seats
	ok=0; i=0
	while [ "$i" -lt 60 ]; do
		ky_i=$(grep -oE 'sha256=[0-9a-f]+ g_ir_present=Y' "$D/init-iked.log" 2>/dev/null | head -1)
		ky_r=$(grep -oE 'sha256=[0-9a-f]+ g_ir_present=Y' "$D/resp-iked.log" 2>/dev/null | head -1)
		if [ -n "$ky_i" ] && [ "$ky_i" = "$ky_r" ]; then ok=1; break; fi
		i=$((i+1)); sleep 1
	done
	[ "$ok" -eq 1 ] || log "FAIL: immediate ADDKE rekey not seen in 60s (ky_i=${ky_i:-none} ky_r=${ky_r:-none})"

	# F = the followup request (exchange 44, R flag clear, SKF first payload)
	F=$(awk -v i="$HI" '$5 == i && $2 == 44 && int($3 / 32) % 2 == 0 && $4 == 53 { m = $1 } END { if (m != "") print m }' "$FR")
	later=0
	if [ -n "$F" ]; then
		i=0
		while [ "$i" -lt 30 ]; do
			# the responder must have ANSWERED a later initiator request
			# (the DELETE at F+1: a response, R set, from $HR, id > F),
			# so its window and its armed response have moved past F
			if awk -v f="$F" -v r="$HR" '$5 == r && $1 > f && int($3 / 32) % 2 == 1 { x = 1 } END { exit !x }' "$FR"; then
				later=1; break
			fi
			i=$((i+1)); sleep 1
		done
		sleep 3
	fi
	[ -n "$F" ] || log "FAIL: no fragmented IKE_FOLLOWUP_KE request captured ($(wc -l <"$FR") frames tapped)"
	[ -n "$F" ] && [ "$later" -ne 1 ] && log "FAIL: no initiator request after the followup (id $F) within 30s"

	pass=0
	if [ "$ok" -eq 1 ] && [ -n "$F" ] && [ "$later" -eq 1 ]; then
		cnt() { grep -cF "$1" "$D/resp-iked.log" 2>/dev/null || true; }
		skf0=$(cnt "SKF fragment recv (next=SKF, msgid=$F,")
		uno0=$(cnt "dropping unordered message (id $F)")
		hnd0=$(cnt "IKE_FOLLOWUP_KE msgid $F (window at")
		snf0=$(cnt "IKE_FOLLOWUP_KE: no pending ADDKE state for link")
		esp0=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		nsent=$(ip netns exec "$NSI" "$PY" "$TOOL" send "$VI" "$FR" --msgid "$F" --exch 44 --src "$HI" 2>"$D/send.err")
		sleep 4
		skf1=$(cnt "SKF fragment recv (next=SKF, msgid=$F,")
		uno1=$(cnt "dropping unordered message (id $F)")
		hnd1=$(cnt "IKE_FOLLOWUP_KE msgid $F (window at")
		snf1=$(cnt "IKE_FOLLOWUP_KE: no pending ADDKE state for link")
		esp1=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		abt=$(grep -cE 'abort' "$D/resp-iked.log" 2>/dev/null || true)
		d_skf=$((skf1 - skf0)); d_uno=$((uno1 - uno0)); d_hnd=$((hnd1 - hnd0)); d_snf=$((snf1 - snf0))
		ev="id=$F frames=${nsent:-0} skf+=$d_skf unordered+=$d_uno handler+=$d_hnd state_not_found+=$d_snf esp=$esp0->$esp1 abort=$abt"
		if [ "${nsent:-0}" -ge 2 ] && [ "$d_skf" -ge "$nsent" ] && [ "$d_uno" -ge 1 ] \
		   && [ "$d_hnd" -eq 0 ] && [ "$d_snf" -eq 0 ] && [ "$esp1" -ge 2 ] && [ "${abt:-0}" -eq 0 ]; then
			pass=1
			log "SKF-REPLAY: replayed fragmented IKE_FOLLOWUP_KE dropped by the Message ID window, handler not re-entered ($ev)"
		else
			log "FAIL: SKF replay of an old request ($ev; need frames>=2, skf+>=frames, unordered+>=1, handler+=0, state_not_found+=0, esp>=2, abort=0)"
		fi
	fi

	kill "$TAP" 2>/dev/null || true
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"
	if [ "$pass" -ne 1 ]; then
		log "--- resp-iked.log (window/followup) ---"
		grep -E "msgid=$F|id $F\)|FOLLOWUP|unordered|abort" "$D/resp-iked.log" 2>/dev/null | tail -12
		return 1
	fi
	return 0
}
