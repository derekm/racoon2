#!/bin/sh
# kinds/i2io4.sh — IPv6-over-IPv4 rows: a v4 ESP tunnel carrying a v6
# inner selector, cross-matrix parity with freebsd-ci/i2io4-cbc128/-gcm256.
#   * IKE transport + outer SA endpoints are IPv4 (192.0.5.1/::2 on the
#     veth, `establish-sa ... inet`), mirroring the v4 matrix rows.
#   * The SPD selector (protected inner traffic) is the v6 pair
#     2001:db8:1::1 / ::2 on the SAME veth /64 — a v6 selector installed
#     over a v4 template (xfrm sel ::/0, SA src/dst 192.0.5.x).
#   * The data-plane ping6 runs from the initiator's inner v6 to the
#     responder's inner v6 and MUST transit inside the v4 ESP tunnel
#     (in/out ipsec_level require — no clear v6 path exists).
# No ND6 handling is needed here (unlike i2iv6): the inner v6 packet is
# wrapped by ipsec before output, so only the v4 outer needs ARP (L2),
# which the SPD never sees.  This is the clean half of the i2iv6 story —
# the FreeBSD leg proved the same: i2io4 rows have no ND gate.
#
# Gate: ESP child up BOTH seats (v4 outer) AND the xfrm state carries a v6
# selector (sel ::/0) over the v4 SA pair AND ping6 of the inner v6
# transits the tunnel.
kind_i2io4() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	NCBC=0
	case "$name" in
	i2io4-cbc128) ESP_ENC="aes128_cbc"; ESP_AUTH="hmac_sha2_256"; ESP_CPL="aes128_cbc"; NCBC=1; ;;
	i2io4-gcm256) ESP_ENC="aes_gcm"; ESP_AUTH="non_auth"; ESP_CPL="aes_gcm"; ;;
	*) log "FAIL: $name unknown i2io4 variant"; return 1 ;;
	esac

	row_ns "$name"
	# v4 IKE + outer SA endpoints; v6 inner selector on the same /64.
	HR=192.0.5.1; HI=192.0.5.2
	S6R=2001:db8:1::1; S6I=2001:db8:1::2
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
		kmp_enc_alg { aes128_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "$S6R"; dst "$S6I";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "$S6R"; src "$S6I";
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
	esp_enc_alg { $ESP_ENC; };
	esp_auth_alg { $ESP_AUTH; };
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
		kmp_enc_alg { aes128_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "$S6I"; dst "$S6R";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "$S6I"; src "$S6R";
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
	esp_enc_alg { $ESP_ENC; };
	esp_auth_alg { $ESP_AUTH; };
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
	ip netns exec "$NSR" ip addr add "$S6R/64" dev "$VR"
	ip link set "$VI" netns "$NSI"
	ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"
	ip netns exec "$NSI" ip addr add "$S6I/64" dev "$VI"

	# IKE-port UDP bypass rows (Linux XFRM does honor per-port SPs; the
	# matrix's require SPD would otherwise swallow iked's UDP/500-4500).
	# triples are v4 here (IKE is v4) — '|' separator, never ':'.
	for ns in "$NSR|$HR|$HI" "$NSI|$HI|$HR"; do
		NSX=${ns%%|*}; rest=${ns#*|}; LX=${rest%%|*}; PX=${rest#*|}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	[ -S "$SPMIF_R" ] || { log "FAIL: responder spmd did not open $SPMIF_R in 15s (see $D/resp-spmd.log)"; return 1; }
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	i=0; until [ -S "$SOCK_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	[ -S "$SOCK_R" ] || { log "FAIL: responder iked did not open $SOCK_R in 15s (see $D/resp-iked.log)"; return 1; }

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	[ -S "$SPMIF_I" ] || { log "FAIL: initiator spmd did not open $SPMIF_I in 15s (see $D/init-spmd.log)"; return 1; }
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	# IKE is v4: family token `inet` (192.0.5.x SA), NOT inet6.
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "IPv6-over-IPv4 $ESP_ENC child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$up" -eq 1 ] || log "FAIL: no i2io4 child in 45s (resp=$re init=$ie)"

	# NDcPP v3.0e CPL for this row — wired cells are family-agnostic; the
	# i2io4-specific proof is the v6-selector-over-v4-SA gate below.
	i2i_compliance "$D" "$C" "$NSR" "$NSI" "$HR" "$HI" "$name"; cpl=$?

	# v6 selector over v4 SA: every ESP state must carry sel ::/0 (the v6
	# template family) while its SA src/dst are the v4 192.0.5.x pair.
	v6sel=1
	for _ns in "$NSR" "$NSI"; do
		_xfrm=$(ip netns exec "$_ns" ip xfrm state 2>/dev/null)
		esp=$(printf '%s\n' "$_xfrm" | grep -c 'proto esp'); esp=${esp:-0}
		v6sels=$(printf '%s\n' "$_xfrm" | grep -cE 'sel src ::/0 dst ::/0'); v6sels=${v6sels:-0}
		[ "$esp" -ge 2 ] && [ "$v6sels" -eq "$esp" ] || v6sel=0
	done
	if [ "$v6sel" -eq 1 ]; then
		log "CPL X6: PASS v6 selector (xfrm sel ::/0) over v4 SA pair on both seats"
	else
		log "CPL X6: FAIL xfrm state not v6-selector (sel ::/0 missing over v4 SA)"
	fi

	# Data plane: ping6 of the inner v6 through the v4 ESP tunnel.
	TUN_OK=0
	if [ "$up" -eq 1 ]; then
		if ip netns exec "$NSI" ping6 -c 2 -W 2 "$S6R" > "$D/ping-tun.txt" 2>&1; then
			log "data-plane OK (inner $S6I -> $S6R ping6 through v4 tunnel)"
			TUN_OK=1
		else
			log "FAIL data-plane (inner v6 ping6 did not transit the v4 tunnel)"
			cat "$D/ping-tun.txt" 2>/dev/null || true
		fi
	fi

	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	i2i_peer_i_cleanup iked
	i2i_peer_r_cleanup iked "$name"
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$up" -ne 1 ] || [ "$cpl" -ne 0 ] || [ "$v6sel" -ne 1 ] || [ "$TUN_OK" -ne 1 ]; then
		log "FAIL: IPv6-over-IPv4 incomplete (up=${up:-0} cpl=${cpl:-?} v6sel=${v6sel:-0} tun_ok=${TUN_OK:-0})"
		log "--- init-iked.log (ESTABLISHED / errors) ---"
		[ -f "$D/init-iked.log" ] && sed -n 's/.*\('"'"'ESTABLISHED\|no proposal\|unacceptable\|NO_PROPOSAL\|GETSPI\|err=\|Cannot assign'"'"'\).*/\1: &/p' \
			"$D/init-iked.log" 2>/dev/null | tail -6
		log "--- resp-iked.log (ESTABLISHED / errors) ---"
		[ -f "$D/resp-iked.log" ] && sed -n 's/.*\('"'"'ESTABLISHED\|no proposal\|unacceptable\|NO_PROPOSAL\|GETSPI\|err=\|Cannot assign'"'"'\).*/\1: &/p' \
			"$D/resp-iked.log" 2>/dev/null | tail -6
		return 1
	fi
	return 0
}
