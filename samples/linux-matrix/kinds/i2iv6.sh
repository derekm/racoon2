#!/bin/sh
# kinds/i2iv6.sh — IPv6 conformance rows (NDcPP v3.0e / RFC 7296-IPv6).
# iked<->iked on a P2P veth in separate netnss using GLOBAL IPv6
# addresses (2001:db8:1::1/128 .. ::2/128).  The matrix's other i2i rows
# are IPv4-only (192.0.x.x /32 SPD rows, `establish-sa ... inet`); this
# kind proves the same SALG stack over AF_INET6:
#   * IKEv2 transport over IPv6 (socket family inet6, sendfromto v6)
#   * ESP tunnel-mode SADB keyed with v6 selectors (:128, xfrm sel ::/0)
#   * the xfrm backend's sa_to_xaddr/sa2str AF_INET6 branches (the
#     INET6 gate in lib/if_xfrm.c — without it sa_to_xaddr returns -1
#     and GETSPI fails with "GETSPI addresses required")
#   * the A1..A14 CPL cells unchanged (i2i_compliance is family-agnostic;
#     A2's 0.0.0.0/0 catch-all test simply cannot false-match a v6 SPD)
# The box prefix iked is built with lib/config.h `#define INET6 1`
# (RC_IF_IPV6_ENABLE).  Rows are gate=box until a container run admits
# them (same rule as i2idh-*-charon).
#
# Row suffix selects the ESP cipher: i2iv6-esp = AES-GCM (v3.0e claimed),
# i2iv6-esp-cbc128 = AES-CBC-128 + HMAC-SHA-256 (RFC 4868 claimed set).
#
# Pass gate: ESP child up on BOTH seats over v6 (getspi must round-trip
# through the v6 xfrm backend) AND i2i_compliance CPL cells all PASS.
kind_i2iv6() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	# IPv6 must be compiled into the installed iked prefix.
	if ! grep -aq "sin6_family" "$SBIN/iked" 2>/dev/null; then
		log "FAIL: $SBIN/iked has no IPv6 (INET6) support"
		return 1
	fi

	# Reset row-scoped I2I_* knobs leaked into the shared run.sh shell by
	# an earlier i2iinit-*ppk* row (see 6dd0c58 — PPK-leak fix).
	I2I_PPK=0
	I2I_PPK_MANDATORY=0

	NCBC=0
	case "$name" in
	i2iv6-esp) ESP_ENC="aes_gcm"; ESP_AUTH="non_auth"; ESP_CPL="aes_gcm"; ;;
	i2iv6-esp-cbc128) ESP_ENC="aes128_cbc"; ESP_AUTH="hmac_sha2_256"; ESP_CPL="aes128_cbc"; NCBC=1; ;;
	*) log "FAIL: $name unknown i2iv6 variant"; return 1 ;;
	esac

	NSR=i2iv6-r; NSI=i2iv6-i; VR=i2v6-vr; VI=i2v6-vi
	# GLOBAL unicast v6 — no zone scope; both ends on the same veth /64.
	HR=2001:db8:1::1; HI=2001:db8:1::2
	PRIVRES_R=/tmp/r2-i2iv6-resume-r; PRIVRES_I=/tmp/r2-i2iv6-resume-i
	D=/tmp/r2-i2iv6-$NCBC; C=/tmp/r2-i2iv6-conf-$NCBC
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2iv6-r"; };
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
	spmd { unix "/tmp/spmif-i2iv6-i"; };
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
	rm -f /tmp/spmif-i2iv6-r /tmp/spmif-i2iv6-i /tmp/iked.sock-i2iv6-r /tmp/iked.sock-i2iv6-i

	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"
	ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSR" ip addr add "$HR/64" dev "$VR"
	ip link set "$VI" netns "$NSI"
	ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSI" ip addr add "$HI/64" dev "$VI"

	# IPv6 neighbor discovery over the veth is unreliable on this box
	# (NS/NA race: the initiator's nd entry lands FAILED and unicast IKE
	# is dropped before it ever reaches the responder — probe1/kind runs
	# showed resp=1 init=0 with 'message received' count 0 and nd FAILED).
	# A ping warmup "works" but is nondeterministic (33% loss, 512ms RTT).
	# Program the peer MACs statically: deterministic, no NS/NA at all.
	VMAC_I=$(ip netns exec "$NSI" ip link show "$VI" 2>/dev/null | awk '/ether/{print $2}')
	VMAC_R=$(ip netns exec "$NSR" ip link show "$VR" 2>/dev/null | awk '/ether/{print $2}')
	ip netns exec "$NSR" ip -6 neigh add "$HI" lladdr "$VMAC_I" dev "$VR" nud permanent 2>/dev/null || true
	ip netns exec "$NSI" ip -6 neigh add "$HR" lladdr "$VMAC_R" dev "$VI" nud permanent 2>/dev/null || true

	# Multi-party loop over netns+addr triples.  Field separator is '|'
	# — NEVER ':' here, the payload IS an IPv6 literal (see probe history:
	# a ':' split mangled 2001:db8:1::1 into fields and the SPD rows never
	# matched, failing GETSPI).  Selectors are /128, not /32.
	for ns in "$NSR|$HR|$HI" "$NSI|$HI|$HR"; do
		NSX=${ns%%|*}; rest=${ns#*|}; LX=${rest%%|*}; PX=${rest#*|}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/128 dst "$LX"/128 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/128 dst "$PX"/128 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S /tmp/spmif-i2iv6-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2iv6-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	i=0; until [ -S /tmp/spmif-i2iv6-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done

	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2iv6-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2iv6-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	# family token is `inet6` — the v4-only rows use `inet` and would pass
	# the string "192.0.x.x" to ikedctl, which fails on a v6 SA.
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2iv6-i establish-sa isakmp inet6 "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "IPv6 $ESP_ENC child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$up" -eq 1 ] || log "FAIL: no IPv6 ESP child in 45s (resp=$re init=$ie)"

	# NDcPP v3.0e CPL for this row — wired cells are family-agnostic; the
	# v6-specific proof is the SA/SADB/ESTABLISHED gates above (a v4-only
	# build dies at GETSPI: "GETSPI addresses required").
	i2i_compliance "$D" "$C" "$NSR" "$NSI" "$HR" "$HI" "$name"; cpl=$?

	# v6 sel shape on the SADB: xfrm sel ::/0 (INET6 template family) on
	# every tunnel SA proves the AF_INET6 xfrm template branch, not a v4
	# template with a v6 endpoint (the xfrm-tmpl-family cell).
	v6sel=1
	for _ns in "$NSR" "$NSI"; do
		s=$(ip netns exec "$_ns" ip xfrm state 2>/dev/null | grep -A2 'proto esp')
		printf '%s\n' "$s" | grep -qE 'sel src ::/0' || v6sel=0
		printf '%s\n' "$s" | grep -qE 'sel dst ::/0' || v6sel=0
	done
	if [ "$v6sel" -eq 1 ]; then
		log "CPL X6: PASS IPv6 template family (xfrm sel ::/0) on both seats"
	else
		log "CPL X6: FAIL xfrm state not v6-template (sel ::/0 missing)"
	fi

	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	i2i_peer_i_cleanup iked
	i2i_peer_r_cleanup iked "$name"
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$up" -ne 1 ] || [ "$cpl" -ne 0 ] || [ "$v6sel" -ne 1 ]; then
		log "FAIL: IPv6 conformance incomplete (up=${up:-0} cpl=$cpl v6sel=${v6sel:-0})"
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
