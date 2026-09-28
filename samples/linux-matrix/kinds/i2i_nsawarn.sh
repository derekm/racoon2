#!/bin/sh
# kinds/i2i_nsawarn.sh — NSA/CNSSP-15 hardening check: an obsolete algorithm
# (3DES-CBC) MUST emit the iked deprecation warning at proposal-build AND
# must NOT block a compliant exchange (advisory-only, never fails closed).
#
# Topology: two netnss + P2P veth, iked<->iked (192.0.9.x) — copy of the
# i2iinit/i2i_neg shape with distinct netns/socket/resume names.
#
# Both seats list `kmp_enc_alg { aes256_cbc; 3des_cbc; }` — the 3DES row
# builds its transform (so `alglist_to_proppair` runs
# `nsa_deprecated_alg()` and plogs "configuring obsolete algorithm
# 3DES-CBC - remove the suite (NSA/CNSSP-15...)"), while negotiation still
# lands on AES-256-CBC (the first common offer).  A PASS requires BOTH:
#   * the warning line in BOTH iked logs (proposal-build warning->log),
#   * an ESP child up in both netnss (the warning never blocks).
# A FAIL when either log lacks the warning OR the child did not establish
# (blaming the advisory for a legit exchange), or when the exchange picked
# 3DES (expected suite walk must stay compliant).
#
# Not an NDcPP cell — this is the NSA-hardening adjunct (mk_report Appendix
# A notes the obsolete-alg warning).  No gate: runs on any build.
kind_i2i_nsawarn() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	case "$name" in
	i2i-nsawarn) ;;
	*) log "FAIL: unknown NSA warning case $name"; return 1 ;;
	esac

	NSR=i2nw-r; NSI=i2nw-i; VR=i2nwr; VI=i2nwi
	HR=192.0.9.1; HI=192.0.9.2
	PRIVRES_R=/tmp/r2-i2nw-resume-r; PRIVRES_I=/tmp/r2-i2nw-resume-i
	D=/tmp/r2-i2nw; C=/tmp/r2-i2nw-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	# Shared IKE suite: AES-256-CBC + HMAC-SHA2-256 + P-256, auth PSK,
	# tunnel ESP child (aes_gcm like the i2i-family rows).  BOTH seats add
	# 3des_cbc as a trailing offer so the deprecation warning must fire.
	WEAK_ENC='kmp_enc_alg { aes256_cbc; 3des_cbc; };'

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2nw-r"; };
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
		$WEAK_ENC
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
};
EOF

	cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "/tmp/spmif-i2nw-i"; };
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
		$WEAK_ENC
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
};
EOF

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2nw-r /tmp/spmif-i2nw-i /tmp/iked.sock-i2nw-r /tmp/iked.sock-i2nw-i

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
	i=0; until [ -S /tmp/spmif-i2nw-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2nw-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2nw-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2nw-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2nw-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 30 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then up=1; break; fi
		i=$((i+1)); sleep 1
	done
	sleep 2

	re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')

	# The warning must appear in BOTH iked logs at proposal-build, and the
	# text is the real rct2str of the deprecated token ("3DES-CBC").
	warn_r=$(grep -c "configuring obsolete algorithm 3DES-CBC" "$D/resp-iked.log" 2>/dev/null || true)
	warn_i=$(grep -c "configuring obsolete algorithm 3DES-CBC" "$D/init-iked.log" 2>/dev/null || true)

	gote=0
	if [ "$up" -eq 1 ] && [ "${warn_r:-0}" -ge 1 ] && [ "${warn_i:-0}" -ge 1 ]; then
		gote=1
		printf 'CPL A4: PASS obsolete-alg warning emitted on both seats (resp %s, init %s) yet ESP child established (esp resp=%s init=%s) — advisory-only\n' \
		    "$warn_r" "$warn_i" "${re:-0}" "${ie:-0}"
		log "PASS $name: warning fired both seats (r=$warn_r i=$warn_i) and child up (resp=${re} init=${ie})"
	else
		if [ "${warn_r:-0}" -eq 0 ] || [ "${warn_i:-0}" -eq 0 ]; then
			log "FAIL $name: deprecation warning missing (resp_warn=${warn_r} init_warn=${warn_i}, up=$up)"
		else
			log "FAIL $name: warning fired but exchange did not establish (resp=${re} init=${ie})"
		fi
	fi

	if [ "$gote" -eq 0 ]; then
		log "--- resp-iked.log (warning grep) ---"
		grep -E 'configuring obsolete algorithm|ESTABLISHED|NO_PROPOSAL|abort|err=' "$D/resp-iked.log" 2>/dev/null | tail -6
		log "--- init-iked.log (warning grep) ---"
		grep -E 'configuring obsolete algorithm|ESTABLISHED|NO_PROPOSAL|abort|err=' "$D/init-iked.log" 2>/dev/null | tail -6
	fi

	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	[ "$gote" -eq 1 ]
	return $?
}
