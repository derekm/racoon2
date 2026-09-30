#!/bin/sh
# kinds/i2i_nsawarn.sh — NSA/CNSSP-15 hardening check family: EVERY obsolete
# algorithm (nsa_deprecated_alg in iked/ike_conf.c) MUST emit the iked
# deprecation warning at proposal-build AND must NOT silently downgrade the
# negotiated suite.  Two outcome classes:
#
#   advisory  (3des_cbc, hmac_md5, hmac_sha1, modp768/1024/1536, ESP-side
#              variants): the weak token has a real transform, so the warning
#              fires but negotiation still lands on the compliant first-common
#              offer and the ESP child establishes (advisory-only, never
#              fails closed).  PASS = warning in BOTH iked logs + child up.
#
#   fail-closed (des_cbc): RCT_ALG_DES_CBC is commented OUT of the IKE
#              transform table (iked/ike_conf.c), so iked refuses the config
#              at ike_conf_check_ikev2 with "kmp_enc_alg DES-CBC
#              unsupported" BEFORE proposal build -- there is no
#              "configuring obsolete algorithm" warning for DES.  PASS =
#              that conf-check reject string in BOTH logs + child did NOT
#              establish (DES cannot be offered at all).
#
# Topology: two netnss + P2P veth, iked<->iked (192.0.9.x) — copy of the
# i2iinit/i2i_neg shape with distinct netns/socket/resume names.
#
# Each row configures the deprecated token in ONE proposal position (IKE
# ENCR / IKE PRF / IKE HASH / IKE DH / ESP ENCR / ESP AUTH); every other
# position stays compliant.  The weak token is always listed AFTER the
# compliant one so "first common" negotiation picks the compliant suite —
# the warning fires at build, the child lands compliant.
#
# Not an NDcPP cell — this is the NSA-hardening adjunct (mk_report Appendix
# A notes the obsolete-alg warning).  No gate: runs on any build.
kind_i2i_nsawarn() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	# Weak-algorithm placement per row.  WARN_STR is the REAL rct2str output
	# (lib/rc_type.c); EXPECT_FAILCLOSED=1 flips the gate for des_cbc.
	WEAK_ENC='kmp_enc_alg { aes256_cbc; };'
	WEAK_PRF='kmp_prf_alg { hmac_sha2_256; };'
	WEAK_HASH='kmp_hash_alg { hmac_sha2_256; };'
	WEAK_DH='kmp_dh_group { ecp256; };'
	WEAK_ESP_ENC='esp_enc_alg { aes_gcm; };'
	WEAK_ESP_AUTH='esp_auth_alg { non_auth; };'
	WARN_STR=
	EXPECT_FAILCLOSED=0
	case "$name" in
	i2i-nsawarn)
		WARN_STR="3DES-CBC"
		WEAK_ENC='kmp_enc_alg { aes256_cbc; 3des_cbc; };'
		;;
	i2i-nsawarn-md5)
		WARN_STR="HMAC-MD5"
		WEAK_PRF='kmp_prf_alg { hmac_sha2_256; hmac_md5; };'
		WEAK_HASH='kmp_hash_alg { hmac_sha2_256; hmac_md5; };'
		;;
	i2i-nsawarn-sha1)
		WARN_STR="HMAC-SHA-1"
		WEAK_PRF='kmp_prf_alg { hmac_sha2_256; hmac_sha1; };'
		WEAK_HASH='kmp_hash_alg { hmac_sha2_256; hmac_sha1; };'
		;;
	i2i-nsawarn-modp768)
		WARN_STR="MODP768"
		WEAK_DH='kmp_dh_group { ecp256; modp768; };'
		;;
	i2i-nsawarn-modp1024)
		WARN_STR="MODP1024"
		WEAK_DH='kmp_dh_group { ecp256; modp1024; };'
		;;
	i2i-nsawarn-modp1536)
		WARN_STR="MODP1536"
		WEAK_DH='kmp_dh_group { ecp256; modp1536; };'
		;;
	i2i-nsawarn-esp3des)
		WARN_STR="3DES-CBC"
		WEAK_ESP_ENC='esp_enc_alg { aes256_cbc; 3des_cbc; };'
		WEAK_ESP_AUTH='esp_auth_alg { hmac_sha2_256; };'
		;;
	i2i-nsawarn-espsha1)
		WARN_STR="HMAC-SHA-1"
		WEAK_ESP_ENC='esp_enc_alg { aes256_cbc; };'
		WEAK_ESP_AUTH='esp_auth_alg { hmac_sha2_256; hmac_sha1; };'
		;;
	i2i-nsawarn-des)
		WARN_STR="DES-CBC"
		EXPECT_FAILCLOSED=1
		WEAK_ENC='kmp_enc_alg { aes256_cbc; des_cbc; };'
		;;
	*)
		log "FAIL: unknown NSA warning case $name"; return 1 ;;
	esac

	NSR=i2nw-r; NSI=i2nw-i; VR=i2nwr; VI=i2nwi
	HR=192.0.9.1; HI=192.0.9.2
	PRIVRES_R=/tmp/r2-i2nw-resume-r; PRIVRES_I=/tmp/r2-i2nw-resume-i
	D=/tmp/r2-i2nw; C=/tmp/r2-i2nw-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

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
		$WEAK_PRF
		$WEAK_HASH
		$WEAK_DH
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
	$WEAK_ESP_ENC
	$WEAK_ESP_AUTH
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
		$WEAK_PRF
		$WEAK_HASH
		$WEAK_DH
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
	$WEAK_ESP_ENC
	$WEAK_ESP_AUTH
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

	# The warning must appear in BOTH iked logs at proposal-build; the text
	# is the real rct2str of the deprecated token (lib/rc_type.c).
	warn_r=$(grep -c "configuring obsolete algorithm $WARN_STR" "$D/resp-iked.log" 2>/dev/null || true)
	warn_i=$(grep -c "configuring obsolete algorithm $WARN_STR" "$D/init-iked.log" 2>/dev/null || true)

	if [ "$EXPECT_FAILCLOSED" = 1 ]; then
		# des_cbc is rejected at IKE_CONF CHECK time (ike_conf.c
		# ike_conf_check_ikev2 -> "kmp_enc_alg DES-CBC unsupported",
		# since the DES transform row is commented out), so iked refuses
		# the config before any proposal-build -- there is no
		# "configuring obsolete" warning for DES.  PASS requires the
		# conf-check reject string on both seats and NO child.
		uns_r=$(grep -c "kmp_enc_alg $WARN_STR unsupported" "$D/resp-iked.log" 2>/dev/null || true)
		uns_i=$(grep -c "kmp_enc_alg $WARN_STR unsupported" "$D/init-iked.log" 2>/dev/null || true)
		gote=0
		if [ "$up" -eq 0 ] && [ "${uns_r:-0}" -ge 1 ] && [ "${uns_i:-0}" -ge 1 ]; then
			gote=1
			printf 'CPL A4: PASS fail-closed DES refusal at conf-check on both seats (unsupported r=%s i=%s; no child) — obsolete DES-CBC cannot be offered\n' \
			    "$uns_r" "$uns_i"
			log "PASS $name: conf-check refusal of DES-CBC both seats (r=$uns_r i=$uns_i), no child"
		else
			log "FAIL $name: fail-closed DES alloy — up=$up unsupported(r=$uns_r i=$uns_i)"
		fi
	else
		# advisory: warning fires on both seats AND the exchange still lands
		# a compliant ESP child (the weak offer never blocks / downgrades).
		gote=0
		if [ "$up" -eq 1 ] && [ "${warn_r:-0}" -ge 1 ] && [ "${warn_i:-0}" -ge 1 ]; then
			gote=1
			printf 'CPL A4: PASS obsolete-alg warning emitted on both seats (resp %s, init %s) yet ESP child established (esp resp=%s init=%s) — advisory-only\n' \
			    "$warn_r" "$warn_i" "${re:-0}" "${ie:-0}"
			log "PASS $name: $WARN_STR warning fired both seats (r=$warn_r i=$warn_i) and child up (resp=${re} init=${ie})"
		else
			if [ "${warn_r:-0}" -eq 0 ] || [ "${warn_i:-0}" -eq 0 ]; then
				log "FAIL $name: deprecation warning missing (resp_warn=${warn_r} init_warn=${warn_i}, up=$up)"
			else
				log "FAIL $name: warning fired but exchange did not establish (resp=${re} init=${ie})"
			fi
		fi
	fi

	if [ "$gote" -eq 0 ]; then
		log "--- resp-iked.log (warning grep) ---"
		grep -E 'configuring obsolete algorithm|unsupported algorithm|ESTABLISHED|NO_PROPOSAL|abort|err=' "$D/resp-iked.log" 2>/dev/null | tail -6
		log "--- init-iked.log (warning grep) ---"
		grep -E 'configuring obsolete algorithm|unsupported algorithm|ESTABLISHED|NO_PROPOSAL|abort|err=' "$D/init-iked.log" 2>/dev/null | tail -6
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
