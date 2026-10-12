#!/bin/sh
# kinds/i2i_nsawarn.sh — deprecated-transform family (NSA/CNSSP-15 and RFC
# 8247 / RFC 8221 / RFC 9395), iked<->iked.  Both switches default OFF
# (allow_nsa_deprecated / allow_rfc_deprecated): a deprecated algorithm is
# refused unless the config turns its class on.  Row classes:
#
#   advisory  (3des_cbc, hmac_md5, hmac_sha1, modp768/1024/1536, ESP-side
#              variants): the row's config enables exactly the switch(es)
#              the token's class needs (DEPR_SW), so the token is usable;
#              the "configuring obsolete algorithm" warning must fire at
#              proposal-build on BOTH seats while negotiation lands on the
#              compliant first-common offer and the ESP child establishes.
#              PASS = warning in BOTH iked logs + child up.
#
#   refusal   (i2i-nsawarn-des, *-default-*, *-rfcoff-*, i2i-cipher-*-default,
#              i2i-cipher-3idea, and an unavailable cipher): iked refuses the
#              config at ike_conf_check before any proposal build.  PASS =
#              the row's refusal string(s) in BOTH logs + NO child.
#              i2i-nsawarn-des keeps its fail-closed gate; since DES is now
#              implemented, the refusal it proves is the default-off one
#              ("is NSA-deprecated ... allow_nsa_deprecated is off").
#
#   cipher    (i2i-cipher-<x>): kmp_enc_alg / esp_enc_alg lists ONLY the
#              deprecated cipher on both seats with its switch(es) on, so
#              nothing else can be negotiated.  PASS = "IKE SA encryption
#              <name>" in BOTH logs (ESP rows: the kernel SA carries the
#              cipher on BOTH netns) + child up.  IDEA/RC5 depend on the
#              linked OpenSSL: the row probes `openssl list` and expects
#              either a working SA or the "unsupported by crypto library"
#              refusal accordingly.
#
# Topology: two netnss + P2P veth, iked<->iked (192.0.9.x) — copy of the
# i2iinit/i2i_neg shape with distinct netns/socket/resume names.
#
# Advisory rows configure the deprecated token in ONE proposal position (IKE
# ENCR / IKE PRF / IKE HASH / IKE DH / ESP ENCR / ESP AUTH); every other
# position stays compliant.  The weak token is always listed AFTER the
# compliant one so "first common" negotiation picks the compliant suite —
# the warning fires at build, the child lands compliant.
#
# Not an NDcPP cell — this is the NSA-hardening adjunct (mk_report Appendix
# A notes the obsolete-alg warning).  No gate: runs on any build.

# legacy_cipher_available EVPNAME: the linked OpenSSL provides the cipher
# (default or legacy provider).  Matches iked's runtime probe
# (eay_evp_cipher_available) because both use the system libcrypto.
legacy_cipher_available() {
	openssl list -cipher-algorithms -provider default -provider legacy 2>/dev/null |
		grep -qiE "(^|[[:space:],{])$1([[:space:],}]|$)"
}

kind_i2i_nsawarn() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	# Weak-algorithm placement per row.  WARN_STR is the REAL rct2str output
	# (lib/rc_type.c).  MODE: advisory | refusal | cipher (see header).
	# DEPR_SW: the switch line(s) the row's config needs (both seats).
	WEAK_ENC='kmp_enc_alg { aes256_cbc; };'
	WEAK_PRF='kmp_prf_alg { hmac_sha2_256; };'
	WEAK_HASH='kmp_hash_alg { hmac_sha2_256; };'
	WEAK_DH='kmp_dh_group { ecp256; };'
	WEAK_ESP_ENC='esp_enc_alg { aes_gcm; };'
	WEAK_ESP_AUTH='esp_auth_alg { non_auth; };'
	WARN_STR=
	MODE=advisory
	DEPR_SW=
	REFUSE_STR=
	REFUSE_STR2=
	CIPHER=
	ESP_XFRM=
	SW_NSA='allow_nsa_deprecated on;'
	SW_RFC='allow_rfc_deprecated on;'
	SW_BOTH='allow_nsa_deprecated on; allow_rfc_deprecated on;'
	# ERE patterns (grep -E) for the ike_conf_check refusal lines
	off_nsa() { echo "$1 is NSA-deprecated \\(CNSSP-15\\) and allow_nsa_deprecated is off"; }
	off_rfc() { echo "$1 is RFC-deprecated \\(.*\\) and allow_rfc_deprecated is off"; }
	case "$name" in
	i2i-nsawarn)
		WARN_STR="3DES-CBC"; DEPR_SW=$SW_NSA
		WEAK_ENC='kmp_enc_alg { aes256_cbc; 3des_cbc; };'
		;;
	i2i-nsawarn-md5)
		WARN_STR="HMAC-MD5"; DEPR_SW=$SW_BOTH
		WEAK_PRF='kmp_prf_alg { hmac_sha2_256; hmac_md5; };'
		WEAK_HASH='kmp_hash_alg { hmac_sha2_256; hmac_md5; };'
		;;
	i2i-nsawarn-sha1)
		WARN_STR="HMAC-SHA-1"; DEPR_SW=$SW_NSA
		WEAK_PRF='kmp_prf_alg { hmac_sha2_256; hmac_sha1; };'
		WEAK_HASH='kmp_hash_alg { hmac_sha2_256; hmac_sha1; };'
		;;
	i2i-nsawarn-modp768)
		WARN_STR="MODP768"; DEPR_SW=$SW_BOTH
		WEAK_DH='kmp_dh_group { ecp256; modp768; };'
		;;
	i2i-nsawarn-modp1024)
		WARN_STR="MODP1024"; DEPR_SW=$SW_BOTH
		WEAK_DH='kmp_dh_group { ecp256; modp1024; };'
		;;
	i2i-nsawarn-modp1536)
		WARN_STR="MODP1536"; DEPR_SW=$SW_BOTH
		WEAK_DH='kmp_dh_group { ecp256; modp1536; };'
		;;
	i2i-nsawarn-esp3des)
		WARN_STR="3DES-CBC"; DEPR_SW=$SW_BOTH
		WEAK_ESP_ENC='esp_enc_alg { aes256_cbc; 3des_cbc; };'
		WEAK_ESP_AUTH='esp_auth_alg { hmac_sha2_256; };'
		;;
	i2i-nsawarn-espsha1)
		WARN_STR="HMAC-SHA-1"; DEPR_SW=$SW_NSA
		WEAK_ESP_ENC='esp_enc_alg { aes256_cbc; };'
		WEAK_ESP_AUTH='esp_auth_alg { hmac_sha2_256; hmac_sha1; };'
		;;
	i2i-nsawarn-des)
		# fail-closed: switches left at the default (off)
		WARN_STR="DES-CBC"; MODE=refusal
		WEAK_ENC='kmp_enc_alg { aes256_cbc; des_cbc; };'
		REFUSE_STR="kmp_enc_alg $(off_nsa DES-CBC)"
		REFUSE_STR2="kmp_enc_alg $(off_rfc DES-CBC)"
		;;
	# --- default-off refusal, one row per class -------------------------
	i2i-nsawarn-default-nsa)
		# NSA-only token (3DES is MAY in RFC 8247): the NSA switch alone
		MODE=refusal
		WEAK_ENC='kmp_enc_alg { aes256_cbc; 3des_cbc; };'
		REFUSE_STR="kmp_enc_alg $(off_nsa 3DES-CBC)"
		;;
	i2i-nsawarn-default-rfc)
		# RFC-only token (group 23, RFC 8247 s2.4 SHOULD NOT; not NSA)
		MODE=refusal
		WEAK_DH='kmp_dh_group { ecp256; modp2048_224; };'
		REFUSE_STR="kmp_dh_group $(off_rfc MODP2048-224POS)"
		;;
	i2i-nsawarn-rfcoff-md5)
		# independence: NSA on does not admit an RFC MUST NOT
		MODE=refusal; DEPR_SW=$SW_NSA
		WEAK_PRF='kmp_prf_alg { hmac_sha2_256; hmac_md5; };'
		REFUSE_STR="kmp_prf_alg $(off_rfc HMAC-MD5)"
		;;
	# --- deprecated ENCR transforms (RFC 9395 s5 / RFC 8247 s2.1) ---------
	i2i-cipher-des)      MODE=cipher; DEPR_SW=$SW_BOTH; CIPHER=des-cbc
		WEAK_ENC='kmp_enc_alg { des_cbc; };' ;;
	i2i-cipher-desiv64)  MODE=cipher; DEPR_SW=$SW_BOTH; CIPHER=des-cbc-iv64
		WEAK_ENC='kmp_enc_alg { des_cbc_iv64; };' ;;
	i2i-cipher-desiv32)  MODE=cipher; DEPR_SW=$SW_BOTH; CIPHER=des-cbc-iv32
		WEAK_ENC='kmp_enc_alg { des_cbc_iv32; };' ;;
	i2i-cipher-cast)     MODE=cipher; DEPR_SW=$SW_RFC; CIPHER=cast128-cbc
		WEAK_ENC='kmp_enc_alg { cast128_cbc; };' ;;
	i2i-cipher-blowfish) MODE=cipher; DEPR_SW=$SW_RFC; CIPHER=blowfish-cbc
		WEAK_ENC='kmp_enc_alg { blowfish_cbc; };' ;;
	i2i-cipher-idea)     MODE=cipher; DEPR_SW=$SW_RFC; CIPHER=idea-cbc
		WEAK_ENC='kmp_enc_alg { idea_cbc; };'
		legacy_cipher_available IDEA-CBC || {
			MODE=refusal
			REFUSE_STR="kmp_enc_alg IDEA-CBC unsupported by crypto library"
		} ;;
	i2i-cipher-rc5)      MODE=cipher; DEPR_SW=$SW_RFC; CIPHER=rc5-cbc
		WEAK_ENC='kmp_enc_alg { rc5_cbc; };'
		legacy_cipher_available RC5-CBC || {
			MODE=refusal
			REFUSE_STR="kmp_enc_alg RC5-CBC unsupported by crypto library"
		} ;;
	i2i-cipher-3idea)
		# no specification exists: refused even with the switch on
		MODE=refusal; DEPR_SW=$SW_RFC
		WEAK_ENC='kmp_enc_alg { 3idea_cbc; };'
		REFUSE_STR="kmp_enc_alg IDEA3-CBC unsupported: ENCR_3IDEA has no specification"
		;;
	i2i-cipher-des-default)      MODE=refusal
		WEAK_ENC='kmp_enc_alg { des_cbc; };'
		REFUSE_STR="kmp_enc_alg $(off_nsa DES-CBC)"
		REFUSE_STR2="kmp_enc_alg $(off_rfc DES-CBC)" ;;
	i2i-cipher-desiv64-default)  MODE=refusal
		WEAK_ENC='kmp_enc_alg { des_cbc_iv64; };'
		REFUSE_STR="kmp_enc_alg $(off_nsa DES-CBC-IV64)"
		REFUSE_STR2="kmp_enc_alg $(off_rfc DES-CBC-IV64)" ;;
	i2i-cipher-desiv32-default)  MODE=refusal
		WEAK_ENC='kmp_enc_alg { des_cbc_iv32; };'
		REFUSE_STR="kmp_enc_alg $(off_nsa DES-CBC-IV32)"
		REFUSE_STR2="kmp_enc_alg $(off_rfc DES-CBC-IV32)" ;;
	i2i-cipher-cast-default)     MODE=refusal
		WEAK_ENC='kmp_enc_alg { cast128_cbc; };'
		REFUSE_STR="kmp_enc_alg $(off_rfc CAST-128-CBC)" ;;
	i2i-cipher-blowfish-default) MODE=refusal
		WEAK_ENC='kmp_enc_alg { blowfish_cbc; };'
		REFUSE_STR="kmp_enc_alg $(off_rfc Blowfish-CBC)" ;;
	i2i-cipher-idea-default)     MODE=refusal
		WEAK_ENC='kmp_enc_alg { idea_cbc; };'
		REFUSE_STR="kmp_enc_alg $(off_rfc IDEA-CBC)" ;;
	i2i-cipher-rc5-default)      MODE=refusal
		WEAK_ENC='kmp_enc_alg { rc5_cbc; };'
		REFUSE_STR="kmp_enc_alg $(off_rfc RC5-CBC)" ;;
	# ESP: Linux XFRM offers cbc(des), cbc(cast5), cbc(blowfish) (no
	# IDEA/RC5/3IDEA, no DES_IV32/IV64 framings)
	i2i-cipher-esp-des)      MODE=cipher; DEPR_SW=$SW_BOTH; ESP_XFRM='cbc(des)'
		WEAK_ESP_ENC='esp_enc_alg { des_cbc; };'
		WEAK_ESP_AUTH='esp_auth_alg { hmac_sha2_256; };' ;;
	i2i-cipher-esp-cast)     MODE=cipher; DEPR_SW=$SW_RFC; ESP_XFRM='cbc(cast5)'
		WEAK_ESP_ENC='esp_enc_alg { cast128_cbc; };'
		WEAK_ESP_AUTH='esp_auth_alg { hmac_sha2_256; };' ;;
	i2i-cipher-esp-blowfish) MODE=cipher; DEPR_SW=$SW_RFC; ESP_XFRM='cbc(blowfish)'
		WEAK_ESP_ENC='esp_enc_alg { blowfish_cbc; };'
		WEAK_ESP_AUTH='esp_auth_alg { hmac_sha2_256; };' ;;
	i2i-cipher-esp-des-default) MODE=refusal
		WEAK_ESP_ENC='esp_enc_alg { des_cbc; };'
		WEAK_ESP_AUTH='esp_auth_alg { hmac_sha2_256; };'
		REFUSE_STR="esp_enc_alg $(off_nsa DES-CBC)"
		REFUSE_STR2="esp_enc_alg $(off_rfc DES-CBC)" ;;
	*)
		log "FAIL: unknown NSA warning case $name"; return 1 ;;
	esac

	row_ns "$name"
	HR=192.0.9.1; HI=192.0.9.2
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
		$WEAK_ENC
		$WEAK_PRF
		$WEAK_HASH
		$WEAK_DH
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		$DEPR_SW
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
		$WEAK_ENC
		$WEAK_PRF
		$WEAK_HASH
		$WEAK_DH
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		$DEPR_SW
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
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 30 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then up=1; break; fi
		i=$((i+1)); sleep 1
	done
	sleep 2
	[ "$up" -eq 1 ] && i2i_dataplane "$NSI" "$HR" "$name"

	re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
	ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')

	# The warning must appear in BOTH iked logs at proposal-build; the text
	# is the real rct2str of the deprecated token (lib/rc_type.c).
	warn_r=$(grep -c "configuring obsolete algorithm $WARN_STR" "$D/resp-iked.log" 2>/dev/null || true)
	warn_i=$(grep -c "configuring obsolete algorithm $WARN_STR" "$D/init-iked.log" 2>/dev/null || true)

	gote=0
	case "$MODE" in
	refusal)
		# Config refused at ike_conf_check (both seats) BEFORE any
		# proposal build; PASS requires the row's refusal string(s) on
		# both seats and NO child.
		uns_r=$(grep -cE "$REFUSE_STR" "$D/resp-iked.log" 2>/dev/null || true)
		uns_i=$(grep -cE "$REFUSE_STR" "$D/init-iked.log" 2>/dev/null || true)
		un2_r=1; un2_i=1
		if [ -n "$REFUSE_STR2" ]; then
			un2_r=$(grep -cE "$REFUSE_STR2" "$D/resp-iked.log" 2>/dev/null || true)
			un2_i=$(grep -cE "$REFUSE_STR2" "$D/init-iked.log" 2>/dev/null || true)
		fi
		if [ "$up" -eq 0 ] && [ "${uns_r:-0}" -ge 1 ] && [ "${uns_i:-0}" -ge 1 ] &&
		   [ "${un2_r:-0}" -ge 1 ] && [ "${un2_i:-0}" -ge 1 ]; then
			gote=1
			printf 'CPL A4: PASS fail-closed refusal at conf-check on both seats (r=%s/%s i=%s/%s; no child): %s\n' \
			    "$uns_r" "$un2_r" "$uns_i" "$un2_i" "$REFUSE_STR"
			log "PASS $name: conf-check refusal both seats (r=$uns_r/$un2_r i=$uns_i/$un2_i), no child"
		else
			log "FAIL $name: fail-closed — up=$up refusal(r=$uns_r/$un2_r i=$uns_i/$un2_i) want '$REFUSE_STR' ${REFUSE_STR2:+and '$REFUSE_STR2'}"
		fi
		;;
	cipher)
		if [ -n "$CIPHER" ]; then
			ev_r=$(grep -c "IKE SA encryption $CIPHER " "$D/resp-iked.log" 2>/dev/null || true)
			ev_i=$(grep -c "IKE SA encryption $CIPHER " "$D/init-iked.log" 2>/dev/null || true)
			what="IKE SA encryption $CIPHER"
		else
			ev_r=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -cF "enc $ESP_XFRM " || true)
			ev_i=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -cF "enc $ESP_XFRM " || true)
			what="kernel ESP SA enc $ESP_XFRM"
		fi
		if [ "$up" -eq 1 ] && [ "${ev_r:-0}" -ge 1 ] && [ "${ev_i:-0}" -ge 1 ]; then
			gote=1
			printf 'CPL A4: PASS deprecated cipher usable with its switch on: %s on both seats (r=%s i=%s), child up\n' \
			    "$what" "$ev_r" "$ev_i"
			log "PASS $name: $what both seats (r=$ev_r i=$ev_i), child up"
		else
			log "FAIL $name: cipher row — up=$up evidence(r=${ev_r:-0} i=${ev_i:-0}) want '$what'"
		fi
		;;
	*)
		# advisory: warning fires on both seats AND the exchange still lands
		# a compliant ESP child (the weak offer never blocks / downgrades).
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
		;;
	esac

	if [ "$gote" -eq 0 ]; then
		log "--- resp-iked.log (warning grep) ---"
		grep -E 'configuring obsolete algorithm|deprecated|unsupported|IKE SA encryption|ESTABLISHED|NO_PROPOSAL|abort|err=' "$D/resp-iked.log" 2>/dev/null | tail -8
		log "--- init-iked.log (warning grep) ---"
		grep -E 'configuring obsolete algorithm|deprecated|unsupported|IKE SA encryption|ESTABLISHED|NO_PROPOSAL|abort|err=' "$D/init-iked.log" 2>/dev/null | tail -8
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

