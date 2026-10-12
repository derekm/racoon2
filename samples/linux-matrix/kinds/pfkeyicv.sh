#!/bin/sh
# kinds/pfkeyicv.sh -- Linux pfkey backend ICV decision (gate=pfkey).
#
# Linux af_key installs hmac(sha256) with a 96-bit ICV and PF_KEY cannot
# ask for RFC 4868's 128 (rdratlos/racoon-ipsec-tools #145/#147).  The
# pfkey backend therefore REFUSES hmac_sha2_256 (lib/if_pfkeyv2.c
# rcpfk_supported_auth).  This row proves the refusal is loud and fatal:
# iked, started on a config whose only ESP integrity is hmac_sha2_256,
# must log the refusal and exit instead of running.  The positive side
# (sha384/512 at 192/256 bits, GCM) is the regular i2iinit-esp-* rows in
# the pfkey lane, whose ICV lengths xfrm_audit.sh asserts exactly.
#
# pfkeyicv-gcm: Linux af_key has no AEAD at all (no SADB_X_EALG_AES_GCM_*
# in its SADB_REGISTER reply, and pfkey_msg2xfrm_state only looks up ealg/
# aalg), so an ESP aes128gcm16 config is refused by the config check
# ("enc_alg AES-GCM not supported by kernel").  This is the kernel, not
# racoon2: the row proves the refusal is loud, which is why the pfkey lane
# runs only CBC + SHA2-384/512 i2i rows.
kind_pfkeyicv() {
	name=$1
	case $name in
	*-gcm)
		_esp_enc=aes128gcm16; _esp_auth=
		_want_refuse=
		_want_check='enc_alg AES-GCM not supported by kernel'
		_what="ESP aes128gcm16 (af_key has no AEAD)" ;;
	*)
		_esp_enc=aes128_cbc; _esp_auth=hmac_sha2_256
		_want_refuse='hmac_sha2_256 refused on the Linux pfkey backend: af_key installs a 96-bit ICV'
		_want_check='auth_alg .* not supported by kernel'
		_what="hmac_sha2_256 (af_key 96-bit ICV)" ;;
	esac
	_esp_authline=
	[ -z "$_esp_auth" ] || _esp_authline=" esp_auth_alg { $_esp_auth; };"
	require_root || return 1
	row_ns "$name"
	ip netns del "$NSR" 2>/dev/null
	ip netns add "$NSR" && ip -n "$NSR" link set lo up || return 1
	rm -rf "$D" "$C"; mkdir -p "$D" "$C"
	printf 'pfkeyicv-spmd-pwd' > "$C/spmd.pwd"; printf 'pfkeyicv-psk' > "$C/test.psk"
	chmod 600 "$C/spmd.pwd" "$C/test.psk"
	cat > "$C/resp.conf" <<CONF
interface {
	ike { "127.0.0.1" port 500; };
	spmd { unix "$SPMIF_R"; };
	spmd_password "$C/spmd.pwd";
};
resolver { resolver off; };
remote r1 {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "resp.test"; peers_id fqdn "init.test";
		peers_ipaddr "127.0.0.2";
		kmp_enc_alg { aes128_cbc; }; kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; }; kmp_dh_group { modp2048; };
		kmp_auth_method { psk; }; pre_shared_key "$C/test.psk";
	};
	selector_index sel_in;
};
selector sel_out { direction outbound; src "127.0.0.1"; dst "127.0.0.2"; policy_index pol; };
selector sel_in { direction inbound; dst "127.0.0.1"; src "127.0.0.2"; policy_index pol; };
policy pol { action auto_ipsec; remote_index r1; ipsec_mode transport; ipsec_index { ipsec_e; }; ipsec_level require; };
ipsec ipsec_e { ipsec_sa_lifetime_time 60 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { $_esp_enc; };$_esp_authline };
CONF
	RACOON2_ADMIN_SOCK="$SOCK_R" ip netns exec "$NSR" timeout 15 \
		"$SBIN/iked" -F -f "$C/resp.conf" -D 0x0001 -l "$D/resp-iked.log" > "$D/resp-iked.out" 2>&1
	_st=$?
	ip netns del "$NSR" 2>/dev/null
	tail -5 "$D/resp-iked.log" "$D/resp-iked.out" 2>/dev/null
	_bad=
	[ "$_st" = 124 ] && _bad="iked kept running on an ESP $_what config"
	[ "$_st" = 0 ] && _bad="${_bad:+$_bad; }iked exited 0"
	if [ -n "$_want_refuse" ]; then
		grep -q "$_want_refuse" "$D/resp-iked.log" "$D/resp-iked.out" 2>/dev/null ||
			_bad="${_bad:+$_bad; }no refusal message"
	fi
	grep -q "$_want_check" "$D/resp-iked.log" "$D/resp-iked.out" 2>/dev/null ||
		_bad="${_bad:+$_bad; }config check did not count it as an error ('$_want_check')"
	if [ -n "$_bad" ]; then log "FAIL $name: $_bad (exit $_st)"; return 1; fi
	log "PASS $name (pfkey backend refuses $_what loudly; iked exit $_st)"
	return 0
}
