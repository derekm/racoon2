#!/bin/sh
# samplecheck.sh -- every shipped samples/*.conf passes "iked -C" (the full
# configuration check, incl. the deprecated-transform switches), each
# included the way racoon2.conf.in includes them (vals.conf + default.conf),
# plus the switch semantics on hand-written configs:
#   - an IKEv1 remote with only clean algorithms is refused by default
#     (RFC 9395 s3) and loads with allow_rfc_deprecated on in its own
#     ikev1 clause;
#   - that per-remote override does not leak: an IKEv2 remote in the same
#     file using hmac_md5 is still refused;
#   - an IKEv1 remote with 3DES needs allow_nsa_deprecated as well.
# Unprivileged: iked -C opens neither PF_KEY nor spmd.
set -u
srcdir=${srcdir:-.}
SAMPLES=$srcdir/../samples
IKED=./iked
[ -x "$IKED" ] || { echo "samplecheck: no $IKED"; exit 1; }
T=$(mktemp -d "${TMPDIR:-/tmp}/samplecheck.XXXXXX") || exit 1
trap 'rm -rf "$T"' EXIT INT TERM
E=$T/etc/racoon2
mkdir -p "$E/psk" "$E/cert"
chmod 700 "$E" "$E/psk" "$E/cert"
for f in "$E/psk/test.psk" "$E/psk/wildcard.psk" "$E/spmd.pwd"; do
	echo "samplecheck-secret" > "$f"; chmod 600 "$f"
done
sed "s|@prefix@|$T|g" "$SAMPLES/vals.conf.in" > "$E/vals.conf"
cp "$SAMPLES/default.conf" "$E/default.conf"
sed "s|@prefix@|$T|g" "$SAMPLES/racoon2.conf.in" > "$E/racoon2.conf"

fail=0; n=0
check() {	# check NAME want(ok|fail) CONF [GREP-FIXED-STRING...]
	_name=$1; _want=$2; _conf=$3; shift 3
	n=$((n + 1))
	"$IKED" -C -f "$_conf" > "$T/out" 2>&1
	_rc=$?
	_got=ok; [ $_rc -eq 0 ] || _got=fail
	if [ "$_got" != "$_want" ]; then
		echo "FAIL $_name: want $_want, got $_got (rc=$_rc)"
		grep -E 'INTERNAL_ERR|INTERNAL_WARN|configuration' "$T/out" | tail -8
		fail=$((fail + 1)); return
	fi
	for _s in "$@"; do
		if ! grep -qF -- "$_s" "$T/out"; then
			echo "FAIL $_name: missing '$_s'"
			grep -E 'INTERNAL_ERR|INTERNAL_WARN' "$T/out" | tail -8
			fail=$((fail + 1)); return
		fi
	done
	echo "PASS $_name ($_want)"
}

# 1. racoon2.conf (default.conf + its IKEv1 example remote), then every
#    other shipped sample on top of it.
check racoon2.conf ok "$E/racoon2.conf"
for s in "$SAMPLES"/*.conf; do
	b=$(basename "$s")
	case "$b" in
	racoon2.conf|vals.conf|default.conf) continue ;;	# generated / base
	esac
	cp "$s" "$E/$b"
done
for s in "$SAMPLES"/*.conf; do
	b=$(basename "$s")
	inc=$b
	case "$b" in
	racoon2.conf|vals.conf|default.conf) continue ;;
	transport_ike_natt.conf)
		# an add-on: transport_ike.conf includes it (commented out)
		inc="transport_ike.conf $b" ;;
	local-test.conf)
		# upper_layer_protocol "icmp6" is the BSD /etc/protocols name
		# (glibc spells it ipv6-icmp)
		if ! getent protocols icmp6 >/dev/null 2>&1; then
			echo "SKIP sample $b (no icmp6 in /etc/protocols)"
			continue
		fi ;;
	esac
	{ cat "$E/racoon2.conf"
	  for i in $inc; do echo "include \"$E/$i\";"; done; } > "$T/top-$b"
	check "sample $b" ok "$T/top-$b"
done

# 2. switch semantics on hand-written configs
base() {	# base FILE: interface + resolver
	cat > "$1" <<EOT
interface { ike { 127.0.0.1 port 500; }; spmd { unix "$T/spmif"; }; spmd_password "$E/spmd.pwd"; };
resolver { resolver off; };
EOT
}
v1remote() {	# v1remote NAME PEER SWITCHES ENC
	cat <<EOT
remote $1 {
	acceptable_kmp { ikev1; };
	ikev1 {
		$3
		my_id ipaddr "127.0.0.1"; peers_id ipaddr "$2"; peers_ipaddr "$2";
		kmp_enc_alg { $4; }; kmp_hash_alg { sha2_256; }; kmp_dh_group { modp2048; };
		kmp_auth_method { psk; }; pre_shared_key "$E/psk/test.psk";
	};
};
EOT
}
v2remote() {	# v2remote NAME PEER PRF
	cat <<EOT
remote $1 {
	acceptable_kmp { ikev2; };
	ikev2 {
		my_id ipaddr "127.0.0.1"; peers_id ipaddr "$2"; peers_ipaddr "$2";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { $3; };
		kmp_hash_alg { hmac_sha2_256; }; kmp_dh_group { modp2048; };
		kmp_auth_method { psk; }; pre_shared_key "$E/psk/test.psk";
	};
};
EOT
}
C=$T/v1clean-default.conf; base "$C"; v1remote legacy 127.0.0.2 "" aes256_cbc >> "$C"
check "ikev1 clean remote, default switches" fail "$C" \
    "remote legacy ikev1 acceptable_kmp ikev1 is RFC-deprecated (IKEv1 RFC 9395 s3 DEPRECATED) and allow_rfc_deprecated is off"
C=$T/v1clean-on.conf; base "$C"; v1remote legacy 127.0.0.2 "allow_rfc_deprecated on;" aes256_cbc >> "$C"
check "ikev1 clean remote, per-remote allow_rfc_deprecated" ok "$C" \
    "remote legacy ikev1 acceptable_kmp ikev1 is RFC-deprecated (IKEv1 RFC 9395 s3 DEPRECATED) - allowed by allow_rfc_deprecated on"
C=$T/noleak.conf; base "$C"
v1remote legacy 127.0.0.2 "allow_rfc_deprecated on;" aes256_cbc >> "$C"
v2remote modern 127.0.0.3 hmac_md5 >> "$C"
check "per-remote override does not leak to an ikev2 remote" fail "$C" \
    "remote modern ikev2 kmp_prf_alg HMAC-MD5 is RFC-deprecated" \
    "remote modern ikev2 kmp_prf_alg HMAC-MD5 is NSA-deprecated (CNSSP-15) and allow_nsa_deprecated is off"
if grep -qF "remote legacy ikev1 acceptable_kmp ikev1 is RFC-deprecated (IKEv1 RFC 9395 s3 DEPRECATED) and" "$T/out"; then
	echo "FAIL noleak: the legacy remote itself was refused"; fail=$((fail + 1))
fi
C=$T/v1-3des-rfconly.conf; base "$C"; v1remote legacy 127.0.0.2 "allow_rfc_deprecated on;" 3des_cbc >> "$C"
check "ikev1 3des needs allow_nsa_deprecated too" fail "$C" \
    "remote legacy ikev1 kmp_enc_alg 3DES-CBC is NSA-deprecated (CNSSP-15) and allow_nsa_deprecated is off"
C=$T/v1-3des-both.conf; base "$C"; v1remote legacy 127.0.0.2 "allow_rfc_deprecated on; allow_nsa_deprecated on;" 3des_cbc >> "$C"
check "ikev1 3des with both per-remote switches" ok "$C" \
    "remote legacy ikev1 kmp_enc_alg 3DES-CBC is NSA-deprecated (CNSSP-15) - allowed by allow_nsa_deprecated on"
C=$T/v1-global.conf; base "$C"
cat >> "$C" <<EOT
default { remote { ikev1 { allow_rfc_deprecated on; }; }; };
EOT
v1remote legacy 127.0.0.2 "" aes256_cbc >> "$C"
v2remote modern 127.0.0.3 hmac_md5 >> "$C"
check "global ikev1 switch: ikev1 loads, ikev2 md5 still refused" fail "$C" \
    "remote legacy ikev1 acceptable_kmp ikev1 is RFC-deprecated (IKEv1 RFC 9395 s3 DEPRECATED) - allowed" \
    "remote modern ikev2 kmp_prf_alg HMAC-MD5 is RFC-deprecated"

# 3. X.509-from-wire trust anchor must be explicit (cert_validate on needs
#    ca_file XOR cert_trust_system on).
if command -v openssl >/dev/null 2>&1; then
	openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=samplecheck \
	    -keyout "$E/cert/me.key" -out "$E/cert/me.crt" -days 2 >/dev/null 2>&1
	v2cert() {	# v2cert NAME PEER EXTRA
		cat <<EOT
remote $1 {
	acceptable_kmp { ikev2; };
	ikev2 {
		my_id fqdn "gw.example.com"; peers_id fqdn "peer.example.com"; peers_ipaddr "$2";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; }; kmp_dh_group { modp2048; };
		kmp_auth_method { rsasig; };
		my_public_key x509pem "$E/cert/me.crt" "$E/cert/me.key";
		cert_validate on;
		$3
	};
};
EOT
	}
	C=$T/cv-noanchor.conf; base "$C"; v2cert wire 127.0.0.4 "" >> "$C"
	check "cert_validate without ca_file or cert_trust_system" fail "$C" \
	    "remote wire ikev2: cert_validate on requires ca_file, or cert_trust_system on to trust the OS default CA store"
	C=$T/cv-cafile.conf; base "$C"; v2cert wire 127.0.0.4 "ca_file \"$E/cert/me.crt\";" >> "$C"
	check "cert_validate with ca_file" ok "$C"
	C=$T/cv-system.conf; base "$C"; v2cert wire 127.0.0.4 "cert_trust_system on;" >> "$C"
	check "cert_validate with explicit cert_trust_system on" ok "$C" \
	    "remote wire ikev2: cert_trust_system on: peer chains are validated against the OS default CA store"
	C=$T/cv-both.conf; base "$C"; v2cert wire 127.0.0.4 "ca_file \"$E/cert/me.crt\"; cert_trust_system on;" >> "$C"
	check "ca_file and cert_trust_system are exclusive" fail "$C" \
	    "remote wire ikev2: ca_file and cert_trust_system on are mutually exclusive"
else
	echo "FAIL: openssl needed for the cert_validate config checks"; fail=$((fail + 1))
fi

# 4. RFC 8598 split-DNS allowlist entries must be valid domain names.
v2dns() {	# v2dns NAME PEER EXTRA
	cat <<EOT
remote $1 {
	acceptable_kmp { ikev2; };
	ikev2 {
		my_id fqdn "gw.example.com"; peers_id fqdn "peer.example.com"; peers_ipaddr "$2";
		kmp_enc_alg { aes256_cbc; }; kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; }; kmp_dh_group { modp2048; };
		kmp_auth_method { psk; }; pre_shared_key "$E/psk.txt";
		$3
	};
};
EOT
}
[ -f "$E/psk.txt" ] || echo samplecheck-psk > "$E/psk.txt"
C=$T/dns-ok.conf; base "$C"; v2dns sd 127.0.0.5 'accept_dns_domain "corp.example, lab.test.";' >> "$C"
check "accept_dns_domain with valid domains" ok "$C"
C=$T/dns-bad.conf; base "$C"; v2dns sd 127.0.0.5 'accept_dns_domain "corp.example,*.lab";' >> "$C"
check "accept_dns_domain refuses a wildcard entry" fail "$C" \
    'remote sd ikev2: accept_dns_domain entry "*.lab" is not a valid domain name'
C=$T/lsn-on.conf; base "$C"; v2dns ln 127.0.0.6 'legacy_split_netmask on;' >> "$C"
check "legacy_split_netmask on parses" ok "$C"
C=$T/lsn-off.conf; base "$C"; v2dns lf 127.0.0.7 'legacy_split_netmask off;' >> "$C"
check "legacy_split_netmask off parses" ok "$C"
C=$T/lsn-bad.conf; base "$C"; v2dns lb 127.0.0.8 'legacy_split_netmask maybe;' >> "$C"
check "legacy_split_netmask refuses a non-boolean" fail "$C"
# RFC 4739 / RFC 4478 / INTERNAL_IP4_NBNS knobs
C=$T/ma-on.conf; base "$C"; v2dns ma 127.0.0.9 'multiple_auth on; auth_lifetime 3600; honor_auth_lifetime on;' >> "$C"
check "multiple_auth / auth_lifetime / honor_auth_lifetime parse" ok "$C"
C=$T/ma-bad.conf; base "$C"; v2dns mb 127.0.0.10 'multiple_auth maybe;' >> "$C"
check "multiple_auth refuses a non-boolean" fail "$C"
C=$T/al-zero.conf; base "$C"; v2dns az 127.0.0.11 'auth_lifetime 0;' >> "$C"
check "auth_lifetime 0 is refused" fail "$C" 'auth_lifetime must be > 0'
C=$T/nbns.conf; base "$C"; v2dns nb 127.0.0.12 'request { ip4_nbns; }; provide { nbns 192.0.2.53; };' >> "$C"
check "request ip4_nbns / provide nbns parse" ok "$C"

echo "samplecheck: $n checks, $fail failures"
[ $fail -eq 0 ]
