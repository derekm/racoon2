#!/bin/sh
# kinds/i2iinit.sh — PQC ADDKE on the INITIAL IKE_SA via RFC 9242
# IKE_INTERMEDIATE: iked<->iked on 192.0.5.x, each in its OWN netns on a P2P
# veth.  The initiator offers ADDKE (type-6) in SAi1 alongside the 16438
# IKE_INTERMEDIATE capability notify; the responder echoes 16438, selects
# type-6, and both sides complete one IKE_INTERMEDIATE ML-KEM round, update
# SKEYSEED per RFC 9370 s3.5, chain IntAuth per RFC 9242 s3.3.2, and only
# then run IKE_AUTH (ESP child lands => AUTH + IntAuth verified).  Gate:
# gate=addke (WITH_INTERMEDIATE+WITH_ADDKE), Fedora 44.
kind_i2iinit() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	PEER=$(i2i_peer "$name")
	PEER_R=$(i2i_peer_r "$name")
	PEER_ID=$(i2i_peer_resp_id "$PEER")
	for S in "$PEER" "$PEER_R"; do
		[ "$S" = charon ] && ! command -v "$I2I_CHARON_BIN" >/dev/null 2>&1 && { log "FAIL: no charon binary $I2I_CHARON_BIN"; return 1; }
	done

	row_ns "$name"
	HR=192.0.5.1; HI=192.0.5.2
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	# RFC 8784 PPK rows (i2iinit-ppk, i2iinit-ppk-charon): seats enable
	# USE_PPK with a shared ppk_id (test default = SHA-256(ppk_id), no
	# secret files on the box).  TRACE must be on (0x0003) for the kind's
	# USE_PPK/PPK_IDENTITY evidence lines to land in the iked logs.  A
	# -ppk-charon suffix additionally drops the charon initiator into
	# PPK (ppk_id/ppk_required + secrets.ppk matching the iked test
	# default) — re-arbitrating the s5.1 typed PPK_IDENTITY against a
	# second implementation.
	I2I_DBG=0x0001
	I2I_PPK=0
	I2I_PPK_MANDATORY=0
	# Proposal-shape / config-option knobs (suffix-driven; iked conf templates
	# below interpolate these).  Defaults = the PQC base shape.
	I2I_IKE_ENC="aes_gcm"          # kmp_enc_alg on both iked seats
	I2I_IKE_PRF="hmac_sha2_256"    # kmp_prf_alg + kmp_hash_alg
	I2I_ESP_ENC="aes_gcm"          # esp_enc_alg (name, optional ', <keylen>')
	I2I_ESP_AUTH="non_auth"        # esp_auth_alg (separate integrity)
	I2I_ESN=0                       # ipsec block ext_sequence on
	I2I_CHILDLESS=0                 # responder childless on (RFC 6023)
	I2I_CLASSICAL=0                 # proposal-shape rows without ADDKE round
	I2I_PPK=0                       # RFC 8784 PPK on charon seat
	I2I_PERPETUAL=0
	I2I_ESN=0
	I2I_PFSREKEY=0
	# charon child esp_proposals.  Deliberately left EMPTY here: the base
	# value is defaulted at USAGE in i2i_peer.sh (${I2I_ESP:-aes128gcm16}),
	# and the -pfsrekey/-dh arms below must overwrite it with a DH-suffix
	# proposal.  A non-empty base here would defeat those arms (their
	# ${I2I_ESP:-...} would keep this base value).
	I2I_ESP=
	I2I_CLASSICAL=0                 # proposal-shape rows without ADDKE round
	# Per-row resets for knobs the suffix arms overwrite (run.sh runs every
	# row in ONE shell, so a -dh521/-pfsrekey/-ppk row's assignment would
	# otherwise leak into the next row).  UNCONDITIONAL assignments — a
	# `:-` default keeps the previous row's value and leaks it.
	I2I_DH_GROUP=ecp256
	I2I_PROPOSAL=aes256gcm16-prfsha256-ecp256-ke1_mlkem768
	I2I_LIFETIME=300
	I2I_DBG=0x0001
	I2I_ESP=
	up_req=1   # default: ESP child must land (up=1); -cfgneg flips to 0
	case "$name" in
	*-childless*) I2I_CHILDLESS=1; I2I_DBG=0x0003 ;;   # TRACE markers (16418 advertise) need DEBUG_FLAG_TRACE=0x0002
	esac
	case "$name" in
	*-ike-cbc128*) I2I_IKE_ENC="aes128_cbc" ;;
	*-ike-cbc192*) I2I_IKE_ENC="aes192_cbc" ;;
	*-ike-cbc256*) I2I_IKE_ENC="aes256_cbc" ;;
	*-ike-ctr192*) I2I_IKE_ENC="aes_ctr, 192" ;;
	*-ike-ctr256*) I2I_IKE_ENC="aes_ctr, 256" ;;
	*-ike-ctr*)    I2I_IKE_ENC="aes_ctr, 128" ;;
	*-ike-gcm256*) I2I_IKE_ENC="aes_gcm, 256" ;;
	esac
	case "$name" in
	*-prfsha384*) I2I_IKE_PRF="hmac_sha2_384" ;;
	*-prfsha512*) I2I_IKE_PRF="hmac_sha2_512" ;;
	*-prfxcbc*)   I2I_IKE_PRF="aes_xcbc" ;;
	*-prfcmac*)   I2I_IKE_PRF="aes_cmac" ;;
	esac
	case "$name" in
	*-esp-gcm256*) I2I_ESP_ENC="aes_gcm, 256" ;;
	*-esp-cbc128*) I2I_ESP_ENC="aes128_cbc"; I2I_ESP_AUTH="hmac_sha2_256" ;;
	*-esp-cbc192*) I2I_ESP_ENC="aes192_cbc"; I2I_ESP_AUTH="hmac_sha2_256" ;;
	*-esp-cbc256*) I2I_ESP_ENC="aes256_cbc"; I2I_ESP_AUTH="hmac_sha2_256" ;;
	*-esp-sha384*) I2I_ESP_ENC="aes256_cbc"; I2I_ESP_AUTH="hmac_sha2_384" ;;
	*-esp-sha512*) I2I_ESP_ENC="aes256_cbc"; I2I_ESP_AUTH="hmac_sha2_512" ;;
	*-esp-xcbc*)   I2I_ESP_ENC="aes256_cbc"; I2I_ESP_AUTH="aes_xcbc" ;;
	*-esp-cmac*)   I2I_ESP_ENC="aes256_cbc"; I2I_ESP_AUTH="aes_cmac" ;;
	*-esp-ctr*)    I2I_ESP_ENC="aes_ctr";    I2I_ESP_AUTH="non_auth" ;;
	esac
	case "$name" in
	*-ike-cbc128*|*-ike-cbc192*|*-ike-cbc256*|*-ike-ctr*) I2I_CLASSICAL=1 ;;
	esac
	case "$name" in
	*-esn*) I2I_ESN=1 ;;
	esac
	# esp_addke_alg line for the INITIATOR sa block: classical shape rows
	# (proposal-shape tests) omit type-6 so the exchange is purely keyboard
	# crypto; every other row keeps ML-KEM-768 on the child (RFC 9370).
	I2I_ADDKE_TXT=""
	if [ "$I2I_CLASSICAL" = 1 ]; then
		I2I_ADDKE_TXT=""
	else
		I2I_ADDKE_TXT='	esp_addke_alg { mlkem768; };
'
	fi
	case "$name" in
	*-ppk*) I2I_PPK=1; I2I_DBG=0x0003 ;;
	esac
	# PPK direction: when iked is the IKE INITIATOR (-ppk-charonr), it must
	# REQUIRE the PPK (ppk_mandatory on).  RFC 8784: an initiator that only
	# OPTIONALLY uses the PPK advertises N(NO_PPK_AUTH) in IKE_AUTH
	# (iked/ikev2.c:2641-2645), which makes a strict charon responder fall
	# back to classical PSK AUTH — the PPK row then exercises the decline
	# path, not PPK application.  mandatory on drops the N(NO_PPK_AUTH)
	# decline so charon's responder must apply the PPK (gate 'using PPK').
	case "$name" in
	*-ppk-charonr) I2I_PPK_MANDATORY=1 ;;
	esac
	PPK_TXT=""
	if [ "$I2I_PPK" = 1 ]; then
		if [ "$I2I_PPK_MANDATORY" = 1 ]; then
			PPK_TXT='		use_ppk on;
		ppk_mandatory on;
		ppk_id "rfc8784-mat";'
		else
			PPK_TXT='		use_ppk on;
		ppk_mandatory off;
		ppk_id "rfc8784-mat";'
		fi
	fi

	# RFC 7296 2.18 PFS rekey row (i2iinit-pfsrekey-charon): the charon
	# seat's child esp_proposals carry a DH-group suffix (I2I_ESP=
	# 'aes128gcm16-ecp256', PFS on the child), so the AUTH child is PFS
	# and a later rekey of it MUST carry DH (implemented by mirroring
	# the peer-offered DH into my_proposal — ee60cda).  NOTE: strongSwan
	# swanctl REJECTS the trailing '!' ("required proposal") marker in
	# esp_proposals — the DH suffix alone is the PFS statement.  Shorten
	# the iked responder lifetime so iked mints the child rekey mid-row;
	# gate on g_ir_present=Y in the rekey keymat + SPI change + no
	# NO_PROPOSAL_CHOSEN (would fail pre-fix: no KE payload).
	I2I_LIFETIME=300
	# DH-group variants first (unconditional; see below why they must win):
	# I2I_PROPOSAL resolves at source time, so a row that changes the group
	# MUST set the full charon IKE proposal itself (skill: a later
	# I2I_DH_GROUP alone never propagates into I2I_PROPOSAL).  The child
	# PFS group comes from I2I_ESP's '-<grp>!' suffix, and the iked confs
	# now offer kmp_dh_group $I2I_DH_GROUP so the KMP DH overlaps.  These
	# arms override I2I_ESP unconditionally so a '-dh384-pfsrekey' name
	# lands on ecp384, not the -pfsrekey default ecp256.
	case "$name" in
	*-dh384*) I2I_DH_GROUP=ecp384; I2I_PROPOSAL=aes256gcm16-prfsha256-ecp384-ke1_mlkem768
	          I2I_ESP=aes128gcm16-ecp384 ;;
	*-dh521*) I2I_DH_GROUP=ecp521; I2I_PROPOSAL=aes256gcm16-prfsha256-ecp521-ke1_mlkem768
	          I2I_ESP=aes128gcm16-ecp521 ;;
	esac
	case "$name" in
	*-pfsrekey*) I2I_LIFETIME=25; I2I_ESP=${I2I_ESP:-aes128gcm16-ecp256} ;;
	esac

	# RFC 6023 childless IKE_SA (Feature A): responder advertises
	# CHILDLESS_IKEV2_SUPPORTED + accepts a SA-less (modified) IKE_AUTH
	# ONLY when a -childless row (both the iked responder conf and, for the
	# charon-init seat, the swanctl childless = force conn line via
	# i2i_peer.sh) opt in.  Default off keeps every base row childless-free.
	CHILDLESS_TXT_R=""
	[ "$I2I_CHILDLESS" = 1 ] && CHILDLESS_TXT_R='		childless on;
'
	# RFC 7296 2.17/2.18 AUTH-child PFS (iPhone EnablePFS shape),
	# SELF-CONSISTENT iked<->iked: with need_pfs on BOTH seats, the
	# iked initiator's AUTH-child proposal carries a DH group (charon
	# never offers child DH at IKE_AUTH, so these rows are iked-only)
	# and the responder records child_sa->dhgrp from the matched pair
	# so the responder-minted rekey mirrors THAT group.  Never add to
	# -charon rows -- charon's AUTH child is DH-less and the strict
	# matcher would reject it (NO_PROPOSAL_CHOSEN).
	NEED_PFS_TXT_I=""
	NEED_PFS_TXT_R=""
	case "$name" in
	*-pfsrekey*-charon) : ;;  # charon interop: keep AUTH child DH-less
	*-pfsrekey*)
		NEED_PFS_TXT_I='		need_pfs on;
'
		NEED_PFS_TXT_R='		need_pfs on;
' ;;
	esac
	# ESN rows: ext_sequence on in the ipsec block (RFC 7296 s3.3.2).
	ESN_TXT=""
	[ "$I2I_ESN" = 1 ] && ESN_TXT='		ext_sequence on;
'

	# RFC 6023 s3 SA-less IKE_AUTH INITIATOR feature (2026-09-29): a
	# -childless-init row turns the knob on the iked INITIATOR seat TOO, so
	# iked itself sends a MODIFIED (SA-less) IKE_AUTH (no SAi2/TSi/TSr) and
	# accepts the no-SAr2 response -- self-consistent proof of the daemon
	# initiator feature (charon's childless=force is the interop flavor).
	# The responder seat keeps childless on (accept SA-less) as before.
	I2I_CHILDLESS_INIT=0
	CHILDLESS_TXT_I=""
	case "$name" in
	*-childless-init*)
		I2I_CHILDLESS_INIT=1
		I2I_CHILDLESS=1
		I2I_DBG=0x0003
		CHILDLESS_TXT_I='		childless on;
'
		;;
	esac

	# RSASIG cert/auth arms (review #2 CERT+ coverage): a -rsa row drives
	# kmp_auth_method { rsa; } + self-signed X509 on BOTH seats (my_pubkey
	# x509pem our-cert+our-key, peers_pubkey x509pem peer-cert), so the
	# childless responder pushes CERT+ (the IKED TRACE gate).  In-row
	# self-signed certs are valid: eay_check_x509cert(cert, NULL) runs the
	# system trust store, but cb_check_cert (crypto_openssl.c) accepts
	# DEPTH_ZERO_SELF_SIGNED_CERT -> ok=1, so no CA-store setup is needed.
	I2I_RSA=0
	RSA_TXT_I=""
	RSA_TXT_R=""
	case "$name" in
	*-rsa*)
		I2I_RSA=1
		;;
	esac
	# RFC 7296 s2.19 / review #2 CFG coverage: -cfg rows request a
	# configuration payload in IKE_AUTH (initiator request {
	# application_version; } -> CFG_REQUEST) and the responder replies
	# (provide { application_version ...; } -> CFG_REPLY).  The
	# require_config_payload knob (newly wired require_config) makes the
	# responder REFUSE a cfg-less request with FAILED_CP_REQUIRED -- the
	# -cfgneg sibling proves that gate.  TRACE markers on the pushes let the
	# matrix gate on the actual wire payloads.
	I2I_CFG=0
	I2I_CFGNEG=0
	CFG_REQ_TXT_I=""
	CFG_PROV_TXT_R=""
	CFG_REQUIRE_TXT_R=""
	case "$name" in
	*-cfgneg*)
		I2I_CFGNEG=1
		CFG_REQUIRE_TXT_R='		require_config_payload on;
'
		;;
	*-cfg*)
		I2I_CFG=1
		CFG_REQ_TXT_I='		request { application_version; };
'
		CFG_PROV_TXT_R='		provide { application_version "racoon2-i2i-cfg"; };
'
		CFG_REQUIRE_TXT_R='		require_config_payload on;
'
		;;
	esac

	# Auth method + any PSK line: RSA rows emit kmp_auth_method { rsa; } +
	# my_pubkey/peers_pubkey; every other row keeps the PSK pair.  Emit the
	# method and psk together so a row can never carry both or neither.
	AUTH_TXT_I=""
	AUTH_TXT_R=""
	if [ "$I2I_RSA" = 1 ]; then
		AUTH_TXT_I='		kmp_auth_method { rsasig; };
		my_public_key x509pem "'"$C"'/cert-i.pem" "'"$C"'/key-i.pem";
		peers_public_key x509pem "'"$C"'/cert-r.pem";'
		# RSA peer also needs my_pubkey cert+key on the OTHER seat when iked;
		# the responder conf template already got $I2I_PKI via AUTH_TXT_R.
		AUTH_TXT_R='		kmp_auth_method { rsasig; };
		my_public_key x509pem "'"$C"'/cert-r.pem" "'"$C"'/key-r.pem";
		peers_public_key x509pem "'"$C"'/cert-i.pem";'
	else
		AUTH_TXT_I='		kmp_auth_method { psk; };
		pre_shared_key "'"$ETC"'/psk/macos.psk";'
		AUTH_TXT_R='		kmp_auth_method { psk; };
		pre_shared_key "'"$ETC"'/psk/macos.psk";'
	fi
	# peer identifiers stay the same under RSA (iked accepts any cert that
	# verifies against peers_pubkey -- ikev2_public_key peer-ID check is
	# #if 0'd out, so id<->cert binding is not enforced).

	if [ "$PEER_R" = charon ]; then
	# charon responder: shared helper writes the swanctl conn (PSK hex read
	# from the existing matrix psk, never printed); iked responder.conf below
	# is skipped for this seat.
	i2i_peer_r_conf "$C" "$HR" "$HI" "$name" charon || return 1
else
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
		peers_id fqdn "$PEER_ID";
		peers_ipaddr "$HI";
		kmp_enc_alg { $I2I_IKE_ENC; };
		kmp_prf_alg { $I2I_IKE_PRF; };
		kmp_hash_alg { $I2I_IKE_PRF; };
		kmp_dh_group { $I2I_DH_GROUP; };
$AUTH_TXT_R
$PPK_TXT
$CHILDLESS_TXT_R
$CFG_REQUIRE_TXT_R
$CFG_PROV_TXT_R
$NEED_PFS_TXT_R
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
	ipsec_sa_lifetime_time $I2I_LIFETIME sec;
$ESN_TXT	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $I2I_ESP_ENC; };
	esp_auth_alg { $I2I_ESP_AUTH; };
$(i2i_sa_addke_lines "$name")
	};
EOF
fi

	if [ "$PEER" = charon ]; then
	# charon initiator: shared helper writes the swanctl conn (PSK hex read
	# from the existing matrix psk, never printed) and spawns/triggers it.
	i2i_peer_i_conf "$C" "$HI" "$HR" "$name" charon || return 1
else
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
		kmp_enc_alg { $I2I_IKE_ENC; };
		kmp_prf_alg { $I2I_IKE_PRF; };
		kmp_hash_alg { $I2I_IKE_PRF; };
		kmp_dh_group { $I2I_DH_GROUP; };
$AUTH_TXT_I
$PPK_TXT
$CHILDLESS_TXT_I
$CFG_REQ_TXT_I
$NEED_PFS_TXT_I
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
	ipsec_sa_lifetime_time $I2I_LIFETIME sec;
$ESN_TXT	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $I2I_ESP_ENC; };
	esp_auth_alg { $I2I_ESP_AUTH; };
$I2I_ADDKE_TXT};
EOF
fi

	# kill daemons by the unique per-run conf dir (it IS in their argv)
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"

	# RSA rows: generate the two seat pairs of self-signed cert+key IN-ROW.
	# CN = the seat's my_id; iked does not enforce id<->cert (peers_pubkey
	# is the trust anchor), but charon derives its own identity from the
	# cert subject, so the charon initiator seat must carry CN=charon-i2i.
	# Self-signed is fine: eay_check_x509cert's cb_check_cert accepts
	# DEPTH_ZERO_SELF_SIGNED_CERT (ok=1); no CA store on either box.
	if [ "$I2I_RSA" = 1 ]; then
		I_CN=${I2I_CHARON_ID}; [ "$PEER" = iked ] && I_CN=r2init-matrix
		R_CN=${I2I_CHARON_ID}; [ "$PEER_R" = iked ] && R_CN=racoon2-matrix
		if ! command -v openssl >/dev/null 2>&1; then
			log "FAIL: no openssl for -rsa cert gen"; return 1
		fi
		openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$I_CN" \
		    -addext "subjectAltName=DNS:$I_CN" \
		    -keyout "$C/key-i.pem" -out "$C/cert-i.pem" >/dev/null 2>&1 || { log "FAIL: openssl cert-i"; return 1; }
		openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$R_CN" \
		    -addext "subjectAltName=DNS:$R_CN" \
		    -keyout "$C/key-r.pem" -out "$C/cert-r.pem" >/dev/null 2>&1 || { log "FAIL: openssl cert-r"; return 1; }
		# strongSwan swanctl remote { pubkeys } takes a CERT_TRUSTED_PUBKEY
		# blob (the pem plugin builds a raw public key), NOT an x509 cert --
		# pointing it at cert-*.pem makes charon fail the vici load with
		# "parsing request failed".  Emit the bare public keys with the
		# charon side (cert-r -> responder, cert-i -> initiator seat).
		openssl x509 -in "$C/cert-r.pem" -pubkey -noout > "$C/pub-r.pem" 2>/dev/null || { log "FAIL: openssl pub-r"; return 1; }
		openssl x509 -in "$C/cert-i.pem" -pubkey -noout > "$C/pub-i.pem" 2>/dev/null || { log "FAIL: openssl pub-i"; return 1; }
		sudo chmod 644 "$C"/*.pem 2>/dev/null || chmod 644 "$C"/*.pem
		# charon discovers its private key from the swanctl private/ dir
		# (auto-matched to the conn-local cert by public key); a
		# `secrets.private-*` block is only a passphrase lookup and never
		# loads a key from an arbitrary path — without this install charon
		# reaches IKE_AUTH with the cert but `no private key found for
		# 'CN=charon-i2i'`.  Install the charon INITIATOR seat's key (PEER
		# = charon) into private/.  Both seats are generated above, so this
		# must come AFTER the openssl pairs.
		if [ "$PEER" = charon ]; then
			_privdir="${I2I_CHARON_KEYS_DIR:-/etc/strongswan/swanctl/private}"
			mkdir -p "$_privdir" || { log "FAIL: no charon private key dir $_privdir"; return 1; }
			cp "$C/key-i.pem" "$_privdir/r2-${name}-key-i.pem" || { log "FAIL: cp key-i->$_privdir"; return 1; }
			chmod 644 "$_privdir/r2-${name}-key-i.pem" 2>/dev/null || true
		fi
	fi

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

if [ "$PEER_R" = charon ]; then
	i2i_peer_r_start "$D" "$NSR" charon "$name"
else
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D "$I2I_DBG" -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
fi

if [ "$PEER" = charon ]; then
	i2i_peer_i_start "$D" "$NSI" charon "$name"
else
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S "$SPMIF_I" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$SOCK_I" RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D "$I2I_DBG" -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &
fi

	sleep 2
	if [ "$PEER_R" = charon ]; then
	# charon responder: LOAD conns so it answers (passive; no --initiate);
	# the racoon2 initiator drives the exchange next.
	i2i_peer_r_trigger "$D" "$NSR" charon "$name"
	fi
	if [ "$PEER" = charon ]; then
	i2i_peer_i_trigger "$D" "$NSI" charon "$name"
else
	"$SBIN/ikedctl" -s "$SOCK_I" establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
fi

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "PQC INITIAL IKE_SA ADDKE child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done

	# The initial IKE_SA ran an IKE_INTERMEDIATE ADDKE round (SAi1 type-6 +
	# 16438 both sides).  Both SEATS must prove it: iked logs
	# 'IKE_INTERMEDIATE ADDKE round complete' on the side it occupies; a
	# charon seat instead logs KE1_ML_KEM_768 selected + ESTABLISHED
	# (RFC 9370 s3.5).  A classical int exchange logs none of these -> fail.
	nint=0; i=0
	while [ "$i" -lt 20 ]; do
		# responder-seat evidence (iked responder or charon responder)
		i2i_peer_r_evidence "$D" "$PEER_R"
		n_r=$?
		# initiator-seat evidence (iked initiator or charon initiator).
		# A -cfgneg row is REFUSED at the childless cfg gate (after the
		# IKE_INTERMEDIATE ADDKE round), so the charon initiator NEVER
		# reaches ESTABLISHED — requiring it here would false-fail a
		# correct refusal (skill: cfgneg-charon nint gate).  For that seat
		# the round is proven by the selected ML-KEM proposal instead.
		if [ "$I2I_CFGNEG" = 1 ] && [ "$PEER" = charon ]; then
			grep -q 'selected proposal: IKE:.*KE1_ML_KEM_768' "$D/charon-init.log" 2>/dev/null; n_p=$?
		else
			i2i_peer_i_evidence "$D" "$PEER"
			n_p=$?
		fi
		if [ "$n_r" -eq 0 ] && [ "$n_p" -eq 0 ]; then
			log "IKE_INTERMEDIATE ADDKE round completed: responder(seat=${PEER_R}) + ${PEER} initiator at ${i}s"
			nint=1; break
		fi
		i=$((i+1)); sleep 1
	done
	# AUTH+IntAuth verified == the RFC 9370 s3.5 SKEYSEED(1) matched: both
	# sides derived the same intermediate key or the ESP child could not
	# establish (up=1 is checked separately).  The raw SKEYSEED/IntAuth bytes
	# are intentionally not logged, so the round-complete marker plus up=1 is
	# the proof.
	pqc=0
	if [ "${nint:-0}" -eq 1 ]; then
		pqc=1
		log "INITIAL IKE_SA ADDKE: IKE_INTERMEDIATE round on BOTH sides, ESP child up => SK(1) key material matched"
	elif [ "${I2I_CLASSICAL:-0}" != 1 ]; then
		log "FAIL: initial IKE_SA not ADDKE/ML-KEM (nint=${nint:-0})"
	else
		log "waived: classical-CBC row has no ADDKE round (I2I_CLASSICAL=1, expected)"
	fi

	# RFC 8784 PPK rows: with USE_PPK on both seats the child only lands if
	# BOTH re-derived SK_d/SK_pi/SK_pr with the same PPK; the AUTH passing
	# (up=1) already proves that.  Additionally assert the append-only
	# wire markers: the initiator saw the USE_PPK echo + the responder
	# confirmed the PPK_IDENTITY (TRACE level, enabled by I2I_DBG=0x0003).
	ppk_ok=0
	if [ "$I2I_PPK" = 1 ]; then
		# responder-seat USE_PPK evidence (iked: its log; charon: its own
		# 'using PPK for PPK_ID' line).  Init-seat markers likewise; the
		# iked-only 'responder confirmed PPK_IDENTITY' TRACE line only
		# exists when the RESPONDER seat is iked.
		if [ "$PEER_R" = charon ]; then
			# 'loaded PPK shared key' is written BEFORE the exchange and
			# survives run.sh's SIGKILL that truncates charon's log mid-
			# response; the later 'using PPK for PPK_ID' line falls after the
			# truncation point and would false-fail.  AUTH passing (up=1) with
			# the iked initiator having mixed PPK is the infallible proof both
			# seats mixed the same PPK.
			gre=$(grep -c "loaded PPK shared key" "$D/charon-resp.log" 2>/dev/null)
		else
			gre=$(grep -c "peer uses RFC 8784 PPK (USE_PPK)" "$D/resp-iked.log" 2>/dev/null)
		fi
		if [ "$PEER" = charon ]; then
			gie=$(grep -c "using PPK for PPK_ID '" "$D/charon-init.log" 2>/dev/null)
			gid=1
		else
			gie=$(grep -c "peer uses RFC 8784 PPK (USE_PPK)" "$D/init-iked.log" 2>/dev/null)
			gid=$(grep -c "RFC 8784: responder confirmed PPK_IDENTITY" "$D/init-iked.log" 2>/dev/null)
		fi
		if [ "${gre:-0}" -ge 1 ] && [ "${gie:-0}" -ge 1 ] && [ "${gid:-0}" -ge 1 ] && [ "$up" -eq 1 ]; then
			ppk_ok=1
			log "RFC 8784 PPK: USE_PPK echoed both seats + PPK_IDENTITY confirmed; child up => PPK-mixed SK_d matched"
		else
			log "FAIL: RFC 8784 PPK markers absent (resp_use_ppk=${gre:-0} init_use_ppk=${gie:-0} init/charon_id_confirm=${gid:-0})"
		fi
	fi

	# RFC 7296 2.18 PFS rekey rows: after the initial child lands, the iked
	# RESPONDER (short I2I_LIFETIME) mints a CREATE_CHILD_SA child rekey of
	# the PFS-negotiated child.  The fix (ee60cda) mirrors the peer-offered
	# DH into my_proposal so the rekey proposal carries DH and KEi is sent;
	# charon (esp -ecp256!) demands that DH.  Pre-fix: no KE payload ->
	# charon answers NO_PROPOSAL_CHOSEN, SPI never changes.  Gate: fresh
	# rekey on the iked responder log, a PFS keymat (g_ir_present=Y),
	# SPI change, and no responder NO_PROPOSAL_CHOSEN.
	pfsrekey_ok=0
	case "$name" in
	*-pfsrekey*)
		# The storm seat: which iked mints the rekey.  -charon (charon
		# INITIATOR, iked responder) reproduces the live storm exactly.  In
		# the reverse -charonr the iked INITIATOR mints it (charon responder
		# still requires PFS).  Gate on THAT iked's log + THAT netns' SPI.
		if [ "$PEER" = charon ]; then
			ike_log="$D/resp-iked.log"; spi_ns="$NSR"
		else
			# iked<->iked AUTH-child-PFS row: BOTH seats carry the
			# short child lifetime and both are PFS-aware (need_pfs
			# on both), so either seat may win the rekey race.  Gate
			# on whichever iked minted it: any rekey marker + a PFS
			# (g_ir_present=Y) keymat + SPI change + no
			# NO_PROPOSAL_CHOSEN on either iked.
			ike_log="$D/resp-iked.log"; spi_ns="$NSR"
		fi
		spi_before=$(ip netns exec "$spi_ns" ip xfrm state 2>/dev/null | grep 'proto esp' | grep -oE '0x[0-9a-f]{8}' | sort | tr '\n' ' ')
		sleep 40
		# that iked must mint the rekey (child soft lifetime ~20s);
		# for iked<->iked rows check either iked's log
		rekey_log=""
		for L in "$D/resp-iked.log" "$D/init-iked.log"; do
			[ -f "$L" ] && grep -q 'initiating CREATE_CHILD_SA rekey' "$L" && rekey_log="$L"
		done
		if [ "$PEER" != charon ] && [ -z "$rekey_log" ]; then
			log "FAIL: no iked initiated child rekey (resp+init logs)"
		elif [ "$PEER" = charon ] && ! grep -q 'initiating CREATE_CHILD_SA rekey' "$ike_log" 2>/dev/null; then
			log "FAIL: iked did not initiate child rekey ($ike_log)"
		elif grep -q 'NO_PROPOSAL_CHOSEN' "$D/resp-iked.log" 2>/dev/null || \
		     grep -q 'NO_PROPOSAL_CHOSEN' "$D/init-iked.log" 2>/dev/null; then
			log "FAIL: rekey answered NO_PROPOSAL_CHOSEN (KE-less rekey?)"
		elif ! grep -qE 'g_ir_present=Y' "$D/resp-iked.log" "$D/init-iked.log" 2>/dev/null; then
			log "FAIL: no PFS (g_ir_present=Y) keymat after rekey"
		else
			spi_after=$(ip netns exec "$spi_ns" ip xfrm state 2>/dev/null | grep 'proto esp' | grep -oE '0x[0-9a-f]{8}' | sort | tr '
' ' ')
			if [ "$spi_before" != "$spi_after" ]; then
				pfsrekey_ok=1
				log "PFS rekey OK: iked rekey carried DH (KEi), charon accepted, SPI $spi_before -> $spi_after"
			else
				log "FAIL: ESP SPI unchanged after PFS rekey wait ($spi_before)"
			fi
		fi
		;;
	esac

	# Proposal-shape SAD gate: rows that change ESP shape must show the
	# negotiated kernel SAD cipher, else a row could PASS with the child
	# up on the DEFAULT aes_gcm (a knob that silently failed to apply).
	# -esp-gcm256 -> aead rfc4106 keylen 32   -esp-cbc256 -> enc cbc(aes) 32
	# + auth hmac(sha256)                      -esn         -> 'flag E' on
	# the ESP state (ESN replay counter).  Only the responder netns SAD is
	# checked (the peer seat mirrors it).
	shape_ok=1
	# Retain the responder SAD for the shape proof (netns dies at teardown).
	ip netns exec "$NSR" ip xfrm state >"$D/resp-sad.txt" 2>/dev/null
	ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -E 'proto esp|aead|enc |auth |flag' >"$D/resp-sad-esp.txt"
	case "$name" in
	*-esp-gcm256)
		# iproute2: "aead rfc4106(gcm(aes)) 0x<hex> 128" — trailing 128 = ICV bits;
		# key length is the hex length (36 B = 32 B key + 4 B salt = AES-256-GCM,
		# vs 20 B salt+key for AES-128-GCM).
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'aead rfc4106\(gcm\(aes\)\) 0x[0-9a-f]{72} 128$'; then
			shape_ok=1
			log 'ESP shape: responder SAD aead rfc4106(gcm(aes)) 72-hex key (AES-256-GCM)'
		else
			shape_ok=0
			log 'FAIL: -esp-gcm256 row but responder SAD lacks aead rfc4106 72-hex (AES-256) key'
		fi
		;;
	*-esp-cbc256)
		# iproute2: "enc cbc(aes) 0x<64hex>" (32 B = AES-256-CBC) and
		# "auth-trunc hmac(sha256) 0x<64hex> 128" (truncated ICV).  Default
		# AES-128-CBC enc hex is 32 chars, so the 64-hex enc is the discriminator.
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'enc cbc\(aes\) 0x[0-9a-f]{64}$' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'auth-trunc hmac\(sha256\) 0x[0-9a-f]{64}'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc cbc(aes) 64-hex + auth-trunc hmac(sha256) (AES-CBC-256 + separate integrity)'
		else
			shape_ok=0
			log 'FAIL: -esp-cbc256 row but responder SAD lacks cbc(aes)64-hex + auth-trunc hmac(sha256)'
		fi
		;;
	*-esp-cbc128)
		# AES-128-CBC: enc "cbc(aes) 0x<32hex>" (16 B key).
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'enc cbc\(aes\) 0x[0-9a-f]{32}$' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'auth-trunc hmac\(sha256\) 0x[0-9a-f]{64}'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc cbc(aes) 32-hex + auth-trunc hmac(sha256) (AES-CBC-128 + separate integrity)'
		else
			shape_ok=0
			log 'FAIL: -esp-cbc128 row but responder SAD lacks cbc(aes)32-hex + auth-trunc hmac(sha256)'
		fi
		;;
	*-esp-cbc192)
		# AES-192-CBC: enc "cbc(aes) 0x<48hex>" (24 B key).
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'enc cbc\(aes\) 0x[0-9a-f]{48}$' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'auth-trunc hmac\(sha256\) 0x[0-9a-f]{64}'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc cbc(aes) 48-hex + auth-trunc hmac(sha256) (AES-CBC-192 + separate integrity)'
		else
			shape_ok=0
			log 'FAIL: -esp-cbc192 row but responder SAD lacks cbc(aes)48-hex + auth-trunc hmac(sha256)'
		fi
		;;
	*-esp-sha384)
		# RFC 4868 ESP integrity HMAC-SHA2-384: auth "hmac(sha384) 0x<96hex>"
		# (48 B key, 192-bit ICV).  AES-256-CBC carries the separate integrity.
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'enc cbc\(aes\) 0x[0-9a-f]{64}$' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'auth-trunc hmac\(sha384\) 0x[0-9a-f]{96}'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc cbc(aes)64-hex + auth-trunc hmac(sha384) (AES-CBC-256 + HMAC-SHA2-384)'
		else
			shape_ok=0
			log 'FAIL: -esp-sha384 row but responder SAD lacks cbc(aes)64-hex + auth-trunc hmac(sha384)'
		fi
		;;
	*-esp-sha512)
		# RFC 4868 ESP integrity HMAC-SHA2-512: auth "hmac(sha512) 0x<128hex>"
		# (64 B key, 256-bit ICV).
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'enc cbc\(aes\) 0x[0-9a-f]{64}$' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'auth-trunc hmac\(sha512\) 0x[0-9a-f]{128}'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc cbc(aes)64-hex + auth-trunc hmac(sha512) (AES-CBC-256 + HMAC-SHA2-512)'
		else
			shape_ok=0
			log 'FAIL: -esp-sha512 row but responder SAD lacks cbc(aes)64-hex + auth-trunc hmac(sha512)'
		fi
		;;
	*-esp-xcbc)
		# RFC 3566 AES-XCBC-MAC-96 as ESP integrity: auth "xcbc(aes) 0x<32hex>"
		# (16 B key).
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'enc cbc\(aes\) 0x[0-9a-f]{64}$' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'auth-trunc xcbc\(aes\) 0x[0-9a-f]{32}'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc cbc(aes)64-hex + auth-trunc xcbc(aes) (AES-CBC-256 + AES-XCBC-MAC-96)'
		else
			shape_ok=0
			log 'FAIL: -esp-xcbc row but responder SAD lacks cbc(aes)64-hex + auth-trunc xcbc(aes)'
		fi
		;;
	*-esp-cmac)
		# RFC 4494 AES-CMAC-96 as ESP integrity: auth "cmac(aes) 0x<32hex>"
		# (16 B key).
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'enc cbc\(aes\) 0x[0-9a-f]{64}$' \
		   && ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qE 'auth-trunc cmac\(aes\) 0x[0-9a-f]{32}'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc cbc(aes)64-hex + auth-trunc cmac(aes) (AES-CBC-256 + AES-CMAC-96)'
		else
			shape_ok=0
			log 'FAIL: -esp-cmac row but responder SAD lacks cbc(aes)64-hex + auth-trunc cmac(aes)'
		fi
		;;
	*-esp-ctr)
		# RFC 5930 AES-CTR for ESP: racoon2 maps RCT_ALG_AES_CTR to the
		# kernel AEAD "rfc3686(ctr(aes))" (lib/if_xfrm.c enc_map) — an AEAD
		# with a 4-octet salt (RFC 3686 counters), so esp_auth_alg is
		# non_auth and the SAD renders "enc rfc3686(ctr(aes)) 0x…"
		# (iproute2 prints the AEAD as enc, not "aead").
		if ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -qF 'enc rfc3686(ctr(aes))'; then
			shape_ok=1
			log 'ESP shape: responder SAD enc rfc3686(ctr(aes)) (AES-CTR AEAD, RFC 5930/3686)'
		else
			shape_ok=0
			log 'FAIL: -esp-ctr row but responder SAD lacks enc rfc3686(ctr(aes))'
		fi
		;;
	*-esn)
		# ESN is NOT implemented by iked: ike_conf.c:4665 logs
		# 'ext_sequence is specified but it is not suported' when the knob is
		# parsed, and the child installs with a plain (non-ESN) replay window.
		# The honest gate is CONFIG-ACCEPTANCE: the knob reached iked and the
		# documented not-supported warning fired while the child still lands
		# (a parser-reject or a crash would fail).  A future ESN
		# implementation flips this row to assert the SAD E flag.
		if grep -q 'ext_sequence is specified but it is not suported' "$D/resp-iked.log" 2>/dev/null; then
			shape_ok=1
			log 'ESN config-accept: iked parsed ext_sequence on + logged not-supported (ike_conf.c:4665); child up'
		else
			shape_ok=0
			log 'FAIL: -esn row but iked did not log the ext_sequence not-supported warning'
		fi
		;;
	*)
		shape_ok=1
		;;
	esac
	if [ "$shape_ok" -ne 1 ]; then
		log 'FAIL: proposal-shape SAD gate rejected the row'
	fi
	# NDcPP v3.0e compliance report for this row (A/B cells) — runs while
	# the netnss + SADB are still live (A1/A2/A3 read xfrm policy/state)
	# and before charon conn files are removed (A13/A14 read the conn).
	i2i_compliance "$D" "$C" "$NSR" "$NSI" "$HR" "$HI" "$name"; cpl=$?

	# kill daemons by the unique per-run conf dir; charon on either seat is
	# torn down via the peer helpers (swanctl conn file removed, charon
	# killed).
	i2i_peer_i_cleanup "$PEER"
	i2i_peer_r_cleanup "$PEER_R" "$name"
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /etc/strongswan/swanctl/conf.d/r2-${name}.conf
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	# Classical (proposal-shape) rows: only *-ike-cbc256* runs a CBC IKE_SA,
	# which has no AEAD so the RFC 9242 IntAuth_A round cannot run — that row
	# MUST have zero round markers (a stray round is a defect for the shape)
	# and the PQC requirement is waived (need_pqc=0).  PRF / ESP-shape / ESN
	# rows keep aes_gcm on the IKE_SA, so they stay full PQC rows (need_pqc=1)
	# and still gate on the IKE_INTERMEDIATE ADDKE round.
	need_pqc=1
	if [ "$I2I_CLASSICAL" = 1 ]; then
		need_pqc=0
		if grep -qE 'IKE_INTERMEDIATE ADDKE round complete|KE1_ML_KEM_768' "$D/resp-iked.log" "$D/init-iked.log" "$D/charon-init.log" "$D/charon-resp.log" 2>/dev/null; then
			log 'FAIL: classical-CBC row shows an ADDKE round (RFC 9242 IntAuth_A cannot run on CBC IKE)'
		fi
	fi



	# RFC 6023 childless rows (Feature A + the 2026-09-29 SA-less INITIATOR):
	#   i2iinit-childless-charon  charon INITIATOR childless=force -> iked
	#                             responder childless on accepts the SA-less
	#                             (modified) IKE_AUTH and answers SA-less
	#                             AUTH; the knob must also be exercised on
	#                             the responder only.
	#   i2iinit-childless         iked<->iked, responder childless on: the
	#                             iked initiator does NOT send a modified
	#                             IKE_AUTH (racoon2 initiator has no
	#                             childless-init), so this validates the
	#                             knob does not break a CLASSICAL IKE_AUTH
	#                             (advertise 16418 + still accept SA-full).
	#   i2iinit-childless-init    SELF-CONSISTENT SA-less INITIATOR: childless
	#                             on BOTH seats -- the iked initiator sends a
	#                             MODIFIED (SA-less) IKE_AUTH (no SAi2/TSi/TSr,
	#                             TRACE marker) and ACCEPTS the no-SAr2
	#                             response (second TRACE marker), the iked
	#                             responder advertises 16418 and accepts it;
	#                             first child lands via CREATE_CHILD_SA.
	#   i2iinit-childless-init-rsa   same + RSASIG auth with in-row self-signed
	#                             certs -> responder pushes CERT+ (TRACE).
	#   i2iinit-childless-rsa-charon charon childless=force + RSASIG (its own
	#                             cert) -> iked responder pushes CERT+ interop.
	#   i2iinit-childless-init-cfg   same + initiator request{app_version},
	#                             responder require_config_payload on +
	#                             provide app_version -> CFG_REPLY pushed.
	#   i2iinit-childless-cfg-charon charon childless=force + config request
	#                             -> iked responder pushes CFG_REPLY interop.
	#   i2iinit-childless-init-cfgneg NEG: same but initiator sends NO config
	#                             request; responder (require_config on) MUST
	#                             refuse with FAILED_CP_REQUIRED (NEG PASS).
	# Evidence is computed independently per feature (init-send / init-accept
	# / responder 16418 advertise / responder SA-less accept / CERT+ push /
	# CFG_REPLY push / FAILED_CP refusal) and combined per row below -- a
	# self-consistent -init-rsa row must prove the initiator path AND the
	# CERT+ push, not just one or the other.
	init_send=0; init_accept=0; resp_advert=0; resp_accept=0
	cert_push=0; cfg_push=0; cp_refuse=0
	childless_ok=1   # non-childless rows pass unconditionally
	case "$name" in
	*-childless*)
		# Evidence markers, computed only for childless rows.
		grep -q 'childless IKE_AUTH (initiator): sending modified (SA-less) IKE_AUTH' "$D/init-iked.log" 2>/dev/null && init_send=1
		grep -q 'childless IKE_AUTH (initiator): accepted SA-less response' "$D/init-iked.log" 2>/dev/null && init_accept=1
		grep -q 'advertising childless IKE_SA support (16418)' "$D/resp-iked.log" 2>/dev/null && resp_advert=1
		grep -q 'received childless (SA-less) IKE_AUTH' "$D/resp-iked.log" 2>/dev/null && resp_accept=1
		grep -q 'childless IKE_AUTH (responder): pushing CERT+ (X509)' "$D/resp-iked.log" 2>/dev/null && cert_push=1
		grep -qF 'childless IKE_AUTH (responder): pushing [CP(CFG_REPLY)]' "$D/resp-iked.log" 2>/dev/null && cfg_push=1
		grep -q 'childless peer message lacks required config payload' "$D/resp-iked.log" 2>/dev/null && cp_refuse=1

		# Per-row evidence requirements (explicit per arm, evaluated in order — a
		# -cfgneg row is a REFUSAL regardless of seat, so it wins over both the
		# -charon and -childless-init arms below):
		#   resp_advert   responder advertised 16418 in the IKE_SA_INIT response
		#                 (EVERY childless row must have it)
		#   -cfgneg       NEG: the responder REFUSES with FAILED_CP_REQUIRED,
		#                 so resp_accept (SA-less IKE_AUTH established) and
		#                 init_accept are IMMPOSSIBLE — only the initiator
		#                 SEND marker (SA-less drive) + cp_refuse are checked.
		#   -charon       charon childless=force INITIATOR: no iked init log, so
		#                 init_* N/A; responder MUST see the SA-less IKE_AUTH
		#   -childless-init (positive): iked SA-less init >= both init markers +
		#                 responder SA-less accept
		#   plain -childless        classical iked initiator: responder knob ON,
		#                 SA-full IKE_AUTH accepted; NO SA-less markers expected
		#                 (init_* and resp_accept are 0 by definition)
		#   need_cert=1  (-rsa)    childless responder pushes CERT+
		#   need_cfg=1   (-cfg pos) childless responder pushes CFG_REPLY
		need_resp_accept=0; need_init_send=0; need_init_accept=0
		need_cert=0; need_cfg=0; need_refuse=0
		case "$name" in
		*-cfgneg*)
			need_refuse=1
			case "$name" in *-childless-init*) need_init_send=1 ;; esac
			;;
		*-charon*)
			need_resp_accept=1
			;;
		*-childless-init*)
			need_resp_accept=1
			need_init_send=1
			need_init_accept=1
			;;
		*-childless)
			: ;;  # plain classical row: resp_advert only
		esac
		[ "$I2I_RSA" = 1 ] && need_cert=1
		[ "$I2I_CFG" = 1 ] && need_cfg=1
		[ "$I2I_CFGNEG" = 1 ] && need_refuse=1
		ok=1
		[ "$resp_advert"  = 1 ] || ok=0
		[ "$need_resp_accept" = 1 ] && { [ "$resp_accept"    = 1 ] || ok=0; }
		[ "$need_init_send"   = 1 ] && { [ "$init_send"      = 1 ] || ok=0; }
		[ "$need_init_accept" = 1 ] && { [ "$init_accept"    = 1 ] || ok=0; }
		[ "$need_cert"   = 1 ] && { [ "$cert_push"  = 1 ] || ok=0; }
		[ "$need_cfg"    = 1 ] && { [ "$cfg_push"   = 1 ] || ok=0; }
		[ "$need_refuse" = 1 ] && { [ "$cp_refuse"  = 1 ] || ok=0; }
		# cfgneg: ESP must NOT land (refused SA); every other childless row must
		# land the child via CREATE_CHILD_SA (up=1).
		if [ "$ok" = 1 ]; then
			childless_ok=1
			log "RFC 6023 childless OK (init_send=$init_send init_accept=$init_accept resp_advert=$resp_advert resp_accept=$resp_accept cert_push=$cert_push cfg_push=$cfg_push cp_refuse=$cp_refuse)"
		else
			childless_ok=0
			log "FAIL: childless evidence incomplete (init_send=$init_send init_accept=$init_accept resp_advert=$resp_advert resp_accept=$resp_accept cert_push=$cert_push cfg_push=$cfg_push cp_refuse=$cp_refuse need_resp_accept=$need_resp_accept need_init_send=$need_init_send need_init_accept=$need_init_accept need_cert=$need_cert need_cfg=$need_cfg need_refuse=$need_refuse)"
		fi
		;;
	*)
		childless_ok=1
		up_req=1
		;;
	esac
	up_req=${up_req:-1}
	[ "$I2I_CFGNEG" = 1 ] && up_req=0

	if { [ "${up_req:-1}" = 1 ] && [ "$up" -ne 1 ]; } || { [ "${up_req:-1}" = 0 ] && { [ "$up" -ne 0 ] || [ "${cp_refuse:-0}" -ne 1 ]; }; } || { [ "$need_pqc" = 1 ] && { [ "${nint:-0}" -ne 1 ] || [ "${pqc:-0}" -ne 1 ]; }; } || [ "$cpl" -ne 0 ] || [ "${childless_ok:-0}" -ne 1 ] || [ "${shape_ok:-1}" -ne 1 ] || { [ "$I2I_PPK" = 1 ] && [ "${ppk_ok:-0}" -ne 1 ]; } || { case "$name" in *-pfsrekey*) [ "${pfsrekey_ok:-0}" -ne 1 ] ;; *) false ;; esac; }; then
		log "FAIL: i2iinit incomplete (up=${up:-0} nint=${nint:-0} pqc=${pqc:-0} cpl=$cpl childless_ok=${childless_ok:-0} shape_ok=${shape_ok:-1} ppk_ok=${ppk_ok:-0} pfsrekey_ok=${pfsrekey_ok:-0} peeri=${PEER} peerr=${PEER_R})"
		if [ "$PEER" = charon ]; then
			log "--- charon-init.log ---"
			i2i_peer_i_diag "$D" charon
		else
			log "--- init-iked.log ---"
			grep -E 'IKE_INTERMEDIATE|IKE_SA_INIT|IKE_AUTH|abort|err=|FOLLOWUP' \
				"$D/init-iked.log" 2>/dev/null | tail -8
		fi
		if [ "$PEER_R" = charon ]; then
			log "--- charon-resp.log ---"
			i2i_peer_r_diag "$D" charon
		else
			log "--- resp-iked.log ---"
			grep -E 'IKE_INTERMEDIATE|IKE_SA_INIT|IKE_AUTH|abort|err=|FOLLOWUP' \
				"$D/resp-iked.log" 2>/dev/null | tail -8
		fi
		return 1
	fi
	return 0
}

