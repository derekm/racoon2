#!/bin/sh
# kinds/i2ipubkey.sh — X.509 public-key (cert) authentication, iked<->iked.
#
# Both seats configure kmp_auth_method { rsasig; } (RSA) or { ecdsa; }
# (ECDSA, methods 9/10/11), a per-run self-signed test CA signs leaf certs
# for BOTH seats, my_public_key/peers_public_key point at the leaf cert
# files, and NO pre_shared_key is set anywhere => the IKE_AUTH step can only
# succeed through the PK path.  The test CA is made visible to iked's
# chain-verify (eay_check_x509cert -> X509_STORE_set_default_paths) via the
# SSL_CERT_FILE env var set per-daemon (the system trust store is never
# touched, so the host state is unchanged and the run stays self-contained).
#
# Gate: ESP child UP on both seats (proves IKE_AUTH authenticated), the iked
# TRACE 'auth method %d' (1 = RSASIG, 9/10/11 = ECDSA) on BOTH seats, and CPL.
# Row suffix selects the method: i2ipubkey-rsa | i2ipubkey-ecdsa.
kind_i2ipubkey() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }

	# defaults: RSA
	AUTH_METHOD=rsasig
	AUTH_HEX=1
	EXP_METHOD='auth method 1'
	CURVE=''
	case "$name" in
	*-ecdsa) AUTH_METHOD=ecdsa; AUTH_HEX=10; EXP_METHOD='auth method 10'; CURVE='P-384' ;;
	esac

	PEER=$(i2i_peer "$name")
	PEER_R=$(i2i_peer_r "$name")
	PEER_ID=$(i2i_peer_resp_id "$PEER")
	if [ "$PEER" != iked ] || [ "$PEER_R" != iked ]; then
		log "FAIL: i2ipubkey is iked<->iked only (got i=$PEER r=$PEER_R)"
		return 1
	fi

	NSR=i2pub-r; NSI=i2pub-i; VR=i2pub-vr; VI=i2pub-vi
	HR=192.0.6.1; HI=192.0.6.2
	PRIVRES_R=/tmp/r2-i2pubkey-resume-r; PRIVRES_I=/tmp/r2-i2pubkey-resume-i
	D=/tmp/r2-i2pubkey; C=/tmp/r2-i2pubkey-conf
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C" "$C/certs"

	if ! command -v openssl >/dev/null 2>&1; then
		log "FAIL: no openssl on this host"; return 1
	fi

	# --- build the test PKI: CA + one leaf per seat ------------------------
	# All keys are generated at run time, used once, then deleted with $C; no
	# key material is ever committed.  openssl 3.x writes PKCS#8 by default,
	# which eay_get_pkcs1privkey (PEM_read_PrivateKey) accepts.
	if [ "$AUTH_METHOD" = ecdsa ]; then
		openssl ecparam -name "$CURVE" -genkey -noout -out "$C/certs/ca.key" 2>/dev/null \
			|| { log "FAIL: openssl ecparam genkey"; return 1; }
	else
		openssl genrsa -out "$C/certs/ca.key" 2048 2>/dev/null \
			|| { log "FAIL: openssl genrsa ca"; return 1; }
	fi
	openssl req -new -x509 -key "$C/certs/ca.key" -out "$C/certs/ca.crt" -days 3650 \
		-subj "/CN=r2-matrix-test-ca" 2>/dev/null \
		|| { log "FAIL: openssl req ca self-signed"; return 1; }

	for seat in init resp; do
		if [ "$AUTH_METHOD" = ecdsa ]; then
			openssl ecparam -name "$CURVE" -genkey -noout -out "$C/certs/$seat.key" 2>/dev/null \
				|| { log "FAIL: ecparam $seat"; return 1; }
		else
			openssl genrsa -out "$C/certs/$seat.key" 2048 2>/dev/null \
				|| { log "FAIL: genrsa $seat"; return 1; }
		fi
		openssl req -new -key "$C/certs/$seat.key" -out "$C/certs/$seat.csr" \
			-subj "/CN=r2-matrix-$seat" 2>/dev/null \
			|| { log "FAIL: req $seat"; return 1; }
		openssl x509 -req -in "$C/certs/$seat.csr" -CA "$C/certs/ca.crt" \
			-CAkey "$C/certs/ca.key" -CAcreateserial -out "$C/certs/$seat.crt" -days 3650 2>/dev/null \
			|| { log "FAIL: x509 $seat"; return 1; }
	done
	openssl x509 -in "$C/certs/ca.crt" -noout 2>/dev/null || { log "FAIL: ca.crt unreadable"; return 1; }

	# Both seats must trust the test CA -> pass it via SSL_CERT_FILE to each
	# iked (chain-verify honours the default store which honours SSL_CERT_FILE;
	# verified on the Fedora 44 box that `verify` + X509_STORE_set_default_paths
	# accept it).  The system anchors are never modified.
	SSLENV="SSL_CERT_FILE=$C/certs/ca.crt"

cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2pub-r"; };
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
		kmp_enc_alg { aes_gcm; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { $AUTH_METHOD; };
		my_public_key x509pem "$C/certs/resp.crt" "$C/certs/resp.key";
		peers_public_key x509pem "$C/certs/init.crt";
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
	spmd { unix "/tmp/spmif-i2pub-i"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_init {
	acceptable_kmp { ikev2; };
	ikev2 {
		my_id fqdn "r2init-matrix";
		peers_id fqdn "racoon2-matrix";
		peers_ipaddr "$HR";
		kmp_enc_alg { aes_gcm; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { $AUTH_METHOD; };
		my_public_key x509pem "$C/certs/init.crt" "$C/certs/init.key";
		peers_public_key x509pem "$C/certs/resp.crt";
		dpd_delay 60 sec;
	};
	selector_index sel_out;
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

	# kill daemons by the unique per-run conf dir (it IS in their argv)
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2pub-r /tmp/spmif-i2pub-i /tmp/iked.sock-i2pub-r /tmp/iked.sock-i2pub-i

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

	( ip netns exec "$NSR" env "$SSLENV" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S /tmp/spmif-i2pub-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env "$SSLENV" RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2pub-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0003 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	( ip netns exec "$NSI" env "$SSLENV" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2pub-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSI" env "$SSLENV" RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2pub-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0003 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2pub-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "X.509 PK child UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done

	# PK-auth evidence: the iked TRACE 'auth method %d' must appear on BOTH
	# seats (it is the method actually used to verify the peer AUTH).  Child
	# up additionally proves the signature verified (no PSK anywhere, so the
	# only way IKE_AUTH succeeded was the PK path).  -- NOT the only gate;
	# the A13/A5 CPL cells re-check conf + session too.
	pkm=0; i=0
	while [ "$i" -lt 10 ]; do
		gr=$(grep -c "$EXP_METHOD" "$D/resp-iked.log" 2>/dev/null)
		gi=$(grep -c "$EXP_METHOD" "$D/init-iked.log" 2>/dev/null)
		if [ "${gr:-0}" -ge 1 ] && [ "${gi:-0}" -ge 1 ]; then
			log "PK auth method verified on BOTH seats ($EXP_METHOD)"
			pkm=1; break
		fi
		i=$((i+1)); sleep 1
	done
	if [ "${pkm:-0}" -ne 1 ]; then
		log "FAIL: expected '$EXP_METHOD' not in both logs (resp=${gr:-0} init=${gi:-0})"
	fi

	# NDcPP compliance report for this row (A/B cells) — runs while the
	# netnss + SADB are still live and before config files are removed.
	i2i_compliance "$D" "$C" "$NSR" "$NSI" "$HR" "$HI" "$name"; cpl=$?

	# kill daemons + teardown netns
	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$C"

	if [ "$up" -ne 1 ] || [ "${pkm:-0}" -ne 1 ] || [ "$cpl" -ne 0 ]; then
		log "FAIL: X.509 PK auth incomplete (up=${up:-0} pkm=${pkm:-0} cpl=$cpl method=$AUTH_METHOD)"
		log "--- resp-iked.log ---"
		grep -E "${EXP_METHOD}|IKE_AUTH|AUTH|abort|err=|FOLLOWUP|certificate|verify" "$D/resp-iked.log" 2>/dev/null | tail -8
		log "--- init-iked.log ---"
		grep -E "${EXP_METHOD}|IKE_AUTH|AUTH|abort|err=|FOLLOWUP|certificate|verify" "$D/init-iked.log" 2>/dev/null | tail -8
		return 1
	fi
	return 0
}
