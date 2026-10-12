#!/bin/sh
# kinds/ikev1.sh — strongSwan charon (IKEv1) vs racoon2 iked, two netnss.
#
# Same netns isolation as ikev2.sh: the SUT iked runs in NSR bound to its
# own P2P veth (HR), charon in NSI.  Never touches the host :500, so it
# cannot collide with a live/prod iked.
kind_ikev1() {
	name=$1
	require_root || return 1
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	# Deprecation switches (ikev1 clause, per remote; doc s8).  IKEv1
	# itself is RFC-deprecated (RFC 9395 s3), so every row that brings an
	# SA up needs allow_rfc_deprecated on; SHA-1 / 3DES are NSA-class
	# too.  MODE=up: the SA comes up (and WARN_STR, if set, is logged);
	# MODE=refuse: iked refuses the configuration with REFUSE_STR.
	MODE=up; WARN_STR=""; REFUSE_STR=""
	P1ENC=aes256_cbc; P1HASH=sha1; ESPENC=aes256_cbc; ESPAUTH=hmac_sha1
	V1SW="allow_rfc_deprecated on; allow_nsa_deprecated on;"
	CH_IKE=aes256-sha1-modp2048; STRONG_ESP='aes256-sha1'
	EXPECT_AUTH='auth-trunc hmac(sha1)'; EXPECT_ENC=""
	V1RFC='matrix_resp ikev1 acceptable_kmp ikev1 is RFC-deprecated (IKEv1 RFC 9395 s3 DEPRECATED)'
	case "$name" in
	ikev1-depr-default)	# clean algorithms, no switch: IKEv1 refused
		P1HASH=sha2_256; ESPAUTH=hmac_sha2_256; V1SW=""
		MODE=refuse
		REFUSE_STR="$V1RFC and allow_rfc_deprecated is off - refusing the configuration" ;;
	ikev1-depr-clean)	# clean algorithms + per-remote RFC switch
		P1HASH=sha2_256; ESPAUTH=hmac_sha2_256
		V1SW="allow_rfc_deprecated on;"
		CH_IKE=aes256-sha256-modp2048; STRONG_ESP='aes256-sha256'
		EXPECT_AUTH='auth-trunc hmac(sha256)'
		WARN_STR="$V1RFC - allowed by allow_rfc_deprecated on; migrate the remote to IKEv2" ;;
	ikev1-depr-nsa-default)	# RFC switch only: SHA-1 still refused
		V1SW="allow_rfc_deprecated on;"
		MODE=refuse
		REFUSE_STR="matrix_resp ikev1 kmp_hash_alg SHA-1 is NSA-deprecated (CNSSP-15) and allow_nsa_deprecated is off - refusing the configuration" ;;
	ikev1-depr-3des)	# both switches: 3DES phase 1 + ESP comes up
		P1ENC=3des_cbc; P1HASH=sha2_256; ESPENC=3des_cbc
		ESPAUTH=hmac_sha2_256
		CH_IKE=3des-sha256-modp2048; STRONG_ESP='3des-sha256'
		EXPECT_AUTH='auth-trunc hmac(sha256)'
		EXPECT_ENC='enc cbc(des3_ede)'
		WARN_STR="matrix_resp ikev1 kmp_enc_alg 3DES-CBC is NSA-deprecated (CNSSP-15) - allowed by allow_nsa_deprecated on" ;;
	esac

	row_ns "$name"
	HR=192.0.15.1; HI=192.0.15.2
	NS="$NSI"; VETH_H="$VI"; CIP="$HI"
	rm -rf "$PRIVRES_R" "$D" "$C"; mkdir -p "$PRIVRES_R" "$D" "$C"
	charon_reset

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "$SPMIF_R"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_resp {
	acceptable_kmp { ikev1; };
	ikev1 {
		$V1SW
		passive on;
		my_id ipaddr "$HR";
		peers_id ipaddr "$HI";
		peers_ipaddr "$HI";
		kmp_enc_alg { $P1ENC; };
		kmp_hash_alg { $P1HASH; };
		kmp_dh_group { modp2048; };
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
	ipsec_sa_lifetime_time 7200 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { $ESPENC; };
	esp_auth_alg { $ESPAUTH; };
};
EOF

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"
	for NSX in "$NSR" "$NSI"; do
		ip netns del "$NSX" 2>/dev/null || true
		ip netns add "$NSX"
		ip netns exec "$NSX" ip link set lo up
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

	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	_WK=""
	[ -n "${R2_WORKERS-}" ] && _WK="RACOON2_CRYPTO_WORKERS=$R2_WORKERS"
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" \
	    RACOON2_RESUME_DIR="$PRIVRES_R" $_WK \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	R2_IKED_EPHEMERAL_PID=$!
	if [ "$MODE" = refuse ]; then
		# the configuration check must stop iked before it serves
		i=0
		while kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null && [ "$i" -lt 15 ]; do
			sleep 1; i=$((i+1))
		done
		_rc=0
		if kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null; then
			log "FAIL: iked accepted a configuration it must refuse"
			_rc=1
		elif ! cat "$D/resp-iked.log" "$D/resp-iked.out" 2>/dev/null |
		    grep -qF -- "$REFUSE_STR"; then
			log "FAIL: refusal missing: $REFUSE_STR"
			grep -h INTERNAL_ERR "$D/resp-iked.log" "$D/resp-iked.out" 2>/dev/null | head -5
			_rc=1
		else
			log "iked refused: $REFUSE_STR"
		fi
		kill -9 "$RSPMD" 2>/dev/null || true
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return $_rc
	fi
	i=0
	until kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null || [ "$i" -ge 10 ]; do sleep 1; i=$((i+1)); done
	if ! kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null; then
		log "FAIL: ephemeral iked died workers=${R2_WORKERS-} in NSR"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi
	log "NSR iked pid=$R2_IKED_EPHEMERAL_PID workers=${R2_WORKERS-} (netns $NSR, bind $HR)"

	# IKEv1 main mode: IP-typed IDs (RFC 2409).  PSK is the whole
	# file, not 0x-hex (that is the IKEv2 encoding of the same bytes).
	psk=$(cat "$ETC/psk/macos.psk")
	# swanctl conn: IKEv1 (version = 1), IP-typed IDs, whole-file PSK.
	# racoon2 iked's ikev1 kmp is $P1ENC-$P1HASH-modp2048 (CH_IKE).
	CHARON_CONN="$I2I_CHARON_VDIR/r2-ikev1.conf"
	rm -f "$CHARON_CONN"
	cat > "$CHARON_CONN" <<EOF
connections {
	r2macos {
		version = 1
		# IKEv1: rekey_time is the ISAKMP SA lifetime carried in the
		# proposal (0s makes racoon2 reject "invalid life duration").
		rekey_time = 1h
		proposals = $CH_IKE
		local_addrs = $HI
		remote_addrs = $HR
		local {
			id = $HI
			auth = psk
		}
		remote {
			id = $HR
			auth = psk
		}
		children {
			ch {
				local_ts = $HI/32
				remote_ts = $HR/32
				esp_proposals = $STRONG_ESP
				rekey_time = 1h
			}
		}
	}
}
secrets {
	ike-r2macos {
		secret = "$psk"
	}
}
EOF
	chmod 600 "$CHARON_CONN"

	if [ ! -x "$I2I_CHARON_BIN" ]; then
		log "FAIL: charon not found ($I2I_CHARON_BIN; set I2I_CHARON_BIN)"
		_ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi
	# line-buffered (i2i_charon_run): a plain redirect left charon-init.log
	# EMPTY on the sid kernel lane (stdio buffer lost to the SIGKILL), so a
	# failed row carried no charon diagnostics at all
	i2i_charon_run "$NSI" "$D/charon-init.log"
	_CHARON_PID=$_I2I_CHARON_PID
	sleep 2
	( ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --load-all --debug 2 ) >"$D/swanctl-load.log" 2>&1
	( ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --initiate --child ch --debug 2 >"$D/swanctl-init.log" 2>&1 ) || true
	sleep 2
	# Responder SAD/SPD with the exact auth/trunc content first (iked's
	# netns).  The old note here said charon-in-netns could not install
	# its SAs on GH-hosted kernels; the Ubuntu shards' data-plane audit
	# (both responder counters rise, so echo replies came back) shows
	# it does.  Each row now also waits for charon's SA pair and pings
	# across the child below.
	if [ -n "$EXPECT_AUTH" ]; then
		_sadpat="$EXPECT_AUTH"
	else
		_sadpat='aead rfc4106(gcm(aes))'
	fi
	_sad_ok=0
	for _ in $(seq 1 30); do
		if ip netns exec "$NSR" ip xfrm state | grep -q "$_sadpat"; then
			_sad_ok=1
			break
		fi
		sleep 1
	done
	if [ "$_sad_ok" != 1 ]; then
		if [ -n "$EXPECT_AUTH" ]; then
			log "FAIL: SAD missing $EXPECT_AUTH (NSR)"
			ip netns exec "$NSR" ip xfrm state | grep -E 'auth|aead' | head -6
		else
			log "FAIL: no GCM SAD (NSR)"
		fi
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi
	# the child must carry traffic both ways: wait for the initiator's
	# own SAs, then ICMP across it (the audit then checks both seats)
	if ! i2i_wait_seat_sa "$NSI" 20 || ! i2i_dataplane "$NSI" "$HR" "$name"; then
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi

	if [ -n "$EXPECT_ENC" ] && ! ip netns exec "$NSR" ip xfrm state | grep -qF "$EXPECT_ENC"; then
		log "FAIL: SAD missing $EXPECT_ENC (NSR)"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi
	if [ -n "$WARN_STR" ] && ! grep -qF -- "$WARN_STR" "$D/resp-iked.log" "$D/resp-iked.out" 2>/dev/null; then
		log "FAIL: warning missing: $WARN_STR"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi

	show=$("$SBIN/ikedctl" -s "$SOCK_R" show-sa isakmp) || {
		log "FAIL: show-sa (NSR)"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	if ! fwd_tmpl_check "$NSR"; then
		log "FAIL: fwd tmpl != in tmpl (NSR)"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi
	echo "$show" | grep -q "$HI" || {
		log "FAIL: show-sa missing $HI"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	"$SBIN/ikedctl" -s "$SOCK_R" vpn-disconnect "$HI" || {
		log "FAIL: vpn-disconnect"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	show2=$("$SBIN/ikedctl" -s "$SOCK_R" show-sa isakmp) || {
		log "FAIL: show-sa after disconnect"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	if echo "$show2" | grep -q "$HI"; then
		log "FAIL: SA still listed after vpn-disconnect"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi
	if ! kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null; then
		log "FAIL: NSR iked died after vpn-disconnect"
		charon_reset; _ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi

	charon_reset
	_ikev1_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
	return 0
}

# _ikev1_clean — tear down the two netnss, daemons, and resume dir.
_ikev1_clean() {
	_NSR=$1; _NSI=$2; _C=$3; _PRR=$4
	pkill -9 -f "$_C/" 2>/dev/null || true
	killall -9 charon 2>/dev/null || true
	rm -f "$I2I_CHARON_VDIR/r2-ikev1.conf" 2>/dev/null || true
	sleep 1
	ip netns del "$_NSR" 2>/dev/null || true
	ip netns del "$_NSI" 2>/dev/null || true
	rm -rf "$_PRR"
	R2_IKED_EPHEMERAL_PID=
}

