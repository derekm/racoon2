#!/bin/sh
# kinds/ikev2.sh — strongSwan charon vs racoon2 iked, two isolated netnss.
#
# The SUT (racoon2 iked with the R2_WORKERS knob) runs in its OWN netns NSR
# bound to the P2P veth address HR, never to the host :500 — so it never
# collides with the live/prod iked (which may be a manual -F process not
# stoppable via systemctl).  charon runs in netns NSI on HI.  All SAD/SPD
# and show-sa assertions run inside the responder netns via
# `ip netns exec "$NSR"` + the per-netns admin socket.
# One charon at a time.  Workers cell applies to the NSR iked only.
kind_ikev2() {
	name=$1
	require_root || return 1
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	# --- two-netns P2P topology (i2idh-style) --------------------------------
	NSR=ikev2-r; NSI=ikev2-i; VR=i2v2a-vr; VI=i2v2a-vi
	HR=192.0.14.1; HI=192.0.14.2
	PRIVRES_R=/tmp/r2-ikev2-resume-r
	D=/tmp/r2-ikev2; C=/tmp/r2-ikev2-conf
	# legacy names charon_reset still reads
	NS="$NSI"; VETH_H="$VI"; CIP="$HI"
	rm -rf "$PRIVRES_R" "$D" "$C"; mkdir -p "$PRIVRES_R" "$D" "$C"
	charon_reset

	# responder.conf — the SUT iked config, bound to HR inside NSR.  The
	# remote{}/selector/policy/sa block mirrors the i2i kinds; the esp
	# algs cover every STRONG_ESP the rows select (gcm16/gcm8/gcm12/CBC +
	# sha1/sha2 family), matching the coverage macos_ikev2.conf once gave.
	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2v2-r"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_resp {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "racoon2-wsl";
		peers_id fqdn "macos.client";
		peers_ipaddr "$HI";
		kmp_enc_alg { aes256_cbc; aes128_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; modp2048; };
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
	ipsec_index { ipsec_e_gcm; ipsec_e_gcm12; ipsec_e_gcm8; ipsec_e_sha2; };
	ipsec_level require;
	peers_sa_ipaddr "$HI";
	my_sa_ipaddr "$HR";
};
ipsec ipsec_e_gcm {
	ipsec_sa_lifetime_time 3600 sec;
	sa_index esp_e_gcm;
};
ipsec ipsec_e_gcm12 {
	ipsec_sa_lifetime_time 3600 sec;
	sa_index esp_e_gcm12;
};
ipsec ipsec_e_gcm8 {
	ipsec_sa_lifetime_time 3600 sec;
	sa_index esp_e_gcm8;
};
ipsec ipsec_e_sha2 {
	ipsec_sa_lifetime_time 3600 sec;
	sa_index esp_e_sha2;
};
sa esp_e_gcm {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
sa esp_e_gcm12 {
	sa_protocol esp;
	esp_enc_alg { aes_gcm12; };
	esp_auth_alg { non_auth; };
};
sa esp_e_gcm8 {
	sa_protocol esp;
	esp_enc_alg { aes_gcm8; };
	esp_auth_alg { non_auth; };
};
sa esp_e_sha2 {
	sa_protocol esp;
	esp_enc_alg { aes256_cbc; aes128_cbc; };
	esp_auth_alg { hmac_sha2_256; hmac_sha2_384; hmac_sha2_512; };
};
EOF

	# racoon2-initiated CHILD rekey: shorten our ipsec lifetime so we
	# mint CREATE_CHILD; charon rekey=no.  The conf is a per-run file (not
	# the shipped macos_ikev2.conf), so no restore trap is needed.
	case "$name" in
	*-r2rekey)
		sed -i 's/ipsec_sa_lifetime_time 3600 sec/ipsec_sa_lifetime_time 30 sec/' "$C/responder.conf"
		;;
	esac

	# clean any once-used netns, then build the pair + P2P veth
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2v2-r /tmp/spmif-i2v2-i /tmp/iked.sock-i2v2-r /tmp/iked.sock-i2v2-i
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

	# UDP-allow rows BEFORE any spmd (first-in-bucket at prio 0) so IKE is
	# not captured by the auto_ipsec tunnel input policy (XfrmInNoStates).
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	# SUT iked in NSR, with the workers knob via env and its own admin sock.
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S /tmp/spmif-i2v2-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	# iked_apply_workers exports RACOON2_CRYPTO_WORKERS only for numeric
	# cells; empty mean "live", and iked treats unset as its default.
	_WK=""
	[ -n "${R2_WORKERS-}" ] && _WK="RACOON2_CRYPTO_WORKERS=$R2_WORKERS"
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2v2-r \
	    RACOON2_RESUME_DIR="$PRIVRES_R" $_WK \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	R2_IKED_EPHEMERAL_PID=$!
	i=0
	until kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null || [ "$i" -ge 10 ]; do sleep 1; i=$((i+1)); done
	if ! kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null; then
		log "FAIL: ephemeral iked died workers=${R2_WORKERS-} in NSR"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi
	# worker count proof: the NSR iked must log it (same gate as before).
	# Poll — the -l logfile is block-buffered, so the line lands a moment
	# after "starting iked"; a one-shot grep right after spawn races it.
	if [ "${R2_WORKERS:-0}" -gt 0 ]; then
		_wk_ok=0
		for _ in $(seq 1 15); do
			if grep -q "crypto workers: $R2_WORKERS" "$D/resp-iked.log" 2>/dev/null; then
				_wk_ok=1
				break
			fi
			sleep 1
		done
		if [ "$_wk_ok" != 1 ]; then
			log "FAIL: no 'crypto workers: $R2_WORKERS' in NSR iked log"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		fi
	fi
	log "NSR iked pid=$R2_IKED_EPHEMERAL_PID workers=${R2_WORKERS-} (netns $NSR, bind $HR)"

	# ESP proposal selection: case name suffix drives the strongSwan
	# esp= line -- -s384 -> aes256-sha384!, -s512 -> aes256-sha512!,
	# default stays aes128gcm16!
	STRONG_ESP=aes128gcm16!
	EXPECT_AUTH=
	case "$name" in
	*-s384) STRONG_ESP='aes256-sha384!'; EXPECT_AUTH='auth-trunc hmac(sha384).* 192$' ;;
	*-s512) STRONG_ESP='aes256-sha512!'; EXPECT_AUTH='auth-trunc hmac(sha512).* 256$' ;;
	*-g8)  STRONG_ESP='aes128gcm8!';  EXPECT_AUTH='aead rfc4106(gcm(aes)).* 64$' ;;
	*-g12) STRONG_ESP='aes128gcm12!'; EXPECT_AUTH='aead rfc4106(gcm(aes)).* 96$' ;;
	*-dh19)
		STRONG_ESP='aes128gcm16-ecp256!'
		EXPECT_AUTH='aead rfc4106(gcm(aes)).* 128$'
		;;
	*-childrekey)
		STRONG_ESP='aes128gcm16-ecp256!'
		;;
	*-r2rekey)
		STRONG_ESP='aes128gcm16-ecp256!'
		;;
	*-frag|*-mobike|*-cookie2)
		;;
	esac
	pskhex=$(psk_file_hex "$ETC/psk/macos.psk") || {
		log "FAIL: empty PSK hex from $ETC/psk/macos.psk"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	# charon defaults table: swanctl conn options mirror the ipsec.conf
	# knobs the rows used to set (rekey drift, frag, mobike, child PFS).
	_REKEY_TIME=0s
	_CHILD_REKEY_TIME=0s
	_FRAG_OPT=
	_MOBIKE_OPT=
	case "$name" in
	*-childrekey) _CHILD_REKEY_TIME=30s ;;
	*-ikesa-rekey) _REKEY_TIME=30s ;;
	*-frag) _FRAG_OPT='fragmentation = yes' ;;
	*-mobike|*-cookie2) _MOBIKE_OPT='mobike = yes' ;;
	esac
	# swanctl conn: IKE proposal = responder kmp (aes256-sha256-modp2048);
	# child esp proposal per STRONG_ESP; local/remote ids match the iked
	# responder's my_id/peers_id (fqdn, no @ prefix in swanctl ids).
	CHARON_CONN="$I2I_CHARON_VDIR/r2-ikev2.conf"
	rm -f "$CHARON_CONN"
	cat > "$CHARON_CONN" <<EOF
connections {
	r2macos {
		version = 2
		rekey_time = $_REKEY_TIME
		proposals = aes256-sha256-modp2048
		local_addrs = $HI
		remote_addrs = $HR
		local {
			id = macos.client
			auth = psk
		}
		remote {
			id = racoon2-wsl
			auth = psk
		}
		$_FRAG_OPT
		$_MOBIKE_OPT
		children {
			ch {
				local_ts = $HI/32
				remote_ts = $HR/32
				esp_proposals = ${STRONG_ESP%!}
				rekey_time = $_CHILD_REKEY_TIME
			}
		}
	}
}
secrets {
	ike-r2macos {
		secret = "0x$pskhex"
	}
}
EOF
	chmod 600 "$CHARON_CONN"

	( ip netns exec "$NSI" "$I2I_CHARON_BIN" --debug-ike 3 --debug-knl 1 \
	    --debug-cfg 2 --debug-mgr 2 --debug-net 1 ) >"$D/charon-init.log" 2>&1 &
	_CHARON_PID=$!
	sleep 2
	( ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --load-all --debug 2 ) >"$D/swanctl-load.log" 2>&1
	( ip netns exec "$NSI" "$I2I_SWANCTL_BIN" --initiate --child ch --debug 2 >"$D/swanctl-init.log" 2>&1 ) || true
	# NB: no inner-ping gate on the netns rows — charon-in-netns cannot
	# install its side of the SAs on these kernels (mirrored WSL2 and
	# GH-hosted; manual netns xfrm adds work, so it is charon's netlink
	# path that fails, not the tree).  The netns rows prove negotiation +
	# the responder SAD/SPD with exact auth/trunc content — read from the
	# RESPONDER netns, which iked owns.
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
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi

	show=$("$SBIN/ikedctl" -s /tmp/iked.sock-i2v2-r show-sa isakmp) || {
		log "FAIL: show-sa (NSR)"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	echo "$show" | grep -q "$HI" || {
		log "FAIL: show-sa missing $HI"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	# FWD must mirror the IN tmpl (SSH-death regression, e2bd9ef) — in the
	# responder netns, which iked owns.
	if ! fwd_tmpl_check "$NSR"; then
		log "FAIL: fwd tmpl != in tmpl (NSR)"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi

	case "$name" in
	*-resume-dump)
		dump=$(find "$PRIVRES_R" -type f 2>/dev/null | head -1)
		[ -n "$dump" ] || { log "FAIL: no resume dump after IKE_AUTH"; charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"; return 1; }
		mag=$(od -An -tx1 -N4 "$dump" 2>/dev/null | tr -d ' \n')
		echo "$mag" | grep -qi '^53523252' || {
			log "FAIL: resume dump magic $mag want 53 52 32 52"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		log "resume dump $dump magic SR2R"
		;;
	*-qcd)
		grep -q 'sending QCD_TOKEN' "$D/resp-iked.log" || {
			log "FAIL: no sending QCD_TOKEN in NSR iked log"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		;;
	*-ikesa-rekey)
		# charon rekey_time=30s starts at IKE_SA ESTABLISHED; on the fast
		# P2P veth the SA lands quickly, so a fixed 28s sleep races the
		# rekey (observed flake: passed first run, missed second).  Poll
		# for the rekey marker up to 50s instead of a one-shot sleep.
		_rk_ok=0
		for _ in $(seq 1 50); do
			if grep -Eq 'received IKE_SA rekey request|initiating IKE_SA rekey' "$D/resp-iked.log"; then
				_rk_ok=1
				break
			fi
			sleep 1
		done
		[ "$_rk_ok" = 1 ] || {
			log "FAIL: no IKE_SA rekey in NSR iked log"
			tail -30 "$D/resp-iked.log"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		showr=$("$SBIN/ikedctl" -s /tmp/iked.sock-i2v2-r show-sa isakmp) || true
		echo "$showr" | grep -q "$HI" || {
			log "FAIL: IKE_SA gone after rekey wait"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		;;
	*-childrekey)
		spi_before=$(ip netns exec "$NSR" ip xfrm state | grep -E 'proto esp' | grep -oE '0x[0-9a-f]{8}' | sort | tr '\n' ' ')
		sleep 35
		showr=$("$SBIN/ikedctl" -s /tmp/iked.sock-i2v2-r show-sa isakmp) || true
		echo "$showr" | grep -q "$HI" || {
			log "FAIL: IKE_SA gone after child rekey wait"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		spi_after=$(ip netns exec "$NSR" ip xfrm state | grep -E 'proto esp' | grep -oE '0x[0-9a-f]{8}' | sort | tr '\n' ' ')
		[ "$spi_before" != "$spi_after" ] || {
			log "FAIL: ESP SPI unchanged after childrekey wait (no rekey fired)"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		log "child rekey replaced SPI: $spi_before -> $spi_after"
		;;
	*-r2rekey)
		spi_before=$(ip netns exec "$NSR" ip xfrm state | grep -E 'proto esp' | grep -oE '0x[0-9a-f]{8}' | sort | tr '\n' ' ')
		sleep 35
		grep -q 'initiating CREATE_CHILD_SA rekey' "$D/resp-iked.log" || {
			log "FAIL: racoon2 did not initiate CHILD rekey"
			tail -30 "$D/resp-iked.log"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		grep -q INVALID_SYNTAX "$D/resp-iked.log" && {
			log "FAIL: peer rejected CREATE_CHILD (INVALID_SYNTAX; msgid 0?)"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		showr=$("$SBIN/ikedctl" -s /tmp/iked.sock-i2v2-r show-sa isakmp) || true
		echo "$showr" | grep -q "$HI" || {
			log "FAIL: IKE_SA gone after r2 child rekey"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		spi_after=$(ip netns exec "$NSR" ip xfrm state | grep -E 'proto esp' | grep -oE '0x[0-9a-f]{8}' | sort | tr '\n' ' ')
		[ "$spi_before" != "$spi_after" ] || {
			log "FAIL: ESP SPI unchanged after r2rekey wait"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		log "r2-initiated child rekey replaced SPI: $spi_before -> $spi_after"
		;;
	*-cookie2)
		grep -q 'NO_ADDITIONAL_ADDRESSES' "$D/resp-iked.log" || {
			log "FAIL: no NO_ADDITIONAL_ADDRESSES in NSR iked log"
			charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
			return 1
		}
		;;
	esac

	"$SBIN/ikedctl" -s /tmp/iked.sock-i2v2-r vpn-disconnect "$HI" || {
		log "FAIL: vpn-disconnect"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	show2=$("$SBIN/ikedctl" -s /tmp/iked.sock-i2v2-r show-sa isakmp) || {
		log "FAIL: show-sa after disconnect"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	}
	if echo "$show2" | grep -q "$HI"; then
		log "FAIL: SA still listed after vpn-disconnect"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi
	if ! kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null; then
		log "FAIL: NSR iked died after vpn-disconnect"
		charon_reset; _ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
		return 1
	fi

	charon_reset
	_ikev2_clean "$NSR" "$NSI" "$C" "$PRIVRES_R"
	return 0
}

# _ikev2_clean — tear down the two netnss, daemons, and resume dir.
_ikev2_clean() {
	_NSR=$1; _NSI=$2; _C=$3; _PRR=$4
	pkill -9 -f "$_C/" 2>/dev/null || true
	killall -9 charon 2>/dev/null || true
	rm -f "$I2I_CHARON_VDIR/r2-ikev2.conf" 2>/dev/null || true
	sleep 1
	ip netns del "$_NSR" 2>/dev/null || true
	ip netns del "$_NSI" 2>/dev/null || true
	rm -rf "$_PRR"
	# clear ephemeral pid so iked_restore (run.sh EXIT trap) does nothing
	R2_IKED_EPHEMERAL_PID=
}
