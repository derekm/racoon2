#!/bin/sh
# kinds/i2idh.sh — classical DH-group negotiation row (RFC 8247 groups).
# One row per group; the group is taken from the row name suffix
# (i2idh-ecp384 = group 20, i2idh-ecp521 = group 21, i2idh-modp3072 = 15,
# i2idh-modp4096 = 16, ...).  iked<->iked on a P2P veth in separate netnss;
# `-charon`/`-charonr` suffixes swap the seat via kinds/i2i_peer.sh so the
# SAME DH group is validated against a strongSwan charon implementation of
# the curve (strongSwan supports ecp384(20)/ecp521(21) natively).
# NB: the box build is WITH_ADDKE, so charon's proposal string keeps the
# ke1_mlkem768 element (I2I_DH_GROUP only swaps the DH group inside it);
# the iked side negotiates the DH group regardless — ADDKE is orthogonal.
# Gate: rows ship gate=box until a container run passes.
#
# Pass gate: ESP child up on BOTH seats (the DH KE payload of the required
# group must exchange and keymat must derive — a wrong group id or curve
# yields NO_PROPOSAL or a KE-length mismatch) AND the A11 CPL cell reports
# the requested group (i2i_compliance.sh matches kmp_dh_group/charon
# selected-proposal).  FAIL on any of those.
kind_i2idh() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }

	# group <- row name suffix: i2idh-ecp384 -> ecp384
	G=${name#i2idh-}
	G=${G%%-*}
	case "$G" in
	modp768|modp1024|modp1536|modp2048|modp3072|modp4096|modp6144|modp8192|\
	ecp256|ecp384|ecp521) ;;
	*) log "FAIL: $name unknown DH group '$G'"; return 1 ;;
	esac
	# charon supports all of the above except modp768(modp768 unsupported in
	# strongSwan 6.0) — refuse only that one so a -charon row can't silently
	# degrade to a no-proposal FAIL.
	case "$name" in
	*-charon*)
		[ "$G" = modp768 ] && { log "FAIL: charon has no modp768 group"; return 1; }
		;;
	esac

	I2I_DH_GROUP=$G
	export I2I_DH_GROUP
	PEER_I=$(i2i_peer "$name")
	PEER_R=$(i2i_peer_r "$name")
	# the charon seats negotiate CLASSICAL IKE here (no ADDKE on the i2idh
	# iked side): drop the -ke1_mlkem768 element charon's default carries.
	if [ "$PEER_I" = charon ] || [ "$PEER_R" = charon ]; then
		I2I_PROPOSAL="aes256gcm16-prfsha256-${I2I_DH_GROUP}"
		export I2I_PROPOSAL
	fi
	NSR=i2idh-r; NSI=i2idh-i; VR=i2dh-vr; VI=i2dh-vi
	HR=192.0.14.1; HI=192.0.14.2
	PRIVRES_R=/tmp/r2-i2idh-resume-r; PRIVRES_I=/tmp/r2-i2idh-resume-i
	D=/tmp/r2-i2idh-$G; C=/tmp/r2-i2idh-conf-$G
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	cat > "$C/responder.conf" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "/tmp/spmif-i2idh-r"; };
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
		kmp_dh_group { $G; };
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
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF

	cat > "$C/initiator.conf" <<EOF
interface {
	ike { "$HI"; };
	spmd { unix "/tmp/spmif-i2idh-i"; };
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
		kmp_dh_group { $G; };
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
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF

	# kill daemons by the unique per-run conf dir (it IS in their argv).
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f /tmp/spmif-i2idh-r /tmp/spmif-i2idh-i /tmp/iked.sock-i2idh-r /tmp/iked.sock-i2idh-i

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

	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	# seat spawn: responder then initiator (either iked or charon)
	i2i_peer_r_conf "$C" "$HR" "$HI" "$name" "$PEER_R"
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S /tmp/spmif-i2idh-r ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	i2i_peer_r_start "$D" "$NSR" "$PEER_R" "$name"
	[ "$PEER_R" = charon ] || \
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2idh-r RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D 0x0001 -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &
	i=0; until [ -S /tmp/spmif-i2idh-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done

	i2i_peer_i_conf "$C" "$HI" "$HR" "$name" "$PEER_I"
	( ip netns exec "$NSI" "$SBIN/spmd" -F -f "$C/initiator.conf" ) >"$D/init-spmd.log" 2>&1 &
	ISPMD=$!
	i=0; until [ -S /tmp/spmif-i2idh-i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	i2i_peer_i_start "$D" "$NSI" "$PEER_I" "$name"
	[ "$PEER_I" = charon ] || \
	( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2idh-i RACOON2_RESUME_DIR="$PRIVRES_I" \
	    "$SBIN/iked" -F -f "$C/initiator.conf" -D 0x0001 -l "$D/init-iked.log" ) >"$D/init-iked.out" 2>&1 &

	sleep 2
	i2i_peer_r_trigger "$D" "$NSR" "$PEER_R" "$name"
	[ "$PEER_R" = charon ] || true
	"$SBIN/ikedctl" -s /tmp/iked.sock-i2idh-i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
	i2i_peer_i_trigger "$D" "$NSI" "$PEER_I" "$name"

	up=0
	i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "DH group $G child UP: responder esp=$re initiator esp=$ie after ${i}s ($PEER_I / $PEER_R)"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	[ "$up" -eq 1 ] || log "FAIL: no ESP child for DH group $G in 45s (resp=$re init=$ie)"

	# NDcPP v3.0e CPL for this row — A11 asserts the requested group is in
	# the claimed set from the actual conf (kmp_dh_group) or charon proposal.
	i2i_compliance "$D" "$C" "$NSR" "$NSI" "$HR" "$HI" "$name"; cpl=$?

	pkill -9 -f "$C/" 2>/dev/null || true
	sleep 1
	i2i_peer_i_cleanup "$PEER_I"
	i2i_peer_r_cleanup "$PEER_R" "$name"
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$up" -ne 1 ] || [ "$cpl" -ne 0 ]; then
		log "FAIL: DH group $G negotiation incomplete (up=${up:-0} cpl=$cpl)"
		log "--- init-iked.log (proposal/ESTABLISHED) ---"
		[ -f "$D/init-iked.log" ] && sed -n 's/.*\(ESTABLISHED\|no proposal\|unacceptable\|NO_PROPOSAL\|err=\).*/\1: &/p' \
			"$D/init-iked.log" 2>/dev/null | tail -6
		log "--- resp-iked.log (proposal/ESTABLISHED) ---"
		[ -f "$D/resp-iked.log" ] && sed -n 's/.*\(ESTABLISHED\|no proposal\|unacceptable\|NO_PROPOSAL\|err=\).*/\1: &/p' \
			"$D/resp-iked.log" 2>/dev/null | tail -6
		return 1
	fi
	return 0
}
