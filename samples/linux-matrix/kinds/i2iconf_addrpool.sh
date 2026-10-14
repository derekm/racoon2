#!/bin/sh
# kinds/i2iconf_addrpool.sh - Item B.5: RFC 8983 IP4_ALLOWED/IP6_ALLOWED
# live proof.  A strongSwan charon INITIATOR (conn vips = 0.0.0.0 -> sends
# CP(CFG_REQUEST) INTERNAL_IP4_ADDRESS in a CHILDFUL IKE_AUTH and drives the
# child with a wildcard TSi) brings a CHILDFUL SA up against an iked
# RESPONDER that provides an RFC 8983 addresspool.  The responder allocates
# a v4 lease from the pool ('allocated 10.99.0.x'), matches the peer TSi
# against the lease (ike_conf_find_ikev2sel_by_ts lease branch, CFG_REQUEST
# already populated child_sa->lease_list), lets the child SA land (ESP UP
# both seats, data plane carries ICMP from the assigned VIP), and pushes
# N(IP4_ALLOWED)=16439 beside the CFG_REPLY (TRACE 'RFC8983: responder emits
# IP4_ALLOWED').
#
# WHY charon, not iked: racoon2's own iked-as-initiator NEVER substitutes the
# CFG-assigned internal address into its own TSi, so a self-consistent
# iked<->iked CP row always ends 'ts unacceptable' (ikev2_child.c:1484) - the
# iked initiator sends its static veth address in TSi, which never matches the
# pool lease.  A strongSwan charon initiator with vips = 0.0.0.0 sends the
# wildcard, which the responder's lease branch accepts - the pool-narrowed
# selector is matched to the actually-allocated lease.  gate=box (needs
# charon + netns); not an ADDKE / PQC row.
kind_i2iconf_addrpool() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	PEER=$(i2i_peer "$name")
	PEER_R=$(i2i_peer_r "$name")
	[ "$PEER" = charon ] || { log "FAIL: B.5 needs a charon initiator (iked-as-initiator cannot substitute the pool lease into its own TSi)"; return 1; }
	[ "$PEER_R" = iked ] || { log "FAIL: B.5 responder seat must be iked (the IP4_ALLOWED emit is responder code)"; return 1; }
	command -v "$I2I_CHARON_BIN" >/dev/null 2>&1 || { log "FAIL: no charon binary $I2I_CHARON_BIN"; return 1; }

	row_ns "$name"
	HR=192.0.5.1; HI=192.0.5.2
	# This is a childful IKE_AUTH row: never leave I2I_CHARON_INIT_IKE set to 1
	# from a prior *-zerochild* row (i2iinit.sh:340 sets it; i2i_peer.sh:429
	# would then initiate the IKE_SA alone with no child).  A child must be
	# driven via CREATE_CHILD_SA so the CP lease + IP4_ALLOWED emit happen.
	I2I_CHARON_INIT_IKE=0
	# RFC 8983 addresspool (v4) + the allowed-route subnet the responder's
	# TS selector mirrors the pool against.
	POOL_START="10.99.0.10"; POOL_END="10.99.0.20"; POOL_SUB="10.99.0.0/24"
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	PEER_ID=$(i2i_peer_resp_id "$PEER")      # charon-i2i
	# TRACE on: the RFC8983 emit marker is at DEBUG_FLAG_TRACE=0x0002.
	I2I_DBG=0x0003

	# charon initiator conn (inline below): vips = 0.0.0.0 + a proposal
	# matching the iked responder's IKE algs (aes_gcm / hmac_sha2_256 /
	# ecp256), NO ADDKE round (this is not a PQC row).
	I2I_PROPOSAL=aes256gcm16-prfsha256-ecp256
	I2I_ESP=aes128gcm16

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
		kmp_enc_alg { aes_gcm; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
		dpd_delay 60 sec;
		provide {
			addresspool i2i_pool;
		};
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "192.0.5.1"; dst "$POOL_SUB";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "192.0.5.1"; src "$POOL_SUB";
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_resp;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr IP_ANY;
	my_sa_ipaddr "192.0.5.1";
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
addresspool i2i_pool {
	"$POOL_START" - "$POOL_END";
};
EOF

	# charon initiator swanctl conn: PSK, vips = 0.0.0.0 (CFG_REQUEST
	# INTERNAL_IP4_ADDRESS), and local_ts = 0.0.0.0/0 so charon's TSi at
	# IKE_AUTH covers the pool lease the responder allocates.  Written
	# inline (not i2i_peer_i_conf) because that helper hardcodes
	# local_ts = $HI/32, which would send TSi=192.0.5.2 and never match
	# the pool lease.
	I2I_CHARON_CONF="$I2I_CHARON_VDIR/r2-${name}.conf"
	mkdir -p "$I2I_CHARON_VDIR" || return 1
	_pskhex=$(psk_file_hex "$ETC/psk/macos.psk") || { log "FAIL: charon psk hex"; return 1; }
	cat > "$I2I_CHARON_CONF" <<EOF
connections {
	$name {
		version = 2
		vips = 0.0.0.0
		proposals = $I2I_PROPOSAL
		local_addrs = $HI
		remote_addrs = $HR
		local {
			id = $I2I_CHARON_ID
			auth = psk
		}
		remote {
			id = racoon2-matrix
			auth = psk
		}
		children {
			ch {
				local_ts = 0.0.0.0/0
				remote_ts = $HR/32
				esp_proposals = ${I2I_ESP:-aes128gcm16}
			}
		}
	}
}
secrets {
	ike-$name {
		secret = "0x$_pskhex"
	}
}
EOF

	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"

	# netns + veth pair on a P2P 192.0.5.0/24.
	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"; ip netns exec "$NSR" ip link set "$VR" up
	ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
	ip link set "$VI" netns "$NSI"; ip netns exec "$NSI" ip link set "$VI" up
	ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"

	# UDP IKE-bypass policies so IKE is not captured by the tunnel SPD.
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
	done

	# Strict rp_filter (Fedora default) drops the ESP-decapsulated inner
	# packet on the responder because its source is the peer's CFG pool VIP
	# (10.99.0.10) - not a locally routable net - so the echo never reaches
	# the local stack and no reply goes out (inbound ESP seq advances, oseq
	# stays 0).  Road-warrior CP rows must relax it on both seats.
	for ns in "$NSR" "$NSI"; do
		ip netns exec "$ns" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
		ip netns exec "$ns" sysctl -w net.ipv4.conf."$VR".rp_filter=0 >/dev/null 2>&1 || true
		ip netns exec "$ns" sysctl -w net.ipv4.conf."$VI".rp_filter=0 >/dev/null 2>&1 || true
		ip netns exec "$ns" sysctl -w net.ipv4.conf.lo.rp_filter=0 >/dev/null 2>&1 || true
	done
	# The responder's own fib has no route to the CP pool subnet (unlike the
	# i2i rows, whose TS is the connected 192.0.5.0/24), so a reply towards
	# the peer's assigned VIP is dropped at routing ("no route") before it
	# ever reaches the XFRM output policy.  Give the pool subnet a route via
	# the veth on the responder seat; the outbound tunnel policy then
	# encapsulates the reply as normal.
	ip netns exec "$NSR" ip route add "$POOL_SUB" dev "$VR" 2>/dev/null || true

	# iked responder (the seat that allocates + emits IP4_ALLOWED).
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/responder.conf" ) >"$D/resp-spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/responder.conf" -D "$I2I_DBG" -l "$D/resp-iked.log" ) >"$D/resp-iked.out" 2>&1 &

	# charon initiator: spawn + load conns + initiate the child.
	i2i_peer_i_start "$D" "$NSI" charon "$name"
	sleep 2
	i2i_peer_i_trigger "$D" "$NSI" charon "$name"

	# Gate 1: the CHILDFUL SA lands - ESP state pair on BOTH seats.
	up=0; i=0
	while [ "$i" -lt 45 ]; do
		re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then
			log "RFC 8983 childful SA UP: responder esp=$re initiator esp=$ie after ${i}s"
			up=1
			break
		fi
		i=$((i+1)); sleep 1
	done
	dp=0
	if [ "$up" -eq 1 ]; then
		# charon narrowed the installed TSi to the CFG-assigned VIP
		# (10.99.0.10/32 -> 192.0.5.1/32), so the dataplane ping must
		# source from the VIP, not the veth address (192.0.5.2).
		if ip netns exec "$NSI" ping -c 3 -i 0.2 -W 2 -I "$POOL_START" "$HR" >/dev/null 2>&1; then
			log "data plane: ICMP echo to $HR from VIP $POOL_START answered across the ESP child"
			dp=1
		else
			log "FAIL: data plane: no ICMP echo reply to $HR from VIP $POOL_START"
		fi
	fi
	i2i_charon_list_sas "$D" "$NSI" end

	# Evidence markers.
	emit=0; lease=0; est=0
	# This is a v4 pool: only IP4_ALLOWED is expected.  grep the exact v4
	# string (IP[46] would also match in a hypothetical dual-stack log).
	grep -Eq 'RFC8983: responder emits IP4_ALLOWED' "$D/resp-iked.log" && emit=1
	grep -Eq "allocated $POOL_START" "$D/resp-iked.log" && lease=1
	grep -q 'state change: CONNECTING => ESTABLISHED' "$D/charon-init.log" && est=1

	# Diag dump: the TS the initiator really sent + the emit/lease markers.
	grep -nE 'TS Starting Address|TS Ending Address|RFC8983|allocated |ts unacceptable|state change|received Notify' \
	    "$D/resp-iked.log" "$D/charon-init.log" 2>/dev/null | tail -30

	i2i_peer_i_cleanup charon
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$I2I_CHARON_VDIR"/r2-${name}.conf
	sleep 1
	ip netns del "$NSR" 2>/dev/null || true
	ip netns del "$NSI" 2>/dev/null || true
	ip link del "$VR" 2>/dev/null || true
	rm -rf "$PRIVRES_R" "$PRIVRES_I"

	if [ "$up" -ne 1 ]; then
		log "FAIL: childful SA not UP (up=$up) - see resp-iked.log TS dump"
		return 1
	fi
	[ "$lease" -eq 1 ] || { log "FAIL: no pool lease allocated (lease=$lease)"; return 1; }
	[ "$emit" -eq 1 ]  || { log "FAIL: responder did not emit RFC8983 IP4/IP6_ALLOWED (emit=$emit)"; return 1; }
	[ "$est" -eq 1 ]   || { log "FAIL: charon initiator did not reach ESTABLISHED (est=$est)"; return 1; }
	[ "$dp" -eq 1 ]    || { log "FAIL: data plane did not carry ICMP from the CFG VIP (dp=$dp)"; return 1; }
	log "RFC 8983 PROVEN: lease allocated + responder emits IP4_ALLOWED + childful SA UP + VIP dataplane + charon ESTABLISHED (lease=$lease emit=$emit up=$up dp=$dp est=$est)"
	return 0
}
