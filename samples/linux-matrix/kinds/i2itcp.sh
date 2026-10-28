#!/bin/sh
# kinds/i2itcp.sh — RFC 9329 IKE-over-TCP INTEROP against a Libreswan seat.
#
# The racoon2↔racoon2 -tcp rows (kinds/i2ike.sh) prove the racoon2 codec on
# both seats against itself.  These rows prove racoon2 against the one
# independent RFC 9329 implementation available here: libreswan (enable-tcp,
# since v4.0), on a P2P veth, in both directions:
#
#   *-lwsi : racoon2 as the TCP INITIATOR, libreswan as the TCP RESPONDER
#            (libreswan config setup listen-tcp=4500, passive conn).
#   *-lwir : libreswan as the TCP INITIATOR, racoon2 as the TCP RESPONDER
#            (racoon2 passive tcp_encap on; libreswan enable-tcp=yes +
#             tcp-remoteport=4500, auto=add and whack --initiate).
#
# Both seat roles carry the SAME wire gate as i2ike.sh -tcp rows: tcpdump on
# the initiator's veth from before any daemon starts; zero IKE datagrams on
# UDP 500/4500, a TCP SYN to :4500 and a SYN-ACK back, then the ESP child +
# XFRM audit (icv/traffic/safail/xfrm_stat) on the established child.  This
# is transport-priority proof (IKE rode the stream, not UDP), on the wire.
#
# Requires libreswan (pluto with enable-tcp) + CONFIG_XFRM_ESPINTCP kernel +
# tcpdump.  gate=box: runs on the .179 box (not CI).

kind_i2itcp() {
	name=$1
	require_root || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	[ -x "$I2I_LW_PLUTO" ] || { log "FAIL: no libreswan pluto at $I2I_LW_PLUTO"; return 1; }

	# direction from the row suffix
	case "$name" in
	*-lwsi) LW_DIR=responder ;;	# racoon2 initiator, libreswan responder
	*-lwir) LW_DIR=initiator ;;	# libreswan initiator, racoon2 responder
	*) log "FAIL: $name has no -lwsi/-lwir direction suffix"; return 1 ;;
	esac

	row_ns "$name"
	HR=192.0.6.1; HI=192.0.6.2
	rm -rf "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"; mkdir -p "$PRIVRES_R" "$PRIVRES_I" "$D" "$C"

	LW_PSK="$C/psk.bin"
	LW_PSK_TXT="${I2I_LW_PSK:-racoon2-libreswan-tcp-0123456789abcdef}"
	printf '%s' "$LW_PSK_TXT" > "$LW_PSK"; chmod 600 "$LW_PSK"

	# --- racoon2 seat (initiator OR responder, both tcp_encap on) ---
	# HR=racoon2 side, HI=libreswan side.  The non-libreswan seat is always
	# racoon2 here (HR); which direction depends on LW_DIR.
	# Both seats keep the same identities (racoon2-tcp / lw-tcp); only WHICH
	# seat is the TCP ORIGINATOR differs by row.
	MY_ID=racoon2-tcp; PEER_ID=lw-tcp
	if [ "$LW_DIR" = responder ]; then
		# racoon2 = TCP INITIATOR (passive off), peer = libreswan responder
		R_INIT=1; L_INIT=0
		RCFG="$C/r2-init.conf"
		RAC=0; PS_RA="passive off;"; RV="$HI"
		RWIRE="$NSR"	# wire gate on the racoon2 (originator) side
	else
		# racoon2 = TCP RESPONDER (passive on), peer = libreswan initiator
		R_INIT=0; L_INIT=1
		RCFG="$C/r2-resp.conf"
		RAC=1; PS_RA="passive on;"; RV="$HI"
		RWIRE="$NSI"	# wire gate on the libreswan (originator) side
	fi
	cat > "$RCFG" <<EOF
interface {
	ike { "$HR"; };
	spmd { unix "$SPMIF_R"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix {
	acceptable_kmp { ikev2; };
	ikev2 {
		$PS_RA
		my_id fqdn "$MY_ID";
		peers_id fqdn "$PEER_ID";
		peers_ipaddr "$RV";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$LW_PSK";
		dpd_delay 60 sec;
		tcp_encap on;
		esp_tcp_encap on;
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
	remote_index matrix;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$HI";
	my_sa_ipaddr "$HR";
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 3600 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
EOF

	# --- libreswan seat (initiator enable-tcp / responder listen-tcp) ---
	LW_XAUTH_TODAY_CACHE_DIR=no
	mkdir -p "$C/lw-etc" "$C/lw-nss"
	if [ "$LW_DIR" = initiator ]; then
		LW_TCP_LINES="enable-tcp=yes
	tcp-remoteport=4500"
		LW_CONFIG_SETUP=""
	else
		LW_TCP_LINES=""
		LW_CONFIG_SETUP="listen-tcp=yes"
	fi
	cat > "$C/lw-etc/ipsec.conf" <<EOF
config setup
	logfile=/tmp/$name-ipsec.log
	protostack=netkey
	nssdir=$C/lw-nss
	ipsecdir=$C/lw-etc
	uniqueids=yes
	${LW_CONFIG_SETUP}

conn r2tcp
	type=tunnel
	ikev2=insist
	left=$HI
	leftid=@lw-tcp
	leftsubnet=$HI/32
	right=$HR
	rightid=@racoon2-tcp
	rightsubnet=$HR/32
	authby=secret
	ike=aes256-sha2_256-ecp256
	esp=aes_gcm
	ikelifetime=24h
	auto=add
	${LW_TCP_LINES}
EOF
	{
		printf '@racoon2-tcp @lw-tcp : PSK "%s"\n' "$LW_PSK_TXT"
	} > "$C/lw-etc/ipsec.secrets"
	chmod 600 "$C/lw-etc/ipsec.secrets"

	# kill any stale daemons from a prior same-named row
	pkill -9 -f "$C/" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SPMIF_I" "$SOCK_R" "$SOCK_I"

	for NS in "$NSR" "$NSI"; do
		ip netns del "$NS" 2>/dev/null || true
		ip netns add "$NS"
		ip netns exec "$NS" ip link set lo up
	done
	ip link add "$VR" type veth peer name "$VI"
	ip link set "$VR" netns "$NSR"; ip netns exec "$NSR" ip link set "$VR" up; ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
	ip link set "$VI" netns "$NSI"; ip netns exec "$NSI" ip link set "$VI" up; ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"

	# SPD-allow rows so IKE (UDP) and the IKE-over-TCP control socket (TCP
	# 4500) are not captured by the tunnel policy.  racoon2's own IKE sockets
	# take the per-socket bypass; these rows additionally cover the TCP 4500
	# path so the libreswan SYN and racoon2's reply are not parked on ACQUIRE.
	for ns in "$NSR:$HR:$HI" "$NSI:$HI:$HR"; do
		NSX=${ns%%:*}; rest=${ns#*:}; LX=${rest%%:*}; PX=${rest#*:}
		for p in 500 4500; do
			ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
			ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
		done
		ip netns exec "$NSX" ip xfrm policy add src "$PX"/32 dst "$LX"/32 proto tcp sport 4500 dport 4500 dir in  ptype main action allow 2>/dev/null || true
		ip netns exec "$NSX" ip xfrm policy add src "$LX"/32 dst "$PX"/32 proto tcp sport 4500 dport 4500 dir out ptype main action allow 2>/dev/null || true
	done

	# RFC 9329 wire gate: capture the INITIATOR's veth (RWIRE netns) from
	# before any daemon starts.
	WIREPID=
	rm -f "$D/wire.pcap"
	( ip netns exec "$RWIRE" tcpdump -n -U -s 128 -i "$( [ "$RWIRE" = "$NSI" ] && echo "$VI" || echo "$VR" )" -w "$D/wire.pcap" \
	    'udp port 500 or udp port 4500 or tcp' >"$D/wire.log" 2>&1 ) &
	WIREPID=$!
	sleep 1

	# --- pluto NSS init (before pluto launch) ---
	if ! ls "$C/lw-nss"/cert9.db >/dev/null 2>&1; then
		LWIPSEC=$(command -v ipsec || echo /usr/sbin/ipsec)
		[ -x "$LWIPSEC" ] || { log "FAIL: no 'ipsec' for initnss"; return 1; }
		"$LWIPSEC" initnss --nssdir "$C/lw-nss" >"$D/lw-nssinit.log" 2>&1 \
			|| [ -f "$C/lw-nss/cert9.db" ] || { cat "$D/lw-nssinit.log" >&2; log "FAIL: ipsec initnss"; return 1; }
	fi

	# --- launch: spmd + iked in NSR (racoon2), pluto in NSI (libreswan) ---
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$RCFG" ) >"$D/resp-spmd.log" 2>&1 &
	RSPMD=$!
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$RCFG" -D 0x0001 -l "$D/r2-iked.log" ) >"$D/r2-iked.out" 2>&1 &
	RSPMD_IKED=$!
	( ip netns exec "$NSI" "$I2I_LW_PLUTO" --nofork \
	    --ipsecdir "$C/lw-etc" --conf "$C/lw-etc/ipsec.conf" \
	    --secretsfile "$C/lw-etc/ipsec.secrets" --nssdir "$C/lw-nss" \
	    --logfile "$D/lw-pluto.log" --stderrlog ) >"$D/lw-pluto.out" 2>&1 &
	LWPLUTO=$!
	LWWHACK=$(command -v whack || echo /usr/libexec/ipsec/whack)
	i=0
	while [ "$i" -lt 30 ]; do
		if ip netns exec "$NSI" "$LWWHACK" --status >/dev/null 2>&1; then break; fi
		i=$((i+1)); sleep 1
	done
	sleep 2

	# --- establish ---
	lwhack() { ip netns exec "$NSI" "$LWWHACK" --name r2tcp "$@"; }
	if [ "$L_INIT" = 1 ]; then
		lwhack --initiate >"$D/lw-init.txt" 2>&1 || true
	else
		# racoon2 initiates the IKE over the TCP stream
		"$SBIN/ikedctl" -s "$SOCK_R" establish-sa isakmp inet "$HR" "$HI" sel_out \
			>"$D/r2-init.txt" 2>&1 || true
	fi

	up=""
	i=0
	while [ "$i" -lt 40 ]; do
		n=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
		if [ "${n:-0}" -ge 2 ]; then up=1; break; fi
		i=$((i+1)); sleep 1
	done

	# --- wire gate (initiator veth) ---
	sleep 1
	[ -n "$WIREPID" ] && kill "$WIREPID" 2>/dev/null; sleep 1
	WIRE_FAIL=
	if [ ! -s "$D/wire.pcap" ]; then
		WIRE_FAIL="no capture (tcpdump missing or failed)"
	else
		udpike=$(ip netns exec "$RWIRE" tcpdump -n -r "$D/wire.pcap" 'udp port 500 or (udp port 4500 and udp[4:2] > 9 and udp[8:4] = 0)' 2>/dev/null | wc -l)
		syn=$(ip netns exec "$RWIRE" tcpdump -n -r "$D/wire.pcap" "tcp and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" 2>/dev/null | wc -l)
		synack=$(ip netns exec "$RWIRE" tcpdump -n -r "$D/wire.pcap" "tcp and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack != 0" 2>/dev/null | wc -l)
		[ "$udpike" -eq 0 ] && [ "$syn" -ge 1 ] && [ "$synack" -ge 1 ] \
			|| WIRE_FAIL="wire gate (udp_ike=$udpike tcp_syn=$syn tcp_synack=$synack; want 0/>=1/>=1)"
	fi

	fail=0
	if [ -n "$WIRE_FAIL" ]; then log "FAIL: $WIRE_FAIL"; fail=1; fi
	if [ "$up" != 1 ]; then log "FAIL: IKE-over-TCP child not established"; fail=1; fi
	if [ "$fail" = 0 ]; then
		log "wire gate: udp_ike=$udpike tcp_syn=$syn tcp_synack=$synack"
		# the ESP child data-plane audit (icv/traffic/safail/xfrm_stat)
		# runs automatically via run.sh's xa_check after this returns
	fi

	# cleanup
	for p in "$LWPLUTO" "$RSPMD_IKED" "$RSPMD"; do kill "$p" 2>/dev/null; done
	return $fail
}
