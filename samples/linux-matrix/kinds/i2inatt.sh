#!/bin/sh
# kinds/i2inatt.sh — NAT-T transport across iptables SNAT (N3/N4/G5 Linux).
#
# Three netns: initiator 10.9.0.2 -- NAT (SNAT to 192.0.5.254) -- responder
# 192.0.5.1.  iked<->iked, transport mode, nat_traversal on.
#
# Row variants:
#   i2inatt-transport       specific SPD (G5 twin): ICMP + TCP across NAT-T
#   i2inatt-transport-wild  N3: responder wildcard 0.0.0.0/0 SPD; assert
#                           'substituted TSi with 192.0.5.254' + N4 NAT-OA
kind_i2inatt() {
	name=$1
	require_root || return 1
	require_procps || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	command -v iptables >/dev/null 2>&1 || { log "FAIL: no iptables"; return 1; }

	_wild=0
	case "$name" in *-wild) _wild=1 ;; esac

	_tag=$(printf '%s' "$name" | cksum | awk '{printf "%06x", $1}')
	NSI="n${name}-i"; NSN="n${name}-n"; NSR="n${name}-r"
	VI1="v${_tag}a"; VI2="v${_tag}b"; VR1="v${_tag}c"; VR2="v${_tag}d"
	D="/tmp/r2-${name}"; C="/tmp/r2-${name}-conf"
	rm -rf "$D" "$C"; mkdir -p -m 700 "$D" "$C"
	PRIVRES_I="$D/resume-i"; PRIVRES_R="$D/resume-r"
	mkdir -p "$PRIVRES_I" "$PRIVRES_R"

	cleanup() {
		ip netns exec "$NSI" pkill -9 -f "$SBIN/iked" 2>/dev/null || true
		ip netns exec "$NSR" pkill -9 -f "$SBIN/iked" 2>/dev/null || true
		ip netns exec "$NSI" pkill -9 -f "$SBIN/spmd" 2>/dev/null || true
		ip netns exec "$NSR" pkill -9 -f "$SBIN/spmd" 2>/dev/null || true
		ip netns del "$NSI" 2>/dev/null || true
		ip netns del "$NSN" 2>/dev/null || true
		ip netns del "$NSR" 2>/dev/null || true
		ip link del "$VI1" 2>/dev/null || true
		ip link del "$VR1" 2>/dev/null || true
	}
	cleanup
	trap 'cleanup' EXIT

	ip netns add "$NSI" && ip netns add "$NSN" && ip netns add "$NSR" || {
		log "FAIL: netns create"; return 1; }
	ip link add "$VI1" type veth peer name "$VI2" || { log "FAIL: veth i"; return 1; }
	ip link add "$VR1" type veth peer name "$VR2" || { log "FAIL: veth r"; return 1; }
	ip link set "$VI1" netns "$NSI"
	ip link set "$VI2" netns "$NSN"
	ip link set "$VR1" netns "$NSN"
	ip link set "$VR2" netns "$NSR"
	ip netns exec "$NSI" ip addr add 10.9.0.2/24 dev "$VI1"
	ip netns exec "$NSI" ip link set "$VI1" up
	ip netns exec "$NSI" ip link set lo up
	ip netns exec "$NSI" ip route add default via 10.9.0.1
	ip netns exec "$NSN" ip addr add 10.9.0.1/24 dev "$VI2"
	ip netns exec "$NSN" ip addr add 192.0.5.254/24 dev "$VR1"
	ip netns exec "$NSN" ip link set "$VI2" up
	ip netns exec "$NSN" ip link set "$VR1" up
	ip netns exec "$NSN" ip link set lo up
	ip netns exec "$NSN" sysctl -q net.ipv4.ip_forward=1
	ip netns exec "$NSR" ip addr add 192.0.5.1/24 dev "$VR2"
	ip netns exec "$NSR" ip link set "$VR2" up
	ip netns exec "$NSR" ip link set lo up
	# SNAT initiator traffic to 192.0.5.254
	ip netns exec "$NSN" iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$VR1" \
		-j SNAT --to-source 192.0.5.254
	ip netns exec "$NSN" iptables -A FORWARD -j ACCEPT

	dd if=/dev/urandom of="$D/test.psk" bs=32 count=1 status=none
	chmod 600 "$D/test.psk"
	cp "$ETC/spmd.pwd" "$D/spmd.pwd" 2>/dev/null || printf 'ci-spmd-pw\n' > "$D/spmd.pwd"
	chmod 600 "$D/spmd.pwd"

	_nat_conf() {
		_seat=$1 _my=$2 _peer=$3 _myid=$4 _peerid=$5 _passive=$6 _selwild=$7
		if [ "$_selwild" = 1 ]; then
			_sout_s="0.0.0.0/0"; _sout_d="0.0.0.0/0"
			_sin_s="0.0.0.0/0"; _sin_d="0.0.0.0/0"
		else
			_sout_s="$_my"; _sout_d="$_peer"
			_sin_s="$_peer"; _sin_d="$_my"
		fi
		cat > "$C/$_seat.conf" <<EOF
interface {
	ike { $_my; };
	spmd { unix "$D/$_seat-spmif"; };
	spmd_password "$D/spmd.pwd";
};
resolver { resolver off; };
remote matrix_$_seat {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive $_passive;
		my_id fqdn "$_myid";
		peers_id fqdn "$_peerid";
		peers_ipaddr $_peer;
		nat_traversal on;
		kmp_enc_alg { aes_gcm; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$D/test.psk";
		dpd_delay 60 sec;
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src $_sout_s; dst $_sout_d;
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst $_sin_d; src $_sin_s;
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_$_seat;
	ipsec_mode transport;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr $_peer;
	my_sa_ipaddr $_my;
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
	}
	_nat_conf init 10.9.0.2 192.0.5.1 r2init-matrix racoon2-matrix off 0
	_nat_conf resp 192.0.5.1 192.0.5.254 racoon2-matrix r2init-matrix on $_wild

	ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$D/resp-ctl" RACOON2_RESUME_DIR="$PRIVRES_R" \
		"$SBIN/spmd" -F -f "$C/resp.conf" > "$D/resp-spmd.log" 2>&1 &
	ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$D/init-ctl" RACOON2_RESUME_DIR="$PRIVRES_I" \
		"$SBIN/spmd" -F -f "$C/init.conf" > "$D/init-spmd.log" 2>&1 &
	_w=0; while [ "$_w" -lt 15 ] && { [ ! -S "$D/resp-spmif" ] || [ ! -S "$D/init-spmif" ]; }; do
		_w=$((_w+1)); sleep 1
	done
	sleep 1
	ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$D/resp-ctl" RACOON2_RESUME_DIR="$PRIVRES_R" \
		"$SBIN/iked" -F -f "$C/resp.conf" -D 0x0003 > "$D/resp-iked.log" 2>&1 &
	ip netns exec "$NSI" env RACOON2_ADMIN_SOCK="$D/init-ctl" RACOON2_RESUME_DIR="$PRIVRES_I" \
		"$SBIN/iked" -F -f "$C/init.conf" -D 0x0003 > "$D/init-iked.log" 2>&1 &
	sleep 3
	ip netns exec "$NSI" "$SBIN/ikedctl" -s "$D/init-ctl" \
		establish-sa isakmp inet 10.9.0.2 192.0.5.1 sel_out > "$D/ctl.out" 2>&1 || true

	_up=0; _i=0
	while [ "$_i" -lt 45 ]; do
		_er=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp' || true)
		_ei=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp' || true)
		[ "${_er:-0}" -ge 2 ] && [ "${_ei:-0}" -ge 2 ] && { _up=1; break; }
		_i=$((_i+1)); sleep 1
	done
	_bad=""
	[ "$_up" = 1 ] || _bad="no esp transport SA pair in both netns (r=${_er:-0} i=${_ei:-0})"

	if [ "$_up" = 1 ]; then
		ip netns exec "$NSI" ping -c 1 -W 5 192.0.5.1 > "$D/ping.txt" 2>&1 || true
		grep -q '1 received' "$D/ping.txt" || _bad="${_bad:+$_bad; }ICMP did not cross NAT-T transport"
		rm -f "$D/tcp-recv.txt"
		ip netns exec "$NSR" /bin/sh -c "nc -l -w 15 -p 5001 > '$D/tcp-recv.txt' 2>/dev/null &"
		sleep 1
		echo "racoon2-natt-tcp-$$" | ip netns exec "$NSI" nc -w 5 192.0.5.1 5001 > "$D/tcp-send.txt" 2>&1 || true
		_w=0; while [ "$_w" -lt 10 ] && ! grep -q "racoon2-natt-tcp-$$" "$D/tcp-recv.txt" 2>/dev/null; do
			_w=$((_w+1)); sleep 1
		done
		grep -q "racoon2-natt-tcp-$$" "$D/tcp-recv.txt" 2>/dev/null || \
			_bad="${_bad:+$_bad; }TCP payload did not cross NAT-T transport"
	fi

	if [ "$_wild" = 1 ] && [ -z "$_bad" ]; then
		if grep -qF 'NAT-T transport: substituted TSi with 192.0.5.254' "$D/resp-iked.log" 2>/dev/null; then
			log "N3 OK - responder substituted TSi with post-NAT 192.0.5.254"
		else
			_bad="N3: no 'substituted TSi with 192.0.5.254' in responder log"
		fi
	fi
	if [ -z "$_bad" ]; then
		if grep -qE 'NAT-T OA for (inbound|outbound) SA:.*10\.9\.0\.2' "$D/resp-iked.log" 2>/dev/null; then
			log "N4 OK - NAT-OA carries original TSi 10.9.0.2"
		else
			_bad="N4: no NAT-OA with original TSi 10.9.0.2 in responder log"
		fi
	fi

	if [ -z "$_bad" ]; then
		if [ "$_wild" = 1 ]; then
			log "PASS $name (N3 wildcard SPD + post-NAT TSi, N4 NAT-OA, ICMP+TCP)"
		else
			log "PASS $name (NAT-T transport across SNAT: esp SAs, ICMP+TCP, N4 NAT-OA)"
		fi
		trap - EXIT; cleanup
		return 0
	fi
	log "FAIL $name ($_bad)"
	log "--- resp iked (NAT/TS) ---"
	grep -iE 'nat|TS|substitut|OA|error|fail' "$D/resp-iked.log" 2>/dev/null | tail -40 || true
	log "--- init iked (NAT/TS) ---"
	grep -iE 'nat|TS|substitut|OA|error|fail' "$D/init-iked.log" 2>/dev/null | tail -40 || true
	trap - EXIT; cleanup
	return 1
}
