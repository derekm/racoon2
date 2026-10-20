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
#   i2inatt-rebind          XFRM_MSG_MAPPING: after the SA is up, the NAT
#                           box rebinds the initiator to a new UDP port
#                           (conntrack expiry + SNAT to :40000-40100).  The
#                           responder (natt_follow_mapping on) must get the
#                           kernel MAPPING event, migrate its outbound SA to
#                           the new encap dport, and replies must flow again.
#   i2inatt-rebind-off      same rebind with natt_follow_mapping off: the
#                           MAPPING is logged and ignored, the outbound encap
#                           dport stays 4500 and replies stay lost (proves
#                           the on-row is not passing by accident).
#   i2inatt-xfrmflood       netlink ENOBUFS: SIGSTOP the responder iked and
#                           spmd, flood ~6000 XFRM SA events and delete the
#                           live inbound SA behind iked's back, SIGCONT.  Both
#                           daemons must report the overflow and resync;
#                           iked must notice its inbound SA is gone and rekey
#                           the child (new SPI, ping works); the SPD policy
#                           count must be unchanged.
kind_i2inatt() {
	name=$1
	require_root || return 1
	require_procps || return 1
	[ -x "$SBIN/iked" ] || { log "FAIL: no $SBIN/iked"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { log "FAIL: no $ETC/spmd.pwd"; return 1; }
	command -v iptables >/dev/null 2>&1 || { log "FAIL: no iptables"; return 1; }

	_wild=0 _rebind=0 _follow=off _flood=0 _natk=0
	case "$name" in
	*-wild) _wild=1 ;;
	*-keepalive) _natk=1 ;;
	*-rebind-off) _rebind=1 _follow=off ;;
	*-rebind) _rebind=1 _follow=on ;;
	*-xfrmflood) _flood=1 ;;
	esac

	_tag=$(printf '%s' "$name" | cksum | awk '{printf "%06x", $1}')
	NSI="n${name}-i"; NSN="n${name}-n"; NSR="n${name}-r"
	VI1="v${_tag}a"; VI2="v${_tag}b"; VR1="v${_tag}c"; VR2="v${_tag}d"
	D="/tmp/r2-${name}"; C="/tmp/r2-${name}-conf"
	rm -rf "$D" "$C"; mkdir -p -m 700 "$D" "$C"
	PRIVRES_I="$D/resume-i"; PRIVRES_R="$D/resume-r"
	mkdir -p "$PRIVRES_I" "$PRIVRES_R"

	cleanup() {
		# Rules live in the NAT netns, not on the runner host.  Flush
		# them before the netns delete: an early return hits this EXIT
		# trap, and a busy netns del must not leave the SNAT behind.
		ip netns exec "$NSN" iptables -t nat -F POSTROUTING 2>/dev/null || true
		ip netns exec "$NSN" iptables -F FORWARD 2>/dev/null || true
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
		dpd_delay 60 sec;$_extra
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
	_extra=
	_nat_conf init 10.9.0.2 192.0.5.1 r2init-matrix racoon2-matrix off 0
	# _natk is 0 or 1, never empty.  [ -z "$_natk" ] is false for "0",
	# which omitted natt_follow_mapping and made the on-row behave as off
	# (MAPPING logged, encap stayed dport 4500, 0/6 pings).
	if [ "$_rebind" = 1 ] && [ "$_natk" != 1 ]; then _extra="
		natt_follow_mapping $_follow;"; fi
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

	# NAT Keepalive capture: open it BEFORE the ICMP/TCP probes so it spans
	# the whole SA-up period.  Keepalives are emitted on a ~20s cadence from
	# SA establishment; opening the capture only AFTER the probes (which run
	# 20-50s under 3-shard load) used to miss the periodic 1-byte 0xff frames.
	_tp=
	if [ "$_up" = 1 ] && [ "$_natk" = 1 ]; then
		command -v tcpdump >/dev/null 2>&1 || \
			_bad="keepalive: no tcpdump (needed to capture the 1-byte 0xff frame)"
	fi
	if [ "$_up" = 1 ] && [ "$_natk" = 1 ] && [ -z "$_bad" ]; then
		ip netns exec "$NSR" tcpdump -nni "$VR2" -c 1 \
			'udp port 4500 and less 50' \
			> "$D/natk.txt" 2>"$D/natk-err.txt" &
		_tp=$!
	fi

	if [ "$_up" = 1 ]; then
		# ICMP across NAT-T.  This is a READINESS wait, not a single shot:
		# "esp SA pair present" can be true while the child data path is
		# still being installed (under 3-shard loads the responder's
		# spmd_pfkey may be a second or two behind the SA being listed),
		# so a single `ping -c 1` races that window and drops valid rows.
		# Poll until a reply crosses (or 20s), THEN assert data really
		# flowed.  A real data-path failure still fails the row.
		_icmpok=0
		_p=0
		while [ "$_p" -lt 20 ]; do
			ip netns exec "$NSI" ping -c 1 -W 3 192.0.5.1 > "$D/ping.txt" 2>&1 || true
			if grep -q '1 received' "$D/ping.txt"; then _icmpok=1; break; fi
			_p=$((_p+1)); sleep 1
		done
		grep -q '1 received' "$D/ping.txt" || \
			_bad="${_bad:+$_bad; }ICMP did not cross NAT-T transport"
		rm -f "$D/tcp-recv.txt"
		# TCP across the NAT-T transport.  Ncat 7.92's nested
		# `ip netns exec sh -c "nc -l ... &"` exits the inner shell
		# immediately, so the listener is often gone before the client
		# connects (observed: 'TCP payload did not cross' while ICMP/XA
		# traffic passed — the only probe that needs a listener).  Make
		# the listener a DIRECT background of this shell, wait for :5001
		# to listen in the responder netns, then send; retry the whole
		# exchange (the listener may die with a per-attempt restart).
		_tpass=0
		for _a in 1 2 3; do
			rm -f "$D/tcp-recv.txt"
			ip netns exec "$NSR" nc -l -w 15 -p 5001 > "$D/tcp-recv.txt" 2>/dev/null &
			_ncl=$!
			_w=0
			while [ "$_w" -lt 10 ] && \
			      ! ip netns exec "$NSR" sh -c 'ss -ltn 2>/dev/null' | grep -q ':5001'; do
				_w=$((_w+1)); sleep 1
			done
			echo "racoon2-natt-tcp-$$" | ip netns exec "$NSI" nc -w 5 192.0.5.1 5001 > "$D/tcp-send.txt" 2>&1 || true
			_w=0; while [ "$_w" -lt 10 ] && ! grep -q "racoon2-natt-tcp-$$" "$D/tcp-recv.txt" 2>/dev/null; do
				_w=$((_w+1)); sleep 1
			done
			kill "$_ncl" 2>/dev/null || true
			wait "$_ncl" 2>/dev/null || true
			if grep -q "racoon2-natt-tcp-$$" "$D/tcp-recv.txt" 2>/dev/null; then
				_tpass=1; break
			fi
		done
		grep -q "racoon2-natt-tcp-$$" "$D/tcp-recv.txt" 2>/dev/null || \
			_bad="${_bad:+$_bad; }TCP payload did not cross NAT-T transport"
	fi

	if [ "$_natk" = 1 ] && [ -z "$_bad" ]; then
		# RFC 3948 §2.2 / RFC 7296 §3.23.5 NAT-T Keepalive, LIVE proof of
		# natt_natk_callback (armed by natt_start_natk once a seat sees
		# itself behind a NAT or its peer behind a NAT).  In this SNAT
		# topology BOTH iked seats arm it and each sends a 1-byte 0xff
		# keepalive to the floated UDP:4500; capture ANY 1-byte UDP:4500
		# frame on the responder's veth (1-byte keepalive = 43 wire bytes,
		# 'less 50' catches it; ESP-in-UDP is far larger).  The capture was
		# already opened BEFORE the data probes; wait up to 90s total from
		# here for a frame (20s cadence; the window must span >=1 period
		# even under 3-shard CPU load).
		_w=0
		while [ "$_w" -lt 240 ] && \
		      ! grep -qE 'isakmp-nat-keep-alive|length 1' "$D/natk.txt" 2>/dev/null; do
			_w=$((_w+1)); sleep 1
		done
		kill "$_tp" 2>/dev/null || true
		if grep -qE 'isakmp-nat-keep-alive|length 1' "$D/natk.txt" 2>/dev/null; then
			log "RFC 3948 NAT Keepalive (1-byte 0xff on UDP:4500) observed"
		else
			_bad="${_bad:+$_bad; }no 1-byte NAT Keepalive (0xff) on UDP:4500"
			cat "$D/natk-err.txt" "$D/natk.txt" 2>/dev/null | tail -5
			# KP-DIAG: the row dirs are wiped per-row, so dump the live
			# wire/capture state here (it survives in the merged log) to
			# tell "keepalive never sent" from "sent but tcpdump missed":
			# a fresh 6s tcpdump on the responder veth while the SA is up.
			log "KP-DIAG: natk_lines=$(wc -l <"$D/natk.txt" 2>/dev/null) netns=$(ip netns list 2>/dev/null | wc -l) avmem=$(free -m 2>/dev/null | awk 'NR==2{print $7}')"
			log "KP-DIAG-live: $( ( ip netns exec "$NSR" timeout 6 tcpdump -nni "$VR2" -c 2 'udp port 4500 and less 50' 2>&1 ) | tr '\n' ' ' | tail -c 300 )"
		fi
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
	# M1 (RFC 7296 s2.23.1): the initiator's OA is the TSi the responder
	# returned (post-NAT 192.0.5.254), never its own SA endpoint.
	if [ -z "$_bad" ]; then
		if ! grep -qE 'NAT-T OA for outbound SA: src=192\.0\.5\.254 ' "$D/init-iked.log" 2>/dev/null; then
			_bad="M1: initiator OA is not the returned post-NAT TSi 192.0.5.254"
		elif grep -qE 'NAT-T OA for (inbound|outbound) SA:.*=10\.9\.0\.2( |$)' "$D/init-iked.log" 2>/dev/null; then
			_bad="M1: initiator OA equals its own SA endpoint 10.9.0.2"
		else
			log "M1 OK - initiator OA is the returned post-NAT TSi 192.0.5.254"
		fi
	fi

	# --- NAT rebinding (XFRM_MSG_MAPPING, natt_follow_mapping) ---
	_out_encap() {
		# encap line of the responder's OUTBOUND SA (192.0.5.1 -> NAT)
		ip netns exec "$NSR" ip xfrm state 2>/dev/null | awk '
			/^src /{ f = ($2 == "192.0.5.1" && $4 == "192.0.5.254") }
			f && /encap type/ { print; exit }'
	}
	if [ "$_rebind" = 1 ] && [ -z "$_bad" ]; then
		_e0=$(_out_encap)
		log "rebind: outbound encap before: ${_e0:-none}"
		case "$_e0" in *"dport 4500"*) ;; *)
			_bad="rebind: outbound SA encap is not dport 4500 before the rebind (${_e0:-none})" ;;
		esac
	fi
	if [ "$_rebind" = 1 ] && [ -z "$_bad" ]; then
		# Expire the UDP conntrack entry fast, stay silent past it, then
		# force new mappings onto 40000-40100: the next ESP-in-UDP from the
		# initiator arrives at the responder from a new source port.
		ip netns exec "$NSN" sysctl -q net.netfilter.nf_conntrack_udp_timeout=2 \
			net.netfilter.nf_conntrack_udp_timeout_stream=2 2>/dev/null || true
		ip netns exec "$NSN" iptables -t nat -I POSTROUTING 1 -s 10.9.0.0/24 \
			-o "$VR1" -p udp -j SNAT --to-source 192.0.5.254:40000-40100
		# Idle timeout alone does not drop the 4500 mapping (any
		# IKE/keepalive datagram refreshes it).  Delete the NAT's UDP
		# conntrack entries so the next ESP-in-UDP datagram MUST take a
		# new 40000-40100 mapping.
		if ! command -v conntrack >/dev/null 2>&1; then
			_bad="rebind: conntrack(8) not installed (needed to drop the NAT mapping)"
		else
			ip netns exec "$NSN" conntrack -D -p udp -s 10.9.0.2 >/dev/null 2>&1 || true
		fi
	fi
	if [ "$_rebind" = 1 ] && [ -z "$_bad" ]; then
		# Stimulus, then poll kernel state.  The proof pings are not the
		# wait: follow=on does not start them until the outbound encap
		# dport has moved (or 20s).  follow=off must not wait for a move
		# that is a failure.
		ip netns exec "$NSI" ping -c 1 -W 2 192.0.5.1 > "$D/ping-stim.txt" 2>&1 || true
		_w=0
		if [ "$_follow" = on ]; then
			while [ "$_w" -lt 20 ]; do
				_e1=$(_out_encap)
				case "$_e1" in *"dport 40"[01][0-9][0-9]*) break ;; esac
				_w=$((_w+1)); sleep 1
			done
		fi
		ip netns exec "$NSI" ping -c 6 -i 1 -W 2 192.0.5.1 > "$D/ping-rebind.txt" 2>&1 || true
		_w=0; while [ "$_w" -lt 5 ] && ! grep -q 'received XFRM MAPPING' "$D/resp-iked.log" 2>/dev/null; do
			_w=$((_w+1)); sleep 1
		done
		_e1=$(_out_encap)
		_rx=$(sed -n 's/.* \([0-9][0-9]*\) received.*/\1/p' "$D/ping-rebind.txt" | head -1)
		log "rebind: outbound encap after: ${_e1:-none}; pings answered: ${_rx:-0}/6"
		if ! grep -qE 'received XFRM MAPPING spi=0x[0-9a-f]+ .*192\.0\.5\.254.*-> .*192\.0\.5\.254' "$D/resp-iked.log" 2>/dev/null; then
			_bad="rebind: responder never got an XFRM MAPPING event for the new NAT port"
		elif [ "$_follow" = on ]; then
			grep -q 'NAT-T mapping change' "$D/resp-iked.log" 2>/dev/null ||
				_bad="rebind: no 'NAT-T mapping change' (iked did not follow)"
			case "$_e1" in *"dport 40"[01][0-9][0-9]*) ;; *)
				_bad="${_bad:+$_bad; }rebind: outbound encap did not move to the new port (${_e1:-none})" ;;
			esac
			[ "${_rx:-0}" -ge 3 ] ||
				_bad="${_bad:+$_bad; }rebind: only ${_rx:-0}/6 pings answered after the rebind"
		else
			grep -q 'ignored (natt_follow_mapping off)' "$D/resp-iked.log" 2>/dev/null ||
				_bad="rebind-off: MAPPING was not logged as ignored"
			case "$_e1" in *"dport 4500"*) ;; *)
				_bad="${_bad:+$_bad; }rebind-off: outbound encap moved although natt_follow_mapping is off (${_e1:-none})" ;;
			esac
			[ "${_rx:-0}" -eq 0 ] ||
				_bad="${_bad:+$_bad; }rebind-off: ${_rx} pings answered although replies go to the dead mapping"
		fi
	fi

	# --- netlink notification overflow (ENOBUFS) + resync ---
	if [ "$_flood" = 1 ] && [ -z "$_bad" ]; then
		_inspi=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | awk '
			/^src /{ f = ($2 == "192.0.5.254" && $4 == "192.0.5.1"); next }
			f && /proto esp spi/ { print $4; exit }')
		_pol0=$(ip netns exec "$NSR" ip xfrm policy 2>/dev/null | grep -c '^src')
		_ikp=$(pgrep -f "$SBIN/iked -F -f $C/resp.conf" | head -1)
		_smp=$(pgrep -f "$SBIN/spmd -F -f $C/resp.conf" | head -1)
		log "flood: responder inbound spi=${_inspi:-?} policies=$_pol0 iked=$_ikp spmd=$_smp"
		if [ -z "$_inspi" ] || [ -z "$_ikp" ] || [ -z "$_smp" ]; then
			_bad="flood: could not find the inbound SA or the responder daemons"
		else
			: > "$D/flood.batch"
			_k=1
			while [ "$_k" -le 3000 ]; do
				printf 'xfrm state add src 198.18.0.1 dst 198.18.0.2 proto esp spi %d mode transport enc cbc(aes) 0x00112233445566778899aabbccddeeff auth-trunc hmac(sha256) 0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 128\n' \
					$((65536 + _k)) >> "$D/flood.batch"
				_k=$((_k+1))
			done
			kill -STOP "$_ikp" "$_smp"
			# explicit per-SPI deletes in the same batch: twice the events
			# (the filtered "deleteall" left all 3000 behind on CI)
			_k=1
			while [ "$_k" -le 3000 ]; do
				printf 'xfrm state delete src 198.18.0.1 dst 198.18.0.2 proto esp spi %d\n' \
					$((65536 + _k)) >> "$D/flood.batch"
				_k=$((_k+1))
			done
			ip -n "$NSR" -force -batch "$D/flood.batch" > "$D/flood.out" 2>&1 || true
			# the event iked needs is now lost in the overflow
			ip -n "$NSR" xfrm state delete src 192.0.5.254 dst 192.0.5.1 proto esp spi "$_inspi" 2>/dev/null || true
			kill -CONT "$_ikp" "$_smp"
			_w=0; _newspi=
			while [ "$_w" -lt 40 ]; do
				_newspi=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | awk -v old="$_inspi" '
					/^src /{ f = ($2 == "192.0.5.254" && $4 == "192.0.5.1"); next }
					f && /proto esp spi/ && $4 != old { print $4; exit }')
				[ -n "$_newspi" ] && break
				_w=$((_w+1)); sleep 1
			done
			sleep 2
			ip netns exec "$NSI" ping -c 3 -W 3 192.0.5.1 > "$D/ping-flood.txt" 2>&1 || true
			_pol1=$(ip netns exec "$NSR" ip xfrm policy 2>/dev/null | grep -c '^src')
			_left=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c '^src 198\.18\.0\.1 ' || true)
			log "flood: new inbound spi=${_newspi:-none} policies $_pol0 -> $_pol1 leftover-dummies=$_left"
			grep -q 'notification socket overflowed (ENOBUFS)' "$D/resp-iked.log" 2>/dev/null ||
				_bad="flood: iked never saw ENOBUFS on its notification socket"
			grep -qE 'SAD/SPD resync [0-9]+ complete' "$D/resp-iked.log" 2>/dev/null ||
				_bad="${_bad:+$_bad; }flood: iked did not complete a SAD/SPD resync"
			grep -q "resync: inbound SA spi=$_inspi is gone from the kernel" "$D/resp-iked.log" 2>/dev/null ||
				_bad="${_bad:+$_bad; }flood: iked did not notice its deleted inbound SA $_inspi"
			grep -q 'notification socket overflowed (ENOBUFS)' "$D/resp-spmd.log" 2>/dev/null ||
				_bad="${_bad:+$_bad; }flood: spmd never saw ENOBUFS"
			grep -qE 'SAD/SPD resync [0-9]+ complete' "$D/resp-spmd.log" 2>/dev/null ||
				_bad="${_bad:+$_bad; }flood: spmd did not complete a resync"
			[ -n "$_newspi" ] ||
				_bad="${_bad:+$_bad; }flood: child was not rekeyed after the resync"
			grep -q '[1-9][0-9]* received' "$D/ping-flood.txt" 2>/dev/null ||
				_bad="${_bad:+$_bad; }flood: no ICMP across the tunnel after the resync"
			[ "$_pol1" = "$_pol0" ] ||
				_bad="${_bad:+$_bad; }flood: SPD changed across the overflow ($_pol0 -> $_pol1 policies)"
			[ "${_left:-0}" -eq 0 ] ||
				_bad="${_bad:+$_bad; }flood: $_left dummy SAs left behind"
		fi
	fi

	if [ -z "$_bad" ]; then
		if [ "$_wild" = 1 ]; then
			log "PASS $name (N3 wildcard SPD + post-NAT TSi, N4 NAT-OA, ICMP+TCP)"
		elif [ "$_rebind" = 1 ]; then
			log "PASS $name (NAT rebinding, natt_follow_mapping $_follow)"
		elif [ "$_flood" = 1 ]; then
			log "PASS $name (ENOBUFS overflow resynced, child rekeyed, SPD intact)"
		elif [ "$_natk" = 1 ]; then
			log "PASS $name (NAT-T across SNAT + RFC 3948 NAT Keepalive 0xff on UDP:4500)"
		else
			log "PASS $name (NAT-T transport across SNAT: esp SAs, ICMP+TCP, N4 NAT-OA)"
		fi
		trap - EXIT; cleanup
		return 0
	fi
	log "FAIL $name ($_bad)"
	log "--- resp iked (NAT/TS) ---"
	grep -iE 'nat|TS|substitut|OA|error|fail|mapping|resync|enobufs|overflow' "$D/resp-iked.log" 2>/dev/null | tail -60 || true
	log "--- resp spmd ---"
	tail -30 "$D/resp-spmd.log" 2>/dev/null || true
	log "--- init iked (NAT/TS) ---"
	grep -iE 'nat|TS|substitut|OA|error|fail' "$D/init-iked.log" 2>/dev/null | tail -40 || true
	trap - EXIT; cleanup
	return 1
}
