#!/bin/sh
# kinds/veth_account.sh — veth accounting identity audit (review #2/#5).
#
# Every counted-drop gate (i2ike-drop, i2iinit-drop, *drop576) reads the
# netem qdisc's own "dropped" counter (lib.sh tc_dropped) and asserts
# the IKE exchange recovered.  That premise — that every datagram the
# sender socket handed over is EITHER received by the peer veth OR
# dropped at the netem qdisc, with no third bucket (kernel xfrm, socket
# buffer, rp_filter...) silently eating packets — was never audited.
# This kind is the audit, as a standalone link test (no iked, no ADDKE):
#
#   sent == peer_received + qdisc_dropped
#
# for both directions, measured three ways that must AGREE:
#   1. N  = exact number of UDP datagrams the generator emitted
#           (explicit bash (/dev/udp) loop; also covers UDP/500 AND
#            UDP/4500, the two IKE ports, on alternating datagrams)
#   2. RX = veth peer RX packet-counter delta (kernel truth, ip -s link)
#   3. D  = netem qdisc dropped delta on the sender egress (tc -s qdisc)
#
# Passes:
#   A->B with 30% netem loss on A's egress:  N == RX_B + D_A  AND  D_A >= 1
#   B->A with 30% netem loss on B's egress:  N == RX_A + D_B  AND  D_B >= 1
#   A->B with NO loss:                       N == RX_B        AND  D_A == 0
#
# If any identity fails, the counted-drop gates built on tc_dropped()
# are not trustworthy and the row FAILs loudly with the numbers.
#
# ARP priming (review #5, retained verdict: "`veth-account` does not
# measure the identity it asserts. N is userspace UDP sends; peer RX and
# qdisc dropped count every packet on that veth, including the ARP
# request the first send generates through the same netem qdisc. On a
# correct kernel R+D is not 200."): the kernel resolves ARP lazily, so
# the FIRST packet of a fresh flow emits an ARP request that rides the
# sender egress qdisc and lands in the peer RX counter — a third bucket
# outside N.  Before every baseline we therefore prime the link: send
# single UDP datagrams (retried until one provably arrives, which also
# proves ARP resolved) until the peer RX counter ticks, THEN take the
# d0/r0 baselines.  The priming traffic is excluded from every delta by
# construction.  ARP entries (dest reached, ~600s STALE hold) cover the
# whole 200-packet flood with no new ARP frames.  ICMP port-unreachable
# replies from the unbound receiver travel the REVERSE direction only,
# never the asserted forward egress/RX (baselines taken immediately
# after priming; 2s settle before each re-read).
kind_veth_account() {
	name=$1
	require_root || return 1
	command -v bash >/dev/null 2>&1 || { log "FAIL: bash (UDP generator) not installed"; return 1; }
	[ -x "$(command -v ip)" ] || { log "FAIL: iproute2 not installed"; return 1; }

	NA=vethacc-a; NB=vethacc-b; VA=vethacc-a; VB=vethacc-b
	IA=192.0.12.1; IB=192.0.12.2
	ip netns del "$NA" 2>/dev/null || true
	ip netns del "$NB" 2>/dev/null || true
	ip link del "$VA" 2>/dev/null || true

	ip netns add "$NA"; ip netns add "$NB"
	ip netns exec "$NA" ip link set lo up
	ip netns exec "$NB" ip link set lo up
	ip link add "$VA" type veth peer name "$VB"
	ip link set "$VA" netns "$NA"
	ip netns exec "$NA" ip link set "$VA" up
	ip netns exec "$NA" ip addr add "$IA/24" dev "$VA"
	ip link set "$VB" netns "$NB"
	ip netns exec "$NB" ip link set "$VB" up
	ip netns exec "$NB" ip addr add "$IB/24" dev "$VB"

	# RX/TX packet counters on a veth end, from `ip -s link` "RX: bytes
	# packets errors ..." -> data line: $1 bytes, $2 packets.
	dev_pkts() {
		_ns=$1 _dev=$2 _dir=$3
		ip netns exec "$_ns" ip -s link show dev "$_dev" 2>/dev/null \
			| awk -v d="$_dir" '
				$1 == d ":" { getline; print $2; exit }
			  '
	}
	# Prime ARP on the path _nsfrom->(_nstop,_devstop): single-datagram
	# sends, retried until the PEER's RX counter ticks (delivery proves
	# ARP resolved).  Runs before every baseline so no priming frame
	# lands inside an asserted delta.
	prime_arp() {
		_nsfrom=$1 _nstop=$2 _devstop=$3 _dst=$4
		_seen=$(dev_pkts "$_nstop" "$_devstop" RX)
		_t=0
		while [ "$_t" -lt 40 ]; do
			ip netns exec "$_nsfrom" bash -c \
				'printf x > "/dev/udp/$1/500"' _ "$_dst" 2>/dev/null || true
			sleep 0.5
			_now=$(dev_pkts "$_nstop" "$_devstop" RX)
			if [ "${_now:-0}" -gt "${_seen:-0}" ]; then
				sleep 0.2
				return 0
			fi
			_t=$((_t + 1))
		done
		log "FAIL: ARP prime saw no delivery on $_nstop/$_devstop"
		return 1
	}
	flood() {
		_ns=$1 _dst=$2 _n=$3
		# UDP/500 + UDP/4500 on alternating datagrams (the two IKE ports).
		ip netns exec "$_ns" bash -c '
			n=$1; dst=$2
			for i in $(seq 1 "$n"); do
				if [ $((i % 2)) -eq 0 ]; then p=500; else p=4500; fi
				printf x > "/dev/udp/$dst/$p" || exit 1
		done
		' _ "$_n" "$_dst"
	}

	fail=0
	# --- pass 1: A->B with 30% loss on A egress ---
	if ! ip netns exec "$NA" tc qdisc replace dev "$VA" root netem loss 30% 2>/dev/null; then
		log "FAIL: cannot apply netem loss on $NA/$VA (no tc?)"
		fail=1
	else
		prime_arp "$NA" "$NB" "$VB" "$IB" || fail=1
		d0=$(tc_dropped "$NA" "$VA" || true)
		r0=$(dev_pkts "$NB" "$VB" RX)
		flood "$NA" "$IB" 200 || fail=1
		sleep 2
		d1=$(tc_dropped "$NA" "$VA" || true)
		r1=$(dev_pkts "$NB" "$VB" RX)
		D=$(( ${d1:-0} - ${d0:-0} ))
		R=$(( ${r1:-0} - ${r0:-0} ))
		if [ "$((R + D))" -eq 200 ] && [ "$D" -ge 1 ]; then
			log "VETH-ACCOUNT A->B: sent=200 received=$R qdisc_dropped=$D (200 == $R + $D) OK"
		else
			log "FAIL: VETH-ACCOUNT A->B identity broken: sent=200 received=$R qdisc_dropped=$D (need 200 == $R + $D AND dropped >= 1)"
			fail=1
		fi
		ip netns exec "$NA" tc qdisc del dev "$VA" root 2>/dev/null || true
	fi

	# --- pass 2: B->A with 30% loss on B egress ---
	if ! ip netns exec "$NB" tc qdisc replace dev "$VB" root netem loss 30% 2>/dev/null; then
		log "FAIL: cannot apply netem loss on $NB/$VB (no tc?)"
		fail=1
	else
		prime_arp "$NB" "$NA" "$VA" "$IA" || fail=1
		d0=$(tc_dropped "$NB" "$VB" || true)
		r0=$(dev_pkts "$NA" "$VA" RX)
		flood "$NB" "$IA" 200 || fail=1
		sleep 2
		d1=$(tc_dropped "$NB" "$VB" || true)
		r1=$(dev_pkts "$NA" "$VA" RX)
		D=$(( ${d1:-0} - ${d0:-0} ))
		R=$(( ${r1:-0} - ${r0:-0} ))
		if [ "$((R + D))" -eq 200 ] && [ "$D" -ge 1 ]; then
			log "VETH-ACCOUNT B->A: sent=200 received=$R qdisc_dropped=$D (200 == $R + $D) OK"
		else
			log "FAIL: VETH-ACCOUNT B->A identity broken: sent=200 received=$R qdisc_dropped=$D (need 200 == $R + $D AND dropped >= 1)"
			fail=1
		fi
		ip netns exec "$NB" tc qdisc del dev "$VB" root 2>/dev/null || true
	fi

	# --- pass 3: A->B with NO loss (exact delivery; dropped must be 0) ---
	prime_arp "$NA" "$NB" "$VB" "$IB" || fail=1
	r0=$(dev_pkts "$NB" "$VB" RX)
	flood "$NA" "$IB" 200 || fail=1
	sleep 2
	r1=$(dev_pkts "$NB" "$VB" RX)
	R=$(( ${r1:-0} - ${r0:-0} ))
	if [ "$R" -eq 200 ]; then
		log "VETH-ACCOUNT clean: sent=200 received=$R qdisc_dropped=0 OK"
	else
		log "FAIL: VETH-ACCOUNT clean link lost packets: sent=200 received=$R"
		fail=1
	fi

	ip netns del "$NA" 2>/dev/null || true
	ip netns del "$NB" 2>/dev/null || true
	ip link del "$VA" 2>/dev/null || true

	[ "$fail" -eq 0 ] || return 1
	return 0
}
