#!/bin/bash
# pcap measurement of the IKE_FOLLOWUP_KE fragments (no racoon2 instrumentation).
# Brings up the isolated ring, tcpdumps the RESPONDER veth (500/4500) to a
# persistent pcap, so the initiator's followup fragments can be counted and
# their SKF envelopes decoded offline in Python (keyless).
set -u
D=/tmp/r2cap; CAP="$D/cap.pcap"; PREFIX=/usr/local/racoon2-i2i; SBIN=$PREFIX/sbin
CONF=/tmp/r2i2i_boot; NSI=r2i; NSR=r2r
HI=192.0.2.2; HR=192.0.2.1; VI=vi2i; VR=vr2r
PATT="/usr/local/racoon2-i2i/sbin/"
mkdir -p "$D"; rm -f "$D"/* 2>/dev/null
pkill -9 -f "$PATT" 2>/dev/null; sleep 1
rm -f /tmp/spmif-r2i2 /tmp/spmif-i2i /tmp/iked.sock-i2i /tmp/iked.sock-r2r
PRIVRES=/tmp/r2i2i-resume; rm -rf "$PRIVRES"; mkdir -p "$PRIVRES"
for NS in "$NSI" "$NSR"; do ip netns del "$NS" 2>/dev/null; ip netns add "$NS"; ip netns exec "$NS" ip link set lo up; done
ip link add "$VI" type veth peer name "$VR"
ip link set "$VI" netns "$NSI"; ip netns exec "$NSI" ip link set "$VI" up; ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"
ip link set "$VR" netns "$NSR"; ip netns exec "$NSR" ip link set "$VR" up; ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
add_allow(){ ns=$1; L=$2; P=$3; for p in 500 4500; do
  ip netns exec "$ns" ip xfrm policy add src "$P"/32 dst "$L"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
  ip netns exec "$ns" ip xfrm policy add src "$L"/32 dst "$P"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
done; }
add_allow "$NSR" "$HR" "$HI"; add_allow "$NSI" "$HI" "$HR"
(ip netns exec "$NSR" "$SBIN/spmd" -F -f "$CONF/responder.conf") >"$D/rspmd.log" 2>&1 &
i=0; until [ -S /tmp/spmif-r2i2 ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
(ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-r2r RACOON2_RESUME_DIR="$PRIVRES" \
    "$SBIN/iked" -F -f "$CONF/responder.conf" -D 0x0001 -l "$D/rlog") >"$D/ri.out" 2>&1 &
(ip netns exec "$NSI" "$SBIN/spmd" -F -f "$CONF/initiator.conf") >"$D/ispmd.log" 2>&1 &
i=0; until [ -S /tmp/spmif-i2i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
(ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2i RACOON2_RESUME_DIR="$PRIVRES" \
    "$SBIN/iked" -F -f "$CONF/initiator.conf" -D 0x0001 -l "$D/ilog") >"$D/ii.out" 2>&1 &
# capture BEFORE establish so we get every IKE datagram (incl frags)
ip netns exec "$NSR" tcpdump -i "$VR" -nn -s 0 udp port 500 or 4500 -w "$CAP" >"$D/td.log" 2>&1 &
TCPID=$!
sleep 2
"$SBIN/ikedctl" -s /tmp/iked.sock-i2i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
sleep 14
# also dump the responder xfrm state right before teardown (child present?)
ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp'
kill "$TCPID" 2>/dev/null; sleep 1
pkill -9 -f "$PATT" 2>/dev/null
ip netns del "$NSI" 2>/dev/null; ip netns del "$NSR" 2>/dev/null; ip link del "$VI" 2>/dev/null
echo "CAP=$CAP  size=$(ls -l "$CAP" 2>/dev/null | awk '{print $5}')"
exit 0
