#!/bin/bash
# iked<->iked netns diagnostic: single bring-up, establish, then snapshot every
# xfrm/path counter so a stuck-IKE_SA_INIT run tells us WHERE the reply dies.
# Discriminators:
#   netns veth tcpdump shows the reply arriving -> xfrm/route drop INSIDE netns.
#   tcpdump shows NO reply                  -> reply never left the host.
set -u
PATT="/usr/local/racoon2-i2i/sbin/"
pkill -9 -f "$PATT" 2>/dev/null; sleep 1
NS="r2c2"; VH=r2h2; VC=r2n2; HIP=192.0.2.1; CIP=192.0.2.2
D=/tmp/r2diag; PREFIX=/usr/local/racoon2-i2i; SBIN=$PREFIX/sbin
CONF=/tmp/r2i2i_boot
mkdir -p "$D"
ip netns del "$NS" 2>/dev/null; ip link del "$VH" 2>/dev/null
systemctl stop iked spmd 2>/dev/null
ip netns add "$NS"
ip link add "$VH" type veth peer name "$VC"
ip link set "$VC" netns "$NS"
ip addr add "$HIP/24" dev "$VH"; ip link set "$VH" up
ip netns exec "$NS" ip addr add "$CIP/24" dev "$VC"
ip netns exec "$NS" ip link set "$VC" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$HIP"
echo 1 >/proc/sys/net/ipv4/ip_forward
# netns veth capture BEFORE stacks so the whole exchange is captured at the NIC
ip netns exec "$NS" tcpdump -i "$VC" -nn -c 4000 udp -w "$D/netns-cap.pcap" \
    >/dev/null 2>&1 &
TCPID=$!
sleep 1
(systemctl start iked spmd 2>/dev/null || true)   # no-op guard signal (unused)
(cd "$D" && "$SBIN/spmd" -F -f "$CONF/responder.conf") >"$D/resp-spmd.log" 2>&1 &
RSPMD=$!
i=0; until [ -S /tmp/spmif-r2i2 ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
"$SBIN/iked" -F -f "$CONF/responder.conf" -D 0x0001 -l "$D/resp-iked.log" >"$D/resp-iked.out" 2>&1 &
RPIKED=$!
ip netns exec "$NS" "$SBIN/spmd" -F -f "$CONF/initiator.conf" >"$D/init-spmd.log" 2>&1 &
ISPMD=$!
i=0; until [ -S /tmp/spmif-i2i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
ip netns exec "$NS" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2i \
    "$SBIN/iked" -F -f "$CONF/initiator.conf" -D 0x0001 -l "$D/init-iked.log" >"$D/init-iked.out" 2>&1 &
IIKED=$!
for p in 500 4500; do
    ip netns exec "$NS" ip xfrm policy add src "$HIP"/32 dst "$CIP"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
    ip netns exec "$NS" ip xfrm policy add src "$CIP"/32 dst "$HIP"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
    ip xfrm policy add src "$CIP"/32 dst "$HIP"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
    ip xfrm policy add src "$HIP"/32 dst "$CIP"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
done
sleep 2
"$SBIN/ikedctl" -s /tmp/iked.sock-i2i establish-sa isakmp inet "$CIP" "$HIP" sel_out >/dev/null 2>&1 || true
# let it reach sticking quickly (~12s), then snapshot everything
sleep 12
echo "=== initiator state ==="
ip netns exec "$NS" ip xfrm policy 2>/dev/null | grep -E 'src |priority|dir |action' 
echo "=== host policy (priority-annotated) ==="
ip xfrm policy 2>/dev/null | grep -E 'src |priority|dir |action'
echo "=== xfrm_stat host ==="; grep -E 'XfrmInNoStates|XfrmInTmplMismatch|XfrmInNoPols|XfrmOutNoStates' /proc/net/xfrm_stat
echo "=== xfrm_stat netns ==="; ip netns exec "$NS" grep -E 'XfrmInNoStates|XfrmInTmplMismatch|XfrmInNoPols|XfrmOutNoStates' /proc/net/xfrm_stat
echo "=== netns cap: IKE exchanges seen at the veth ==="
ip netns exec "$NS" tcpdump -nn -r "$D/netns-cap.pcap" 'udp port 500 or 4500' 2>/dev/null | head -20
echo "=== netns cap: count ==="; ip netns exec "$NS" tcpdump -nn -r "$D/netns-cap.pcap" 2>/dev/null | wc -l
echo "=== init-iked.log progress ==="
grep -iE 'INI_|RES_|GETSPI|sadb|CREATE_CHILD|IKE_AUTH|error|abort|err=' "$D/init-iked.log" 2>/dev/null | head -25
echo "=== resp-iked.log progress ==="
grep -iE 'INI_|RES_|GETSPI|CREATE_CHILD|IKE_AUTH|error|abort|err=' "$D/resp-iked.log" 2>/dev/null | head -20
for p in "$RSPMD" "$RPIKED" "$ISPMD" "$IIKED"; do kill "$p" 2>/dev/null; done
kill "$TCPID" 2>/dev/null
pkill -9 -f "$PATT" 2>/dev/null
systemctl start iked spmd 2>/dev/null || true
ip netns del "$NS" 2>/dev/null; ip link del "$VH" 2>/dev/null || true
exit 0
