#!/bin/bash
# iked<->iked PQC matrix tile — FULLY ISOLATED from production.
#
# Both racoon2 peers run inside their own NETWORK NAMESPACE (initiator nsI,
# responder nsR) joined by a P2P veth.  Each netns is a complete network + XFRM
# stack, so the test NEVER touches the live production iked/spmd:
#   - no `systemctl stop iked spmd`
#   - no host UDP 500/4500 bind (the netns socket table is separate)
#   - no host `ip xfrm` SPD/SAD mutation (netns XFRM tables are separate)
# The matrix tile is side-effect-free w.r.t. production.
#
# XFRM ordering note: the udp-allow UGK bypass rows are inserted *before* each
# netns's spmd starts, so they land FIRST in the equal-priority(0) bucket and
# beat the auto_ipsec tunnel input policy (which spmd installs later) that would
# otherwise swallow inbound IKE and drop it as XfrmInNoStates.
set -u
PATT="/usr/local/racoon2-i2i/sbin/"
pkill -9 -f "$PATT" 2>/dev/null; sleep 1
D=/tmp/r2i2i; PREFIX=/usr/local/racoon2-i2i; SBIN=$PREFIX/sbin
CONF="${R2_CONF:-/tmp/r2i2i_boot}"
NSI="r2i"; NSR="r2r"; VI=veth-i2i; VR=veth-r2r
HI=192.0.2.2; HR=192.0.2.1      # HI initiator, HR responder
mkdir -p "$D"
for NS in "$NSI" "$NSR"; do
    ip netns del "$NS" 2>/dev/null || true
    ip netns add "$NS"
    ip netns exec "$NS" ip link set lo up
done
# P2P veth: one end in each netns (crossover), both on 192.0.2.0/24
ip link add "$VI" type veth peer name "$VR"
ip link set "$VI" netns "$NSI"; ip link set "$VI" up
ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"
ip link set "$VR" netns "$NSR"; ip link set "$VR" up
ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"

# udp-allow rows BEFORE any spmd in each netns (first-in-bucket at prio 0)
add_allow () { # $1=ns  $2=local  $3=peer
    local ns="$1" L="$2" P="$3"
    for p in 500 4500; do
        ip netns exec "$ns" ip xfrm policy add src "$P"/32 dst "$L"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
        ip netns exec "$ns" ip xfrm policy add src "$L"/32 dst "$P"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
    done
}
add_allow "$NSR" "$HR" "$HI"
add_allow "$NSI" "$HI" "$HR"

# responder stack in nsR
(ip netns exec "$NSR" "$SBIN/spmd" -F -f "$CONF/responder.conf") >"$D/resp-spmd.log" 2>&1 &
RSPMD=$!
i=0; until [ -S /tmp/spmif-r2i2 ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
(ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-r2r \
    "$SBIN/iked" -F -f "$CONF/responder.conf" -D 0x0001 -l "$D/resp-iked.log") >"$D/resp-iked.out" 2>&1 &
RPIKED=$!

# initiator stack in nsI
(ip netns exec "$NSI" "$SBIN/spmd" -F -f "$CONF/initiator.conf") >"$D/init-spmd.log" 2>&1 &
ISPMD=$!
i=0; until [ -S /tmp/spmif-i2i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
(ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2i \
    "$SBIN/iked" -F -f "$CONF/initiator.conf" -D 0x0001 -l "$D/init-iked.log") >"$D/init-iked.out" 2>&1 &
IIKED=$!

# ikedctl reaches the initiator via its admin socket on the host FS
sleep 2
"$SBIN/ikedctl" -s /tmp/iked.sock-i2i establish-sa isakmp inet "$HI" "$HR" sel_out 2>&1 | head -5 || true

up=0; i=0
while [ "$i" -lt 40 ]; do
    re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp' || true)
    ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp' || true)
    if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then echo "CHILD UP (isolated): resp_esp=$re init_esp=$ie after ${i}s"; up=1; break; fi
    i=$((i+1)); sleep 1
done
[ "$up" -eq 1 ] || echo "NOT UP after ${i}s: resp_esp=${re:-0} init_esp=${ie:-0}  -- production iked+spmd were never touched"
echo "=== esp count nsR / nsI ==="; ip netns exec "$NSR" ip xfrm state | grep -c 'proto esp'; ip netns exec "$NSI" ip xfrm state | grep -c 'proto esp'
echo "=== iked logs (IKE progress) ==="
grep -hiE 'INI_|RES_|GETSPI|CREATE_CHILD|IKE_AUTH|ADDKE|FOLLOWUP|no proposal|sadb_poll|abort|err=' "$D/init-iked.log" "$D/resp-iked.log" 2>/dev/null | head -25
echo "=== DONE; production untouched. logs: $D. cleanup ---"
sleep 1
for p in "$RSPMD" "$RPIKED" "$ISPMD" "$IIKED"; do kill "$p" 2>/dev/null; done
pkill -9 -f "$PATT" 2>/dev/null
sleep 1
ip netns del "$NSI" 2>/dev/null || true
ip netns del "$NSR" 2>/dev/null || true
exit 0
