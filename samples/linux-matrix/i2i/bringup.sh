#!/bin/bash
# iked<->iked netns bring-up (host responder + netns initiator), root-only.
# Stops/restores production iked+spmd, kills stale i2i daemons, brings up the
# two stacks (test prefix /usr/local/racoon2-i2i), triggers establish-sa.
# See README.md for the current blockers and every learned gotcha.
set -u
# kill *daemons* only — never pkill a pattern present in this script's own
# /tmp/r2i2i_boot path or the invoking ssh line (it SIGKILLs the runner).
PATT="/usr/local/racoon2-i2i/sbin/"
pkill -9 -f "$PATT" 2>/dev/null
sleep 1
NS="${R2_NS:-r2c2}"; VH=r2h2; VC=r2n2; HIP=192.0.2.1; CIP=192.0.2.2
D=/tmp/r2i2i; PREFIX="${R2_I2I_PREFIX:-/usr/local/racoon2-i2i}"
SBIN=$PREFIX/sbin; CONF="${R2_CONF:-/tmp/r2i2i_boot}"
RESP_PID=; INIT_PID=; RESP_SPMD=; INIT_SPMD=

cleanup() {
	for p in "$INIT_PID" "$RESP_PID" "$INIT_SPMD" "$RESP_SPMD"; do
		[ -n "$p" ] && kill "$p" 2>/dev/null
	done
	pkill -9 -f "/usr/local/racoon2-i2i/sbin/" 2>/dev/null
	systemctl start iked spmd 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VH" 2>/dev/null || true
}
trap cleanup EXIT
systemctl stop iked spmd 2>/dev/null || true
sleep 1

rm -f /tmp/spmif-r2i2 /tmp/spmif-i2i /var/run/iked.sock /tmp/iked.sock-i2i
mkdir -p "$D"
ip netns del "$NS" 2>/dev/null || true
ip link del "$VH" 2>/dev/null || true
ip netns add "$NS"
ip link add "$VH" type veth peer name "$VC"
ip link set "$VC" netns "$NS"
ip addr flush dev "$VH" 2>/dev/null
ip addr add "$HIP/24" dev "$VH"; ip link set "$VH" up
ip netns exec "$NS" ip addr add "$CIP/24" dev "$VC"
ip netns exec "$NS" ip link set "$VC" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$HIP"
echo 1 >/proc/sys/net/ipv4/ip_forward

echo "=== host responder spmd+iked ==="
(cd "$D" && "$SBIN/spmd" -F -f "$CONF/responder.conf") >"$D/resp-spmd.log" 2>&1 &
RESP_SPMD=$!
i=0; while [ ! -S /tmp/spmif-r2i2 ]; do i=$((i+1)); [ "$i" -gt 15 ] && { echo "FAIL: no resp spmif"; break; }; kill -0 "$RESP_SPMD" 2>/dev/null || { echo "FAIL: resp spmd died"; break; }; sleep 1; done
"$SBIN/iked" -F -f "$CONF/responder.conf" -D 0x0001 -l "$D/resp-iked.log" >"$D/resp-iked.out" 2>&1 &
RESP_PID=$!
echo "=== netns initiator spmd+iked ==="
ip netns exec "$NS" "$SBIN/spmd" -F -f "$CONF/initiator.conf" >"$D/init-spmd.log" 2>&1 &
INIT_SPMD=$!
i=0; while [ ! -S /tmp/spmif-i2i ]; do i=$((i+1)); [ "$i" -gt 15 ] && { echo "FAIL: no init spmif"; break; }; sleep 1; done
ip netns exec "$NS" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2i "$SBIN/iked" -F -f "$CONF/initiator.conf" -D 0x0001 -l "$D/init-iked.log" >"$D/init-iked.out" 2>&1 &
INIT_PID=$!
# IKE UDP must bypass the auto_ipsec SPD — but only AFTER spmd has finished
# its startup policy flush (spmd flushes all xfrm policies at boot, wiping any
# rows added before it).  Add the 500/4500 allow rows on both sides now.
for p in 500 4500; do
	ip netns exec "$NS" ip xfrm policy add src "$HIP"/32 dst "$CIP"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
	ip netns exec "$NS" ip xfrm policy add src "$CIP"/32 dst "$HIP"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
	ip netns exec "$NS" ip xfrm policy add src "$HIP"/32 dst "$CIP"/32 proto udp sport "$p" dport "$p" dir fwd ptype main action allow 2>/dev/null || true
	ip xfrm policy add src "$CIP"/32 dst "$HIP"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
	ip xfrm policy add src "$HIP"/32 dst "$CIP"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
	ip xfrm policy add src "$CIP"/32 dst "$HIP"/32 proto udp sport "$p" dport "$p" dir fwd ptype main action allow 2>/dev/null || true
done
sleep 2
echo "=== ikedctl establish-sa (initiator) ==="
"$SBIN/ikedctl" -s /tmp/iked.sock-i2i establish-sa isakmp inet "$CIP" "$HIP" sel_out 2>&1 | head -5 || true
sleep 5
echo "=== responder esp/policy ==="
ip xfrm state 2>/dev/null | grep -c 'proto esp' || true
ip xfrm policy 2>/dev/null | grep -E 'src |dir (in|out|fwd)' | head -8
echo "=== netns esp/policy ==="
ip netns exec "$NS" ip xfrm state 2>/dev/null | grep -c 'proto esp' || true
ip netns exec "$NS" ip xfrm policy 2>/dev/null | grep -E 'src |dir (in|out|fwd)' | head -8
echo "=== LOG GREP ==="
grep -iE 'ESTABLISHED|CREATE_CHILD|ADDKE|FOLLOWUP|no proposal|error|abort|err=|sadb_poll|SADB_GETSPI' "$D/resp-iked.log" "$D/init-iked.log" 2>/dev/null | head -30
echo "=== DONE (cleanup on exit); logs in $D ==="
