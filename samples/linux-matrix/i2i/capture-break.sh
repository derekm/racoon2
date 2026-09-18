#!/bin/bash
# Definitive frag_recv measurement: attach gdb to the LIVE responder BEFORE the
# exchange, break at ikev2_frag.c:641 (post-decrypt/pad) and :724 (reassembled
# full_pkt), and log the responder's own decrypted bytes + keys per fragment.
set -u
D=/tmp/r2key; PREFIX=/usr/local/racoon2-i2i; SBIN=$PREFIX/sbin; CONF=/tmp/r2i2i_boot
NSI=r2i; NSR=r2r; HI=192.0.2.2; HR=192.0.2.1; VI=vi2i; VR=vr2r
PATT="/usr/local/racoon2-i2i/sbin/"
rm -f "$D"/frag_dump.txt 2>/dev/null; mkdir -p "$D"
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
sleep 1
# attach gdb to BOTH daemons BEFORE establish: responder=recv breaks, initiator=send break
RKPID=$(pgrep -f "sbin/iked .*responder.conf" | head -1)
IKPID=$(pgrep -f "sbin/iked .*initiator.conf" | head -1)
echo "attaching: responder pid $RKPID, initiator pid $IKPID"
( gdb -q -x /tmp/r2frag.gdb -p "$RKPID" >"$D/gdb-r.out" 2>&1 ) &
GDBR=$!
( gdb -q -x /tmp/send.gdb -p "$IKPID" >"$D/gdb-i.out" 2>&1 ) &
GDBI=$!
sleep 3
"$SBIN/ikedctl" -s /tmp/iked.sock-i2i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
sleep 8
kill "$GDBR" "$GDBI" 2>/dev/null
pkill -9 -f "$PATT" 2>/dev/null
ip netns del "$NSI" 2>/dev/null; ip netns del "$NSR" 2>/dev/null; ip link del "$VI" 2>/dev/null
echo "=== frag_dump.txt ==="
cat "$D/frag_dump.txt" 2>/dev/null
echo "=== gdb tail ==="
tail -6 "$D/gdb.out" 2>/dev/null
echo DONE
exit 0
