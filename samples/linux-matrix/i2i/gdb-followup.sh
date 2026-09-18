#!/bin/bash
# one-off: re-run the isolated ring with the INITIATOR under `gdb -batch` so a
# `free(): invalid pointer` abort yields a real backtrace.  Responder runs
# normally. Uses the same two-netns isolation (production untouched).
set -u
PATT="/usr/local/racoon2-i2i/sbin/"
pkill -9 -f "$PATT" 2>/dev/null; sleep 1
D=/tmp/r2gdb; PREFIX=/usr/local/racoon2-i2i; SBIN=$PREFIX/sbin
CONF=/tmp/r2i2i_boot; NSI=r2i; NSR=r2r
HI=192.0.2.2; HR=192.0.2.1
mkdir -p "$D"; rm -f "$D"/* 2>/dev/null
for NS in "$NSI" "$NSR"; do ip netns del "$NS" 2>/dev/null; ip netns add "$NS"; ip netns exec "$NS" ip link set lo up; done
ip link add vi2i type veth peer name vr2r
ip link set vi2i netns "$NSI"; ip netns exec "$NSI" ip link set vi2i up; ip netns exec "$NSI" ip addr add "$HI/24" dev vi2i
ip link set vr2r netns "$NSR"; ip netns exec "$NSR" ip link set vr2r up; ip netns exec "$NSR" ip addr add "$HR/24" dev vr2r
add_allow () { ns=$1; L=$2; P=$3; for p in 500 4500; do
  ip netns exec "$ns" ip xfrm policy add src "$P"/32 dst "$L"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
  ip netns exec "$ns" ip xfrm policy add src "$L"/32 dst "$P"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
done; }
add_allow "$NSR" "$HR" "$HI"; add_allow "$NSI" "$HI" "$HR"
(ip netns exec "$NSR" "$SBIN/spmd" -F -f "$CONF/responder.conf") >"$D/rspmd.log" 2>&1 &
i=0; until [ -S /tmp/spmif-r2i2 ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
(ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-r2r "$SBIN/iked" -F -f "$CONF/responder.conf" -D 0x0001 -l "$D/rlog") >"$D/riked.out" 2>&1 &
(ip netns exec "$NSI" "$SBIN/spmd" -F -f "$CONF/initiator.conf") >"$D/ispmd.log" 2>&1 &
i=0; until [ -S /tmp/spmif-i2i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
# INITIATOR UNDER GDB BATCH
( ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2i \
    gdb -q -batch -ex 'set pagination off' -ex run -ex 'bt full' \
        -ex 'info locals' --args "$SBIN/iked" -F -f "$CONF/initiator.conf" -D 0x0001 -l "$D/ilog" ) >"$D/gdb-init.out" 2>&1 &
GDBPID=$!
sleep 2
"$SBIN/ikedctl" -s /tmp/iked.sock-i2i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true
# wait for the abort (~12s), then collect
sleep 20
echo "=== gdb result (all grep'd) ==="
grep -viE "^(Reading|Downloading|\[New|Using|Thread|\[Thread|warning: ".gdbinit" |Breakpoint)" "$D/gdb-init.out" | grep -iE "program received|signal|#0|#1|#2|#3|#4|#5|#6|free|rc_vfree|abort|__libc|ikev2_|Invalid|assert|raised" | head -30
echo "=== init log tail ==="
grep -viE "^[0-9a-f]{8} " "$D/ilog" 2>/dev/null | tail -6
pkill -9 -f "$PATT" 2>/dev/null
kill "$GDBPID" 2>/dev/null
ip netns del "$NSI" 2>/dev/null; ip netns del "$NSR" 2>/dev/null; ip link del vi2i 2>/dev/null
exit 0
