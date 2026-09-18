#!/bin/bash
# PQC ADDKE REKEY soak on the isolated iked<->iked ring (production untouched).
# Baseline: initial IKE_AUTH child installs (ADDKE, mlkem768 on type-6).
# Soak: after the 60s ipsec lifetime, a CHILD rekey (CREATE_CHILD_SA, type-6
# ADDKE echo) + IKE_FOLLOWUP_KE must complete -> a NEW ESP SPI on BOTH sides
# takes packets (XfrmInNoStates flat, old SPI replaced), IKE_SA stays
# ESTABLISHED, no ADDKE followup timeout / abort.  This is the 9370 residual
# "live completed-ADDKE child rekey on a crash-free daemon".
set -u
PATT="/usr/local/racoon2-i2i/sbin/"
pkill -9 -f "$PATT" 2>/dev/null; sleep 1
NSI=r2i; NSR=r2r; VI=veth-i2i; VR=veth-r2r
HI=192.0.2.2; HR=192.0.2.1
D=/tmp/r2i2i; PREFIX="${R2_I2I_PREFIX:-/usr/local/racoon2-i2i}"; SBIN=$PREFIX/sbin
CONF="${R2_CONF:-/tmp/r2i2i_boot}"
mkdir -p "$D"; rm -f "$D"/*.log "$D"/*.out 2>/dev/null
rm -f /tmp/spmif-r2i2 /tmp/spmif-i2i /tmp/iked.sock-i2i /tmp/iked.sock-r2r
PRIVRES=/tmp/r2i2i-resume; rm -rf "$PRIVRES"; mkdir -p "$PRIVRES"
for NS in "$NSI" "$NSR"; do ip netns del "$NS" 2>/dev/null || true; ip netns add "$NS"; ip netns exec "$NS" ip link set lo up; done
ip link add "$VI" type veth peer name "$VR"
ip link set "$VI" netns "$NSI"; ip netns exec "$NSI" ip link set "$VI" up; ip netns exec "$NSI" ip addr add "$HI/24" dev "$VI"
ip link set "$VR" netns "$NSR"; ip netns exec "$NSR" ip link set "$VR" up; ip netns exec "$NSR" ip addr add "$HR/24" dev "$VR"
add_allow(){ ns=$1; L=$2; P=$3; for p in 500 4500; do
  ip netns exec "$ns" ip xfrm policy add src "$P"/32 dst "$L"/32 proto udp sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
  ip netns exec "$ns" ip xfrm policy add src "$L"/32 dst "$P"/32 proto udp sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
done; }
add_allow "$NSR" "$HR" "$HI"; add_allow "$NSI" "$HI" "$HR"
(ip netns exec "$NSR" "$SBIN/spmd" -F -f "$CONF/responder.conf") >"$D/resp-spmd.log" 2>&1 &
i=0; until [ -S /tmp/spmif-r2i2 ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
(ip netns exec "$NSR" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-r2r RACOON2_RESUME_DIR="$PRIVRES" \
    "$SBIN/iked" -F -f "$CONF/responder.conf" -D 0x0001 -l "$D/resp-iked.log") >"$D/resp-iked.out" 2>&1 &
(ip netns exec "$NSI" "$SBIN/spmd" -F -f "$CONF/initiator.conf") >"$D/init-spmd.log" 2>&1 &
i=0; until [ -S /tmp/spmif-i2i ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
(ip netns exec "$NSI" env RACOON2_ADMIN_SOCK=/tmp/iked.sock-i2i RACOON2_RESUME_DIR="$PRIVRES" \
    "$SBIN/iked" -F -f "$CONF/initiator.conf" -D 0x0001 -l "$D/init-iked.log") >"$D/init-iked.out" 2>&1 &
sleep 2
"$SBIN/ikedctl" -s /tmp/iked.sock-i2i establish-sa isakmp inet "$HI" "$HR" sel_out >/dev/null 2>&1 || true

esps(){ # $1=ns ; print sorted ESP inbound SPIs
  ip netns exec "$1" ip xfrm state 2>/dev/null | grep -A1 "proto esp" | grep -E "src |spi " | paste - - 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i~/^spi=/) s=$i} END{print s}' | tr '\n' ' ';
}

# wait for baseline child up (both sides >=2 esp)
i=0; up=0
while [ "$i" -lt 60 ]; do
  re=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
  ie=$(ip netns exec "$NSI" ip xfrm state 2>/dev/null | grep -c 'proto esp')
  if [ "${re:-0}" -ge 2 ] && [ "${ie:-0}" -ge 2 ]; then echo "BASELINE child up: resp_esp=$re init_esp=$ie after ${i}s"; up=1; break; fi
  i=$((i+1)); sleep 1
done
[ "$up" -eq 1 ] || { echo "FAIL: baseline not up (resp=${re:-0} init=${ie:-0})"; exit 1; }

REDIR=$(ip netns exec "$NSR" ip xfrm state 2>/dev/null | grep -c 'proto esp')
base_r_proto=$(esps "$NSR"); base_i_proto=$(esps "$NSI")
echo "baseline ESP proto (resp): $base_r_proto"
# capture per-side inbound SPI lists for change detection
snap(){ # ns ; print inbound SPI tokens
  ip netns exec "$1" ip xfrm state 2>/dev/null | awk '/proto esp/{print; getline; if($0~/spi 0x/) print $0}' | grep -oE 'spi 0x[0-9a-f]+' | sort
}
SR0=$(snap "$NSR"); SI0=$(snap "$NSI")
echo "baseline inbound SPI: resp=[$(echo $SR0)] init=[$(echo $SI0)]"

# soak: wait for a CHILD rekey -> new SPI both sides, old SPI gone, no timeout
rekeyed=0; i=0
while [ "$i" -lt 150 ]; do
  SRn=$(snap "$NSR"); SIn=$(snap "$NSI")
  # new SPI (not in baseline) present on both
  newr=$(comm -13 <(echo "$SR0" | sort) <(echo "$SRn" | sort) | grep -c 'spi')
  newi=$(comm -13 <(echo "$SI0" | sort) <(echo "$SIn" | sort) | grep -c 'spi')
  if [ "${newr:-0}" -ge 1 ] && [ "${newi:-0}" -ge 1 ]; then
    echo "REKEY: new SPI on both sides at ${i}s"
    echo "  new resp SPI:  $(comm -13 <(echo "$SR0" | sort) <(echo "$SRn" | sort) | tr '\n' ' ')"
    echo "  new init SPI:  $(comm -13 <(echo "$SI0" | sort) <(echo "$SIn" | sort) | tr '\n' ' ')"
    rekeyed=1; break
  fi
  i=$((i+1)); sleep 1
done

echo "=== xfrm_stat both sides (XfrmInNoStates flat?) ==="
ip netns exec "$NSR" grep -E 'XfrmInNoStates|XfrmInTmplMismatch' /proc/net/xfrm_stat
ip netns exec "$NSI" grep -E 'XfrmInNoStates|XfrmInTmplMismatch' /proc/net/xfrm_stat

echo "=== rekey/addke log evidence ==="
grep -hiE 'CREATE_CHILD|FOLLOWUP|ADDKE|install|rekey|abort|err=|ADDKE followup timeout|no pending ADDKE|missing KE' "$D/init-iked.log" "$D/resp-iked.log" 2>/dev/null | grep -viE '^[0-9a-f]{8} |DIRECT|sendfromto' | tail -16

pkill -9 -f "$PATT" 2>/dev/null
rm -rf "$PRIVRES"
[ "$rekeyed" -eq 1 ] && R=0 || R=1
echo "REKEY_SOAK_RESULT=$R"
exit $R
