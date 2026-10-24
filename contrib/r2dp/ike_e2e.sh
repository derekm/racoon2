#!/bin/bash
# M0 exit gate: two real racoon2 stacks (spmd + iked, built with
# --with-km-backend=r2dp) complete an IKEv2 exchange over a veth; every
# SA/SP they install lands in a per-namespace r2dp-mockfwd.  PASS means
# both forwarders saw the negotiated ESP SAs and tunnel policies.
#
#   ike_e2e.sh <racoon2-prefix> <r2dp-mockfwd>      (needs root, ip, netns)
set -u
PREFIX="${1:?racoon2 install prefix}"; MOCK="${2:?path to r2dp-mockfwd}"
SBIN="$PREFIX/sbin"
D=/tmp/r2dp-e2e; NSI=r2dpi; NSR=r2dpr
HI=192.0.2.2; HR=192.0.2.1
fail() { echo "FAIL: $*"; exit 1; }
[ "$(id -u)" = 0 ] || { echo "SKIP: needs root"; exit 77; }
command -v ip >/dev/null || { echo "SKIP: needs iproute2"; exit 77; }
[ -x "$SBIN/iked" ] && [ -x "$SBIN/spmd" ] && [ -x "$MOCK" ] || fail "missing binaries"

cleanup() {
	pkill -9 -f "$SBIN/(iked|spmd)" 2>/dev/null; pkill -9 -f "$MOCK -s $D" 2>/dev/null
	sleep 0.3
	ip netns del $NSI 2>/dev/null; ip netns del $NSR 2>/dev/null
	ip link del veth-r2dpi 2>/dev/null
}
trap cleanup EXIT
cleanup; rm -rf "$D"; mkdir -p "$D/psk" "$D/resume-i" "$D/resume-r"
cp "$PREFIX/etc/racoon2/spmd.pwd" "$D/spmd.pwd"; chmod 600 "$D/spmd.pwd"
printf 'r2dp-e2e-secret' > "$D/psk/e2e.psk"; chmod 600 "$D/psk/e2e.psk"

conf() { # $1=file $2=my_ip $3=peer_ip $4=spmif $5=my_id $6=peer_id $7=passive-line
cat > "$1" <<CONF
interface {
	ike { "$2"; };
	spmd { unix "$4"; };
	spmd_password "$D/spmd.pwd";
};
resolver { resolver off; };
remote e2e_remote {
	acceptable_kmp { ikev2; };
	ikev2 {
		$7
		my_id fqdn "$5";
		peers_id fqdn "$6";
		peers_ipaddr "$3" port 500;
		kmp_enc_alg { aes256_cbc; aes128_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; modp2048; };
		kmp_auth_method { psk; };
		pre_shared_key "$D/psk/e2e.psk";
	};
	selector_index sel_in;
};
selector sel_out { direction outbound; src "$2"; dst "$3"; policy_index pol; };
selector sel_in  { direction inbound;  dst "$2"; src "$3"; policy_index pol; };
policy pol {
	action auto_ipsec;
	remote_index e2e_remote;
	ipsec_mode tunnel;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "$3";
	my_sa_ipaddr "$2";
};
ipsec ipsec_e { ipsec_sa_lifetime_time 300 sec; sa_index esp_e; };
sa esp_e { sa_protocol esp; esp_enc_alg { aes_gcm; }; esp_auth_alg { non_auth; }; };
CONF
}
conf "$D/init.conf" $HI $HR "$D/spmif-i" macos.client racoon2.peer ""
conf "$D/resp.conf" $HR $HI "$D/spmif-r" racoon2.peer macos.client "passive on;"

for NS in $NSI $NSR; do ip netns add $NS; ip netns exec $NS ip link set lo up; done
ip link add veth-r2dpi type veth peer name veth-r2dpr
ip link set veth-r2dpi netns $NSI; ip link set veth-r2dpr netns $NSR
ip netns exec $NSI ip addr add $HI/24 dev veth-r2dpi; ip netns exec $NSI ip link set veth-r2dpi up
ip netns exec $NSR ip addr add $HR/24 dev veth-r2dpr; ip netns exec $NSR ip link set veth-r2dpr up
ip netns exec $NSI ping -c1 -W2 $HR >/dev/null || fail "veth not passing traffic"

start_stack() { # $1=ns $2=tag(i|r) $3=conf $4=spmif
	local ns=$1 t=$2 sock="$D/fwd-$2.sock"
	( ip netns exec $ns "$MOCK" -s "$sock" -v ) >"$D/mock-$t.log" 2>&1 & disown
	for _ in $(seq 50); do [ -S "$sock" ] && break; sleep 0.1; done
	[ -S "$sock" ] || fail "mockfwd-$t did not start"
	( ip netns exec $ns env R2DP_SOCK="$sock" R2DP_ROLE=spmd \
	    "$SBIN/spmd" -F -f "$3" ) >"$D/spmd-$t.log" 2>&1 & disown
	for _ in $(seq 50); do [ -S "$4" ] && break; sleep 0.2; done
	[ -S "$4" ] || { tail -5 "$D/spmd-$t.log"; fail "spmd-$t did not create $4"; }
	( ip netns exec $ns env R2DP_SOCK="$sock" R2DP_ROLE=iked \
	    RACOON2_ADMIN_SOCK="$D/iked.sock-$t" RACOON2_RESUME_DIR="$D/resume-$t" \
	    "$SBIN/iked" -F -f "$3" -D 0x0001 -l "$D/iked-$t.log" ) >"$D/iked-$t.out" 2>&1 & disown
}
start_stack $NSR r "$D/resp.conf" "$D/spmif-r"
start_stack $NSI i "$D/init.conf" "$D/spmif-i"
sleep 2
"$SBIN/ikedctl" -s "$D/iked.sock-i" establish-sa isakmp inet $HI $HR sel_out 2>&1 | head -3

show() { grep -E "HELLO|GETSPI|SA_ADD|SA_UPDATE|SA_DEL|SP_ADD|SP_DUMP" "$D/$1" | grep -v "SP_ADD dir=[12] proto=17" | sed 's/^mockfwd: //'; \
         echo "  (+ $(grep -c 'SP_ADD dir=[12] proto=17' "$D/$1") UDP/IKE bypass SPs)"; }
ok=0
for s in $(seq 40); do
	ci=$(grep -c "SA_\(ADD\|UPDATE\).*proto=50" "$D/mock-i.log" 2>/dev/null)
	cr=$(grep -c "SA_\(ADD\|UPDATE\).*proto=50" "$D/mock-r.log" 2>/dev/null)
	[ "${ci:-0}" -ge 2 ] && [ "${cr:-0}" -ge 2 ] && { ok=1; break; }
	sleep 1
done
echo "---- initiator forwarder ----"; show mock-i.log
echo "---- responder forwarder ----"; show mock-r.log
[ $ok = 1 ] || { echo "---- iked-i ----"; tail -8 "$D/iked-i.log" "$D/iked-i.out"; echo "---- iked-r ----"; tail -8 "$D/iked-r.log" "$D/iked-r.out"; fail "no ESP SA pair after ${s}s (init=$ci resp=$cr); logs in $D"; }
# the gate: AES-GCM-16, ESP, tunnel mode, and a tunnel SP with selectors on both sides
for t in i r; do
	grep -q "SA_ADD.*proto=50.*enc=20" "$D/mock-$t.log" || grep -q "SA_UPDATE.*proto=50.*enc=20" "$D/mock-$t.log" || fail "forwarder-$t never got an AES-GCM-16 ESP SA"
	grep -q "SP_ADD.*action=1.*mode=2" "$D/mock-$t.log" || fail "forwarder-$t never got a tunnel-mode protect SP"
done
echo "PASS: IKEv2 completed; both forwarders hold ESP SAs and tunnel policies"
