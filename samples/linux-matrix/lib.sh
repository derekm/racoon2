# shared by linux-matrix kinds. sourced, not executed.
# shellcheck disable=SC2034
NS="${R2_NS:-r2c}"
VETH_H="${R2_VETH_H:-r2h}"
VETH_C="${R2_VETH_C:-r2n}"
HIP="${R2_HIP:-192.0.2.1}"
CIP="${R2_CIP:-192.0.2.2}"
RIP="${R2_RIP:-}"
PREFIX="${R2_PREFIX:-/usr/local/racoon2}"
ETC="${PREFIX}/etc/racoon2"
SBIN="${PREFIX}/sbin"

log() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*" >&2; return 1; }

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		die "need root (wsl.exe -d Ubuntu -u root)"
		return 1
	fi
}

detect_rip() {
	if [ -n "$RIP" ]; then
		return 0
	fi
	RIP=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
	[ -n "$RIP" ] || die "set R2_RIP"
}

charon_reset() {
	killall -9 charon starter 2>/dev/null || true
	rm -f /var/run/charon.pid /var/run/starter.charon.pid /var/run/charon.ctl
	ip netns exec "$NS" ipsec stop 2>/dev/null || true
	sleep 1
}

netns_up() {
	if ! ip netns list | grep -q "^${NS}[[:space:]]"; then
		ip link del "$VETH_H" 2>/dev/null || true
		ip netns add "$NS"
		ip link add "$VETH_H" type veth peer name "$VETH_C"
		ip link set "$VETH_C" netns "$NS"
		ip addr add "$HIP/24" dev "$VETH_H" 2>/dev/null || true
		ip link set "$VETH_H" up
		ip netns exec "$NS" ip addr add "$CIP/24" dev "$VETH_C"
		ip netns exec "$NS" ip link set "$VETH_C" up
		ip netns exec "$NS" ip link set lo up
		ip netns exec "$NS" ip route add default via "$HIP"
	fi
	echo 1 >/proc/sys/net/ipv4/ip_forward
	echo 0 >/proc/sys/net/ipv4/conf/all/rp_filter
	echo 0 >/proc/sys/net/ipv4/conf/${VETH_H}/rp_filter 2>/dev/null || true
}

iked_listening() {
	ss -ulnp | grep -q ":500 "
}
