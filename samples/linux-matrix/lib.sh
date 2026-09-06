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

# R2_WORKERS empty: live systemd. Numeric: stop racoon2-iked, iked -F with
# RACOON2_CRYPTO_WORKERS, restore after the case. Does not touch spmd.
# Does not enable racoon2.target.
iked_apply_workers() {
	R2_IKED_EPHEMERAL_PID=
	R2_IKED_STOPPED=
	case ${R2_WORKERS-} in
	'')
		iked_listening || { log "FAIL: iked not on :500"; return 1; }
		return 0
		;;
	esac
	systemctl stop racoon2-iked 2>/dev/null || true
	R2_IKED_STOPPED=1
	i=0
	while iked_listening; do
		i=$((i + 1))
		if [ "$i" -gt 20 ]; then
			log "FAIL: :500 still bound after stop"
			return 1
		fi
		sleep 1
	done
	: >/tmp/r2-iked-matrix.log
	(
		cd "$ETC" || exit 1
		export RACOON2_CRYPTO_WORKERS="$R2_WORKERS"
		exec "$SBIN/iked" -F -l /tmp/r2-iked-matrix.log
	) >>/tmp/r2-iked-matrix.log 2>&1 &
	R2_IKED_EPHEMERAL_PID=$!
	i=0
	while ! iked_listening; do
		i=$((i + 1))
		if [ "$i" -gt 20 ]; then
			log "FAIL: ephemeral iked workers=$R2_WORKERS not on :500"
			return 1
		fi
		if ! kill -0 "$R2_IKED_EPHEMERAL_PID" 2>/dev/null; then
			log "FAIL: ephemeral iked died workers=$R2_WORKERS"
			return 1
		fi
		sleep 1
	done
	log "iked pid=$R2_IKED_EPHEMERAL_PID workers=$R2_WORKERS"
	envn=$(tr '\0' '\n' <"/proc/${R2_IKED_EPHEMERAL_PID}/environ" 2>/dev/null | grep '^RACOON2_CRYPTO_WORKERS=' || true)
	if [ "$envn" != "RACOON2_CRYPTO_WORKERS=$R2_WORKERS" ]; then
		log "FAIL: environ $envn want RACOON2_CRYPTO_WORKERS=$R2_WORKERS"
		return 1
	fi
	if [ "$R2_WORKERS" -gt 0 ]; then
		grep -q "crypto workers: $R2_WORKERS" /tmp/r2-iked-matrix.log || {
			log "FAIL: no 'crypto workers: $R2_WORKERS' in log"
			return 1
		}
	fi
}

iked_restore() {
	if [ -n "${R2_IKED_EPHEMERAL_PID:-}" ]; then
		kill "$R2_IKED_EPHEMERAL_PID" 2>/dev/null || true
		wait "$R2_IKED_EPHEMERAL_PID" 2>/dev/null || true
		R2_IKED_EPHEMERAL_PID=
	fi
	if [ "${R2_IKED_STOPPED:-}" = 1 ]; then
		ip xfrm state flush || true
		ip xfrm policy flush || true
		systemctl start racoon2-iked 2>/dev/null || true
		R2_IKED_STOPPED=
		i=0
		while ! iked_listening; do
			i=$((i + 1))
			[ "$i" -gt 20 ] && break
			sleep 1
		done
	fi
}
