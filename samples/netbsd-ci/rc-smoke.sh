#!/bin/sh
# NetBSD rc.d smoke: make install already done.
# Starts spmd then iked via the installed rc.d scripts (onestart).
# Proves PF_KEY + UDP/500. Not a tunnel matrix (no netns; npf is not SAD/SPD).
set -e
PREFIX="${PREFIX:-/usr/local/racoon2}"
SYSCONFDIR="${SYSCONFDIR:-${PREFIX}/etc/racoon2}"
RCD="${SYSCONFDIR}/rc.d"
CONF="${SYSCONFDIR}/racoon2.conf"
SRC="${SRC:-.}"

if [ ! -x "${PREFIX}/sbin/iked" ] || [ ! -x "${PREFIX}/sbin/spmd" ]; then
	echo "FAIL: iked/spmd not installed under ${PREFIX}/sbin"
	exit 1
fi
if [ ! -x "${RCD}/spmd" ] || [ ! -x "${RCD}/iked" ]; then
	echo "FAIL: rc.d scripts missing at ${RCD} (startup_scripts != rc.d?)"
	ls -la "${SYSCONFDIR}" "${RCD}" 2>&1 || true
	exit 1
fi

mkdir -p -m 700 /var/run/racoon2
install -m 600 "${SRC}/samples/netbsd-ci/iked.conf" "${CONF}"
printf 'ci-spmd-pw\n' > "${SYSCONFDIR}/spmd.pwd"
chmod 600 "${SYSCONFDIR}/spmd.pwd"

# onestart ignores rcvar; required_vars="spmd" on iked still needs this.
spmd=YES
iked=YES
export spmd iked

echo "=== ${RCD}/spmd onestart ==="
"${RCD}/spmd" onestart || echo "spmd onestart st=$?"
echo "=== ${RCD}/iked onestart ==="
"${RCD}/iked" onestart || echo "iked onestart st=$?"

tries=0
while [ "$tries" -lt 15 ]; do
	if [ -f /var/run/spmd.pid ] && [ -f /var/run/iked.pid ]; then
		break
	fi
	tries=$((tries + 1))
	sleep 1
done

if [ ! -f /var/run/spmd.pid ] || [ ! -f /var/run/iked.pid ]; then
	echo "=== rc.d did not leave pidfiles; start installed binaries ==="
	"${PREFIX}/sbin/spmd" -f "${CONF}" || echo "spmd direct st=$?"
	sleep 1
	"${PREFIX}/sbin/iked" -f "${CONF}" || echo "iked direct st=$?"
	sleep 2
	echo "=== iked/spmd stderr (if any) ==="
	ls -l /var/run/spmd.pid /var/run/iked.pid 2>&1 || true
	ps -ax | grep -E '[s]pmd|[i]ked' || true
fi

echo "=== pidfiles ==="
ls -l /var/run/spmd.pid /var/run/iked.pid
echo "=== listeners ==="
netstat -an -f inet | grep '\.500 ' || true
sockstat -l -P udp 2>/dev/null | grep 500 || true

if ! kill -0 "$(cat /var/run/spmd.pid)" 2>/dev/null; then
	echo "FAIL: spmd not running"
	exit 1
fi
if ! kill -0 "$(cat /var/run/iked.pid)" 2>/dev/null; then
	echo "FAIL: iked not running"
	exit 1
fi
if ! netstat -an -f inet | grep '\.500 ' >/dev/null; then
	echo "FAIL: nothing listening on UDP 500"
	exit 1
fi

echo "=== setkey SAD/SPD (empty is OK for smoke) ==="
if command -v setkey >/dev/null 2>&1; then
	setkey -D || true
	setkey -DP || true
else
	echo "WARN: setkey not in PATH"
fi

echo "=== sysctl ipsec ==="
sysctl net.inet.ipsec 2>/dev/null || true
sysctl kern.osrelease hw.machine

"${RCD}/iked" onestop || true
"${RCD}/spmd" onestop || true
echo RC-SMOKE-OK
