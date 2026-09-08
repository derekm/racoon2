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
# smoke conf hardcodes this path
printf 'ci-spmd-pw\n' > "${SYSCONFDIR}/spmd.pwd"
chmod 600 "${SYSCONFDIR}/spmd.pwd"

# onestart ignores rc.conf rcvar (iked=YES not required)
"${RCD}/spmd" onestart
"${RCD}/iked" onestart

tries=0
while [ "$tries" -lt 15 ]; do
	if [ -f /var/run/spmd.pid ] && [ -f /var/run/iked.pid ]; then
		break
	fi
	tries=$((tries + 1))
	sleep 1
done

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

"${RCD}/iked" onestop
"${RCD}/spmd" onestop
echo RC-SMOKE-OK
