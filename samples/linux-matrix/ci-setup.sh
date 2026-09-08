#!/bin/sh
# Stage the racoon2 daemon config onto a fresh Linux box (CI runner or VM)
# so the linux-matrix cases can run against live systemd units, mirroring
# the WSL live box. Root required.
#   ci-setup.sh [--prefix DIR] [--ip A.B.C.D]
# Defaults: prefix /usr/local/racoon2, ip = eth0 primary address.
set -u
PREFIX=${R2_PREFIX:-/usr/local/racoon2}
IP=
while [ $# -gt 0 ]; do
	case $1 in
	--prefix) PREFIX=$2; shift 2 ;;
	--ip) IP=$2; shift 2 ;;
	*) echo "usage: ci-setup.sh [--prefix DIR] [--ip A.B.C.D]" >&2; exit 2 ;;
	esac
done
[ "$(id -u)" -eq 0 ] || { echo "need root" >&2; exit 1; }
ETC=$PREFIX/etc/racoon2
mkdir -p "$ETC/psk"
# the units must be installed (configure needs libsystemd-dev / systemd.pc
# for the unit dir, else make install skips them — check the files, not
# systemctl, which can be finicky on CI runners)
[ -f /usr/lib/systemd/system/iked.service ] ||
	{ echo "FAIL: iked.service not installed (missing systemd.pc at configure time?)" >&2; exit 1; }
[ -f /usr/lib/systemd/system/spmd.service ] ||
	{ echo "FAIL: spmd.service not installed" >&2; exit 1; }
if [ -z "$IP" ]; then
	IP=$(ip -4 -o addr show eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
fi
[ -n "$IP" ] || { echo "no IP (set --ip)" >&2; exit 1; }
echo "staging racoon2 config for $IP under $ETC"

# printable whole-file PSK (32 chars; the matrix client keys 0x hex of it)
printf 'racoon2-ci-psk-0123456789abcdef' > "$ETC/psk/macos.psk"
chmod 600 "$ETC/psk/macos.psk"
printf 'racoon2-ci-pwd\n' > "$ETC/spmd.pwd"

cat > "$ETC/racoon2.conf" <<EOF
include "$ETC/vals.conf";
interface {
	ike {
		$IP port 500;
		$IP port 4500;
	};
	spmd {
		unix "/var/run/racoon2/spmif";
	};
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
include "$ETC/ikev1_nat.conf";
include "$ETC/macos_ikev2.conf";
EOF

cat > "$ETC/vals.conf" <<EOF
setval {
	PSKDIR			"$ETC/psk";
	CERTDIR			"$ETC/cert";
	MY_FQDN			"racoon2.wsl";
	PEERS_FQDN		"macos.client";
	PRESHRD_KEY		"macos.psk";
	WILDCARD_PRESHRD_KEY	"macos.psk";
	MY_IPADDRESS		"$IP";
	PEERS_IPADDRESS		"IP_ANY";
	MY_PUBLIC_IPADDRESS	"$IP";
	MY_NET			"$IP/32";
	PEERS_NET		"192.0.2.2/32";
	MY_GWADDRESS		"$IP";
	CP_ADDRPL4_START	"10.7.73.128";
	CP_ADDRPL4_END		"10.7.73.254";
	CP_ADDRPL6_START	"fd01::1000";
	CP_ADDRPL6_END		"fd02::2000";
	CP_DNS			"1.1.1.1";
	CP_DHCP			"10.7.73.1";
	CP_APPVER		"Racoon2 iked";
};
EOF

# the proven road-warrior remote/selectors/policy (tree sample, vals-driven)
cp "$(dirname "$0")/../../samples/macos_ikev2.conf" "$ETC/macos_ikev2.conf" 2>/dev/null || {
	echo "$ETC/macos_ikev2.conf needs samples/macos_ikev2.conf (run from the repo)" >&2
	exit 1
}
cp "$(dirname "$0")/../../samples/ikev1_nat.conf" "$ETC/ikev1_nat.conf" 2>/dev/null || {
	echo "$ETC/ikev1_nat.conf needs samples/ikev1_nat.conf" >&2
	exit 1
}

systemctl daemon-reload
systemctl restart iked spmd
i=0
while ! systemctl is-active --quiet iked || ! ss -ulnp | grep -q ':500 '; do
	i=$((i + 1))
	[ "$i" -gt 30 ] && { echo "FAIL: iked unit not active/on :500" >&2; exit 1; }
	sleep 1
done
systemctl is-active iked spmd
echo "ci-setup ok: $IP"
