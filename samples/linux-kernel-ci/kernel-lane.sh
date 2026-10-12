#!/bin/sh
# samples/linux-kernel-ci/kernel-lane.sh -- run the Linux netns matrix on a
# DIFFERENT kernel than the GitHub runner's, booted under QEMU/KVM.
#
# The Linux matrix only ever ran on the runner's one kernel.  The XFRM
# netlink ABI, ESP offload paths, NAT-T encap and xfrm_stat counters
# changed across LTS lines, so this lane boots a stock cloud image of an
# older LTS kernel and of the newest stable kernel and runs the same
# samples/linux-matrix there (idea from rdratlos/racoon-ipsec-tools,
# whose matrix runs several kernels; boot method mirrors
# samples/freebsd-ci/freebsd-16-current-ci.sh).
#
#   kernel-lane.sh <image> [--shard K M] [--cases REGEX]
#     image: jammy   Ubuntu 22.04 cloud image, Linux 5.15 LTS
#            bookworm Debian 12 cloud image,   Linux 6.1 LTS
#            sid     Debian unstable daily,     newest stable kernel
#
# Runs on the HOST ubuntu-latest runner: downloads the image, boots it with
# a NoCloud seed that installs an ephemeral root ssh key, ships the
# checkout, builds the xfrm backend in the guest, stages the live daemon
# config, runs run.sh with R2_REQUIRE_LIVE=1 R2_LANE=kernel, copies the
# log back and exits with the matrix verdict.  Nothing persists.
set -eu
IMGNAME=${1:?usage: kernel-lane.sh jammy|bookworm|sid [--shard K M] [--cases RE]}
shift
SHARD_K=0 SHARD_M=1 CASES=
while [ $# -gt 0 ]; do
	case $1 in
	--shard) SHARD_K=$2; SHARD_M=$3; shift 3 ;;
	--cases) CASES=$2; shift 2 ;;
	*) echo "bad arg $1"; exit 2 ;;
	esac
done
case $IMGNAME in
jammy)    URL=https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img ;;
bookworm) URL=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2 ;;
sid)      URL=https://cloud.debian.org/images/cloud/sid/daily/latest/debian-sid-genericcloud-amd64-daily.qcow2 ;;
*) echo "unknown image $IMGNAME"; exit 2 ;;
esac
WORK=$(pwd)
P=kl-$IMGNAME
IMG=$P.qcow2
SSHPORT=$((18300 + SHARD_K))
LOG="$WORK/kernel-$IMGNAME-matrix-shard-$SHARD_K.log"

if ! command -v qemu-system-x86_64 >/dev/null 2>&1 || ! command -v genisoimage >/dev/null 2>&1; then
	sudo apt-get update -qq
	sudo apt-get install -y -qq qemu-system-x86 qemu-utils genisoimage
fi
test -e /dev/kvm || { echo "FAIL: no /dev/kvm on this runner"; exit 1; }
[ -w /dev/kvm ] || sudo chmod 666 /dev/kvm 2>/dev/null || true

curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 20 --speed-limit 1024 --speed-time 60 -o "$IMG" "$URL"
qemu-img resize "$IMG" 12G >/dev/null

rm -f "$P-key" "$P-key.pub"; ssh-keygen -t ed25519 -N "" -f "$P-key" -q
KEY=$(cat "$P-key.pub")
rm -rf "$P-seed"; mkdir "$P-seed"
printf 'instance-id: kl%d-%d\nlocal-hostname: klci\n' "$$" "$(date +%s)" > "$P-seed/meta-data"
cat > "$P-seed/user-data" <<UD
#cloud-config
disable_root: false
ssh_authorized_keys:
  - $KEY
ssh_pwauth: false
runcmd:
  - sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
  - systemctl restart ssh || systemctl restart sshd
UD
genisoimage -quiet -o "$P-cidata.iso" -V cidata -r -J "$P-seed/meta-data" "$P-seed/user-data"

qemu-system-x86_64 -enable-kvm -machine q35,accel=kvm -cpu host -smp 2 -m 4096 \
	-drive file="$IMG",if=virtio,format=qcow2 \
	-drive file="$P-cidata.iso",if=virtio,media=cdrom \
	-netdev user,id=n0,hostfwd=tcp:127.0.0.1:$SSHPORT-:22 \
	-device virtio-net-pci,netdev=n0 \
	-serial file:"$P-console.log" -display none -daemonize -pidfile "$P-qemu.pid"
trap 'kill $(cat "$P-qemu.pid" 2>/dev/null) 2>/dev/null || true; [ -s "$LOG" ] || tail -40 "$P-console.log" 2>/dev/null || true' EXIT

G() { timeout "$1" ssh -i "$P-key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o IdentitiesOnly=yes -o ServerAliveInterval=30 -p "$SSHPORT" -l root 127.0.0.1 "$2"; }
W=0
until G 8 true 2>/dev/null; do
	W=$((W + 5)); [ "$W" -lt 600 ] || { echo "FAIL: guest ssh never came up"; exit 1; }
	sleep 5
done
echo "guest up after ${W}s: $(G 15 'uname -r; . /etc/os-release; echo $PRETTY_NAME' | tr '\n' ' ')"

G 1200 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq &&
	apt-get install -y -qq autoconf automake libtool pkg-config gcc make \
	libssl-dev libkrb5-dev libpcap-dev bison flex strongswan strongswan-swanctl iproute2 \
	libsystemd-dev iputils-ping xxd iptables conntrack nftables python3 procps \
	netcat-openbsd psmisc kmod >/dev/null && echo deps ok'
tar czf - --exclude="kl-*" --exclude='.git' . | G 300 'mkdir -p /root/rc2 && tar xzf - -C /root/rc2'
G 1800 'cd /root/rc2 && R2_PREFIX=/usr/local/racoon2 bash samples/linux-matrix/run.sh \
	--src /root/rc2 --rebuild xfrm --cases "a^" > /root/build.log 2>&1; rc=$?; tail -5 /root/build.log; exit $rc'
G 300 'cd /root/rc2 && bash samples/linux-matrix/ci-setup.sh --prefix /usr/local/racoon2'

ARGS="--src /root/rc2 --shard $SHARD_K $SHARD_M"
[ -z "$CASES" ] || ARGS="$ARGS --cases '$CASES'"
set +e
G 18000 "cd /root/rc2 && echo KERNEL \$(uname -r) && R2_PREFIX=/usr/local/racoon2 R2_REQUIRE_LIVE=1 R2_LANE=kernel \
	bash samples/linux-matrix/run.sh $ARGS > /root/matrix.log 2>&1; echo matrix_rc=\$? >> /root/matrix.log"
set -e
timeout 120 scp -q -i "$P-key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o IdentitiesOnly=yes -P "$SSHPORT" root@127.0.0.1:/root/matrix.log "$LOG"
test -s "$LOG" || { echo "FAIL: matrix log missing"; exit 1; }
# per-row daemon/peer logs (charon, iked, spmd) for the artifact
G 120 'tar czf /root/rowlogs.tgz /tmp/r2-* 2>/dev/null; true' || true
timeout 120 scp -q -i "$P-key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o IdentitiesOnly=yes -P "$SSHPORT" root@127.0.0.1:/root/rowlogs.tgz "${LOG%.log}-rows.tgz" || true
{ echo "== guest kernel: $(G 15 'uname -r') =="; cat "$LOG"; } | tail -c 200000
grep -q '^matrix_rc=0$' "$LOG"
