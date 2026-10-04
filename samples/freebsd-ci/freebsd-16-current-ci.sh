#!/bin/sh
# samples/freebsd-ci/freebsd-16-current-ci.sh - FreeBSD 16.0-CURRENT amd64
# build + vnet conformance leg, booted from the OFFICIAL project snapshot.
#
# vmactions/freebsd-vm has no 16.0 turnkey image yet (their builder shelves
# 16.0/CURRENT: freebsd-16.0.conf exists but is not in the build matrix, so
# no freebsd-16.0*.qcow2.zst release asset exists for the action to fetch).
# FreeBSD 16.0 swapped cloud-init for nuageinit; the BASIC-CLOUDINIT image
# accepts a config-2/cidata seed whose user-data STARTING WITH "#!" is
# executed as root at first boot.  We use that to enable root SSH in the
# guest, then drive the same samples/freebsd-ci scripts we run in the
# 15.1 vmactions leg.  Guest disk/ssh are ephemeral per job.
#
# This script runs on the HOST ubuntu-latest runner.  It:
#   1. installs qemu-system-x86 (+ tools), downloads + decompresses the
#      official 16.0-CURRENT amd64 zfs snapshot,
#   2. boots it under -enable-kvm with a seed that installs the runner's
#      ephemeral ssh key for root,
#   3. scp's the checkout tree into the guest, runs
#      freebsd-vmactions-build.sh then freebsd-vnet-matrix.sh --shard K M,
#   4. copies the matrix log back out and gate-exits non-zero on any
#      'FAIL freebsd-vnet' row.
#
# Sharding mirrors the 15.1 vmactions matrix and the Linux matrices:
#   freebsd-16-current-ci.sh --shard K M
# runs only the rows whose dispatcher index % M == K (each GitHub job is its
# own VM, so jail names / epair / /tmp/freeb never collide).  --shard 0 1
# (default) is a full run; the merged report job sums the per-shard logs and
# gates the 32-row total, exactly like freebsd-vnet-report.
#
# No Persistence: the qcow2 is thrown away; every run boots the live
# "Latest" snapshot, matching vmactions' fresh-VM semantics.
set -eu

# ---- parameterisable, mirroring the freebsd.yml 15.1 job ---------------
PREFIX="${PREFIX:-/usr/local/racoon2}"
SNAP_URL="https://download.freebsd.org/snapshots/VM-IMAGES/16.0-CURRENT/amd64/Latest/FreeBSD-16.0-CURRENT-amd64-BASIC-CLOUDINIT-zfs.qcow2.xz"
IMG="fb16-ci.qcow2"
SSHPORT=18226          # hostfwd for the guest's :22 (unique vs other jobs)
WORK="$(pwd)"          # CWD = checkout root (same as the vmactions legs)
SHARD_K=0
SHARD_M=1
while [ $# -gt 0 ]; do
  case $1 in
    --shard) SHARD_K=$2; SHARD_M=$3; shift 3 ;;
    *) echo "usage: $0 [--shard K M] (default full run 0 1)"; exit 2 ;;
  esac
done
LOG="$WORK/freebsd-16-current-matrix-shard-$SHARD_K.log"

echo "=== [16.x] FreeBSD 16.0-CURRENT self-hosted leg starting on $(hostname) ==="
echo "prefix=$PREFIX snapshot=$SNAP_URL"

# ---- 1. host deps + guest disk -----------------------------------------
if ! command -v qemu-system-x86_64 >/dev/null 2>&1 || ! command -v genisoimage >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y -qq qemu-system-x86 genisoimage
fi
command -v qemu-system-x86_64 || { echo "FAIL: qemu-system-x86_64 not installed"; exit 1; }
command -v genisoimage || { echo "FAIL: genisoimage not installed"; exit 1; }
test -e /dev/kvm || { echo "FAIL: no /dev/kvm on this runner - cannot boot the guest"; exit 1; }
# GitHub-hosted runners may expose /dev/kvm root:kvm 660 (vmactions grants
# access internally; we self-host the boot so we must too).
if [ ! -w /dev/kvm ]; then
  sudo chmod 666 /dev/kvm 2>/dev/null || true
fi

if [ ! -f "$IMG" ]; then
  echo "downloading official 16.0-CURRENT amd64 snapshot (~701MB)..."
  # -f fail on HTTP error, --retry for flaky pipes, -S show errors, bounded
  # connect-timeout so a stalled download fails loudly instead of hanging
  # the job until the 90-minute job timeout.
  curl -fsSL --retry 3 --retry-delay 5 --connect-timeout 20 --speed-limit 1024 --speed-time 60 -o "$IMG.xz" "$SNAP_URL"
  unxz -f "$IMG.xz"
fi
qemu-img info "$IMG" >/dev/null || { echo "FAIL: bad guest image"; exit 1; }

# ---- 2. seed: ephemeral ssh key + root login ---------------------------
rm -f fb16-key fb16-key.pub
ssh-keygen -t ed25519 -N "" -f fb16-key -q
KEY=$(cat fb16-key.pub)
SEEDDIR="fb16-seed"
rm -rf "$SEEDDIR"; mkdir -p "$SEEDDIR"
printf 'instance-id: rb%d-%d\nlocal-hostname: fb16ci\n' "$$" "$(date +%s)" > "$SEEDDIR/meta-data"
# user-data that starts with "#!" is executed as ROOT by nuageinit at first
# boot (nuageinit.7: "If this file starts with a '#!' it will be executed at
# the end of the boot via nuageinit_user_data_script").  We open root SSH
# and add the provisioning key; nothing else (build deps come from the
# build script's own pkg install, exactly like the 15.1 leg).
cat > "$SEEDDIR/user-data" <<EOF
#!/bin/sh
mkdir -p /root/.ssh
echo "$KEY" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
sed -i .bak -E 's/^#?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
# nuageinit_user_data_script (this) runs BEFORE firstboot_pkg_upgrade.
# sysrc cannot stop that upgrade: /etc/rc sources rc.conf once
# (_rc_conf_loaded) while the flag is still YES, and CURRENT does not
# reboot after the upgrade.  The upgrade replaces FreeBSD-kernel-generic,
# which owns if_epair.ko, under the running kernel.  A later
# `ifconfig epair create` then autoloads a module that does not match and
# exits non-zero (the matrix used to discard that stderr).  Load the
# matching module now, and lock the package so the upgrade cannot replace it.
kldload -n if_epair 2>/dev/null || true
kldload -n ipsec 2>/dev/null || true
pkg lock -y FreeBSD-kernel-generic 2>/dev/null || true
sysrc firstboot_pkg_upgrade_enable=NO
rm -f /var/db/firstboot-pkg-upgrade /firstboot-pkg-upgrade 2>/dev/null || true
service sshd restart
EOF
chmod 644 "$SEEDDIR/user-data"
genisoimage -quiet -o fb16-cidata.iso -V cidata -r -J "$SEEDDIR/meta-data" "$SEEDDIR/user-data"

# ---- 3. boot QEMU + wait for ssh --------------------------------------
rm -f "$LOG"
qemu-system-x86_64 \
  -enable-kvm -machine q35,accel=kvm -cpu host -smp 2 -m 3072 \
  -drive file="$IMG",if=virtio,format=qcow2 \
  -drive file=fb16-cidata.iso,if=virtio,media=cdrom \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:$SSHPORT-:22 \
  -device virtio-net-pci,netdev=n0 \
  -serial file:fb16-console.log \
  -display none -daemonize -pidfile fb16-qemu.pid
trap 'kill $(cat fb16-qemu.pid 2>/dev/null) 2>/dev/null || true; if [ ! -s "$LOG" ]; then echo "=== guest console tail ==="; tail -40 fb16-console.log 2>/dev/null || true; fi' EXIT

echo "waiting for guest ssh..."
# First boot may run the baked-in firstboot_pkg_upgrade (327 base pkgs on
# the 16.0-CURRENT snapshot); the seed's sshd restart gives us SSH before
# it finishes, but budget generously for the worst case either way.
WAIT=0
while [ "$WAIT" -lt 900 ]; do
  if timeout 8 ssh -i fb16-key -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
      -p "$SSHPORT" -l root 127.0.0.1 'true' 2>/dev/null; then
    echo "guest ssh up after ${WAIT}s"
    break
  fi
  WAIT=$((WAIT+5)); sleep 5
done
[ "$WAIT" -lt 900 ] || { echo "FAIL: guest never came up"; exit 1; }
timeout 15 ssh -i fb16-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
  -p "$SSHPORT" -l root 127.0.0.1 'uname -a' || true

# ---- 4. ship the tree, build, then the vnet matrix ----------------------
echo "sending checkout tree..."
# Exclude the guest image/seed artifacts created in this step - the checkout
# tar must carry only the source tree (the 3.6GB qcow2 would never fit).
# NB: GNU tar strips a leading "./" from member names, so patterns must NOT
# be prefixed with ./ -- "./$IMG" silently fails to match and the image gets
# piped into the guest's disk.
tar czf - --exclude='fb16-*' --exclude='leg*.log' --exclude='.git' . | timeout 120 ssh -i fb16-key -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
  -p "$SSHPORT" -l root 127.0.0.1 'mkdir -p /root/rc2 && tar xzf - -C /root/rc2'

echo "=== build+units ==="
timeout 1200 ssh -i fb16-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes -p "$SSHPORT" -l root 127.0.0.1 \
  'cd /root/rc2 && sh samples/freebsd-ci/freebsd-vmactions-build.sh'

echo "=== copy KAT/CPL evidence back (for the compliance report) ==="
# Same three evidence files the 15.1 leg feeds to ci-comply-report.sh, so the
# merged/compliance step renders an NDcPP report for this CURRENT snapshot too.
# Scp the files the build emitted; missing ones are simply not shipped (the
# reporter treats an unobserved cell as NO EVIDENCE).
for f in iked/ndcppkats.log iked/test-suite.log lib/test-suite.log; do
  timeout 60 scp -q -i fb16-key -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
    -P "$SSHPORT" "root@127.0.0.1:/root/rc2/$f" "$WORK/$f" \
    2>/dev/null && echo "evidence: $f" || echo "evidence: $f MISSING (ok)"
done

echo "=== vnet conformance (iked<->iked ESP over pfkey KM) === $SHARD_K/$SHARD_M"
# Capture the matrix log inside the guest, then copy it back.  A non-zero
# matrix exit is fine here (we copy the log out and gate on its contents,
# same as the vmactions legs).
timeout 1500 ssh -i fb16-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes -p "$SSHPORT" -l root 127.0.0.1 \
  "cd /root/rc2 && ROW=all sh samples/freebsd-ci/freebsd-vnet-matrix.sh --shard $SHARD_K $SHARD_M > /tmp/freebsd-16-matrix-$SHARD_K.log 2>&1; echo matrix_rc=\$?; tail -2 /tmp/freebsd-16-matrix-$SHARD_K.log"
timeout 120 scp -q -i fb16-key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o IdentitiesOnly=yes -P "$SSHPORT" root@127.0.0.1:/tmp/freebsd-16-matrix-$SHARD_K.log "$LOG"
test -s "$LOG" || { echo "FAIL: matrix log empty/missing"; exit 1; }
cat "$LOG"

# ---- 5. gate on red rows (and on a non-vacuous shard) -------------------
# The ==32 full-matrix composition lives in the merged report job, exactly
# like freebsd-vnet-report; this job fails directly on red rows so a broken
# shard is caught at the shard, not only in the report.
PASS=$(grep -cE '^PASS freebsd-vnet ' "$LOG" || true)
FAIL=$(grep -cE '^FAIL freebsd-vnet ' "$LOG" || true)
echo "FREEBSD-16-VNET-SHARD-$SHARD_K-PASS=$PASS"
echo "FREEBSD-16-VNET-SHARD-$SHARD_K-FAIL=$FAIL"
grep -E '^FAIL freebsd-vnet ' "$LOG" || true
TOTAL=$((PASS+FAIL))
if [ -s "$LOG" ] && [ "$TOTAL" -gt 0 ] && [ "$FAIL" -eq 0 ]; then
  echo "FREEBSD-16-VNET-SHARD-$SHARD_K-OK ($TOTAL rows, zero FAIL)"
  exit 0
fi
echo "FAIL: FreeBSD 16.0-CURRENT shard $SHARD_K/$SHARD_M not green (rows=$TOTAL fail=$FAIL)"
exit 1
