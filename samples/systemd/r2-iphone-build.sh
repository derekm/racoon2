#!/bin/bash
# r2-iphone-build.sh — configure + make + DESTDIR-stage the PROD responder
# tree for a single iked/spmd/libracoon swap (repo copy authoritative —
# mirror the box's /tmp copy before use). Produces the stage consumed by
# samples/systemd/r2-iphone-swap.sh: /tmp/r2-iphone-stage, stamped with the
# commit id in .r2-build-commit.
#
#     git archive HEAD | (box) unpack -> /tmp/r2-iphone-b
#     sudo bash r2-iphone-build.sh /tmp/r2-iphone-b <commit>
#     sudo bash r2-iphone-swap.sh --expect <commit>
#
# The selinux/systemd-systemunitdir flag keeps generated units OUT of the
# host /usr/lib/systemd/system so the stage never clobbers live units.
# The stage only ships sbin/iked sbin/spmd lib/libracoon.so.0.0.0 — the
# swap script handles the SONAME symlink pinning + /proc maps proof.
# PROD (unlike the i2i matrix prefix) must NOT get --enable-keymat-oracle.
#
# Usage: sudo bash r2-iphone-build.sh <srcdir> <commit>
set -euo pipefail
SRC="$1"
COMMIT="$2"
STAGE=/tmp/r2-iphone-stage
LOG=/tmp/r2-iphone-build.log

cd "$SRC"
sudo rm -rf "$STAGE"
autoreconf -fi 2>&1 | tail -1
./configure --prefix=/usr/local/racoon2 --enable-addke --enable-intermediate \
  --enable-pcap --with-systemdsystemunitdir=/usr/local/racoon2/lib/systemd \
  --enable-debug >"$LOG" 2>&1
make -j4 >>"$LOG" 2>&1
make install DESTDIR="$STAGE" >>"$LOG" 2>&1

# stamp provenance
echo "$COMMIT" | sudo tee "$STAGE/usr/local/racoon2/.r2-build-commit" >/dev/null

echo "=== config flags in this build ==="
grep -E '#define WITH_(INTERMEDIATE|ADDKE|PCAP)|/\* #undef WITH_KEYMAT_ORACLE \*/' "$SRC/iked/config.h"
echo "=== staged (DESTDIR) artifacts ==="
ls -la "$STAGE/usr/local/racoon2/sbin/iked" "$STAGE/usr/local/racoon2/sbin/spmd" "$STAGE/usr/local/racoon2/lib/libracoon.so.0.0.0"
echo "=== stamp ==="
cat "$STAGE/usr/local/racoon2/.r2-build-commit"
echo BUILD-OK
