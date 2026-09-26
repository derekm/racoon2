#!/bin/bash
# r2-matrix-run.sh — build i2i prefix from the shipped tree, prove hash, run the
# PQC matrix cases that arbitrate the 2026-09-25 review claims:
#   i2ike            type-06 echo + MATCHING ML-KEM keymat both sides (claim #1)
#   i2ike_drop       CREATE_CHILD response-loss -> R2 replay recovery (claim #2)
#   i2iinit-drop     H1 gen-0 replay still green (regression)
#   i2iinit-addke    initial-SA ADDKE still green (regression)
# Never touches /usr/local/racoon2 (prod) or /usr/lib/systemd/system (units go
# into the i2i prefix).  Does not run live iked/spmd; matrix kinds spawn their
# own daemons inside fresh netns.
set -u
SRC=/home/yescorp/r2-matrix-src
PREFIX=/usr/local/racoon2-i2i
UNITDIR=$PREFIX/lib/systemd
TAR=${1:-/home/yescorp/r2-matrix.tar.gz}
LOG=/home/yescorp/r2-matrix.log

echo "=== [$(date +%T)] extract $TAR -> $SRC ===" | tee "$LOG"
rm -rf "$SRC"; mkdir -p "$SRC"
tar xzf "$TAR" -C "$SRC"

echo "=== [$(date +%T)] configure/build (xfrm-addke) ===" | tee -a "$LOG"
cd "$SRC" || exit 1
autoreconf -fi >/dev/null 2>&1
./configure --prefix="$PREFIX" --enable-addke --enable-keymat-oracle \
    --with-systemdsystemunitdir="$UNITDIR" >>"$LOG" 2>&1 || { tail -20 "$LOG"; exit 1; }
make -j"$(nproc)" >>"$LOG" 2>&1 || { tail -40 "$LOG"; exit 1; }

echo "=== [$(date +%T)] install into $PREFIX ===" | tee -a "$LOG"
make install >>"$LOG" 2>&1 || { tail -40 "$LOG"; exit 1; }

echo "=== [$(date +%T)] hash proof: staged vs installed iked ===" | tee -a "$LOG"
# The build tree's iked/iked is the libtool WRAPPER script; the real ELF is
# iked/.libs/iked (make install copies the ELF).  Hash the ELF.
STAGED=$(md5sum "$SRC/iked/.libs/iked" | awk '{print $1}')
INSTALLED=$(md5sum "$PREFIX/sbin/iked" | awk '{print $1}')
echo "staged    $STAGED" | tee -a "$LOG"
echo "installed $INSTALLED" | tee -a "$LOG"
if [ "$STAGED" != "$INSTALLED" ]; then
    echo "HASH MISMATCH — do not trust the run" | tee -a "$LOG"
    exit 1
fi
echo "hash proof OK" | tee -a "$LOG"

CASES=${2:-'i2ike-addke|i2ike-drop|i2iinit-drop|i2iinit-addke|i2ike-dup|i2ike-reqdrop|veth-account'}
echo "=== [$(date +%T)] matrix cases=$CASES ===" | tee -a "$LOG"
cd "$SRC/samples/linux-matrix" || exit 1
R2_ADDKE=yes R2_DPD=yes R2_BOX=yes bash ./run.sh --src "$SRC" --prefix "$PREFIX" \
    --cases "$CASES" >>"$LOG" 2>&1
rc=$?
echo "=== [$(date +%T)] matrix rc=$rc ===" | tee -a "$LOG"
grep -E '^(===|PASS |FAIL |SKIP |pass=)' "$LOG" | tail -20
exit $rc
