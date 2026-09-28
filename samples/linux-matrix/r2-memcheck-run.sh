#!/bin/bash
# r2-memcheck-run.sh — OPTIONAL ASan/UBSan + valgrind pass over the racoon2
# tree on the Fedora box.  Opt-in only: with no R2_SAN/R2_VG its matrix run is
# a plain re-check of r2-matrix-run.sh semantics minus the hash-probe step.
#
#   R2_SAN=asan|ubsan|asan,ubsan   instrumented build: then run the UNIT
#                                  suites (lib check + iked check, incl the
#                                  WITH_ADDKE ML-KEM KATs) and the CASES
#                                  FILTER matrix rows under the sanitizer.
#                                  Fedora/glibc has NO libasan-vs-OpenSSL
#                                  interposer issue, so OpenSSL provider
#                                  units (HMAC, ECDSA) that NetBSD 10.1/10.2
#                                  cannot run under ASan DO run here.
#   R2_VG=1                        plain build: run every unit binary under
#                                  valgrind --leak-check=full
#                                  (error-exitcode => a leak/error fails).
#
# Args: [tarball] [cases-filter]  (same shape as r2-matrix-run.sh)
# Never touches /usr/local/racoon2 (prod) or the i2i prefix: all builds/installs
# land in SANPREFIX (/usr/local/racoon2-san).  Unit suites run in-tree.
set -u
SRC=/home/yescorp/r2-san-src
PREFIX=/usr/local/racoon2-san
UNITDIR=$PREFIX/lib/systemd
TAR=${1:-/home/yescorp/r2-matrix.tar.gz}
LOG=/home/yescorp/r2-memcheck.log
CASES=${2:-'^(i2ike-addke|i2ike-drop|i2iinit-drop|i2iinit-addke|i2ike-dup|i2ike-reqdrop|veth-account)([[:space:]]|$)'}

SAN_FLAG=${R2_SAN:-}
VG=${R2_VG:-0}
export R2_ADDKE=${R2_ADDKE:-yes} R2_DPD=${R2_DPD:-yes} R2_BOX=${R2_BOX:-yes}

echo "=== [$(date +%T)] extract $TAR -> $SRC ===" | tee "$LOG"
rm -rf "$SRC"; mkdir -p "$SRC"
tar xzf "$TAR" -C "$SRC"
cd "$SRC" || exit 1

case "$SAN_FLAG" in
asan|ubsan|asan,ubsan)
    # GCC names (the probe that validated this toolchain used these):
    # asan->address, ubsan->undefined.  Accept the clang spellings too.
    SAN_CFLAGS="-g -O1 -fno-omit-frame-pointer"
    case "$SAN_FLAG" in
        asan)      SAN_CFLAGS="$SAN_CFLAGS -fsanitize=address" ;;
        ubsan)     SAN_CFLAGS="$SAN_CFLAGS -fsanitize=undefined" ;;
        asan,ubsan) SAN_CFLAGS="$SAN_CFLAGS -fsanitize=address,undefined" ;;
    esac
    SAN_LDFLAGS="-fsanitize=address -fsanitize=undefined"
    echo "=== [$(date +%T)] SANITIZED build (clang=>gcc: $SAN_FLAG) ===" | tee -a "$LOG"
    ;;
*)
    SAN_CFLAGS=
    SAN_LDFLAGS=
    echo "=== [$(date +%T)] plain build (no sanitizer) ===" | tee -a "$LOG"
    ;;
esac

autoreconf -fi >/dev/null 2>&1
CFLAGS="$SAN_CFLAGS" LDFLAGS="$SAN_LDFLAGS" \
./configure --prefix="$PREFIX" --enable-addke --enable-keymat-oracle \
    --with-systemdsystemunitdir="$UNITDIR" >>"$LOG" 2>&1 \
    || { tail -20 "$LOG"; exit 1; }
make -j"$(nproc)" >>"$LOG" 2>&1 || { tail -40 "$LOG"; exit 1; }

echo "=== [$(date +%T)] unit suites (in-tree) ===" | tee -a "$LOG"
export ASAN_OPTIONS="detect_leaks=1:halt_on_error=1${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
# lib check is scoped like the NetBSD CI ASan pass: xfrmtmpl/xfrmnatt are
# LIVE-KERNEL PF_KEY test mains (they send a real SPDADD over an AF_KEY
# socket).  They are not memory tests, and on this box's kernel the plain,
# non-sanitized binary fails identically ("SPDADD failed: errno=0").  The
# sanitizer gate covers the config/crypto/memory unit mains that pass under
# ASan both here and in CI (sample kmtest loginkat).
make -C lib check TESTS="sample kmtest loginkat" >>"$LOG" 2>&1 \
    || { echo "LIB CHECK FAILED" | tee -a "$LOG"; tail -40 "$LOG"; exit 1; }
# addketest/addkekat exist only when this tree's OpenSSL ships ml_kem.h
# (box = OpenSSL 3.5.8 -> yes).  Gate from the built config.
if grep -q "^#define WITH_ADDKE 1" iked/config.h 2>/dev/null; then
    IKE_TESTS="eaytest evlooptest workerstest resumetest fragtest ndcppkats addketest addkekat"
else
    IKE_TESTS="eaytest evlooptest workerstest resumetest fragtest ndcppkats"
fi
make -C iked check TESTS="$IKE_TESTS" >>"$LOG" 2>&1 \
    || { echo "IKED CHECK FAILED" | tee -a "$LOG"; tail -60 "$LOG"; exit 1; }

if [ "$VG" = 1 ] && [ -z "$SAN_FLAG" ]; then
    echo "=== [$(date +%T)] valgrind --leak-check=full on unit binaries ===" | tee -a "$LOG"
    unset ASAN_OPTIONS
    VGBIN="valgrind --quiet --error-exitcode=99 --leak-check=full --show-leak-kinds=definite,indirect"
    vg_unit() { # $1 = human name, rest = cmdline
        n=$1; shift
        echo "--- valgrind $n ---" | tee -a "$LOG"
        if "$@" >/tmp/r2-vg-$n.log 2>&1; then
            echo "valgrind $n: clean (no definite/indirect leaks, rc=0)" | tee -a "$LOG"
        else
            rc=$?
            echo "valgrind $n: rc=$rc" | tee -a "$LOG"
            grep -E "definitely lost|indirectly lost|ERROR SUMMARY|Invalid |uninitialised|LEAK SUMMARY" /tmp/r2-vg-$n.log | head -8 \
                | tee -a "$LOG"
            echo "@@@@@ valgrind $n FAILED (exit $rc) @@@@@" | tee -a "$LOG"
            return 1
        fi
    }
    VG_RC=0
    vg_unit lib-sample   env R2_SAMPLE_CONF="$SRC/samples/libsample.conf" $VGBIN "$SRC/lib/sample" "$SRC/samples/libsample.conf" || VG_RC=1
    vg_unit lib-kmtest   $VGBIN "$SRC/lib/kmtest" || VG_RC=1
    vg_unit lib-loginkat $VGBIN "$SRC/lib/loginkat" || VG_RC=1
    for _t in eaytest evlooptest workerstest resumetest fragtest ndcppkats addketest addkekat; do
        [ -x "$SRC/iked/$_t" ] || continue
        vg_unit iked-$_t $VGBIN "$SRC/iked/$_t" || VG_RC=1
    done
    echo "=== valgrind summary: rc=$VG_RC ===" | tee -a "$LOG"
fi

if [ -n "$SAN_FLAG" ]; then
    echo "=== [$(date +%T)] make install (sanitized) ===" | tee -a "$LOG"
    make install >>"$LOG" 2>&1 || { tail -20 "$LOG"; exit 1; }
    # Seed the isolated prefix's psk dir from the box's reference i2i
    # prefix (unit/matrix rows expect e.g. macos.psk).  We never write
    # PSK values here — copy the existing files wholesale.
    if [ -d /usr/local/racoon2-i2i/etc/racoon2/psk ]; then
        cp -a /usr/local/racoon2-i2i/etc/racoon2/psk/. "$PREFIX/etc/racoon2/psk/" 2>/dev/null
        echo "=== [$(date +%T)] psk seeded from i2i prefix ($(ls "$PREFIX/etc/racoon2/psk" | wc -l) files) ===" | tee -a "$LOG"
    fi
    echo "=== [$(date +%T)] matrix cases=$CASES under $SAN_FLAG ===" | tee -a "$LOG"
    cd "$SRC/samples/linux-matrix" || exit 1
    bash ./run.sh --src "$SRC" --prefix "$PREFIX" --cases "$CASES" >>"$LOG" 2>&1
    rc=$?
    echo "=== [$(date +%T)] matrix rc=$rc ===" | tee -a "$LOG"
    grep -E '^(===|PASS |FAIL |SKIP |pass=)' "$LOG" | tail -25
    exit $rc
fi

echo "=== [$(date +%T)] done (unit suites + valgrind rc=${VG_RC:-n/a}) ===" | tee -a "$LOG"
grep -E '^(===|PASS |FAIL |# |TOTAL|valgrind )' "$LOG" | tail -30
[ "${VG_RC:-0}" = 0 ]
