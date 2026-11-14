#!/bin/sh
# samples/freebsd-ci/freebsd-vmactions-build.sh - the FreeBSD build/test/rc.d
# smoke body for the freebsd-vm 15.1 leg.  FreeBSD auto-selects the pfkey KM
# backend (RC_KM_BACKEND: *linux*->xfrm, *->pfkey), so this build exercises
# if_pfkeyv2.c - the REAL BSD PF_KEY kernel SAD/SPD path - with no flag.
# FreeBSD 15.1 base ships OpenSSL 3.5.6, so WITH_ADDKE (RFC 9370 ml-kem
# probe) is on and iked's addketest/addkekat units are in TESTS.
#
# Runs INSIDE the FreeBSD VM (vmactions `run:`).  Deps come from the base
# `pkg` (ipsec-tools for setkey -D; not in FreeBSD base since 12.0).
# Exits non-zero on any step failure.
set -eu

if [ "$(id -u)" = "0" ]; then
	SUDO=
else
	SUDO=sudo
fi

# FreeBSD /usr/bin/make is bmake (same project as NetBSD's, which the
# NetBSD leg proved compatible).  Prefer gmake when present for the
# autotools Makefile either way.
if command -v gmake >/dev/null 2>&1; then MAKE=gmake; else MAKE=make; fi
echo "using MAKE=$MAKE"

echo "=== Installing build dependencies (pkg) ==="
# On a fresh vmactions FreeBSD VM `/usr/sbin/pkg` is the bootstrap stub that
# auto-installs the real pkg on first use; refresh the catalog so the
# install below resolves current package versions.
$SUDO env ASSUME_ALWAYS_YES=yes pkg update >/dev/null || true
$SUDO env ASSUME_ALWAYS_YES=yes pkg install \
	autoconf automake libtool pkgconf gmake m4 bison ipsec-tools strongswan
# ipsec-tools provides /usr/local/sbin/setkey (SAD/SPD dump) - removed from
# FreeBSD base in 12.0.  The vnet conformance leg uses it.  strongswan is
# the charon seat of the *-charon/-charonr vnet rows (charon + swanctl,
# kernel-pfkey, ML-KEM via its ml plugin); its rc.d service stays disabled,
# the matrix starts charon by hand inside a vnet jail.

echo "=== Sanitizer (ASan/UBSan compile probe) ==="
# ASan is OpenSSL-provider incompatible under BSD toolchains on real crypto
# (OpenSSL #25456, same as the NetBSD legs).  FreeBSD 15.1 = OpenSSL 3.5.6
# = WITH_ADDKE, so ASan stays a compile probe and the units run on the
# production rebuild below.
export SAN_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
export SAN_LDFLAGS="-fsanitize=address,undefined"
export CC=cc

echo "=== Bootstrapping build system ==="
autoreconf -fi

echo "=== Configure (sanitized compile probe) ==="
# --enable-admin: defaults to no on non-Linux (iked/configure.ac:306-308),
# which would leave iked WITHOUT the admin socket and ikedctl unbuilt -- and
# the conformance matrix DRIVES establish-sa through ikedctl.  The NetBSD
# legs never hit this (build+rc.d smoke only, no tunnel matrix).  admin.c/
# ikedctl_unix.c are pure POSIX unix sockets, so this is the FreeBSD-leg
# equivalent of the Linux default, not a porting hack.
CFLAGS="-g -O2 ${SAN_CFLAGS}" \
LDFLAGS="${SAN_LDFLAGS}" \
./configure --prefix=/usr/local/racoon2 --enable-admin --enable-keymat-oracle

echo "=== Building (sanitized compile probe) ==="
$MAKE -j2

echo "=== make install (for the unit-test build only) ==="
$SUDO $MAKE install
test -x /usr/local/racoon2/sbin/iked
test -x /usr/local/racoon2/sbin/spmd
test -x /usr/local/racoon2/etc/racoon2/rc.d/iked
test -x /usr/local/racoon2/etc/racoon2/rc.d/spmd

echo "=== REBUILD non-sanitized daemons (production shape) ==="
$MAKE clean >/dev/null
SAN_CFLAGS= SAN_LDFLAGS= \
CFLAGS="-g -O2" \
./configure --prefix=/usr/local/racoon2 --enable-admin --enable-keymat-oracle >/dev/null
$MAKE -j2 >/dev/null
$SUDO $MAKE install
test -x /usr/local/racoon2/sbin/iked
test -x /usr/local/racoon2/sbin/ikedctl

echo "=== Unit/KAT suites on the production-shaped build ==="
# print the per-test logs on failure (the bare make output names the
# failing test but not why; the BSD legs had no other way to see it)
$MAKE -C lib check || { cat lib/test-suite.log 2>/dev/null; exit 1; }
# iked unit suite: run the FULL configured TESTS (no static override).  The
# generated Makefile already conditionally includes addketest/addkekat only
# under WITH_ADDKE (FreeBSD 15/16 OpenSSL has ML-KEM; 14.x/OpenSSL 3.0 does
# not), so the correct inventory comes from configure, not a per-release
# list.  The pre-2026 static 4/6-target override silently dropped ~32
# declared tests (fragtest/resumetest/eap*/tcp*/oakleytest/ikev1fragtest/
# qcdtest...); this mirrors the netbsd-vmactions-build.sh fix (G16).
if grep -q "^#define WITH_ADDKE 1" iked/config.h 2>/dev/null; then
	echo "=== iked unit suite (WITH_ADDKE: includes addketest/addkekat) ==="
else
	echo "=== iked unit suite (no WITH_ADDKE: addketest/addkekat excluded) ==="
fi
# print the per-test logs on failure (the bare make output names the
# failing test but not why; the BSD legs had no other way to see it)
$MAKE -C iked check || { cat iked/test-suite.log 2>/dev/null; exit 1; }

echo "=== FreeBSD build/test OK ==="
echo "vnet conformance leg runs as the next workflow step (separate script)"
