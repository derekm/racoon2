#!/bin/sh
# samples/netbsd-ci/netbsd-vmactions-build.sh — the NetBSD build/test/smoke
# body for all three vmactions/netbsd-vm legs (10.1, 10.2, 11.0).  Kept
# byte-equivalent in intent across the legs so every NetBSD build tests the
# same thing; dependencies are installed with the base pkg_add (PKG_PATH is
# pre-wired to live quarterlies by the action's onStarted hook).
#
# Runs INSIDE the NetBSD VM (vmactions `run:`).  Deps are installed with the
# base pkg_add.  Script is root-agnostic: uses sudo only when not already
# root.  Exits non-zero on any step failure.
set -eu

# root-agnostic: SUDO= when root, else sudo (vmactions VM runs as root; the
# cross-platform-actions 10.1 job runs as root too — non-root is belt+braces)
if [ "$(id -u)" = "0" ]; then
	SUDO=
else
	SUDO=sudo
fi

# ASan/UBSan builds cannot exec under NetBSD's PaX ASLR/mprotect (the
# sanitizer runtime's shadow-memory mprotect is blocked, and on NetBSD 11 the
# ASan-instrumented configure conftest dies at exec under ASLR).  Disable the
# PaX knobs up-front for the whole build/test run; these are what the rc.d
# smoke disables anyway.  Harmless where a knob does not exist.
$SUDO sysctl -w security.pax.aslr.global=0 || true
$SUDO sysctl -w security.pax.aslr.enabled=0 || true
$SUDO sysctl -w security.pax.mprotect.global=0 || true

echo "=== Installing build dependencies (pkg_add) ==="
$SUDO /usr/sbin/pkg_add \
	autoconf automake libtool pkgconf gmake m4 bison

# Sanitizer: ASan/UBSan on for the UNIT suites (the non-Linux check).
export SAN_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
export SAN_LDFLAGS="-fsanitize=address,undefined"
export CC=cc

echo "=== Bootstrapping build system ==="
autoreconf -fi

echo "=== Configure (sanitized build) ==="
CFLAGS="-g -O2 ${SAN_CFLAGS}" \
LDFLAGS="${SAN_LDFLAGS}" \
./configure --prefix=/usr/local/racoon2

echo "=== Building (sanitized compile probe) ==="
make -j2

# ASan-runtime unit suites.  The ADDKE/OpenSSL-3.5 ML-KEM units
# (addketest/addkekat, only present when WITH_ADDKE) are the combination
# that trips the upstream libasan-vs-OpenSSL interposer issue (OpenSSL
# #25456) under ASan.  So the NON-ADDKE legs — NetBSD 10.1/10.2, both
# OpenSSL 3.0 with no addke units — run the full unit/KAT suites UNDER
# ASan here (the former cross-platform 10.1 leg proved this green).  The
# ADDKE leg (11.0, OpenSSL 3.5.7) keeps ASan as a compile probe only and
# runs the suites against the non-sanitized, deployment-shaped rebuild
# below.  Gate from the built config, not the release.
if ! grep -q "^#define WITH_ADDKE 1" iked/config.h 2>/dev/null; then
	echo "=== Unit suites UNDER ASan (non-ADDKE leg) ==="
	# Dump the failing test logs so a sanitizer trip is diagnosable in CI
	# (automake hides per-test stderr by default; the reason lives in
	# test-suite.log / the individual .log files).
	make -C lib check || { cat lib/test-suite.log 2>/dev/null | tail -80; \
			       for _l in lib/*.log; do [ -f "$_l" ] && grep -lE "AddressSanitizer|ERROR|runtime error" "$_l" >/dev/null 2>&1 && { echo "--- $_l ---"; tail -60 "$_l"; }; done; exit 1; }
	make -C iked check TESTS="eaytest evlooptest workerstest ndcppkats" || { cat iked/test-suite.log 2>/dev/null | tail -80; exit 1; }
else
	echo "=== ASan = compile probe only (ADDKE/OpenSSL 3.5 leg) ==="
fi

echo "=== make install (sanitized, for the unit-test build only) ==="
$SUDO make install
test -x /usr/local/racoon2/sbin/iked
test -x /usr/local/racoon2/etc/racoon2/rc.d/iked
test -x /usr/local/racoon2/etc/racoon2/rc.d/spmd

echo "=== REBUILD non-sanitized daemons for the rc.d smoke ==="
# The unit suites above already ran the ASan/UBSan check.  The boot smoke
# (rc.d + PF_KEY + UDP/500) must run PRODUCTION-shaped binaries: ASan breaks
# OpenSSL 3.0's provider-based sha256 EVP ops on the NetBSD toolchain
# (EVP_DigestInit_ex fails, empty ERR, even for a lone EVP_sha256()/HMAC probe
# linked only against /usr/lib/libcrypto.a — OpenSSL issue #25456), which makes
# spmd's keyed HMAC-SHA256 SPMIF login fail at challenge generation.  sha1
# survives only via OpenSSL 3.x's default-provider path; this is a libasan interceptor
# mismatch (NetBSD/FreeBSD only), not a racoon2 defect.  The non-sanitized
# build is the real deployment shape and is proven working by that same probe.
make clean >/dev/null
SAN_CFLAGS= SAN_LDFLAGS= \
CFLAGS="-g -O2" \
./configure --prefix=/usr/local/racoon2 >/dev/null
make -j2 >/dev/null
$SUDO make install
# Re-run the unit/KAT suites on the production-shaped build so the compliance
# report has evidence again (make clean removed the sanitized-run logs; these
# non-sanitized results are the more representative cells anyway).
make -C lib check
# addketest/addkekat (PQC: RFC 9370 ADDKE logic + NIST FIPS 203 ML-KEM-768 KAT)
# are TESTS += under WITH_ADDKE in iked/Makefile.am, so they only exist when
# this leg's base OpenSSL ships ml_kem.h (NetBSD 11.0 = OpenSSL 3.5.7 via the
# PR/60511 pull-up; NetBSD 10.2 = OpenSSL 3.0.21 = addke=no, so check-TESTS
# must NOT be asked for them). Gate from the built config, not the release.
if grep -q "^#define WITH_ADDKE 1" iked/config.h 2>/dev/null; then
	IKE_TESTS="eaytest evlooptest workerstest ndcppkats addketest addkekat"
else
	IKE_TESTS="eaytest evlooptest workerstest ndcppkats"
fi
make -C iked check TESTS="$IKE_TESTS"

echo "=== rc.d smoke (spmd then iked, UDP 500, PF_KEY) ==="
if [ -n "$SUDO" ]; then
	$SUDO -E env PREFIX=/usr/local/racoon2 SRC="$PWD" \
		sh samples/netbsd-ci/rc-smoke.sh
else
	env PREFIX=/usr/local/racoon2 SRC="$PWD" \
		sh samples/netbsd-ci/rc-smoke.sh
fi
echo "=== NetBSD build/test/smoke OK ==="
