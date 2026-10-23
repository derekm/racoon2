# $Id: Makefile.in,v 1.35 2007/05/16 11:05:10 fukumoto Exp $

AM_CPPFLAGS =-DSYSCONFDIR=\"${sysconfdir}\"
AM_CPPFLAGS +=-DCF_DEBUG
#AM_CPPFLAGS +=-DSADB_X_MIGRATE
AM_YFLAGS = -d
LEX_OUTPUT_ROOT = lex\.yy

lib_LTLIBRARIES = libracoon.la
#noinst_LIBRARIES =	libracoon.la
libracoon_la_SOURCES =vmbuf.c rc_type.c rc_net.c rc_str.c \
	if_spmd.c \
	cfsetup.c rc_pcap.c cftoken.l cfparse.y \
	pidfile.c sd_listenfds.c plog.c safefile.c version.c rbuf.c addresspool.c
if USE_XFRM
libracoon_la_SOURCES += if_xfrm.c
else
if USE_USERSPACE
libracoon_la_SOURCES += if_userspace.c
else
libracoon_la_SOURCES += if_pfkeyv2.c
endif
endif
EXTRA_DIST = if_xfrm.c if_pfkeyv2.c if_userspace.c xfrmnatt.c xfrmtmpl.c xfrmnltest.c
libracoon_la_LIBADD = $(LTLIBOBJS) -lpcap
# NOTE: keep the libtool version-info at the default 0:0:0 (soname
# libracoon.so.0). Bumping it to 1:0:0 (libracoon.so.1) IS the right ABI-drift
# guard, but it is a coordinated deploy: every consumer (iked/spmd/kinkd) must
# relink to the new soname and the old .so.0 must be removed in the SAME
# install, otherwise the prefix ends up with a broken mix (verified 2026-10-23:
# a piecemeal bump left spmd with DT_NEEDED on both .so.0 and .so.1 and
# 'libracoon.so.0 => not found'). Do the bump only as a coordinated prod
# deploy per doc/OPERATIONS.md.
TESTS = sample kmtest loginkat icketest
check_PROGRAMS = sample kmtest loginkat icketest
sample_SOURCES = sample.c
sample_LDADD = libracoon.la
loginkat_SOURCES = loginkat.c
loginkat_LDADD = libracoon.la
icketest_SOURCES = icketest.c
icketest_LDADD = libracoon.la
# Extensionless tests ignore per-test *_LOG_COMPILER; the wrapper passes
# the config file to sample and is a no-op for kmtest / xfrmnatt (main).
LOG_COMPILER = $(SHELL) $(srcdir)/sample-wrapper.sh
AM_TESTS_ENVIRONMENT = R2_SAMPLE_CONF='$(abs_srcdir)/../samples/libsample.conf'; export R2_SAMPLE_CONF;
kmtest_SOURCES = kmtest.c kmtest_backend.c
if USE_XFRM
# xfrmnatt and xfrmtmpl talk to the REAL kernel (guarded only by
# geteuid()/return-77) and are kernel-mutating, so auto-running them from
# `make check` on a dev box is hostile. Build them (check_PROGRAMS) but keep
# them OUT of TESTS; run them manually as root when live coverage is wanted.
# Hermetic xfrmnltest (#includes if_xfrm.c under XFRM_UNITTEST, mocks the
# kernel over a socketpair) stays in the default check.
TESTS += xfrmnltest
check_PROGRAMS += xfrmnatt xfrmtmpl xfrmnltest
# xfrmnltest #includes if_xfrm.c (XFRM_UNITTEST) and mocks the kernel
# with socketpairs; libracoon only supplies plog/rcs_* helpers.
xfrmnltest_SOURCES = xfrmnltest.c
# Link the library's objects, NOT libracoon.la: xfrmnltest compiles its
# own copy of if_xfrm.c, and linking the library too defines every
# if_xfrm.c global twice (ASan odr-violation under the sanitizer builds).
xfrmnltest_LDADD = vmbuf.lo rc_type.lo rc_net.lo rc_str.lo if_spmd.lo \
	cfsetup.lo rc_pcap.lo cftoken.lo cfparse.lo pidfile.lo sd_listenfds.lo \
	plog.lo safefile.lo version.lo rbuf.lo addresspool.lo \
	$(LTLIBOBJS) -lpcap -lpthread
xfrmnatt_SOURCES = xfrmnatt.c
xfrmnatt_LDADD = libracoon.la
xfrmtmpl_SOURCES = xfrmtmpl.c
xfrmtmpl_LDADD = libracoon.la
endif

BUILT_SOURCES = cfparse.h
