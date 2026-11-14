# $Id: Makefile.in,v 1.35 2007/05/16 11:05:10 fukumoto Exp $

AM_CPPFLAGS =-DSYSCONFDIR=\"${sysconfdir}\"
AM_CPPFLAGS +=-DCF_DEBUG
# LSC-lane-scoped ENABLE_SECURE delivery: lib/configure.ac AC_DEFINEs
# ENABLE_SECURE into config.h when --enable-secure (default ON) so the
# safefile/privatedir validation in lib/safefile.c compiles in (consumers
# iked/spmd/kinkd link libracoon.la and see it too).  @SUBSECURE@
# (-DENABLE_SECURE, empty with --disable-secure) additionally puts the flag
# literally on this lib's compile lines as the SF-01 regression net.  Keep it
# lib-scoped (safefile.c compiles only here) and NEVER pull in the orphaned
# -Werror/-Wall/-Wmissing-* warning set.
AM_CPPFLAGS += @SUBSECURE@
#AM_CPPFLAGS +=-DSADB_X_MIGRATE
AM_YFLAGS = -d
LEX_OUTPUT_ROOT = lex\.yy

lib_LTLIBRARIES = libracoon.la
#noinst_LIBRARIES =	libracoon.la
libracoon_la_SOURCES =vmbuf.c rc_type.c rc_net.c rc_str.c \
	if_spmd.c \
	cfsetup.c rc_pcap.c cftoken.l cfparse.y \
	pidfile.c sd_listenfds.c plog.c safefile.c version.c rbuf.c addresspool.c \
	rcpfk_util.c
if USE_XFRM
libracoon_la_SOURCES += if_xfrm.c
else
if USE_USERSPACE
libracoon_la_SOURCES += if_userspace.c
else
libracoon_la_SOURCES += if_pfkeyv2.c
endif
endif
EXTRA_DIST = rcpfk_nl.h if_xfrm.c if_pfkeyv2.c if_userspace.c xfrmnatt.c xfrmtmpl.c xfrmnltest.c pfkumigtest.c
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
# vmbuf_test exercises lib/vmbuf.c + lib/rbuf.c hardening (VB-01..VB-05):
# length-wrap rejection, zero-size / empty-buffer semantics, rc_vmemcmp
# sign across INT_MAX, rc_vmem2str scratch-OOM, scratch-ring rinse.
# It needs no ADDKE and touches no kernel state, so it belongs in the
# default check.  Extensionless test -> the sample-wrapper LOG_COMPILER
# passes the (ignored) sample config path; main() ignores argv.
TESTS += vmbuf_test
check_PROGRAMS += vmbuf_test
vmbuf_test_SOURCES = vmbuf_test.c
vmbuf_test_LDADD = vmbuf.lo rbuf.lo $(LTLIBOBJS)
# Route every rc_vcleanse call in the linked vmbuf.lo/rbuf.lo through the
# test's counter so the VB-03 scratch-reuse test asserts the rinse call
# site is present (fails if rbuf_getvb stops cleansing on slot reuse), and
# route calloc/free through the test's fault-injection stubs so the
# VB-02 sentinel-OOM tests can fail the 1-byte rc_calloc(1,1) inside
# rc_vrealloc/rc_vreallocf and prove the OOM contract (--wrap=calloc /
# --wrap=free); --wrap=realloc (with calloc) lets the realloc-failure and
# scratch-OOM tests inject large-allocation failure deterministically, so
# they also run under ASan (no RLIMIT_AS cap, no skip flag).
vmbuf_test_LDFLAGS = -Wl,--wrap=rc_vcleanse -Wl,--wrap=calloc -Wl,--wrap=free -Wl,--wrap=realloc
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
	plog.lo safefile.lo version.lo rbuf.lo addresspool.lo rcpfk_util.lo \
	$(LTLIBOBJS) -lpcap -lpthread
xfrmnatt_SOURCES = xfrmnatt.c
xfrmnatt_LDADD = libracoon.la
xfrmtmpl_SOURCES = xfrmtmpl.c
xfrmtmpl_LDADD = libracoon.la
endif

if !USE_XFRM
if !USE_USERSPACE
# pfkumigtest #includes if_pfkeyv2.c for the no-SADB_X_MIGRATE move's
# message builders; kernel-free, so NetBSD and FreeBSD run it too.
TESTS += pfkumigtest
check_PROGRAMS += pfkumigtest
pfkumigtest_SOURCES = pfkumigtest.c
pfkumigtest_LDADD = vmbuf.lo rc_type.lo rc_net.lo rc_str.lo if_spmd.lo \
	cfsetup.lo rc_pcap.lo cftoken.lo cfparse.lo pidfile.lo sd_listenfds.lo \
	plog.lo safefile.lo version.lo rbuf.lo addresspool.lo rcpfk_util.lo \
	$(LTLIBOBJS) -lpcap -lpthread
endif
endif

# pidfile_test exercises lib/pidfile.c hardening (PF-01..PF-05): reader
# rejects non-positive/malformed/overflow PIDs, writer fully publishes the
# pidstring (EINTR retry + partial-write loop, terminal errors fail), the
# on_dir path rejects an oversized progname before any open, and the writer fd
# is close-on-exec so exec'd helpers cannot prolong the flock.  It needs no
# ADDKE and touches no kernel state; it links the real pidfile.lo and provides
# its own plog/plog_location stubs plus -Wl,--wrap=write/--wrap=open fault
# injection (same pattern as vmbuf_test).  Extensionless test -> the
# sample-wrapper LOG_COMPILER passes the (ignored) sample config; main() runs
# its own probes (and re-execs itself in --flockcheck mode for the PF-05
# fork+exec demonstration).
TESTS += pidfile_test
check_PROGRAMS += pidfile_test
pidfile_test_SOURCES = pidfile_test.c
pidfile_test_LDADD = pidfile.lo $(LTLIBOBJS)
pidfile_test_LDFLAGS = -Wl,--wrap=write -Wl,--wrap=open

# safefile_test exercises rc_safefile()/rc_privatedir() against disposable
# temp fixtures only (never a live config file) and is the SF-01 regression
# net: with ENABLE_SECURE wired to the compile, a world-readable secret is
# rejected (5), foreign-owner (2), non-regular (3); if the wiring is ever
# broken the checks degrade to `return 0` and this test FAILs make check.
# Foreign-owner subtest needs euid 0 to chown (SKIPs otherwise).  No kernel
# state touched.
TESTS += safefile_test
check_PROGRAMS += safefile_test
safefile_test_SOURCES = safefile_test.c
safefile_test_LDADD = safefile.lo $(LTLIBOBJS)

# addresspool_test exercises lib/addresspool.c + the addresspool config
# parsing in lib/cfsetup.c (AP-01..AP-05): full-candidate bytes/lower bound
# for assign_ip6intf, ctor-NULL on allocation failure, lossless move that
# preserves reservations even under an injected allocator failure,
# exhaustion/no-wrap at the address-space maximum, and config-parser
# rejection of overlapping same-family ranges.  It links the real
# addresspool/cfsetup objects and fault-injects malloc/calloc/free
# (--wrap, same pattern as vmbuf_test); the exhaustion probes are bounded
# with an alarm(5) so an unbounded wrap cannot hang the suite.  No kernel
# state touched.  Extensionless test -> the sample-wrapper LOG_COMPILER
# passes the (ignored) sample config; main() runs its own probes.
TESTS += addresspool_test
check_PROGRAMS += addresspool_test
addresspool_test_SOURCES = addresspool_test.c
addresspool_test_LDADD = vmbuf.lo rc_type.lo rc_net.lo rc_str.lo if_spmd.lo \
	cfsetup.lo rc_pcap.lo cftoken.lo cfparse.lo pidfile.lo sd_listenfds.lo \
	plog.lo safefile.lo version.lo rbuf.lo addresspool.lo rcpfk_util.lo \
	$(LTLIBOBJS) -lpcap -lpthread
addresspool_test_LDFLAGS = -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free

# rc_net_test exercises lib/rc_net.c comparators and mask builders with
# synthetic lists (CM-01..CM-04): rcs_addrlist_cmp multiset symmetry and
# duplicate-reuse regression, all 33 IPv4 prefix masks, and zero-on-invalid
# for both mask builders.  plog and plog_location are wrapped to no-ops so
# the invalid-prefix path (which logs via the PLOGLOC macro before zeroing)
# runs without a logging context.  No kernel or policy state is touched.
# Extensionless test -> the sample-wrapper LOG_COMPILER passes the (ignored)
# sample config; main() runs its probes.
TESTS += rc_net_test
check_PROGRAMS += rc_net_test
rc_net_test_SOURCES = rc_net_test.c
rc_net_test_LDADD = vmbuf.lo rc_type.lo rc_net.lo rc_str.lo if_spmd.lo \
	cfsetup.lo rc_pcap.lo cftoken.lo cfparse.lo pidfile.lo sd_listenfds.lo \
	plog.lo safefile.lo version.lo rbuf.lo addresspool.lo rcpfk_util.lo \
	$(LTLIBOBJS) -lpcap -lpthread
rc_net_test_LDFLAGS = -Wl,--wrap=plog -Wl,--wrap=plog_location

# rc_pcap_test checks the synthetic capture records lib/rc_pcap.c writes
# (PC-01 v6 version nibble, PC-02 length guard/consistency, PC-03 stream
# global, PC-05 snaplen) by parsing the file it produces.
TESTS += rc_pcap_test
check_PROGRAMS += rc_pcap_test
rc_pcap_test_SOURCES = rc_pcap_test.c
rc_pcap_test_LDADD = $(rc_net_test_LDADD)
rc_pcap_test_LDFLAGS = -Wl,--wrap=plog -Wl,--wrap=plog_location

# sd_listenfds_test pins SA-01/N4: strict LISTEN_PID/LISTEN_FDS decimal
# parse (no whitespace, sign or trailing text; out-param untouched on
# rejection) and rc_listenfds() end to end in a forked child per case.
# Extensionless test -> the sample-wrapper LOG_COMPILER passes the (ignored)
# sample config.
TESTS += sd_listenfds_test
check_PROGRAMS += sd_listenfds_test
sd_listenfds_test_SOURCES = sd_listenfds_test.c
sd_listenfds_test_LDADD = sd_listenfds.lo $(LTLIBOBJS)

BUILT_SOURCES = cfparse.h
