# $Id: Makefile.in,v 1.51 2009/03/27 07:24:26 mk Exp $


AM_CPPFLAGS =	-I. -I./extra
AM_CPPFLAGS +=	@CPPFLAGS@
AM_CPPFLAGS += -DSYSCONFDIR='"$(sysconfdir)"'
AM_CPPFLAGS += -DDEBUG
AM_CPPFLAGS += -DDEBUG_TRACE
# AM_CPPFLAGS += -DSELFTEST
AM_CPPFLAGS +=  @DEFS@
# AM_CPPFLAGS += -DSADB_X_MIGRATE

IKEV1_SRC= ikev1/ikev1.c ikev1/genlist.c ikev1/ipsec_doi.c ikev1/isakmp_ident.c ikev1/isakmp_quick.c ikev1/isakmp_inf.c ikev1/handler.c ikev1/strnames.c ikev1/oakley.c ikev1/vendorid.c ikev1/algorithm.c ikev1/proposal.c  ikev1/pfkey.c
# NAT-T sources: ikev1_natt.c is ENABLE_NATT-only (its functions touch
# struct ph1handle members natt_options/natt_flags that exist only under
# that define), so it must come out of the build when --disable-natt
# (review D1/G1).  nattraversal.c stays unconditional: IKEv2 calls
# natt_start_natk/natt_create_hash/natt_process_natd from ikev2.c,
# ikev2_notify.c and ikev2_resume.c unconditionally, and it compiles
# cleanly with ENABLE_NATT unset.
IKEV1_NATT_SRC =
if NATT
IKEV1_NATT_SRC = ikev1/ikev1_natt.c
endif
IKEV2_NATT_SRC = nattraversal.c

IKEV2_SRC = ikev2.c ikev2_intermediate.c ikev2_auth.c ikev2_child.c ikev2_cookie.c ikev2_notify.c ikev2_packet.c ikev2_payload.c ikev2_decrypt.c ikev2_proposal.c ikev2_rekey.c ikev2_config.c ikev2_frag.c ikev2_resume.c ikev2_resume_rec.c ikev2_qcd.c ikev2_addke.c ikev2cfg_walk.c
IKED_COMMON = main.c dh.c ike_sa.c ike_conf.c isakmp.c authenticator.c encryptor.c crypto_openssl.c crypto_workers.c str2val.c keyed_hash.c sockmisc.c ike_pfkey.c ike_spmif.c schedule.c ratelimit.c script.c rtsock.c ${IKEV1_SRC} ${IKEV2_SRC} ${IKEV1_NATT_SRC} ${IKEV2_NATT_SRC}

if USE_EPOLL
evlooptest_SOURCES = evlooptest.c evloop_epoll.c
if USE_ADMIN
iked_SOURCES = $(IKED_COMMON) evloop_epoll.c admin.c
else
iked_SOURCES = $(IKED_COMMON) evloop_epoll.c
endif
else
evlooptest_SOURCES = evlooptest.c evloop_select.c
if USE_ADMIN
iked_SOURCES = $(IKED_COMMON) evloop_select.c admin.c
else
iked_SOURCES = $(IKED_COMMON) evloop_select.c
endif
endif

if USE_ADMIN
sbin_PROGRAMS = iked ikedctl
ikedctl_SOURCES = ikedctl_unix.c
else
sbin_PROGRAMS = iked
endif

TESTS = eaytest evlooptest workerstest resumetest fragtest ndcppkats
check_PROGRAMS = eaytest evlooptest workerstest resumetest fragtest ndcppkats
eaytest_SOURCES = eaytest.c crypto_openssl.c str2val.c
# NDcPP v3.0e crypto KATs (A9/A10/B1/B3-B6) against the daemon's OpenSSL
# wrappers; emits a "KAT <cell>: PASS/FAIL <evidence>" line per cell.
ndcppkats_SOURCES = ndcppkats.c crypto_openssl.c str2val.c dh.c crypto_workers.c keyed_hash.c
workerstest_SOURCES = workerstest.c crypto_workers.c
# resume-dump record layer is pure libracoon; test it standalone.
resumetest_SOURCES = resumetest.c ikev2_resume_rec.c
# IKEv2 fragment reassembler (RFC 7383 SKF) tested standalone with real
# crypto; isakmpstat/debug/plog/byte-order stubs live in fragtest.c.
# ikev2_decrypt.c defines the ikev2_decrypt_local() that ikev2_frag_send
# uses for its send-direction decrypt, and is self-contained enough to
# link into the test (unlike the whole ikev2_payload.c).
fragtest_SOURCES = fragtest.c ikev2_frag.c ikev2_decrypt.c \
	encryptor.c authenticator.c keyed_hash.c crypto_openssl.c str2val.c

# IKEv2 Configuration payload attribute walker (bounds-clamped advance
# shared by every CFG attribute walker in ikev2_config.c).  Standalone:
# get_uint16/put_uint16 stubs live in cfgwalktest.c.
TESTS += cfgwalktest
check_PROGRAMS += cfgwalktest
cfgwalktest_SOURCES = cfgwalktest.c ikev2cfg_walk.c

# RFC 9370 ADDKE ML-KEM-768 crypto (configure --enable-addke auto):
# exercised only on OpenSSL >= 3.5 builds that actually have the code.
if ADDKE
TESTS += addketest addkekat
check_PROGRAMS += addketest addkekat
addketest_SOURCES = addketest.c ikev2_addke.c
addkekat_SOURCES = addkekat.c
endif

# RFC 7296 2.23.1 NAT-T transport TS/ID address-substitution unit tests
# (upstream gsoc2026 work, cherry-picked from ssszcmawo/racoon2):
# TS substitution (ike_conf.c), the IKEv1 NAT-OA payload helpers
# (ikev1_natt.c) and the IP_ANY wildcard (historic IP_RW synonym) ID
# handling.  Each links all iked objects except main.o (the tests
# provide their own main() plus the main.o globals).  The object list
# is spelled out via the same source group as iked_SOURCES instead of
# $(filter-out ...) because BSD make (FreeBSD/NetBSD CI) has no GNU
# filter-out builtin and would expand the LDADD to nothing.
# Gated on NAT-T: test_ts_substitute links ikev2_addr_substitute, which
# exists only under ENABLE_NATT (see configure.ac NATT conditional), so
# a --disable-natt build must not try to build these.
if NATT
TESTS += test_ts_substitute test_natoa test_ip_any
check_PROGRAMS += test_ts_substitute test_natoa test_ip_any
test_ts_substitute_SOURCES = test_ts_substitute.c
test_ts_substitute_LDADD = $(addtest_ikedsrc) $(LDADD)
test_natoa_SOURCES = test_natoa.c
test_natoa_CPPFLAGS = $(AM_CPPFLAGS) -Iikev1
test_natoa_LDADD = $(addtest_ikedsrc) $(LDADD)
test_ip_any_SOURCES = test_ip_any.c
test_ip_any_LDADD = $(addtest_ikedsrc) $(LDADD)
endif

if USE_EPOLL
addtest_ikedsrc = dh.$(OBJEXT) ike_sa.$(OBJEXT) ike_conf.$(OBJEXT) \
	isakmp.$(OBJEXT) authenticator.$(OBJEXT) encryptor.$(OBJEXT) \
	crypto_openssl.$(OBJEXT) crypto_workers.$(OBJEXT) str2val.$(OBJEXT) \
	keyed_hash.$(OBJEXT) sockmisc.$(OBJEXT) ike_pfkey.$(OBJEXT) \
	ike_spmif.$(OBJEXT) schedule.$(OBJEXT) ratelimit.$(OBJEXT) \
	script.$(OBJEXT) rtsock.$(OBJEXT) \
	$(addtest_ikev1) $(addtest_ikev2) evloop_epoll.$(OBJEXT) \
	$(addtest_admin)
else
addtest_ikedsrc = dh.$(OBJEXT) ike_sa.$(OBJEXT) ike_conf.$(OBJEXT) \
	isakmp.$(OBJEXT) authenticator.$(OBJEXT) encryptor.$(OBJEXT) \
	crypto_openssl.$(OBJEXT) crypto_workers.$(OBJEXT) str2val.$(OBJEXT) \
	keyed_hash.$(OBJEXT) sockmisc.$(OBJEXT) ike_pfkey.$(OBJEXT) \
	ike_spmif.$(OBJEXT) schedule.$(OBJEXT) ratelimit.$(OBJEXT) \
	script.$(OBJEXT) rtsock.$(OBJEXT) \
	$(addtest_ikev1) $(addtest_ikev2) evloop_select.$(OBJEXT) \
	$(addtest_admin)
endif
addtest_ikev1 = ikev1/ikev1.$(OBJEXT) ikev1/genlist.$(OBJEXT) \
	ikev1/ipsec_doi.$(OBJEXT) ikev1/isakmp_ident.$(OBJEXT) \
	ikev1/isakmp_quick.$(OBJEXT) ikev1/isakmp_inf.$(OBJEXT) \
	ikev1/handler.$(OBJEXT) ikev1/strnames.$(OBJEXT) \
	ikev1/oakley.$(OBJEXT) ikev1/vendorid.$(OBJEXT) \
	ikev1/algorithm.$(OBJEXT) ikev1/proposal.$(OBJEXT) \
	ikev1/pfkey.$(OBJEXT) ikev1/ikev1_natt.$(OBJEXT)
addtest_ikev2 = ikev2.$(OBJEXT) ikev2_intermediate.$(OBJEXT) \
	ikev2_auth.$(OBJEXT) ikev2_child.$(OBJEXT) ikev2_cookie.$(OBJEXT) \
	ikev2_notify.$(OBJEXT) ikev2_packet.$(OBJEXT) ikev2_payload.$(OBJEXT) \
	ikev2_decrypt.$(OBJEXT) ikev2_proposal.$(OBJEXT) ikev2_rekey.$(OBJEXT) \
	ikev2_config.$(OBJEXT) ikev2_frag.$(OBJEXT) ikev2_resume.$(OBJEXT) \
	ikev2_resume_rec.$(OBJEXT) ikev2_qcd.$(OBJEXT) ikev2_addke.$(OBJEXT) \
	ikev2cfg_walk.$(OBJEXT) nattraversal.$(OBJEXT)
if USE_ADMIN
addtest_admin = admin.$(OBJEXT)
else
addtest_admin =
endif

LIBS = @LIBS@

man_MANS = iked.8
EXTRA_DIST = evloop.h evloop_select.c evloop_epoll.c crypto_workers.h \
	ikedctl.c ikedctl.h ikedctl_unix.c admin.c admin.h
