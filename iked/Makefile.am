# $Id: Makefile.in,v 1.51 2009/03/27 07:24:26 mk Exp $


AM_CPPFLAGS =	-I. -I./extra -I$(srcdir)/extra
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

IKEV2_SRC = ikev2.c ikev2_sa_auth.c ikev2_transmit.c ikev2_mobike.c ikev2_sa_init.c ikev2_informational.c ikev2_session_resume.c ikev2_intermediate.c ikev2_auth.c ikev2_child.c ikev2_cookie.c ikev2_notify.c ikev2_packet.c ikev2_payload.c ikev2_decrypt.c ikev2_proposal.c ikev2_rekey.c ikev2_config.c ikev2_frag.c ikev2_resume.c ikev2_resume_rec.c ikev2_resume_ticket.c ikev2_qcd.c ikev2_addke.c ikev2_addke_rounds.c ikev2_addke_rekey.c ikev2_eap.c ikev2_radius.c ikev2_eap_relay.c ikev2_eap_round.c ikev2_eap_drive.c ikev2_eap_emit.c ikev2_drain.c ikev2cfg_walk.c
IKED_COMMON = main.c dh.c hashcmp.c ike_sa.c ike_conf.c ike_deprecated.c isakmp.c authenticator.c encryptor.c crypto_openssl.c crypto_workers.c str2val.c keyed_hash.c sockmisc.c ike_pfkey.c ike_spmif.c schedule.c ratelimit.c script.c rtsock.c ${IKEV1_SRC} ${IKEV2_SRC} ${IKEV1_NATT_SRC} ${IKEV2_NATT_SRC}

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

TESTS = eaytest evlooptest workerstest resumetest fragtest ndcppkats eaptest radiustest relaytest authdertest ticketkat deprtest
check_PROGRAMS = eaytest evlooptest workerstest resumetest fragtest ndcppkats eaptest radiustest relaytest authdertest ticketkat deprtest
# iked -C on every shipped sample + the deprecation-switch semantics
TESTS += samplecheck.sh
# iked -C on the road-warrior sample pack (samples/roadwarrior)
TESTS += rwsamplecheck.sh
# Deprecated-transform classification (ike_deprecated.c): every NSA and
# RFC 8247 / RFC 8221 / RFC 9395 codepoint maps to the right class, level
# and citation, per protocol context.  Pure table, links standalone.
deprtest_SOURCES = deprtest.c ike_deprecated.c
eaytest_SOURCES = eaytest.c crypto_openssl.c str2val.c encryptor.c
# RFC 5723 ticket-layer KAT: the s5.1 resumed-SKEYSEED derivation pinned
# against a python hmac/sha256 vector and the ticket-by-value codec
# round-trip + tamper/wrong-key/expired rejection.  Standalone (lib + EVP
# only), no SA machinery — the same dependency-light shape as eaytest.
ticketkat_SOURCES = ticketkat.c ikev2_resume_ticket.c

# EAP (RFC 3748) framing codec: decode/encode round-trip + malformed-input
# rejection.  Standalone: only the lib allocators/plog/byte helpers are
# pulled in via the default LDADD (libracoon); the codec itself has no
# iked state-machine deps.
eaptest_SOURCES = eaptest.c ikev2_eap.c
# RADIUS client (RFC 2865/2869/3579): independently re-derives the server
# Response-Authenticator with raw OpenSSL MD5 and checks the module
# verifies it (plus wrong-secret / wrong-id / tamper rejection).
radiustest_SOURCES = radiustest.c ikev2_radius.c crypto_openssl.c str2val.c \
	keyed_hash.c
# EAP relay (responder-side state machine): Identity Request opener,
# Challenge pass-through + State echo, and Accept -> 64-octet MSK recovery
# from independently encrypted MS-MPPE keys (RFC 3079/RFC 2548).  Pure over
# decoded RADIUS responses, so no socket/server is needed.
relaytest_SOURCES = relaytest.c ikev2_eap_relay.c ikev2_radius.c ikev2_eap.c \
	crypto_openssl.c str2val.c keyed_hash.c
# EAP responder AUTH derivation (RFC 7296 s2.16): the responder AUTH over
# SignedOctets is prf(prf(MSK,"Key Pad for IKEv2"),octets) - the same MAC as
# the PSK path (IKEV2_AUTH_SHARED_KEY) with the MSK as shared key.  Checks
# the daemon's own HMAC-SHA2-256 primitive against an independent raw
# OpenSSL HMAC oracle (a shared wrapper bug cannot pass).
authdertest_SOURCES = authdertest.c crypto_openssl.c str2val.c keyed_hash.c
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

# RFC 7296 §2.7 receive classification of the core error/status notify
# types (INVALID_SPI, INVALID_MESSAGE_ID, INVALID_SELECTORS,
# TEMPORARY_FAILURE, SINGLE_PAIR_REQUIRED, SET_WINDOW_SIZE, ...).  Drives
# the real ikev2_process_notify()/ikev2_notify_type_str() into the full iked
# object set (ikev2_notify.o + ikev2_child.o + ...), exactly like the other
# full-link tests.  Always built: the notify classifier has no optional-
# feature dependency.
TESTS += notifytest
check_PROGRAMS += notifytest
notifytest_SOURCES = notifytest.c
notifytest_LDADD = $(addtest_ikedsrc) $(LDADD)

# RFC 8229 / RFC 9329 IKE-over-TCP framing codec (iked/ikev2_tcp.c): the
# 16-bit Len (including itself) + 4-octet non-ESP marker wire format, prefix
# validation, Len 0/1 fatal vs Len 2 and keepalive silent-ignore, ESP/IKE
# classification by the non-ESP marker, partial-read resistance,
# multi-record coalescing, build/decap round-trip.
TESTS += tcpframetest
check_PROGRAMS += tcpframetest
tcpframetest_SOURCES = tcpframetest.c ikev2_tcp.c
tcpframetest_LDADD = $(LDADD)

# RFC 9329 s4 bidirectional interop over a real TCP socketpair: the connection
# originator sends the one-time prefix + records, the responder (expect_prefix=1)
# decodes them; the responder replies with no prefix and the originator
# (expect_prefix=0) decodes that; plus real byte-at-a-time writes forcing a
# split inside every field.
TESTS += tcpstreamtest
check_PROGRAMS += tcpstreamtest
tcpstreamtest_SOURCES = tcpstreamtest.c ikev2_tcp.c
tcpstreamtest_LDADD = $(LDADD)

# The per-connection tcp_stream transport object (iked/ikev2_tcp_stream.c)
# over real loopback TCP: non-blocking connect that completes, one-time
# originator prefix vs the responder's no-prefix reply, and marker-stripped
# IKE delivery to the dispatch callback on both sides.
TESTS += tcpobjtest
check_PROGRAMS += tcpobjtest
tcpobjtest_SOURCES = tcpobjtest.c ikev2_tcp_stream.c ikev2_tcp.c
tcpobjtest_LDADD = $(LDADD)

# The TCP listener + stream registry (iked/ikev2_tcp_srv.c), driven like the
# daemon loop (fdset -> select -> process): accepts queued connections,
# covers listener+streams in the read set, delivers client IKE to the
# dispatch callback, and removes a stream on client FIN.
TESTS += tcpsrvtest
check_PROGRAMS += tcpsrvtest
tcpsrvtest_SOURCES = tcpsrvtest.c ikev2_tcp_srv.c ikev2_tcp_stream.c ikev2_tcp.c
tcpsrvtest_LDADD = $(LDADD)

# RFC 7296 §3.15.2 split-tunnel CP attributes (13/15): drives the real
# ikev2_create_config_reply() with a fabricated split selector.
# Full-link (addtest_ikedsrc): unconditional, no optional-feature dep.
TESTS += splitcfgtest
check_PROGRAMS += splitcfgtest
splitcfgtest_SOURCES = splitcfgtest.c
splitcfgtest_LDADD = $(addtest_ikedsrc) $(LDADD)

# RFC 7427 signer-completeness (Item C): sign/verify round-trips for the
# algorithms iked can now PUT on AUTH method 14 — RSA-PKCS1 SHA-256/384/512
# and RSASSA-PSS (salt=hashlen) SHA-256/384/512 — using the production
# eay_rsassa_*_sign() helpers.  Links the full object set (crypto_openssl).
TESTS += signtest
check_PROGRAMS += signtest
signtest_SOURCES = signtest.c
signtest_LDADD = $(addtest_ikedsrc) $(LDADD)

# RFC 9370 ADDKE ML-KEM-768 crypto (configure --enable-addke auto):
# exercised only on OpenSSL >= 3.5 builds that actually have the code.
if ADDKE
TESTS += addketest addkekat
check_PROGRAMS += addketest addkekat
addketest_SOURCES = addketest.c ikev2_addke.c ikev2_addke_rounds.c ikev2_addke_rekey.c
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
TESTS += test_ts_substitute test_natoa test_ip_any eaproundtest eaplocal eapdrivetest eapemittest eapmethodtest test_ikev1_hardening
check_PROGRAMS += test_ts_substitute test_natoa test_ip_any eaproundtest eaplocal eapdrivetest eapemittest eapmethodtest test_ikev1_hardening
# IKEv1 peer-input hardening (hashcmp.c length-checked constant-time
# compares, short Vendor ID, draft NAT-T 00/01 dropped); ideas from
# rdratlos/racoon-ipsec-tools, see the test's header.
test_ikev1_hardening_SOURCES = test_ikev1_hardening.c
test_ikev1_hardening_LDADD = $(addtest_ikedsrc) $(LDADD)
test_ts_substitute_SOURCES = test_ts_substitute.c
test_ts_substitute_LDADD = $(addtest_ikedsrc) $(LDADD)
test_natoa_SOURCES = test_natoa.c
test_natoa_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/ikev1
test_natoa_LDADD = $(addtest_ikedsrc) $(LDADD)
test_ip_any_SOURCES = test_ip_any.c
test_ip_any_LDADD = $(addtest_ikedsrc) $(LDADD)
# EAP worker-round bridge: SA-lifetime guard in done() (live AND dead SA).
# Links the full iked object set like the tests above.
eaproundtest_SOURCES = eaproundtest.c
eaproundtest_LDADD = $(addtest_ikedsrc) $(LDADD)
# EAP-remote decision gate (ikev2_eap_remote): the trigger's fail-closed
# "only for an eap remote" condition, proven with real rmconf/rc_alglist.
eaplocal_SOURCES = eaplocal.c
eaplocal_LDADD = $(addtest_ikedsrc) $(LDADD)
# EAP round DRIVER: bridge -> relay -> MSK stored on a real SA.
eapdrivetest_SOURCES = eapdrivetest.c
eapdrivetest_LDADD = $(addtest_ikedsrc) $(LDADD)
# EAP IKE_AUTH emission: IDr + EAP(48), no AUTH (hermetic composition).
eapemittest_SOURCES = eapemittest.c
eapemittest_LDADD = $(addtest_ikedsrc) $(LDADD)
# EAP responder AUTH-method selection (ikev2_eap_responder_method): ECDSA
# curve -> method 9/10/11, RSA -> DS/RSASIG, and key-failure -> 0 (the
# caller aborts rather than degrade to EAP-only no-CERT+AUTH).  Keys are
# generated at runtime with OpenSSL EVP - no private-key fixtures.
eapmethodtest_SOURCES = eapmethodtest.c
eapmethodtest_LDADD = $(addtest_ikedsrc) $(LDADD)
endif

if USE_EPOLL
addtest_ikedsrc = dh.$(OBJEXT) ike_sa.$(OBJEXT) ike_conf.$(OBJEXT) \
	ike_deprecated.$(OBJEXT) \
	isakmp.$(OBJEXT) authenticator.$(OBJEXT) encryptor.$(OBJEXT) \
	crypto_openssl.$(OBJEXT) crypto_workers.$(OBJEXT) str2val.$(OBJEXT) \
	keyed_hash.$(OBJEXT) hashcmp.$(OBJEXT) sockmisc.$(OBJEXT) ike_pfkey.$(OBJEXT) \
	ike_spmif.$(OBJEXT) schedule.$(OBJEXT) ratelimit.$(OBJEXT) \
	script.$(OBJEXT) rtsock.$(OBJEXT) \
	$(addtest_ikev1) $(addtest_ikev2) evloop_epoll.$(OBJEXT) \
	$(addtest_admin)
else
addtest_ikedsrc = dh.$(OBJEXT) ike_sa.$(OBJEXT) ike_conf.$(OBJEXT) \
	ike_deprecated.$(OBJEXT) \
	isakmp.$(OBJEXT) authenticator.$(OBJEXT) encryptor.$(OBJEXT) \
	crypto_openssl.$(OBJEXT) crypto_workers.$(OBJEXT) str2val.$(OBJEXT) \
	keyed_hash.$(OBJEXT) hashcmp.$(OBJEXT) sockmisc.$(OBJEXT) ike_pfkey.$(OBJEXT) \
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
	ikev2_decrypt.$(OBJEXT) ikev2_proposal.$(OBJEXT) ikev2_sa_auth.$(OBJEXT) ikev2_rekey.$(OBJEXT) ikev2_transmit.$(OBJEXT) ikev2_mobike.$(OBJEXT) \
	ikev2_config.$(OBJEXT) ikev2_frag.$(OBJEXT) ikev2_resume.$(OBJEXT) \
	ikev2_resume_rec.$(OBJEXT) ikev2_resume_ticket.$(OBJEXT) ikev2_sa_init.$(OBJEXT) ikev2_informational.$(OBJEXT) ikev2_session_resume.$(OBJEXT) ikev2_qcd.$(OBJEXT) ikev2_addke.$(OBJEXT) ikev2_addke_rounds.$(OBJEXT) ikev2_addke_rekey.$(OBJEXT) \
	ikev2_eap.$(OBJEXT) ikev2_radius.$(OBJEXT) ikev2_eap_relay.$(OBJEXT) ikev2_eap_round.$(OBJEXT) ikev2_eap_drive.$(OBJEXT) ikev2_eap_emit.$(OBJEXT) \
	ikev2_drain.$(OBJEXT) \
	ikev2cfg_walk.$(OBJEXT) nattraversal.$(OBJEXT)
if USE_ADMIN
addtest_admin = admin.$(OBJEXT)
else
addtest_admin =
endif

LIBS = @LIBS@

man_MANS = iked.8
# libFuzzer harnesses (configure --enable-fuzz, clang).  Not run by make
# check: CI runs each for a bounded time (fuzz-smoke job).
if FUZZ
noinst_PROGRAMS = fuzz_ikev2_payloads fuzz_ikev1_parse
fuzz_ikev2_payloads_SOURCES = fuzz/fuzz_ikev2_payloads.c
fuzz_ikev2_payloads_LDADD = $(addtest_ikedsrc) $(LDADD)
fuzz_ikev2_payloads_LDFLAGS = -fsanitize=fuzzer
fuzz_ikev1_parse_SOURCES = fuzz/fuzz_ikev1_parse.c
fuzz_ikev1_parse_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/ikev1
fuzz_ikev1_parse_LDADD = $(addtest_ikedsrc) $(LDADD)
fuzz_ikev1_parse_LDFLAGS = -fsanitize=fuzzer
endif

EXTRA_DIST = fuzz/fuzz_common.h fuzz/corpus \
	evloop.h evloop_select.c evloop_epoll.c crypto_workers.h \
	ikedctl.c ikedctl.h ikedctl_unix.c admin.c admin.h samplecheck.sh rwsamplecheck.sh

# A per-directory `make install` used to relink against whatever libracoon
# was already installed (a stale .so with a drifted ABI).  Install the
# freshly built library first; the top-level install already orders lib
# before the daemons, so this is a no-op re-install there.
# Spelled through a variable: a literal 'install-sbinPROGRAMS:' rule here
# makes automake drop its own install rule, so the programs are never
# installed (the kernel lane caught exactly that).
racoon_install_sbin = install-sbinPROGRAMS
$(racoon_install_sbin): install-libracoon-first
install-libracoon-first:
	cd $(top_builddir)/../lib && $(MAKE) $(AM_MAKEFLAGS) install-libLTLIBRARIES
.PHONY: install-libracoon-first
