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
IKEV1_NATT_SRC = ikev1/ikev1_natt.c

IKEV2_SRC = ikev2.c ikev2_auth.c ikev2_child.c ikev2_cookie.c ikev2_notify.c ikev2_packet.c ikev2_payload.c ikev2_proposal.c ikev2_rekey.c ikev2_config.c ikev2_frag.c ikev2_resume.c ikev2_qcd.c
IKEV2_NATT_SRC = nattraversal.c

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

TESTS = eaytest evlooptest workerstest
check_PROGRAMS = eaytest evlooptest workerstest
eaytest_SOURCES = eaytest.c crypto_openssl.c str2val.c
workerstest_SOURCES = workerstest.c crypto_workers.c

LIBS = @LIBS@

man_MANS = iked.8
EXTRA_DIST = evloop.h evloop_select.c evloop_epoll.c crypto_workers.h \
	ikedctl.c ikedctl.h ikedctl_unix.c admin.c admin.h
