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
EXTRA_DIST = if_xfrm.c if_pfkeyv2.c if_userspace.c
libracoon_la_LIBADD = $(LTLIBOBJS) -lpcap
TESTS = sample kmtest
check_PROGRAMS = sample kmtest
sample_SOURCES = sample.c
sample_LDADD = libracoon.la
# Extensionless tests ignore per-test *_LOG_COMPILER; the wrapper passes
# the config file to sample and is a no-op for kmtest (main(void)).
LOG_COMPILER = $(SHELL) $(srcdir)/sample-wrapper.sh
AM_TESTS_ENVIRONMENT = R2_SAMPLE_CONF='$(abs_srcdir)/../samples/libsample.conf'; export R2_SAMPLE_CONF;
kmtest_SOURCES = kmtest.c kmtest_backend.c

BUILT_SOURCES = cfparse.h
