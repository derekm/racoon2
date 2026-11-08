AUTOMAKE_OPTIONS = foreign

systemdsystemunitdir = @systemdsystemunitdir@

systemdsystemunit_DATA = \
	spmd.service spmd.socket \
	iked.service iked.socket \
	fwd-nat.service \
	kinkd.service \
	racoon2.target

# systemd instance drop-ins for the production iked/spmd setup
# (capture, core-backtrace, StateDirectory, XFRM crypto pre-step).
# capture.conf adds "-P /tmp/iked-native.pcap", which only exists when
# iked was built --enable-pcap (HAVE_LIBPCAP); installing it on a
# non-pcap build makes iked crash-loop at startup ("invalid option
# 'P'"), so the capture drop-in is installed only under the PCAP
# conditional (configure --enable-pcap).
systemdikeddconfdir = $(systemdsystemunitdir)/iked.service.d
systemdikeddconf_DATA = iked.service.d/state.conf iked.service.d/xfrm-crypto.conf
if PCAP
systemdikeddconf_DATA += iked.service.d/capture.conf
endif

systemdspmddconfdir = $(systemdsystemunitdir)/spmd.service.d
systemdspmddconf_DATA =
systemdikedsbindir = @racoon_sbindir@
systemdikedsbin_SCRIPTS =
if DEBUG_CORES
systemdikeddconf_DATA += iked.service.d/core.conf
systemdspmddconf_DATA += spmd.service.d/core.conf
systemdikedsbin_SCRIPTS += iked-core-bt
endif

TESTS = check-install.sh
AM_TESTS_ENVIRONMENT = DEBUG_CORES='@enable_debug_cores@' \
    UNITDIR='$(systemdsystemunitdir)' SBINDIR='@racoon_sbindir@' \
    MAKE='$(MAKE)'; export DEBUG_CORES UNITDIR SBINDIR MAKE;

EXTRA_DIST = check-install.sh iked-core-bt spmd.service.d/core.conf \
	iked.service.d/state.conf \
	spmd.service.in spmd.socket.in \
	iked.service.in iked.socket.in \
	fwd-nat.service.in \
	iked.service.d/core.conf.in iked.service.d/capture.conf.in \
	iked.service.d/xfrm-crypto.conf.in \
	kinkd.service.in \
	racoon2.target.in
