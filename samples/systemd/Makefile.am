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
if PCAP
systemdikeddconf_DATA = iked.service.d/core.conf iked.service.d/capture.conf \
	iked.service.d/state.conf iked.service.d/xfrm-crypto.conf
else
systemdikeddconf_DATA = iked.service.d/core.conf \
	iked.service.d/state.conf iked.service.d/xfrm-crypto.conf
endif

systemdspmddconfdir = $(systemdsystemunitdir)/spmd.service.d
systemdspmddconf_DATA = spmd.service.d/core.conf

systemdikedsbindir = @racoon_sbindir@
systemdikedsbin_SCRIPTS = iked-core-bt

EXTRA_DIST = \
	spmd.service.in spmd.socket.in \
	iked.service.in iked.socket.in \
	fwd-nat.service.in \
	iked.service.d/core.conf.in iked.service.d/capture.conf.in \
	iked.service.d/xfrm-crypto.conf.in \
	kinkd.service.in \
	racoon2.target.in
