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
systemdikeddconfdir = $(systemdsystemunitdir)/iked.service.d
systemdikeddconf_DATA = iked.service.d/core.conf iked.service.d/capture.conf \
	iked.service.d/state.conf iked.service.d/xfrm-crypto.conf

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
