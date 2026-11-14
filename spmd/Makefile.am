

AM_CPPFLAGS =-DSYSCONFDIR=\"${sysconfdir}\"
#AM_CPPFLAGS += +=-DSADB_X_MIGRATE

sbin_PROGRAMS = spmd spmdctl
man_MANS = spmd.8 spmdctl.8

spmd_SOURCES = main.c dns.c udp.c query.c task.c signal.c shell.c utils.c cache.c spmd_pfkey.c fqdn_query.c
spmdctl_SOURCES = spmdctl.c

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

# RB-03/S6: spmd fails closed when the rc_vmem2str scratch fails.  All spmd
# objects but main.c, with link seams for the scratch converter, the config
# accessors and the PF_KEY/task sinks.  No socket or kernel state is used.
TESTS = spmdoomtest
check_PROGRAMS = spmdoomtest
spmdoomtest_SOURCES = spmdoomtest.c dns.c udp.c query.c task.c signal.c \
	shell.c utils.c cache.c spmd_pfkey.c fqdn_query.c
spmdoomtest_LDFLAGS = -Wl,--wrap=rc_vmem2str \
	-Wl,--wrap=rcf_get_selectorlist -Wl,--wrap=rcf_free_selector \
	-Wl,--wrap=rcf_spmd_resolver -Wl,--wrap=rcf_get_remotebyindex \
	-Wl,--wrap=rcpfk_init -Wl,--wrap=rcpfk_send_spddump \
	-Wl,--wrap=rcpfk_send_spdupdate -Wl,--wrap=rcpfk_handler \
	-Wl,--wrap=task_list_add
