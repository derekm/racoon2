# $Id: Makefile.in,v 1.11 2007/12/12 07:12:22 mk Exp $

sbin_SCRIPTS=pskgen
man_MANS=pskgen.8

install-exec-hook:
	$(INSTALL) -d $(DESTDIR)$(sysconfdir)
	tr -d '\r' < autogen.spmd.pwd > autogen.spmd.pwd.lf && mv autogen.spmd.pwd.lf autogen.spmd.pwd
	if test -f $(DESTDIR)$(sysconfdir)/spmd.pwd; then :; else \
		sh ./autogen.spmd.pwd; \
	fi
