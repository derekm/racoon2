/* $Id$ */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "evloop.h"

int
evloop_init(void)
{
	return 0;
}

void
evloop_fini(void)
{
}

int
evloop_wait(int nfds, fd_set *rfds, struct timeval *timeout)
{
	return evloop_wait_rw(nfds, rfds, NULL, timeout);
}

int
evloop_wait_rw(int nfds, fd_set *rfds, fd_set *wfds, struct timeval *timeout)
{
	return select(nfds, rfds, wfds, NULL, timeout);
}
