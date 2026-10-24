/* $Id$ */
/*
 * Event wait XOR: select vs epoll. Same rcpfk/RTSOCK pattern.
 */
#ifndef _IKED_EVLOOP_H
#define _IKED_EVLOOP_H

#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# include <time.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#endif
#include <sys/select.h>

int evloop_init(void);
void evloop_fini(void);
/* Drop-in for select(nfds, rfds, NULL, NULL, timeout). */
int evloop_wait(int nfds, fd_set *rfds, struct timeval *timeout);
/*
 * select(nfds, rfds, wfds, NULL, timeout).  wfds may be NULL.  A fd set in
 * BOTH rfds and wfds is waited on for read AND write; on return each set is
 * overwritten with the fds actually ready in that direction.  This is what
 * a non-blocking TCP connect/partial-write (IKE-over-TCP, RFC 8229) needs;
 * the read-only evloop_wait() is evloop_wait_rw(nfds, rfds, NULL, timeout).
 */
int evloop_wait_rw(int nfds, fd_set *rfds, fd_set *wfds,
		   struct timeval *timeout);

#endif
