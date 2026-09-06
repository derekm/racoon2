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

#endif
