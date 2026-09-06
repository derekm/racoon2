/* $Id$ */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/epoll.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "evloop.h"

static int epfd = -1;
static fd_set live;
static int live_inited;

int
evloop_init(void)
{
	if (epfd >= 0)
		return 0;
	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0)
		epfd = epoll_create(16);
	if (epfd < 0)
		return -1;
	FD_ZERO(&live);
	live_inited = 1;
	return 0;
}

void
evloop_fini(void)
{
	if (epfd >= 0) {
		close(epfd);
		epfd = -1;
	}
	if (live_inited)
		FD_ZERO(&live);
	live_inited = 0;
}

static int
ctl_add(int fd, struct epoll_event *ev)
{
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, ev) < 0) {
		if (errno != EEXIST)
			return -1;
		if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, ev) < 0)
			return -1;
	}
	return 0;
}

int
evloop_wait(int nfds, fd_set *rfds, struct timeval *timeout)
{
	struct epoll_event ev, evs[64];
	int i, n, ms, max;
	fd_set want;

	if (epfd < 0 && evloop_init() < 0)
		return select(nfds, rfds, NULL, NULL, timeout);

	want = *rfds;
	max = nfds < FD_SETSIZE ? nfds : FD_SETSIZE;
	for (i = 0; i < max; i++) {
		int need = FD_ISSET(i, &want);
		int have = live_inited && FD_ISSET(i, &live);

		ev.events = EPOLLIN;
		ev.data.fd = i;
		if (need) {
			/*
			 * Close/reuse (isakmp_reopen) can keep the fd
			 * number while the kernel dropped the old
			 * epoll entry. MOD then ADD on failure.
			 */
			if (have) {
				if (epoll_ctl(epfd, EPOLL_CTL_MOD, i, &ev) < 0) {
					FD_CLR(i, &live);
					if (ctl_add(i, &ev) < 0)
						continue;
					FD_SET(i, &live);
				}
			} else if (ctl_add(i, &ev) == 0) {
				FD_SET(i, &live);
			}
		} else if (have) {
			(void)epoll_ctl(epfd, EPOLL_CTL_DEL, i, NULL);
			FD_CLR(i, &live);
		}
	}

	if (timeout) {
		long long ms64 = (long long)timeout->tv_sec * 1000
		    + timeout->tv_usec / 1000;
		if (ms64 < 0)
			ms64 = 0;
		if (ms64 > INT_MAX)
			ms64 = INT_MAX;
		ms = (int)ms64;
	} else
		ms = -1;
	n = epoll_wait(epfd, evs, 64, ms);
	FD_ZERO(rfds);
	if (n < 0)
		return n;
	for (i = 0; i < n; i++) {
		int fd = evs[i].data.fd;

		if (fd >= 0 && fd < FD_SETSIZE)
			FD_SET(fd, rfds);
	}
	return n;
}
