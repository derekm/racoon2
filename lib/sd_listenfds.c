/* $Id$ */
/*
 * systemd LISTEN_FDS without libsystemd.
 * Copyright (C) 2026 racoon2 contributors. Same BSD license as libracoon.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd_listenfds.h"

#define RC_LISTEN_FDS_MAX	16

static int nlisten = -1;
static unsigned int used;

int
rc_listenfds(void)
{
	const char *e;
	int n, i;

	if (nlisten >= 0)
		return nlisten;
	nlisten = 0;
	e = getenv("LISTEN_PID");
	if (e == NULL || (pid_t)atoi(e) != getpid())
		return 0;
	e = getenv("LISTEN_FDS");
	if (e == NULL)
		return 0;
	n = atoi(e);
	if (n <= 0)
		return 0;
	if (n > RC_LISTEN_FDS_MAX)
		n = RC_LISTEN_FDS_MAX;
	for (i = 0; i < n; i++) {
		int fd = RC_LISTEN_FDS_START + i;
		int fl = fcntl(fd, F_GETFD);

		if (fl >= 0)
			(void)fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
	}
	nlisten = n;
	return nlisten;
}

int
rc_take_listenfd(int family, int socktype, int port_host)
{
	int i, n, fd, stype;
	socklen_t slen;
	struct sockaddr_storage ss;

	n = rc_listenfds();
	for (i = 0; i < n; i++) {
		if (used & (1u << i))
			continue;
		fd = RC_LISTEN_FDS_START + i;
		slen = sizeof(stype);
		if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &stype, &slen) < 0)
			continue;
		if (stype != socktype)
			continue;
		slen = sizeof(ss);
		memset(&ss, 0, sizeof(ss));
		if (getsockname(fd, (struct sockaddr *)&ss, &slen) < 0)
			continue;
		if (family && ss.ss_family != family)
			continue;
		if (port_host != 0) {
			in_port_t p = 0;

			if (ss.ss_family == AF_INET)
				p = ntohs(((struct sockaddr_in *)&ss)->sin_port);
#ifdef AF_INET6
			else if (ss.ss_family == AF_INET6)
				p = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
#endif
			else
				continue;
			if ((int)p != port_host)
				continue;
		}
		used |= 1u << i;
		return fd;
	}
	(void)errno;
	return -1;
}
