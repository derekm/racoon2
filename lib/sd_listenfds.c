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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sd_listenfds.h"

#define RC_LISTEN_FDS_MAX	16

static int nlisten = -1;
static unsigned int used;

/*
 * Strict base-10 parse of a socket-activation metadata string.
 *
 * Returns 0 (treat as absent / inactive) on any of:
 *   - NULL or empty string
 *   - ERANGE (value out of long range), or a long that does not fit an int
 *   - negative values
 *   - trailing text or other malformed (non-digit) input, e.g. "3junk"
 *   - input that contains no digits at all
 * Otherwise stores the parsed value in *valp and returns 1.
 *
 * This replaces the old atoi() parsing, which silently accepted trailing
 * text ("3junk" -> 3) and int-wrapped huge LISTEN_FDS values (a huge value
 * wrapped negative and made rc_listenfds() silently return 0 via n <= 0,
 * masquerading as "inactive"). We reject all of that input deterministically
 * as "not socket-activated", so the activation metadata is handled with no
 * wrap-around and no trailing-text acceptance.
 *
 * Socket-activation policy (used by rc_listenfds):
 *   - LISTEN_PID must be a valid quoted pid equal to getpid(), else inactive.
 *   - LISTEN_FDS valid 1..16 -> active with that many descriptors (clamp
 *     > 16 to 16); malformed / trailing / overflow / negative / empty ->
 *     treated as absent (rc_listenfds returns 0, not active).
 */
static int
rc_parse_act_meta(const char *s, int *valp)
{
	char *end;
	long v;

	if (s == NULL || *s == '\0')
		return 0;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno == ERANGE || end == s || *end != '\0')
		return 0;

	/* strtol yields a long; keep only values representable as an int. */
	if (v < (long)INT_MIN || v > (long)INT_MAX)
		return 0;

	*valp = (int)v;
	if (*valp < 0)
		return 0;

	return 1;
}

int
rc_listenfds(void)
{
	const char *e;
	int n, i, nfds, pidv;

	if (nlisten >= 0)
		return nlisten;
	nlisten = 0;

	e = getenv("LISTEN_PID");
	if (!rc_parse_act_meta(e, &pidv) || (pid_t)pidv != getpid())
		return 0;

	e = getenv("LISTEN_FDS");
	if (!rc_parse_act_meta(e, &nfds))
		return 0;

	n = nfds;
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
