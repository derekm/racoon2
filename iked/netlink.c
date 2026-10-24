/* $Id: netlink.c,v 1.3 2007/07/24 07:38:34 fukumoto Exp $ */

/*
 * Copyright (C) 2005 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include <stdio.h>		/* for BUFSIZ */
#include <errno.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "racoon.h"
#include "isakmp_impl.h"
#include "rtsock.h"
#include "debug.h"

static int rtnetlink_socket = -1;

/* Shared netlink read/walk helpers (lib/rcpfk_util.c), the same ones the
 * XFRM backend uses; Linux-only, so not in the portable rcpfk header. */
#include "rcpfk_nl.h"

static int
rtnl_dispatch(struct nlmsghdr *nlh, void *arg)
{
	(void)arg;
	TRACE((PLOGLOC, "netlink type %d\n", nlh->nlmsg_type));
	switch (nlh->nlmsg_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_NEWLINK:
	case RTM_DELLINK:
		isakmp_reopen();
		break;
	default:
		TRACE((PLOGLOC, "ignoring\n"));
		break;
	}
	return 0;
}

int
rtsock_init(void)
{
	struct sockaddr_nl snl;

	rtnetlink_socket = socket(PF_NETLINK, SOCK_RAW, 0 /*NETLINK_ROUTE6*/);
	TRACE((PLOGLOC, "rtnetlink_socket: %d\n", rtnetlink_socket));
	if (rtnetlink_socket == -1)
		return -1;

	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	snl.nl_pid = 0;
	snl.nl_groups = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;
	if (bind(rtnetlink_socket, (struct sockaddr *)&snl, sizeof(snl)) == -1)
		return -1;

	return 0;
}


int
rtsock_socket(void)
{
	return rtnetlink_socket;
}


void
rtsock_process(void)
{
	/* rtnetlink address/link notifications are small, but a burst of them
	 * is batched into one datagram: size for a full page group, and treat
	 * MSG_TRUNC / ENOBUFS as lost events, never as a complete read. */
	static char buf[32768];
	ssize_t len;
	int r;

	TRACE((PLOGLOC, "reading netlink socket\n"));
	r = rcpfk_nl_recv(rtnetlink_socket, buf, sizeof(buf), 0, &len);
	TRACE((PLOGLOC, "len %zd (%s)\n", len, rcpfk_nlr_str(r)));
	switch (r) {
	case RCPFK_NLR_DATA:
		break;
	case RCPFK_NLR_AGAIN:
		return;
	case RCPFK_NLR_OVERFLOW:
	case RCPFK_NLR_TRUNC:
		/* address events were lost: MOBIKE may miss a change until
		 * the next one arrives */
		plog(PLOG_INTWARN, PLOGLOC, 0,
		     "netlink: rtnetlink %s; address events lost\n",
		     rcpfk_nlr_str(r));
		/* a truncated datagram's head is not dispatched either: its
		 * last message is cut off, and a partial RTM_NEWADDR must not
		 * be acted on (same rule as the XFRM reader) */
		return;
	case RCPFK_NLR_ERROR:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "netlink: recv: %s\n", strerror(errno));
		return;
	default:
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "netlink: %s\n", rcpfk_nlr_str(r));
		return;
	}
	if (rcpfk_nl_walk(buf, (size_t)len, rtnl_dispatch, NULL) < 0)
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "netlink: malformed rtnetlink message\n");
}
