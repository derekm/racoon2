/*	$Id$	*/
/*
 * rcpfk_nl.h -- Linux netlink read/dispatch helpers shared by every netlink
 * consumer in the tree: the XFRM backend (lib/if_xfrm.c, request and
 * notification sockets) and iked's rtnetlink address monitor
 * (iked/netlink.c). Linux-only; not part of the portable if_pfkeyv2.h ABI.
 *
 * One reader (rcpfk_nl_recv) classifies every way a netlink datagram read
 * can go wrong, so no consumer can mistake a truncated or overflowed read
 * for a short-but-complete one. One walker (rcpfk_nl_walk) does the
 * NLMSG_OK/NLMSG_NEXT bounds-checked iteration.
 */
#ifndef RCPFK_NL_H
#define RCPFK_NL_H

#ifdef __linux__
#include <sys/types.h>
#include <linux/netlink.h>

/* rcpfk_nl_recv() results */
#define RCPFK_NLR_DATA		0	/* *got bytes of whole datagram in buf */
#define RCPFK_NLR_AGAIN		1	/* EAGAIN/EWOULDBLOCK/EINTR: retry later */
#define RCPFK_NLR_OVERFLOW	2	/* ENOBUFS: kernel dropped messages */
#define RCPFK_NLR_TRUNC		3	/* datagram larger than buf: tail lost */
#define RCPFK_NLR_CLOSED	4	/* zero-length read: socket closed */
#define RCPFK_NLR_SHORT		5	/* fewer bytes than one nlmsghdr */
#define RCPFK_NLR_ERROR		6	/* any other errno (left in errno) */

int rcpfk_nl_recv(int fd, void *buf, size_t buflen, int flags, ssize_t *got);
const char *rcpfk_nlr_str(int);

/*
 * Walk buf[0..buflen) calling fn for every message. fn returns 0 to go on,
 * < 0 to abort (walk returns -1) or > 0 to stop early (walk returns that
 * value). After a full walk, returns 0, or -1 when a 4+ byte remainder is a
 * truncated next header (bad nlmsg_len) rather than alignment padding.
 */
int rcpfk_nl_walk(char *buf, size_t buflen,
    int (*fn)(struct nlmsghdr *, void *), void *arg);
#endif /* __linux__ */

#endif /* RCPFK_NL_H */
