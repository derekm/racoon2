/*	$Id$	*/
/*
 * rcpfk_util.c — shared helpers for the rcpfk_* kernel-management ABI.
 *
 * These are pieces that were being re-implemented in each consumer.
 * Centralizing them removes duplicated, correctness-sensitive logic:
 *
 *  - rcpfk_satype_to_proto / rcpfk_proto_to_satype: the portable
 *    RCT_SATYPE_{AH,ESP,IPCOMP} <-> IP protocol number mapping used by the
 *    NETLINK_XFRM backend (sa.id.proto, xfrm tmpl proto) on install and
 *    decode. Kernel-independent; one definition to verify and test. NOTE:
 *    the PF_KEY backend does NOT use this map — it keeps its own
 *    rct2ipproto_satype() in rc_type.c, which errx(1)s on an unknown satype.
 *    Do not retarget PF_KEY at this helper: the ESP fallback below would turn
 *    a PF_KEY reject into an ESP install.
 *
 *  - rcpfk_nl_walk (Linux only): iterate a received netlink buffer of
 *    nlmsghdrs with the kernel's NLMSG_OK/NLMSG_NEXT safe length validation,
 *    dispatching each to a handler, and report a malformed message (bad
 *    nlmsg_len / truncated trailer) as -1 so the caller can log it.
 *
 *  - rcpfk_nl_recv (Linux only): read one netlink datagram and classify the
 *    outcome (data, retry, ENOBUFS overflow, MSG_TRUNC truncation, close,
 *    short read, error).
 *
 *  Both netlink helpers are used by every netlink consumer: iked/netlink.c
 *  (rtnetlink MOBIKE) and both XFRM read loops in if_xfrm.c (xfrm_read_one,
 *  xfrm_sync), which keep only their message-level logic (alignment copies,
 *  seq matching, resync). See rcpfk_nl.h.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdarg.h>
#include <netinet/in.h>

#include "racoon.h"

uint8_t
rcpfk_satype_to_proto(uint8_t satype)
{
	switch (satype) {
	case RCT_SATYPE_AH:
		return IPPROTO_AH;
	case RCT_SATYPE_IPCOMP:
		return IPPROTO_IPCOMP;
	case RCT_SATYPE_ESP:
	default:
		return IPPROTO_ESP;
	}
}

uint8_t
rcpfk_proto_to_satype(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_AH:
		return RCT_SATYPE_AH;
	case IPPROTO_IPCOMP:
		return RCT_SATYPE_IPCOMP;
	case IPPROTO_ESP:
	default:
		return RCT_SATYPE_ESP;
	}
}

/* returns the ABI version this libracoon was compiled with; a fresh consumer
 * expecting RCPFK_ABI_VERSION uses it to detect a stale .so at startup. */
int
rcpfk_abi_version(void)
{
	return RCPFK_ABI_VERSION;
}

#ifdef __linux__
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include <string.h>
#include "rcpfk_nl.h"

int
rcpfk_nl_recv(int fd, void *buf, size_t buflen, int flags, ssize_t *got)
{
	struct iovec iov;
	struct msghdr mh;
	ssize_t len;

	*got = 0;
	memset(&mh, 0, sizeof(mh));
	iov.iov_base = buf;
	iov.iov_len = buflen;
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;
	len = recvmsg(fd, &mh, flags);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return RCPFK_NLR_AGAIN;
		if (errno == ENOBUFS)
			return RCPFK_NLR_OVERFLOW;
		return RCPFK_NLR_ERROR;
	}
	*got = len;
	/* checked before the length: a truncated datagram has lost messages
	 * even when the part that fit parses cleanly */
	if (mh.msg_flags & MSG_TRUNC)
		return RCPFK_NLR_TRUNC;
	if (len == 0)
		return RCPFK_NLR_CLOSED;
	if ((size_t)len < sizeof(struct nlmsghdr))
		return RCPFK_NLR_SHORT;
	return RCPFK_NLR_DATA;
}

const char *
rcpfk_nlr_str(int r)
{
	switch (r) {
	case RCPFK_NLR_DATA:		return "data";
	case RCPFK_NLR_AGAIN:		return "retry";
	case RCPFK_NLR_OVERFLOW:	return "overflow (ENOBUFS)";
	case RCPFK_NLR_TRUNC:		return "datagram truncated (MSG_TRUNC)";
	case RCPFK_NLR_CLOSED:		return "socket closed";
	case RCPFK_NLR_SHORT:		return "short netlink read";
	default:			return "recv error";
	}
}

int
rcpfk_nl_walk(char *buf, size_t buflen,
    int (*fn)(struct nlmsghdr *, void *), void *arg)
{
	struct nlmsghdr *nlh;
	int len = (int)buflen;

	if ((size_t)len != buflen)
		return -1;
	if (buflen < sizeof(struct nlmsghdr))
		return -1;	/* nothing parseable: not a valid netlink result */
	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, len);
	     nlh = NLMSG_NEXT(nlh, len)) {
		int r = fn ? fn(nlh, arg) : 0;

		if (r < 0)
			return -1;
		if (r > 0)
			return r;	/* caller-requested early stop */
	}
	/* NLMSG_OK became false with `len` bytes still unread. NLMSG_NEXT has
	 * already consumed the 4-byte alignment padding of every real message,
	 * so a remainder of 0-3 is slack and is a normal end. A remainder of
	 * >= NLMSG_ALIGNTO (4) is the start of a truncated next header (or a
	 * header declaring a bad nlmsg_len), not padding: report it as
	 * malformed so the caller logs it. */
	if (len >= (int)NLMSG_ALIGNTO)
		return -1;
	return 0;
}
#endif /* __linux__ */
