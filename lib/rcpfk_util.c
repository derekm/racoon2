/*	$Id$	*/
/*
 * rcpfk_util.c — shared helpers for the rcpfk_* kernel-management ABI.
 *
 * These are the pieces that were being re-implemented in each backend and in
 * the netlink consumers. Centralizing them removes duplicated,
 * correctness-sensitive logic (the same mapping must be right in every place:
 *
 *  - rcpfk_satype_to_proto / rcpfk_proto_to_satype: the portable
 *    RCT_SATYPE_{AH,ESP,IPCOMP} <-> IP protocol number mapping. Both the
 *    NETLINK_XFRM backend (sa.id.proto, xfrm tmpl proto) and the PF_KEY
 *    backend (sadb_x_ipsecrequest proto) need it. Kernel-independent; one
 *    definition to verify and test.
 *
 *  - rcpfk_nl_walk: iterate a received netlink buffer of nlmsghdrs with the
 *    kernel's NLMSG_OK/NLMSG_NEXT safe length validation, dispatching each to
 *    a handler. iked/netlink.c (rtnetlink MOBIKE) and the XFRM backend both
 *    raw-iterate nlmsghdrs; a shared walk keeps the malformed-input check in
 *    one place.
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

#ifdef __linux__
#include <linux/netlink.h>

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
		if (fn && fn(nlh, arg) < 0)
			return -1;
	}
	/* NLMSG_OK became false. If a whole header's worth (>= sizeof) is
	 * still left, the message declared a bad nlmsg_len (a length below a
	 * header, or a truncated body whose declared length exceeds what is
	 * present): report it as malformed so the caller logs it. Only the
	 * alignment padding (< sizeof) left after a real message, or the
	 * exact-end case, returns 0. */
	if (len >= (int)sizeof(struct nlmsghdr))
		return -1;
	return 0;
}
#endif /* __linux__ */
