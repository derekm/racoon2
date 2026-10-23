/* $Id$ */
/*
 * Linux NETLINK_XFRM SAD/SPD backend.
 * Same rcpfk_* ABI as if_pfkeyv2.c (XOR compile via --with-km-backend).
 * Socket/bind/recv loop follows iked/netlink.c and iked/parse_coa.c.
 *
 * Copyright (C) 2003-2008 WIDE Project.
 * Copyright (C) 2026 racoon2 contributors.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef __linux__
#error if_xfrm.c is the Linux NETLINK_XFRM backend; use if_pfkeyv2.c elsewhere
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <poll.h>
#include <time.h>

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#ifdef ENABLE_NATT
#include <linux/udp.h>
#endif

#include <netinet/in.h>
#include <net/if.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "racoon.h"

/* Bounded retries for an xfrm resync dump that keeps overflowing the
 * request socket mid-dump (sustained event storm); beyond this the
 * resync gives up with EAGAIN instead of recursing without bound. */
#define XFRM_RESYNC_MAX_RETRY	5

#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif
#ifndef IPPROTO_IPCOMP
#ifdef IPPROTO_COMP
#define IPPROTO_IPCOMP IPPROTO_COMP
#else
#define IPPROTO_IPCOMP 108
#endif
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef XFRM_INF
#define XFRM_INF (~(__u64)0)
#endif
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
#ifndef NETLINK_ADD_MEMBERSHIP
#define NETLINK_ADD_MEMBERSHIP 1
#endif
#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 33
#endif

#define XFRM_BUFLEN		4096
#define XFRM_RCVBUFLEN		(128 * 1024)	/* one recv() worth of messages */

/*
 * Netlink socket model (rdratlos/racoon-ipsec-tools RFC 0002 "KernelPaws"
 * §socket model, §error classification, §buffer management; ideas only,
 * no code copied):
 *
 *  - xfrm_req_fd: bound with no multicast groups.  Every request goes out
 *    here, so the only things that can arrive on it are unicast replies
 *    (ACKs, ALLOCSPI/GETSA bodies, dumps) addressed to our port id.
 *  - xfrm_ntf_fd: non-blocking, joins ACQUIRE/EXPIRE/SA/POLICY/MIGRATE/
 *    MAPPING one group per NETLINK_ADD_MEMBERSHIP call (MIGRATE and
 *    MAPPING have no legacy XFRMGRP_* bit).  Kernel events and the
 *    multicast echo of our own ops arrive here; an echo carries our port
 *    id in nlmsg_pid.
 *  - rc->so (what callers select()/poll() on) is an epoll fd watching
 *    both, so the rcpfk_* ABI is unchanged.
 *
 * ENOBUFS on the notify socket means the kernel dropped events (a lost
 * EXPIRE strands an SA): drain to EAGAIN, then dump the SPD and SAD on
 * the request socket and hand the result to cb_spddump/cb_sadump/
 * cb_resync.  ENOBUFS on the request socket also drops the pending op.
 */
#define XFRM_SOCKBUF		(256 * 1024)
#define XFRM_REPLY_TIMEOUT_MS	5000
#define XFRM_EBUSY_RETRIES	3
#define XFRM_RESYNC_SEQ_BASE	0xf0000000u

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

uint32_t rc_spirange_min = 0x00000100;
uint32_t rc_spirange_max = 0x0fffffff;

static struct rcpfk_cb *cb;
static pid_t pid;
static int f_noharm;
static uint32_t xfrm_seq;
static int pending_type;	/* XFRM_MSG_* we last sent, or 0 */
static uint32_t pending_seq;
static uint32_t pending_dump_seq;	/* seq of in-flight SPD dump, or 0 */
static uint32_t pending_spi;
static uint8_t pending_satype;
static uint8_t pending_samode;
static struct sockaddr_storage pending_src, pending_dst;
static int pending_has_addrs;
static char *xfrm_rcvbuf;
/* 8-byte aligned copies of the messages of one recv (see xfrm_read_one) */
static char *xfrm_alnbuf;
static int xfrm_req_fd = -1;
static int xfrm_ntf_fd = -1;
static int xfrm_ep_fd = -1;
static uint32_t resync_spd_seq;		/* in-flight resync dumps, or 0 */
static uint32_t resync_sa_seq;
static uint32_t resync_count;
static char pending_msg[XFRM_BUFLEN];	/* last request, for EBUSY retry */
static size_t pending_msglen;
static int pending_retries;
static int xfrm_need_resync;

/* counters, exported for the unit test and for debugging */
unsigned long xfrm_stat_enobufs;
unsigned long xfrm_stat_resync;
unsigned long xfrm_stat_idempotent;
unsigned long xfrm_stat_ebusy_retry;
unsigned long xfrm_stat_stale_reply;
unsigned long xfrm_stat_late_error;

#ifdef XFRM_UNITTEST
/* The unit test (lib/xfrmnltest.c) replaces the kernel with socketpairs
 * and can make the next recv() on one fd fail with ENOBUFS. */
int xfrm_test_enobufs_fd = -1;
static ssize_t
xfrm_recv(int fd, void *buf, size_t len, int flags)
{
	if (fd == xfrm_test_enobufs_fd) {
		xfrm_test_enobufs_fd = -1;
		errno = ENOBUFS;
		return -1;
	}
	return recv(fd, buf, len, flags);
}
#else
#define xfrm_recv recv
#endif

struct xfrm_algmap {
	int rct;
	const char *name;
	unsigned int trunc_bits;	/* 0 = use XFRMA_ALG_AUTH / crypt */
};

static const struct xfrm_algmap enc_map[] = {
	{ RCT_ALG_DES_CBC,		"cbc(des)",		0 },
	{ RCT_ALG_DES3_CBC,		"cbc(des3_ede)",	0 },
	{ RCT_ALG_NULL_ENC,		"ecb(cipher_null)",	0 },
	{ RCT_ALG_RIJNDAEL_CBC,		"cbc(aes)",		0 },
	{ RCT_ALG_AES128_CBC,		"cbc(aes)",		0 },
	{ RCT_ALG_AES192_CBC,		"cbc(aes)",		0 },
	{ RCT_ALG_AES256_CBC,		"cbc(aes)",		0 },
	{ RCT_ALG_AES_CTR,		"rfc3686(ctr(aes))",	0 },
	{ RCT_ALG_CAST128_CBC,		"cbc(cast5)",		0 },
	{ RCT_ALG_BLOWFISH_CBC,		"cbc(blowfish)",	0 },
	{ 0, NULL, 0 }
};

#ifndef XFRMA_ALG_AEAD
#define XFRMA_ALG_AEAD 18
#endif

/* RFC 4303 §2.2.1 ESN kernel plumbing.  Fedora/Ubuntu default kernels
 * ship XFRM_STATE_ESN and XFRMA_REPLAY_ESN_VAL; guard so a narrower
 * userspace header still compiles (the kernel rejects the ESN flag if
 * the corresponding replay-ESN attr is absent, so both must go out). */
#ifndef XFRM_STATE_ESN
#define XFRM_STATE_ESN 128
#endif
#ifndef XFRMA_REPLAY_ESN_VAL
#define XFRMA_REPLAY_ESN_VAL 23
#endif

struct xfrm_aeadmap {
	int rct;
	const char *name;
	unsigned int icv_bits;
};

static const struct xfrm_aeadmap aead_map[] = {
	{ RCT_ALG_AES_GCM,	"rfc4106(gcm(aes))",	128 },
	{ RCT_ALG_AES_GCM8,	"rfc4106(gcm(aes))",	64 },
	{ RCT_ALG_AES_GCM12,	"rfc4106(gcm(aes))",	96 },
	{ RCT_ALG_AES_CCM,	"rfc4309(ccm(aes))",	96 },
	{ RCT_ALG_AES_CCM8,	"rfc4309(ccm(aes))",	64 },
	{ RCT_ALG_AES_CCM16,	"rfc4309(ccm(aes))",	128 },
	/* ChaCha20-Poly1305 (RFC 7634).  The kernel name is the rfc7539esp
	 * template with a COMMA (rfc7539esp(chacha20,poly1305)); the
	 * chacha20poly1305 base name binds in AF_ALG but XFRM only resolves
	 * the esp template.  Key is 32 octets + 4-octet salt (nonce_len),
	 * ICV is fixed 128 bits.  The module autoloads via cryptomgr when
	 * the first SA is installed. */
	{ RCT_ALG_CHACHA20_POLY1305, "rfc7539esp(chacha20,poly1305)", 128 },
	{ 0, NULL, 0 }
};

static const struct xfrm_algmap auth_map[] = {
	{ RCT_ALG_NON_AUTH,		"digest_null",		0 },
	{ RCT_ALG_HMAC_MD5,		"hmac(md5)",		96 },
	{ RCT_ALG_HMAC_SHA1,		"hmac(sha1)",		96 },
	{ RCT_ALG_HMAC_SHA2_256,	"hmac(sha256)",		128 },
	{ RCT_ALG_HMAC_SHA2_384,	"hmac(sha384)",		192 },
	{ RCT_ALG_HMAC_SHA2_512,	"hmac(sha512)",		256 },
	{ RCT_ALG_AES_XCBC,		"xcbc(aes)",		96 },
	{ RCT_ALG_AES_CMAC,		"cmac(aes)",		96 },
	{ RCT_ALG_HMAC_RIPEMD160,	"hmac(rmd160)",		96 },
	{ 0, NULL, 0 }
};

static const struct xfrm_algmap *
alg_lookup(const struct xfrm_algmap *m, int rct)
{
	for (; m->name != NULL; m++) {
		if (m->rct == rct)
			return m;
	}
	return NULL;
}

static const struct xfrm_aeadmap *
aead_lookup(int rct)
{
	const struct xfrm_aeadmap *m;

	for (m = aead_map; m->name != NULL; m++) {
		if (m->rct == rct)
			return m;
	}
	return NULL;
}

static void
xfrm_seterror(struct rcpfk_msg *rc, int eno, const char *fmt, ...)
{
	va_list ap;

	rc->eno = eno;
	va_start(ap, fmt);
	vsnprintf(rc->estr, sizeof(rc->estr), fmt, ap);
	va_end(ap);
}

static void
pending_clear(void)
{
	pending_type = 0;
	pending_seq = 0;
	pending_has_addrs = 0;
	pending_msglen = 0;
	pending_retries = 0;
}

static void
pending_set(struct rcpfk_msg *rc, int type, uint32_t seq)
{
	/* NOTE: overlapping ops DO occur (the xfrmnltest harness proves a
	 * second pending_set can fire while one op is outstanding). A hard
	 * assert here crashes on that. The real defect is that a second op
	 * overwrites the single pending slot and the first op's reply is
	 * then not "ours", silently dropping its callback. Tracked: needs an
	 * outstanding-op queue keyed by seq (see plan 2026-10-23_xfrm-review-
	 * followups KR-9) instead of one slot. */
	pending_type = type;
	pending_seq = seq;
	pending_spi = rc->spi;
	pending_satype = rc->satype;
	pending_samode = rc->samode;
	pending_has_addrs = 0;
	if (rc->sa_src && rc->sa_dst) {
		memset(&pending_src, 0, sizeof(pending_src));
		memset(&pending_dst, 0, sizeof(pending_dst));
		memcpy(&pending_src, rc->sa_src, (size_t)rcs_getsalen(rc->sa_src));
		memcpy(&pending_dst, rc->sa_dst, (size_t)rcs_getsalen(rc->sa_dst));
		pending_has_addrs = 1;
	}
}

static void
pending_fill_rc(struct rcpfk_msg *rc)
{
	rc->seq = pending_seq;
	rc->spi = pending_spi;
	rc->satype = pending_satype;
	rc->samode = pending_samode;
	if (pending_has_addrs) {
		memcpy(&rc->sa_src_storage, &pending_src, sizeof(pending_src));
		memcpy(&rc->sa_dst_storage, &pending_dst, sizeof(pending_dst));
		rc->sa_src = (void *)&rc->sa_src_storage;
		rc->sa_dst = (void *)&rc->sa_dst_storage;
	}
}

static int
sa_to_xaddr(const struct sockaddr *sa, xfrm_address_t *xa, uint16_t *family)
{
	memset(xa, 0, sizeof(*xa));
	if (sa == NULL)
		return -1;
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const void *)sa;

		xa->a4 = sin->sin_addr.s_addr;
		if (family)
			*family = AF_INET;
		return 0;
	}
#ifdef INET6
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const void *)sa;

		memcpy(xa->a6, &sin6->sin6_addr, 16);
		if (family)
			*family = AF_INET6;
		return 0;
	}
#endif
	return -1;
}

static int
xaddr_to_sa(uint16_t family, const xfrm_address_t *xa, uint16_t port,
    struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof(*ss));
	if (family == AF_INET) {
		struct sockaddr_in *sin = (void *)ss;

		sin->sin_family = AF_INET;
		sin->sin_port = port;
		sin->sin_addr.s_addr = xa->a4;
#ifdef HAVE_SA_LEN
		sin->sin_len = sizeof(*sin);
#endif
		return 0;
	}
#ifdef INET6
	if (family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (void *)ss;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = port;
		memcpy(&sin6->sin6_addr, xa->a6, 16);
#ifdef HAVE_SA_LEN
		sin6->sin6_len = sizeof(*sin6);
#endif
		return 0;
	}
#endif
	return -1;
}

static uint8_t
satype_to_proto(uint8_t satype)
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

static uint8_t
proto_to_satype(uint8_t proto)
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

static uint8_t
dir_to_x(uint8_t dir)
{
	switch (dir) {
	case RCT_DIR_INBOUND:
		return XFRM_POLICY_IN;
	case RCT_DIR_FWD:
		return XFRM_POLICY_FWD;
	case RCT_DIR_OUTBOUND:
	default:
		return XFRM_POLICY_OUT;
	}
}

static uint8_t
x_to_dir(uint8_t xdir)
{
	switch (xdir) {
	case XFRM_POLICY_IN:
		return RCT_DIR_INBOUND;
	case XFRM_POLICY_FWD:
		return RCT_DIR_FWD;
	case XFRM_POLICY_OUT:
	default:
		return RCT_DIR_OUTBOUND;
	}
}

static uint8_t
mode_to_x(uint8_t samode)
{
	return samode == RCT_IPSM_TUNNEL ? XFRM_MODE_TUNNEL : XFRM_MODE_TRANSPORT;
}

static uint8_t
x_to_mode(uint8_t mode)
{
	return mode == XFRM_MODE_TUNNEL ? RCT_IPSM_TUNNEL : RCT_IPSM_TRANSPORT;
}

static uint64_t
lft_bytes_or_inf(uint64_t v)
{
	return v == 0 || v == RC_LIFETIME_INFINITE ? XFRM_INF : v;
}

static int
xfrm_addattr(struct nlmsghdr *n, size_t maxlen, int type,
    const void *data, size_t alen)
{
	size_t len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return -1;
	rta = (void *)((char *)n + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = (unsigned short)len;
	if (alen && data)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

static int
xfrm_set_rcvbuf(int fd, int size)
{
	/* SO_RCVBUFFORCE ignores rmem_max but needs CAP_NET_ADMIN, which
	 * iked/spmd have; unprivileged (tests, -n) falls back. */
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &size,
	    sizeof(size)) == 0)
		return 0;
	return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
}

static int
xfrm_socket(int nonblock)
{
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd == -1)
		return -1;
#if SOCK_CLOEXEC == 0
	{
		int fl = fcntl(fd, F_GETFD);
		if (fl >= 0)
			(void)fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
	}
#endif
	if (nonblock) {
		int fl = fcntl(fd, F_GETFL);
		if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) {
			close(fd);
			return -1;
		}
	}
	return fd;
}

static void
xfrm_close_all(void)
{
	if (xfrm_ep_fd >= 0)
		close(xfrm_ep_fd);
	if (xfrm_req_fd >= 0)
		close(xfrm_req_fd);
	if (xfrm_ntf_fd >= 0)
		close(xfrm_ntf_fd);
	xfrm_ep_fd = xfrm_req_fd = xfrm_ntf_fd = -1;
}

static int
xfrm_epoll_setup(struct rcpfk_msg *rc)
{
	struct epoll_event ev;

	xfrm_ep_fd = epoll_create1(EPOLL_CLOEXEC);
	if (xfrm_ep_fd == -1)
		return -1;
	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = xfrm_req_fd;
	if (epoll_ctl(xfrm_ep_fd, EPOLL_CTL_ADD, xfrm_req_fd, &ev) == -1)
		return -1;
	ev.data.fd = xfrm_ntf_fd;
	if (epoll_ctl(xfrm_ep_fd, EPOLL_CTL_ADD, xfrm_ntf_fd, &ev) == -1)
		return -1;
	rc->so = xfrm_ep_fd;
	return 0;
}

static int
xfrm_open(struct rcpfk_msg *rc)
{
	static const struct {
		int grp;
		const char *name;
		int required;
	} groups[] = {
		/* enumerators, never #ifdef'd (RFC 0002 rule) */
		{ XFRMNLGRP_ACQUIRE,	"ACQUIRE",	1 },
		{ XFRMNLGRP_EXPIRE,	"EXPIRE",	1 },
		{ XFRMNLGRP_SA,		"SA",		1 },
		{ XFRMNLGRP_POLICY,	"POLICY",	1 },
		{ XFRMNLGRP_MIGRATE,	"MIGRATE",	0 },
		{ XFRMNLGRP_MAPPING,	"MAPPING",	0 },
	};
	struct sockaddr_nl local;
	int sz = XFRM_SOCKBUF;
	socklen_t alen;
	size_t i;

	xfrm_close_all();
	rc->so = -1;
	xfrm_req_fd = xfrm_socket(0);
	xfrm_ntf_fd = xfrm_socket(1);
	if (xfrm_req_fd == -1 || xfrm_ntf_fd == -1)
		goto fail;
	if (xfrm_set_rcvbuf(xfrm_req_fd, sz) == -1 ||
	    setsockopt(xfrm_req_fd, SOL_SOCKET, SO_SNDBUF, &sz,
	    sizeof(sz)) == -1 ||
	    xfrm_set_rcvbuf(xfrm_ntf_fd, sz) == -1)
		goto fail;
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = 0;
	if (bind(xfrm_req_fd, (struct sockaddr *)&local, sizeof(local)) == -1)
		goto fail;
	alen = sizeof(local);
	if (getsockname(xfrm_req_fd, (struct sockaddr *)&local, &alen) == -1)
		goto fail;
	pid = (pid_t)local.nl_pid;
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	if (bind(xfrm_ntf_fd, (struct sockaddr *)&local, sizeof(local)) == -1)
		goto fail;
	for (i = 0; i < sizeof(groups) / sizeof(groups[0]); i++) {
		int g = groups[i].grp;

		if (setsockopt(xfrm_ntf_fd, SOL_NETLINK,
		    NETLINK_ADD_MEMBERSHIP, &g, sizeof(g)) == 0)
			continue;
		if (groups[i].required)
			goto fail;
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "xfrm: cannot join XFRMNLGRP_%s: %s\n",
		    groups[i].name, strerror(errno));
	}
	if (xfrm_epoll_setup(rc) == -1)
		goto fail;
	return 0;
fail:
	xfrm_seterror(rc, errno, "%s", strerror(errno));
	xfrm_close_all();
	rc->so = -1;
	return -1;
}

#ifdef XFRM_UNITTEST
/* Attach caller-made fds in place of the kernel sockets. */
int
xfrm_test_open(struct rcpfk_msg *rc, struct rcpfk_cb *cb0, int reqfd,
    int ntffd, uint32_t portid)
{
	xfrm_close_all();
	xfrm_req_fd = reqfd;
	xfrm_ntf_fd = ntffd;
	pid = (pid_t)portid;
	cb = cb0;
	pending_clear();
	pending_dump_seq = resync_spd_seq = resync_sa_seq = 0;
	resync_count = 0;
	xfrm_need_resync = 0;
	return xfrm_epoll_setup(rc);
}
#endif

static int
xfrm_nl_send(struct rcpfk_msg *rc, struct nlmsghdr *n)
{
	ssize_t nsent;

	/* no address: an unconnected netlink socket sends to the kernel
	 * (nl_pid 0) by default, and the unit test's socketpair accepts it */
	nsent = send(xfrm_req_fd, n, n->nlmsg_len, 0);
	if (nsent < 0 || (size_t)nsent != n->nlmsg_len) {
		xfrm_seterror(rc, errno, "%s", strerror(errno));
		if (pending_type != 0 && pending_seq == n->nlmsg_seq)
			pending_clear();
		return -1;
	}
	/* keep a copy of the pending op so an EBUSY reply can resend it */
	if (pending_type != 0 && pending_seq == n->nlmsg_seq &&
	    n->nlmsg_len <= sizeof(pending_msg) && (void *)n != pending_msg) {
		memcpy(pending_msg, n, n->nlmsg_len);
		pending_msglen = n->nlmsg_len;
	}
	return 0;
}

static int
xfrm_resend_pending(void)
{
	if (pending_msglen == 0)
		return -1;
	if (send(xfrm_req_fd, pending_msg, pending_msglen, 0) !=
	    (ssize_t)pending_msglen)
		return -1;
	return 0;
}

static void
fill_selector(struct xfrm_selector *sel, const struct sockaddr *src,
    const struct sockaddr *dst, uint8_t pref_src, uint8_t pref_dst,
    uint8_t ul_proto, uint32_t flags)
{
	uint16_t family = AF_INET;
	in_port_t *sp, *dp;

	memset(sel, 0, sizeof(*sel));
	if (src)
		sa_to_xaddr(src, &sel->saddr, &family);
	if (dst)
		sa_to_xaddr(dst, &sel->daddr, &family);
	sel->family = family;
	sel->prefixlen_s = pref_src ? pref_src : 0;
	sel->prefixlen_d = pref_dst ? pref_dst : 0;
	if (ul_proto == RC_PROTO_ANY)
		sel->proto = 0;
	else
		sel->proto = ul_proto;
	if ((flags & PFK_FLAG_NOPORTS) == 0 && src && dst) {
		sp = rcs_getsaport(src);
		dp = rcs_getsaport(dst);
		if (sp && *sp) {
			sel->sport = *sp;
			sel->sport_mask = 0xffff;
		}
		if (dp && *dp) {
			sel->dport = *dp;
			sel->dport_mask = 0xffff;
		}
	}
}

static void
fill_lft(struct xfrm_lifetime_cfg *lft, const struct rcpfk_msg *rc)
{
	memset(lft, 0, sizeof(*lft));
	lft->soft_byte_limit = lft_bytes_or_inf(rc->lft_soft_bytes);
	lft->hard_byte_limit = lft_bytes_or_inf(rc->lft_hard_bytes);
	lft->soft_packet_limit = XFRM_INF;
	lft->hard_packet_limit = XFRM_INF;
	/*
	 * Byte/packet 0 → XFRM_INF. Time 0 must stay 0: the kernel
	 * timer is `if (hard_*_expires_seconds)` and XFRM_INF (~0ULL)
	 * is signed −1, so tmo ≤ 0 and the SA hard-expires in ~1s.
	 * iproute2 leaves add/use expires at 0 for unlimited.
	 */
	lft->soft_add_expires_seconds = rc->lft_soft_time;
	lft->hard_add_expires_seconds = rc->lft_hard_time;
	lft->soft_use_expires_seconds = 0;
	lft->hard_use_expires_seconds = 0;
}

static int
fill_usersa(struct xfrm_usersa_info *sa, struct rcpfk_msg *rc)
{
	uint16_t family = AF_INET;

	memset(sa, 0, sizeof(*sa));
	if (sa_to_xaddr(rc->sa_dst, &sa->id.daddr, &family) < 0 ||
	    sa_to_xaddr(rc->sa_src, &sa->saddr, NULL) < 0) {
		xfrm_seterror(rc, EINVAL, "SA addresses required");
		return -1;
	}
	sa->family = family;
	sa->id.spi = rc->spi;
	sa->id.proto = satype_to_proto(rc->satype);
	sa->mode = mode_to_x(rc->samode);
	sa->reqid = rc->reqid;
	sa->replay_window = rc->wsize;
	sa->flags = 0;
	/* RFC 7296 §3.3.2 / RFC 4303 §2.2.1 ESN: portable SADB_X_SAFLAGS_ESN
	 * bit (0x400) set by the IKE layer maps onto XFRM_STATE_ESN.
	 * The window lives in XFRMA_REPLAY_ESN_VAL; a non-zero usersa
	 * replay_window beside that attr is not what iproute2 sends. */
	if (rc->saflags & SADB_X_SAFLAGS_ESN) {
		sa->flags |= XFRM_STATE_ESN;
		sa->replay_window = 0;
	}
	fill_lft(&sa->lft, rc);

	/*
	 * Tunnel SAs: Cilium/kernel practice is sel 0/0; policy tmpl+reqid
	 * binds the SA. iked does not set sp_* on the IKE path, so using
	 * outer /32 here would block v6-in-v4. If sp_* is present, use it
	 * as the inner selector.
	 */
	if (rc->samode == RCT_IPSM_TUNNEL) {
		memset(&sa->sel, 0, sizeof(sa->sel));
		if (rc->sp_src && rc->sp_dst)
			fill_selector(&sa->sel, rc->sp_src, rc->sp_dst,
			    rc->pref_src, rc->pref_dst, rc->ul_proto, rc->flags);
		else
			sa->sel.family = family;
	} else {
		fill_selector(&sa->sel, rc->sa_src, rc->sa_dst,
		    rc->pref_src, rc->pref_dst,
		    rc->ul_proto, rc->flags);
	}
	return 0;
}

static int
add_aead_attr(struct nlmsghdr *n, size_t maxlen, struct rcpfk_msg *rc)
{
	const struct xfrm_aeadmap *m;
	size_t klen, alen;
	struct {
		char alg_name[64];
		unsigned int alg_key_len;
		unsigned int alg_icv_len;
		char alg_key[256];
	} aead;

	m = aead_lookup(rc->enctype);
	if (m == NULL) {
		xfrm_seterror(rc, EOPNOTSUPP, "aead alg %d not mapped",
		    rc->enctype);
		return -1;
	}
	klen = rc->enckeylen;
	if (klen > sizeof(aead.alg_key)) {
		xfrm_seterror(rc, EINVAL, "aead key too long");
		return -1;
	}
	memset(&aead, 0, sizeof(aead));
	strncpy(aead.alg_name, m->name, sizeof(aead.alg_name) - 1);
	aead.alg_key_len = (unsigned int)(klen * 8);
	aead.alg_icv_len = m->icv_bits;
	if (klen && rc->enckey)
		memcpy(aead.alg_key, rc->enckey, klen);
	alen = 64 + sizeof(unsigned int) * 2 + klen;
	return xfrm_addattr(n, maxlen, XFRMA_ALG_AEAD, &aead, alen);
}

static int
add_enc_attr(struct nlmsghdr *n, size_t maxlen, struct rcpfk_msg *rc)
{
	const struct xfrm_algmap *m;
	struct xfrm_algo *alg;
	size_t klen, alen;
	char buf[sizeof(*alg) + 256];

	if (rc->satype == RCT_SATYPE_AH)
		return 0;
	m = alg_lookup(enc_map, rc->enctype);
	if (m == NULL) {
		xfrm_seterror(rc, EOPNOTSUPP, "enc alg %d not mapped to XFRM",
		    rc->enctype);
		return -1;
	}
	klen = rc->enckeylen;
	if (klen > 256) {
		xfrm_seterror(rc, EINVAL, "enc key too long");
		return -1;
	}
	alen = sizeof(*alg) + klen;
	memset(buf, 0, alen);
	alg = (void *)buf;
	strncpy(alg->alg_name, m->name, sizeof(alg->alg_name) - 1);
	alg->alg_key_len = (unsigned int)(klen * 8);
	if (klen && rc->enckey)
		memcpy(alg->alg_key, rc->enckey, klen);
	return xfrm_addattr(n, maxlen, XFRMA_ALG_CRYPT, alg, alen);
}

static int
add_auth_attr(struct nlmsghdr *n, size_t maxlen, struct rcpfk_msg *rc)
{
	const struct xfrm_algmap *m;
	size_t klen, alen;

	if (rc->authtype == 0 || rc->authtype == RCT_ALG_NON_AUTH)
		return 0;
	m = alg_lookup(auth_map, rc->authtype);
	if (m == NULL) {
		xfrm_seterror(rc, EOPNOTSUPP, "auth alg %d not mapped to XFRM",
		    rc->authtype);
		return -1;
	}
	klen = rc->authkeylen;
	if (klen > 256) {
		xfrm_seterror(rc, EINVAL, "auth key too long");
		return -1;
	}
	/*
	 * XFRMA_ALG_AUTH_TRUNC is an enum constant, not a #define — an
	 * #ifdef guard is always false and the missing alg_trunc_len made
	 * the kernel default to a 96-bit ICV for hmac(sha256), which
	 * RFC 4868 peers (Apple, strongSwan) never send. Always emit the
	 * trunc attribute.
	 */
	{
		struct xfrm_algo_auth *aa;
		char buf[sizeof(*aa) + 256];

		alen = sizeof(*aa) + klen;
		memset(buf, 0, alen);
		aa = (void *)buf;
		strncpy(aa->alg_name, m->name, sizeof(aa->alg_name) - 1);
		aa->alg_key_len = (unsigned int)(klen * 8);
		aa->alg_trunc_len = m->trunc_bits;
		if (klen && rc->authkey)
			memcpy(aa->alg_key, rc->authkey, klen);
		return xfrm_addattr(n, maxlen, XFRMA_ALG_AUTH_TRUNC, aa, alen);
	}
}

#ifdef ENABLE_NATT
static int
natt_wanted(const struct rcpfk_msg *rc)
{
	/*
	 * Only when iked set natt_type (NAT actually detected).
	 * IKE often lives on UDP 4500 without ESP-in-UDP (no NAT, or
	 * peer floated IKE only). Port-4500 heuristic caused
	 * XfrmInStateMismatch: SA had encap, on-wire ESP was proto 50.
	 */
	return rc->natt_type != 0;
}
#endif

static int
add_encap_attr(struct nlmsghdr *n, size_t maxlen, struct rcpfk_msg *rc)
{
#ifdef ENABLE_NATT
	struct xfrm_encap_tmpl enc;
	in_port_t *sp, *dp;

	if (!natt_wanted(rc))
		return 0;
	memset(&enc, 0, sizeof(enc));
	enc.encap_type = rc->natt_type ? rc->natt_type : UDP_ENCAP_ESPINUDP;
	if (rc->natt_sport)
		enc.encap_sport = rc->natt_sport;
	else if ((sp = rcs_getsaport(rc->sa_src)) != NULL)
		enc.encap_sport = *sp;
	if (rc->natt_dport)
		enc.encap_dport = rc->natt_dport;
	else if ((dp = rcs_getsaport(rc->sa_dst)) != NULL)
		enc.encap_dport = *dp;
	/*
	 * RFC 3947 NAT-OA → XFRMA_ENCAP encap_oa (one original
	 * address). Prefer src (outbound local OA), else dst (peer OA).
	 */
	{
		struct sockaddr *oa = rc->sa_natoa_src ? rc->sa_natoa_src
		    : rc->sa_natoa_dst;
		if (oa)
			(void)sa_to_xaddr(oa, &enc.encap_oa, NULL);
	}
	return xfrm_addattr(n, maxlen, XFRMA_ENCAP, &enc, sizeof(enc));
#else
	(void)n;
	(void)maxlen;
	(void)rc;
	return 0;
#endif
}

/*
 * RFC 4303 §2.2.1 / RFC 7296 §3.3.2 ESN: when the negotiated child uses
 * extended sequence numbers, the kernel needs the ESN replay state
 * (XFRMA_REPLAY_ESN_VAL) in ADDITION to XFRM_STATE_ESN in usersa_info;
 * a state created with the ESN flag but no replay-ESN struct is
 * rejected.  bmp_len must be (replay_window + 31) / 32.  Linux
 * configure defaults the window to 32 (one word); FreeBSD leaves the
 * header default (64) unless --with-ipsec-window-size is set.  A
 * hardcoded bmp_len of 1 rejects every window above 32.
 */
static int
add_replay_esn_attr(struct nlmsghdr *n, size_t maxlen, struct rcpfk_msg *rc)
{
	uint32_t window, bmp_len, len;
	struct xfrm_replay_state_esn *re;
	unsigned char buf[sizeof(*re) + 8 * sizeof(uint32_t)];

	if (!(rc->saflags & SADB_X_SAFLAGS_ESN))
		return 0;
	window = rc->wsize ? rc->wsize : 32;
	bmp_len = (window + 31) / 32;
	if (bmp_len < 1)
		bmp_len = 1;
	if (bmp_len > 8) {
		xfrm_seterror(rc, EINVAL, "ESN window %u exceeds 256", window);
		return -1;
	}
	len = (uint32_t)(sizeof(*re) + bmp_len * sizeof(uint32_t));
	memset(buf, 0, sizeof(buf));
	re = (struct xfrm_replay_state_esn *)buf;
	re->bmp_len = bmp_len;
	re->replay_window = window;
	return xfrm_addattr(n, maxlen, XFRMA_REPLAY_ESN_VAL, buf, len);
}

static int
sa_is_unspec(const struct sockaddr *sa)
{
	if (sa == NULL)
		return 1;
	if (sa->sa_family == AF_INET)
		return ((const struct sockaddr_in *)sa)->sin_addr.s_addr == 0;
#ifdef INET6
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const void *)sa;
		static const uint8_t z[16];

		/* memcmp — IN6_IS_ADDR_UNSPECIFIED fights linux/in.h vs glibc */
		return memcmp(&sin6->sin6_addr, z, 16) == 0;
	}
#endif
	return 1;
}

static int
append_tmpl(struct xfrm_user_tmpl *t, int *n, uint8_t satype,
    struct rcpfk_msg *rc)
{
	uint16_t src_fam = AF_INET, dst_fam = AF_INET, family = AF_INET;

	if (*n >= 3)
		return -1;
	memset(&t[*n], 0, sizeof(t[0]));
	t[*n].id.proto = satype_to_proto(satype);
	t[*n].mode = mode_to_x(rc->samode);
	t[*n].reqid = rc->reqid;
	t[*n].optional = (rc->ipsec_level == RCT_IPSL_USE);
	t[*n].aalgos = ~0U;
	t[*n].ealgos = ~0U;
	t[*n].calgos = ~0U;
	if ((rc->samode == RCT_IPSM_TUNNEL ||
	     rc->samode == RCT_IPSM_TRANSPORT) && rc->sa_src && rc->sa_dst) {
		if (sa_to_xaddr(rc->sa_dst, &t[*n].id.daddr, &dst_fam) < 0 ||
		    sa_to_xaddr(rc->sa_src, &t[*n].saddr, &src_fam) < 0)
			return -1;
		if (src_fam != dst_fam) {
			/*
			 * IP_ANY expansion used to put :: next to a
			 * v4 local (c0a8:444f::). Coerce the
			 * unspecified side; refuse mixed concrete.
			 */
			if (sa_is_unspec(rc->sa_src) && !sa_is_unspec(rc->sa_dst)) {
				memset(&t[*n].saddr, 0, sizeof(t[*n].saddr));
				family = dst_fam;
			} else if (sa_is_unspec(rc->sa_dst) &&
			    !sa_is_unspec(rc->sa_src)) {
				memset(&t[*n].id.daddr, 0, sizeof(t[*n].id.daddr));
				family = src_fam;
			} else
				return -1;
		} else
			family = dst_fam;
		t[*n].family = family;
	} else
		t[*n].family = family;
	(*n)++;
	return 0;
}

static int
add_tmpls(struct nlmsghdr *n, size_t maxlen, struct rcpfk_msg *rc)
{
	struct xfrm_user_tmpl t[3];
	int nt = 0;

	switch (rc->satype) {
	case RCT_SATYPE_AH:
	case RCT_SATYPE_ESP:
	case RCT_SATYPE_IPCOMP:
		if (append_tmpl(t, &nt, rc->satype, rc))
			return -1;
		break;
	case RCT_SATYPE_AH_ESP:
		if (append_tmpl(t, &nt, RCT_SATYPE_ESP, rc) ||
		    append_tmpl(t, &nt, RCT_SATYPE_AH, rc))
			return -1;
		break;
	case RCT_SATYPE_AH_IPCOMP:
		if (append_tmpl(t, &nt, RCT_SATYPE_IPCOMP, rc) ||
		    append_tmpl(t, &nt, RCT_SATYPE_AH, rc))
			return -1;
		break;
	case RCT_SATYPE_ESP_IPCOMP:
		if (append_tmpl(t, &nt, RCT_SATYPE_ESP, rc) ||
		    append_tmpl(t, &nt, RCT_SATYPE_IPCOMP, rc))
			return -1;
		break;
	case RCT_SATYPE_AH_ESP_IPCOMP:
		if (append_tmpl(t, &nt, RCT_SATYPE_ESP, rc) ||
		    append_tmpl(t, &nt, RCT_SATYPE_IPCOMP, rc) ||
		    append_tmpl(t, &nt, RCT_SATYPE_AH, rc))
			return -1;
		break;
	default:
		xfrm_seterror(rc, EINVAL, "invalid satype=%d", rc->satype);
		return -1;
	}
	return xfrm_addattr(n, maxlen, XFRMA_TMPL, t,
	    (size_t)nt * sizeof(t[0]));
}

static struct nlmsghdr *
xfrm_nlmsg(char *buf, size_t buflen, uint16_t type, uint16_t flags,
    size_t payload, struct rcpfk_msg *rc)
{
	struct nlmsghdr *n;

	if (NLMSG_LENGTH(payload) > buflen)
		return NULL;
	memset(buf, 0, buflen);
	n = (void *)buf;
	n->nlmsg_len = NLMSG_LENGTH(payload);
	n->nlmsg_type = type;
	n->nlmsg_flags = flags;
	/* iked matches replies by param->seq (0x4000000+). Do not invent one. */
	n->nlmsg_seq = rc->seq ? rc->seq : ++xfrm_seq;
	n->nlmsg_pid = (uint32_t)pid;
	return n;
}

static int add_xfrm_mark_ifid_attrs(struct nlmsghdr *, size_t,
    struct rcpfk_msg *);
static int add_xfrm_offload_attr(struct nlmsghdr *, size_t,
    struct rcpfk_msg *);

static int
xfrm_send_sa(struct rcpfk_msg *rc, uint16_t nltype)
{
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_usersa_info *sa;

	n = xfrm_nlmsg(buf, sizeof(buf), nltype,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*sa), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	sa = NLMSG_DATA(n);
	if (fill_usersa(sa, rc))
		return -1;
	if (nltype == XFRM_MSG_NEWSA || nltype == XFRM_MSG_UPDSA) {
		if (aead_lookup(rc->enctype)) {
			if (add_aead_attr(n, sizeof(buf), rc) ||
			    add_encap_attr(n, sizeof(buf), rc) ||
			    add_replay_esn_attr(n, sizeof(buf), rc))
				return -1;
		} else if (add_enc_attr(n, sizeof(buf), rc) ||
		    add_auth_attr(n, sizeof(buf), rc) ||
		    add_encap_attr(n, sizeof(buf), rc) ||
		    add_replay_esn_attr(n, sizeof(buf), rc))
			return -1;
	}
	/* XFRM-native: mark / if_id / device offload (offload is SA-only). */
	if (add_xfrm_mark_ifid_attrs(n, sizeof(buf), rc) ||
	    add_xfrm_offload_attr(n, sizeof(buf), rc))
		return -1;
	pending_set(rc, nltype, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

/*
 * XFRM-native policy/offload attributes (mark, if_id; plus the device offload
 * on the SA path). PF_KEY has no spelling for these; only the Linux backend
 * emits them, and only when the compile-time headers know the attribute
 * (guarded so an older kernel UAPI header still compiles). The *BSD PF_KEY and
 * loopback backends ignore the rcpfk_msg fields entirely.
 */
static int
add_xfrm_mark_ifid_attrs(struct nlmsghdr *n, size_t maxlen,
    struct rcpfk_msg *rc)
{
#if defined(XFRMA_MARK) && defined(XFRMA_IF_ID)
	if (rc->mark_mask != 0) {
		struct xfrm_mark m;

		memset(&m, 0, sizeof(m));
		m.v = rc->mark;
		m.m = rc->mark_mask;
		if (xfrm_addattr(n, maxlen, XFRMA_MARK, &m, sizeof(m)))
			return -1;
	}
	if (rc->if_id != 0)
		if (xfrm_addattr(n, maxlen, XFRMA_IF_ID, &rc->if_id,
		    sizeof(rc->if_id)))
			return -1;
#else
	(void)n;
	(void)maxlen;
	(void)rc;
#endif
	return 0;
}

static int
add_xfrm_offload_attr(struct nlmsghdr *n, size_t maxlen,
    struct rcpfk_msg *rc)
{
#ifdef XFRMA_OFFLOAD_DEV
	struct xfrm_user_offload od;
	uint32_t idx = rc->offload_ifindex;

	if (rc->offload_flags == 0)
		return 0;	/* offload not requested */
	if (idx == 0 && rc->offload_ifname[0] != '\0')
		idx = if_nametoindex(rc->offload_ifname);
	if (idx == 0) {
		xfrm_seterror(rc, ENODEV, "offload device %s not found",
		    rc->offload_ifname[0] ? rc->offload_ifname :
		    "(no ifindex)");
		return -1;
	}
	memset(&od, 0, sizeof(od));
	od.ifindex = (int)idx;
	od.flags = rc->offload_flags;
	return xfrm_addattr(n, maxlen, XFRMA_OFFLOAD_DEV, &od, sizeof(od));
#else
	(void)n;
	(void)maxlen;
	(void)rc;
	return 0;
#endif
}


int
rcpfk_init(struct rcpfk_msg *rc, struct rcpfk_cb *cb0)
{
	pid = getpid();
	if (rc->flags & PFK_FLAG_NOHARM)
		f_noharm++;
	if (xfrm_open(rc))
		return -1;
	cb = cb0;
	pending_clear();
	pending_dump_seq = resync_spd_seq = resync_sa_seq = 0;
	xfrm_need_resync = 0;
	return 0;
}

int
rcpfk_clean(struct rcpfk_msg *rc)
{
	cb = NULL;
	pending_clear();
	if (xfrm_rcvbuf) {
		free(xfrm_rcvbuf);
		xfrm_rcvbuf = NULL;
		free(xfrm_alnbuf);
		xfrm_alnbuf = NULL;
	}
	xfrm_close_all();
	rc->so = -1;
	return 0;
}

int
rcpfk_send_getspi(struct rcpfk_msg *rc)
{
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_userspi_info *spi;
	uint16_t family = AF_INET;

	n = xfrm_nlmsg(buf, sizeof(buf), XFRM_MSG_ALLOCSPI,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*spi), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	spi = NLMSG_DATA(n);
	memset(spi, 0, sizeof(*spi));
	if (sa_to_xaddr(rc->sa_dst, &spi->info.id.daddr, &family) < 0 ||
	    sa_to_xaddr(rc->sa_src, &spi->info.saddr, NULL) < 0) {
		xfrm_seterror(rc, EINVAL, "GETSPI addresses required");
		return -1;
	}
	spi->info.family = family;
	spi->info.id.proto = satype_to_proto(rc->satype);
	spi->info.mode = mode_to_x(rc->samode);
	spi->info.reqid = rc->reqid;
	spi->min = rc_spirange_min;
	spi->max = rc_spirange_max;
	pending_set(rc, XFRM_MSG_ALLOCSPI, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

int
rcpfk_send_update(struct rcpfk_msg *rc)
{
	return xfrm_send_sa(rc, XFRM_MSG_UPDSA);
}

int
rcpfk_send_add(struct rcpfk_msg *rc)
{
	return xfrm_send_sa(rc, XFRM_MSG_NEWSA);
}

int
rcpfk_send_delete(struct rcpfk_msg *rc)
{
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_usersa_id *id;
	uint16_t family = AF_INET;
	xfrm_address_t saddr;

	if (rc->spi == 0) {
		xfrm_seterror(rc, EOPNOTSUPP,
		    "XFRM delete-all (spi=0) not supported; delete by spi");
		return -1;
	}
	n = xfrm_nlmsg(buf, sizeof(buf), XFRM_MSG_DELSA,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*id), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	id = NLMSG_DATA(n);
	memset(id, 0, sizeof(*id));
	if (sa_to_xaddr(rc->sa_dst, &id->daddr, &family) < 0) {
		xfrm_seterror(rc, EINVAL, "DELSA dst required");
		return -1;
	}
	id->spi = rc->spi;
	id->family = family;
	id->proto = satype_to_proto(rc->satype);
	if (rc->sa_src && sa_to_xaddr(rc->sa_src, &saddr, NULL) == 0) {
		if (xfrm_addattr(n, sizeof(buf), XFRMA_SRCADDR, &saddr,
		    sizeof(saddr)))
			return -1;
	}
	pending_set(rc, XFRM_MSG_DELSA, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

int
rcpfk_send_get(struct rcpfk_msg *rc)
{
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_usersa_id *id;
	uint16_t family = AF_INET;

	n = xfrm_nlmsg(buf, sizeof(buf), XFRM_MSG_GETSA,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*id), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	id = NLMSG_DATA(n);
	memset(id, 0, sizeof(*id));
	if (sa_to_xaddr(rc->sa_dst, &id->daddr, &family) < 0) {
		xfrm_seterror(rc, EINVAL, "GETSA dst required");
		return -1;
	}
	id->spi = rc->spi;
	id->family = family;
	id->proto = satype_to_proto(rc->satype);
	pending_set(rc, XFRM_MSG_GETSA, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

int
rcpfk_send_acquire(struct rcpfk_msg *rc)
{
	/* XFRM ACQUIRE is kernel→user only; pfkey sent SADB_ACQUIRE+errno. */
	(void)rc;
	return 0;
}

int
rcpfk_send_register(struct rcpfk_msg *rc)
{
	/* XFRM has no SADB_REGISTER; supported_* are static tables. */
	(void)rc;
	return 0;
}

static int
xfrm_send_policy(struct rcpfk_msg *rc, uint16_t nltype)
{
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_userpolicy_info *xp;
	const struct sockaddr *src, *dst;

	n = xfrm_nlmsg(buf, sizeof(buf), nltype,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*xp), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	xp = NLMSG_DATA(n);
	memset(xp, 0, sizeof(*xp));
	src = rc->sp_src ? rc->sp_src : rc->sa_src;
	dst = rc->sp_dst ? rc->sp_dst : rc->sa_dst;
	fill_selector(&xp->sel, src, dst, rc->pref_src, rc->pref_dst,
	    rc->ul_proto, rc->flags);
	xp->dir = dir_to_x(rc->dir);
	xp->index = rc->slid;
	fill_lft(&xp->lft, rc);
	switch (rc->pltype) {
	case RCT_ACT_DISCARD:
		xp->action = XFRM_POLICY_BLOCK;
		break;
	case RCT_ACT_NONE:
		xp->action = XFRM_POLICY_ALLOW;
		break;
	case RCT_ACT_AUTO_IPSEC:
		xp->action = XFRM_POLICY_ALLOW;
		if (add_tmpls(n, sizeof(buf), rc))
			return -1;
		break;
	default:
		xfrm_seterror(rc, EINVAL, "invalid pltype=%d", rc->pltype);
		return -1;
	}
	/* XFRM-native: mark / if_id on the policy (offload is SA-only). */
	if (add_xfrm_mark_ifid_attrs(n, sizeof(buf), rc))
		return -1;
	pending_set(rc, nltype, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

int
rcpfk_send_spdupdate(struct rcpfk_msg *rc)
{
	return xfrm_send_policy(rc, XFRM_MSG_UPDPOLICY);
}

int
rcpfk_send_spdadd(struct rcpfk_msg *rc)
{
	return xfrm_send_policy(rc, XFRM_MSG_NEWPOLICY);
}

int
rcpfk_send_spddelete(struct rcpfk_msg *rc)
{
	/* pfkey stub returned 0; XFRM deletes by selector (Linux first-class). */
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_userpolicy_id *id;
	const struct sockaddr *src, *dst;

	n = xfrm_nlmsg(buf, sizeof(buf), XFRM_MSG_DELPOLICY,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*id), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	id = NLMSG_DATA(n);
	memset(id, 0, sizeof(*id));
	src = rc->sp_src ? rc->sp_src : rc->sa_src;
	dst = rc->sp_dst ? rc->sp_dst : rc->sa_dst;
	fill_selector(&id->sel, src, dst, rc->pref_src, rc->pref_dst,
	    rc->ul_proto, rc->flags);
	id->dir = dir_to_x(rc->dir);
	pending_set(rc, XFRM_MSG_DELPOLICY, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

int
rcpfk_send_spddelete2(struct rcpfk_msg *rc)
{
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_userpolicy_id *id;

	n = xfrm_nlmsg(buf, sizeof(buf), XFRM_MSG_DELPOLICY,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*id), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	id = NLMSG_DATA(n);
	memset(id, 0, sizeof(*id));
	id->index = rc->slid;
	id->dir = dir_to_x(rc->dir);
	pending_set(rc, XFRM_MSG_DELPOLICY, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

int
rcpfk_send_spdget(struct rcpfk_msg *rc)
{
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_userpolicy_id *id;

	n = xfrm_nlmsg(buf, sizeof(buf), XFRM_MSG_GETPOLICY,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*id), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	id = NLMSG_DATA(n);
	memset(id, 0, sizeof(*id));
	id->index = rc->slid;
	id->dir = dir_to_x(rc->dir);
	pending_set(rc, XFRM_MSG_GETPOLICY, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

int
rcpfk_send_spddump(struct rcpfk_msg *rc)
{
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;

	n = xfrm_nlmsg(buf, sizeof(buf), XFRM_MSG_GETPOLICY,
	    NLM_F_REQUEST | NLM_F_DUMP, 0, rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	pending_set(rc, XFRM_MSG_GETPOLICY, n->nlmsg_seq);
	pending_dump_seq = n->nlmsg_seq;
	return xfrm_nl_send(rc, n);
}

#ifdef XFRM_MSG_MIGRATE
/*
 * Synchronous request on the request socket: send n, then read until the
 * kernel's reply for n's seq arrives.  For a plain request that is its
 * NLMSG_ERROR (0 = ACK); for a dump (NLM_F_DUMP) every NEWSA part goes to
 * each_sa() and NLMSG_DONE ends it.  Replies for OTHER requests met on
 * the way are dispatched normally, so nothing pending is lost.  Returns
 * 0 or a positive errno.
 */
#define XFRM_SYNC_TIMEOUT_MS	3000
static int xfrm_dispatch(struct nlmsghdr *, struct rcpfk_msg *, int);
static int xfrm_wait_req(int);
static uint32_t xfrm_sync_seq = 0xe0000000u;

static int
xfrm_sync(struct nlmsghdr *n, int (*each_sa)(struct nlmsghdr *, void *),
    void *arg)
{
	static char *rbuf;
	struct rcpfk_msg scratch;
	struct nlmsghdr *h;
	unsigned int ulen;
	ssize_t len;
	uint32_t seq;
	int e;

	if (rbuf == NULL && (rbuf = malloc(XFRM_RCVBUFLEN)) == NULL)
		return ENOMEM;
	if (++xfrm_sync_seq < 0xe0000000u || xfrm_sync_seq >= XFRM_RESYNC_SEQ_BASE)
		xfrm_sync_seq = 0xe0000001u;
	n->nlmsg_seq = seq = xfrm_sync_seq;
	n->nlmsg_pid = (uint32_t)pid;
	if (send(xfrm_req_fd, n, n->nlmsg_len, 0) != (ssize_t)n->nlmsg_len)
		return errno ? errno : EIO;
	for (;;) {
		if (xfrm_wait_req(XFRM_SYNC_TIMEOUT_MS) <= 0)
			return ETIMEDOUT;
		len = xfrm_recv(xfrm_req_fd, rbuf, XFRM_RCVBUFLEN, 0);
		if (len < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return errno;
		}
		ulen = (unsigned int)len;
		for (h = (struct nlmsghdr *)rbuf; NLMSG_OK(h, ulen);
		     h = NLMSG_NEXT(h, ulen)) {
			uint32_t hs = h->nlmsg_seq;
			char al[XFRM_BUFLEN];
			struct nlmsghdr *m = h;

			if (h->nlmsg_type == NLMSG_ERROR &&
			    h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				hs = ((struct nlmsgerr *)NLMSG_DATA(h))->msg.nlmsg_seq;
			if (hs != seq) {
				memset(&scratch, 0, sizeof(scratch));
				(void)xfrm_dispatch(h, &scratch, 1);
				continue;
			}
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;
			if (h->nlmsg_type == NLMSG_ERROR) {
				e = -((struct nlmsgerr *)NLMSG_DATA(h))->error;
				return e;
			}
			if (each_sa == NULL || h->nlmsg_type != XFRM_MSG_NEWSA)
				continue;
			/* 4-byte netlink alignment: hand over an aligned copy */
			if (((uintptr_t)h & 7) != 0 && h->nlmsg_len <= sizeof(al)) {
				memcpy(al, h, h->nlmsg_len);
				m = (struct nlmsghdr *)(void *)al;
			}
			if ((e = each_sa(m, arg)) != 0)
				return e;
		}
	}
}

/* NAT-T port change without CONFIG_XFRM_MIGRATE (see rcpfk_send_migrate) */
struct xfrm_encap_job {
	struct rcpfk_msg *rc;
	int family;
	xfrm_address_t s, d;
	int matched, updated;
	int err;
	char (*msgs)[XFRM_BUFLEN];
	int nmsgs;
};
#define XFRM_ENCAP_MAX	64

static int
xfrm_encap_collect(struct nlmsghdr *h, void *arg)
{
	struct xfrm_encap_job *j = arg;
	const struct xfrm_usersa_info *sa = NLMSG_DATA(h);
	uint32_t want = (uint32_t)j->rc->reqid;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*sa)))
		return 0;
	if (sa->family != j->family ||
	    sa->id.proto != satype_to_proto(j->rc->satype) ||
	    memcmp(&sa->saddr, &j->s, sizeof(j->s)) != 0 ||
	    memcmp(&sa->id.daddr, &j->d, sizeof(j->d)) != 0 ||
	    (want != 0 && sa->reqid != want))
		return 0;
	if (j->nmsgs < XFRM_ENCAP_MAX && h->nlmsg_len <= XFRM_BUFLEN) {
		memcpy(j->msgs[j->nmsgs], h, h->nlmsg_len);
		j->nmsgs++;
	}
	j->matched++;
	return 0;
}

/*
 * Rewrite the XFRMA_ENCAP ports of every SA saddr=sa_src daddr=sa_dst
 * (proto, reqid) to the new natt_sport/natt_dport with XFRM_MSG_UPDSA: the
 * kernel's xfrm_state_update() copies a new encap template into a VALID
 * state in place (keys, replay and lifetimes stay), which is enough when
 * a NAT only re-mapped the PORT.  The UPDSA is the SA's own GETSA dump
 * (it carries the keys) with the encap ports changed.
 */
static int
xfrm_update_encap_ports(struct rcpfk_msg *rc)
{
	struct xfrm_encap_job j;
	char req[NLMSG_SPACE(sizeof(struct xfrm_usersa_info))];
	struct nlmsghdr *n = (void *)req;
	uint16_t fam = AF_INET;
	int i, e;

	memset(&j, 0, sizeof(j));
	j.rc = rc;
	if (sa_to_xaddr(rc->sa_src, &j.s, &fam) != 0 ||
	    sa_to_xaddr(rc->sa_dst, &j.d, &fam) != 0)
		return EINVAL;
	j.family = fam;
	j.msgs = malloc(sizeof(*j.msgs) * XFRM_ENCAP_MAX);
	if (j.msgs == NULL)
		return ENOMEM;
	memset(req, 0, sizeof(req));
	n->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	n->nlmsg_type = XFRM_MSG_GETSA;
	n->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	e = xfrm_sync(n, xfrm_encap_collect, &j);
	for (i = 0; e == 0 && i < j.nmsgs; i++) {
		struct nlmsghdr *m = (void *)j.msgs[i];
		struct rtattr *rta;
		int alen, found = 0;

		rta = (struct rtattr *)((char *)NLMSG_DATA(m) +
		    NLMSG_ALIGN(sizeof(struct xfrm_usersa_info)));
		alen = (int)m->nlmsg_len -
		    (int)NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
		for (; RTA_OK(rta, alen); rta = RTA_NEXT(rta, alen)) {
			struct xfrm_encap_tmpl et;

			if (rta->rta_type != XFRMA_ENCAP ||
			    RTA_PAYLOAD(rta) < sizeof(et))
				continue;
			memcpy(&et, RTA_DATA(rta), sizeof(et));
			if (rc->natt_sport)
				et.encap_sport = rc->natt_sport;
			if (rc->natt_dport)
				et.encap_dport = rc->natt_dport;
			memcpy(RTA_DATA(rta), &et, sizeof(et));
			found = 1;
		}
		if (!found)
			continue;	/* not UDP-encapsulated: nothing to move */
		m->nlmsg_type = XFRM_MSG_UPDSA;
		m->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		e = xfrm_sync(m, NULL, NULL);
		if (e == 0)
			j.updated++;
	}
	free(j.msgs);
	if (e == 0 && j.updated == 0)
		e = ESRCH;
	if (e == 0)
		plog(PLOG_INFO, PLOGLOC, NULL,
		    "xfrm: no XFRM_MSG_MIGRATE in this kernel "
		    "(CONFIG_XFRM_MIGRATE off); NAT-T port change applied "
		    "to %d SA(s) with XFRM_MSG_UPDSA\n", j.updated);
	return e;
}

static int
xfrm_same_addr(const struct sockaddr *a, const struct sockaddr *b)
{
	return a != NULL && b != NULL && rcs_cmpsa_wop(a, b) == 0;
}
#endif

int
rcpfk_send_migrate(struct rcpfk_msg *rc)
{
#ifdef XFRM_MSG_MIGRATE
	char buf[XFRM_BUFLEN];
	struct nlmsghdr *n;
	struct xfrm_userpolicy_id *id;
	struct xfrm_user_migrate m;
	uint16_t family = AF_INET;
	const struct sockaddr *src, *dst;

	n = xfrm_nlmsg(buf, sizeof(buf), XFRM_MSG_MIGRATE,
	    NLM_F_REQUEST | NLM_F_ACK, sizeof(*id), rc);
	if (n == NULL) {
		xfrm_seterror(rc, ENOMEM, "netlink buffer");
		return -1;
	}
	id = NLMSG_DATA(n);
	memset(id, 0, sizeof(*id));
	src = rc->sp_src ? rc->sp_src : rc->sa_src;
	dst = rc->sp_dst ? rc->sp_dst : rc->sa_dst;
	fill_selector(&id->sel, src, dst, rc->pref_src, rc->pref_dst,
	    rc->ul_proto, rc->flags);
	id->dir = dir_to_x(rc->dir);
	memset(&m, 0, sizeof(m));
	m.proto = satype_to_proto(rc->satype);
	m.mode = mode_to_x(rc->samode);
	m.reqid = rc->reqid;
	if (rc->sa_src)
		sa_to_xaddr(rc->sa_src, &m.old_saddr, &family);
	if (rc->sa_dst)
		sa_to_xaddr(rc->sa_dst, &m.old_daddr, &family);
	m.old_family = family;
	if (rc->sa2_src)
		sa_to_xaddr(rc->sa2_src, &m.new_saddr, &family);
	if (rc->sa2_dst)
		sa_to_xaddr(rc->sa2_dst, &m.new_daddr, &family);
	m.new_family = family;
	if (xfrm_addattr(n, sizeof(buf), XFRMA_MIGRATE, &m, sizeof(m))) {
		xfrm_seterror(rc, ENOBUFS, "XFRMA_MIGRATE");
		return -1;
	}
#ifdef ENABLE_NATT
	if (add_encap_attr(n, sizeof(buf), rc)) {
		xfrm_seterror(rc, ENOBUFS, "XFRMA_ENCAP");
		return -1;
	}
#endif
	/*
	 * Synchronous: the caller (MOBIKE / NAT mapping move, spmd) commits
	 * the new endpoints only if the kernel really moved the SAs.  Sent
	 * fire-and-forget, a refusal arrived later as a stray error while
	 * iked had already re-pinned the IKE SA to an address the kernel
	 * SAs did not use.
	 */
	{
		int e = xfrm_sync(n, NULL, NULL);

		if (e == ENOPROTOOPT && rc->natt_type != 0 &&
		    xfrm_same_addr(rc->sa_src, rc->sa2_src) &&
		    xfrm_same_addr(rc->sa_dst, rc->sa2_dst))
			e = xfrm_update_encap_ports(rc);
		if (e != 0) {
			xfrm_seterror(rc, e, "xfrm migrate: %s%s", strerror(e),
			    e == ENOPROTOOPT ? " (kernel built without "
			    "CONFIG_XFRM_MIGRATE; only a NAT port change can "
			    "be applied without it)" : "");
			return -1;
		}
		return 0;
	}
#else
	xfrm_seterror(rc, EOPNOTSUPP, "XFRM_MSG_MIGRATE not in headers");
	return -1;
#endif
}

int
rcpfk_supported_auth(int algtype)
{
	if (algtype == RCT_ALG_NON_AUTH)
		return 1;
	return alg_lookup(auth_map, algtype) != NULL;
}

int
rcpfk_supported_enc(int algtype)
{
	return alg_lookup(enc_map, algtype) != NULL ||
	    aead_lookup(algtype) != NULL;
}

/* Read a 64-bit netlink field via memcpy so strict-alignment targets
 * (sparc64, some ARM, s390x) never fault on a direct deref of the
 * packed xfrm_usersa_info payload (rdratlos/racoon-ipsec-tools #145
 * review).  Identical result on x86-64/arm64. */
static uint64_t
xr_u64(const void *ptr)
{
	uint64_t v;
	memcpy(&v, ptr, sizeof(v));
	return v;
}

static void
usersa_to_rc(const struct xfrm_usersa_info *sa, struct rcpfk_msg *rc)
{
	rc->spi = sa->id.spi;
	rc->satype = proto_to_satype(sa->id.proto);
	rc->samode = x_to_mode(sa->mode);
	rc->reqid = sa->reqid;
	rc->wsize = (uint8_t)sa->replay_window;
	rc->lft_hard_time = xr_u64(&sa->lft.hard_add_expires_seconds) == XFRM_INF ? 0 :
	    xr_u64(&sa->lft.hard_add_expires_seconds);
	rc->lft_soft_time = xr_u64(&sa->lft.soft_add_expires_seconds) == XFRM_INF ? 0 :
	    xr_u64(&sa->lft.soft_add_expires_seconds);
	rc->lft_hard_bytes = xr_u64(&sa->lft.hard_byte_limit) == XFRM_INF ? 0 :
	    xr_u64(&sa->lft.hard_byte_limit);
	rc->lft_soft_bytes = xr_u64(&sa->lft.soft_byte_limit) == XFRM_INF ? 0 :
	    xr_u64(&sa->lft.soft_byte_limit);
	rc->lft_current_bytes = xr_u64(&sa->curlft.bytes);
	rc->lft_current_alloc = xr_u64(&sa->curlft.use_time) ? 1 : xr_u64(&sa->curlft.packets);
	rc->lft_current_add = xr_u64(&sa->curlft.add_time);
	rc->lft_current_use = xr_u64(&sa->curlft.use_time);
	rc->sa_src = (void *)&rc->sa_src_storage;
	rc->sa_dst = (void *)&rc->sa_dst_storage;
	xaddr_to_sa(sa->family, &sa->saddr, sa->sel.sport, &rc->sa_src_storage);
	xaddr_to_sa(sa->family, &sa->id.daddr, sa->sel.dport,
	    &rc->sa_dst_storage);
}

static void
userpol_to_rc(const struct xfrm_userpolicy_info *xp, struct rcpfk_msg *rc)
{
	rc->slid = xp->index;
	rc->dir = x_to_dir(xp->dir);
	rc->pref_src = xp->sel.prefixlen_s;
	rc->pref_dst = xp->sel.prefixlen_d;
	rc->ul_proto = xp->sel.proto ? xp->sel.proto : RC_PROTO_ANY;
	rc->pltype = xp->action == XFRM_POLICY_BLOCK ? RCT_ACT_DISCARD :
	    RCT_ACT_AUTO_IPSEC;
	rc->sp_src = (void *)&rc->sp_src_storage;
	rc->sp_dst = (void *)&rc->sp_dst_storage;
	xaddr_to_sa(xp->sel.family, &xp->sel.saddr, xp->sel.sport,
	    &rc->sp_src_storage);
	xaddr_to_sa(xp->sel.family, &xp->sel.daddr, xp->sel.dport,
	    &rc->sp_dst_storage);
}

static int
handle_newsa(struct xfrm_usersa_info *sa, struct rcpfk_msg *rc, uint32_t seq)
{
	int (*fn)(struct rcpfk_msg *) = NULL;
	int ours;

	usersa_to_rc(sa, rc);
	rc->seq = seq;
	if (resync_sa_seq != 0 && seq == resync_sa_seq) {
		rc->flags |= PFK_FLAG_RESYNC;
		if (cb && cb->cb_sadump)
			return cb->cb_sadump(rc) < 0 ? -1 : 0;
		return 0;
	}
	ours = pending_type != 0 && seq == pending_seq;
	if (ours && pending_type == XFRM_MSG_ALLOCSPI)
		fn = cb && cb->cb_getspi ? cb->cb_getspi : NULL;
	else if (ours && pending_type == XFRM_MSG_UPDSA)
		fn = cb && cb->cb_update ? cb->cb_update : NULL;
	else if (ours && pending_type == XFRM_MSG_GETSA)
		fn = cb && cb->cb_get ? cb->cb_get : NULL;
	else if (ours && pending_type == XFRM_MSG_NEWSA)
		fn = cb && cb->cb_add ? cb->cb_add : NULL;
	else if (rc->flags & PFK_FLAG_SEEADD)
		fn = cb && cb->cb_add ? cb->cb_add : NULL;
	else
		return 0;
	if (ours)
		pending_clear();
	if (f_noharm && fn != (cb ? cb->cb_getspi : NULL))
		return 0;
	if (fn && fn(rc) < 0)
		return -1;
	return 0;
}

static int
handle_expire(struct xfrm_user_expire *ex, struct rcpfk_msg *rc)
{
	usersa_to_rc(&ex->state, rc);
	rc->expired = ex->hard ? 2 : 1;
	/*
	 * Linux PF_KEY used to fire soft-expire even unused.  XFRM curlft
	 * is real: iked already gates rekey on lft_current_alloc != 0.
	 */
	if (cb && cb->cb_expire)
		return cb->cb_expire(rc);
	return 0;
}

static int
handle_acquire(struct nlmsghdr *nlh, struct rcpfk_msg *rc)
{
	struct xfrm_user_acquire *ac;
	struct rtattr *rta;
	int attrlen;

	ac = NLMSG_DATA(nlh);
	rc->satype = proto_to_satype(ac->id.proto);
	rc->dir = x_to_dir(ac->policy.dir);
	rc->slid = ac->policy.index;
	rc->reqid = 0;
	rc->sa_src = (void *)&rc->sa_src_storage;
	rc->sa_dst = (void *)&rc->sa_dst_storage;
	rc->sp_src = (void *)&rc->sp_src_storage;
	rc->sp_dst = (void *)&rc->sp_dst_storage;
	/* Inner packet is the selector, not the IKE peer. */
	if (xaddr_to_sa(ac->sel.family, &ac->sel.saddr, ac->sel.sport,
	    &rc->sp_src_storage) < 0 ||
	    xaddr_to_sa(ac->sel.family, &ac->sel.daddr, ac->sel.dport,
	    &rc->sp_dst_storage) < 0)
		return 0;
	rc->pref_src = ac->sel.prefixlen_s;
	rc->pref_dst = ac->sel.prefixlen_d;
	rc->ul_proto = ac->sel.proto ? ac->sel.proto : RC_PROTO_ANY;
	/* reqid + outer endpoints live on the tmpl, not sel / policy.index. */
	attrlen = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ac)));
	rta = (void *)((char *)ac + NLMSG_ALIGN(sizeof(*ac)));
	for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
		if (rta->rta_type == XFRMA_TMPL &&
		    RTA_PAYLOAD(rta) >= sizeof(struct xfrm_user_tmpl)) {
			struct xfrm_user_tmpl *t = RTA_DATA(rta);
			uint16_t fam = t->family ? t->family : ac->sel.family;

			rc->reqid = t->reqid;
			if (t->id.proto)
				rc->satype = proto_to_satype(t->id.proto);
			rc->samode = x_to_mode(t->mode);
			if (xaddr_to_sa(fam, &t->saddr, 0,
			    &rc->sa_src_storage) < 0 ||
			    xaddr_to_sa(fam, &t->id.daddr, 0,
			    &rc->sa_dst_storage) < 0)
				return 0;
			goto have_tmpl;
		}
	}
	/* No tmpl: do not start IKE toward the inner selector. */
	return 0;
have_tmpl:
	if (cb && cb->cb_acquire)
		return cb->cb_acquire(rc);
	return 0;
}

static int
handle_policy(struct xfrm_userpolicy_info *xp, struct rcpfk_msg *rc, int dumped,
    int ours, uint16_t nltype)
{
	int (*fn)(struct rcpfk_msg *) = NULL;

	userpol_to_rc(xp, rc);
	/*
	 * Our own op arrives twice: the ACK (NLMSG_ERROR, delivered via
	 * pending) and the multicast event with the same seq. The ACK fires
	 * the callback; skip our own event or spmd's spid_data_update
	 * double-fires on a seq it already bound.
	 */
	if (!dumped && ours)
		return 0;
	/*
	 * Undumped arrivals are multicast EVENTS, not replies to our ops —
	 * route by the message type, never by a stale pending_type (an
	 * earlier op would misroute foreign events into the update
	 * callback and spid_data misses). Flag them so consumers can skip
	 * seq bookkeeping for other processes' policies.
	 */
	if (!dumped)
		rc->flags |= PFK_FLAG_EVENT;
	if (dumped && resync_spd_seq != 0 && rc->seq == resync_spd_seq)
		rc->flags |= PFK_FLAG_RESYNC;
	if (dumped)
		fn = cb && cb->cb_spddump ? cb->cb_spddump : NULL;
	else if (nltype == XFRM_MSG_UPDPOLICY)
		fn = cb && cb->cb_spdupdate ? cb->cb_spdupdate : NULL;
	else
		fn = cb && cb->cb_spdadd ? cb->cb_spdadd : NULL;
	/*
	 * Foreign multicast events (other processes' policy updates) and
	 * mid-dump messages must NEVER clear the single-slot op-pending:
	 * a concurrent ALLOCSPI/GETSA awaiting its NEWSA reply would lose
	 * the pending match and cb_getspi would never fire (slow connect,
	 * child stuck GETSPI until EXPIRE). Only NLMSG_DONE (M2-guarded)
	 * may touch the op-pending slot.
	 */
	if (fn && fn(rc) < 0)
		return -1;
	return 0;
}

/*
 * XFRM_MSG_MAPPING (XFRMNLGRP_MAPPING): esp_input saw an ESP-in-UDP packet
 * that passed the inbound SA's integrity check arrive from a different
 * source address or port than the SA's encap (NAT rebinding).  The kernel
 * changes nothing itself; the KM must move the SA pair.
 */
static int
handle_mapping(struct xfrm_user_mapping *um, struct rcpfk_msg *rc)
{
	rc->spi = um->id.spi;
	rc->satype = proto_to_satype(um->id.proto);
	rc->reqid = um->reqid;
	rc->sa_src = (void *)&rc->sa_src_storage;
	rc->sa_dst = (void *)&rc->sa_dst_storage;
	rc->sa2_src = (void *)&rc->sa2_src_storage;
	if (xaddr_to_sa(um->id.family, &um->old_saddr, um->old_sport,
	    &rc->sa_src_storage) < 0 ||
	    xaddr_to_sa(um->id.family, &um->id.daddr, 0,
	    &rc->sa_dst_storage) < 0 ||
	    xaddr_to_sa(um->id.family, &um->new_saddr, um->new_sport,
	    &rc->sa2_src_storage) < 0)
		return 0;
	rc->natt_dport = um->new_sport;
	if (cb && cb->cb_mapping)
		return cb->cb_mapping(rc) < 0 ? -1 : 0;
	return 0;
}

/*
 * XFRM_MSG_MIGRATE (XFRMNLGRP_MIGRATE) from another KM (e.g. a Mobile IPv6
 * daemon, or `ip xfrm policy migrate`): xfrm_userpolicy_id, then one
 * XFRMA_MIGRATE per moved template, optionally XFRMA_ENCAP.  Delivered
 * like PF_KEY SADB_X_MIGRATE so iked's existing cb_migrate path applies.
 */
static int
handle_migrate(struct nlmsghdr *nlh, struct rcpfk_msg *rc)
{
	struct xfrm_userpolicy_id *id = NLMSG_DATA(nlh);
	struct rtattr *rta;
	int attrlen, have = 0;

	rc->dir = x_to_dir(id->dir);
	rc->slid = id->index;
	rc->pref_src = id->sel.prefixlen_s;
	rc->pref_dst = id->sel.prefixlen_d;
	rc->ul_proto = id->sel.proto ? id->sel.proto : RC_PROTO_ANY;
	rc->sp_src = (void *)&rc->sp_src_storage;
	rc->sp_dst = (void *)&rc->sp_dst_storage;
	xaddr_to_sa(id->sel.family, &id->sel.saddr, id->sel.sport,
	    &rc->sp_src_storage);
	xaddr_to_sa(id->sel.family, &id->sel.daddr, id->sel.dport,
	    &rc->sp_dst_storage);
	attrlen = (int)(nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*id)));
	rta = (void *)((char *)id + NLMSG_ALIGN(sizeof(*id)));
	for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {
		if (rta->rta_type == XFRMA_MIGRATE && !have &&
		    RTA_PAYLOAD(rta) >= sizeof(struct xfrm_user_migrate)) {
			struct xfrm_user_migrate *m = RTA_DATA(rta);

			rc->satype = proto_to_satype(m->proto);
			rc->samode = x_to_mode(m->mode);
			rc->reqid = m->reqid;
			rc->sa_src = (void *)&rc->sa_src_storage;
			rc->sa_dst = (void *)&rc->sa_dst_storage;
			rc->sa2_src = (void *)&rc->sa2_src_storage;
			rc->sa2_dst = (void *)&rc->sa2_dst_storage;
			if (xaddr_to_sa(m->old_family, &m->old_saddr, 0,
			    &rc->sa_src_storage) < 0 ||
			    xaddr_to_sa(m->old_family, &m->old_daddr, 0,
			    &rc->sa_dst_storage) < 0 ||
			    xaddr_to_sa(m->new_family, &m->new_saddr, 0,
			    &rc->sa2_src_storage) < 0 ||
			    xaddr_to_sa(m->new_family, &m->new_daddr, 0,
			    &rc->sa2_dst_storage) < 0)
				return 0;
			have = 1;
		} else if (rta->rta_type == XFRMA_ENCAP &&
		    RTA_PAYLOAD(rta) >= sizeof(struct xfrm_encap_tmpl)) {
			struct xfrm_encap_tmpl *e = RTA_DATA(rta);

			rc->natt_type = (uint8_t)e->encap_type;
			rc->natt_sport = e->encap_sport;
			rc->natt_dport = e->encap_dport;
		}
	}
	if (!have)
		return 0;
#ifdef SADB_X_MIGRATE
	if (cb && cb->cb_migrate)
		return cb->cb_migrate(rc) < 0 ? -1 : 0;
#endif
	return 0;
}

/*
 * RFC 0002 error classification for the ACK of our pending op.
 * Returns the errno to report (0 = treat as success).
 */
static int
xfrm_classify_error(int e, int ptype)
{
	switch (e) {
	case EEXIST:
		/* retransmitted add: the object is there, which is the goal */
		if (ptype == XFRM_MSG_NEWSA || ptype == XFRM_MSG_NEWPOLICY)
			return 0;
		break;
	case ENOENT:
	case ESRCH:
		/* already expired or deleted by someone else */
		if (ptype == XFRM_MSG_DELSA || ptype == XFRM_MSG_DELPOLICY)
			return 0;
		break;
	default:
		break;
	}
	return e;
}

static int
handle_nlmsg(struct nlmsghdr *nlh, struct rcpfk_msg *rc)
{
	struct nlmsgerr *err;
	int ptype;

	rc->seq = nlh->nlmsg_seq;
	rc->flags = 0;	/* event flag is per-message; container is reused */
	switch (nlh->nlmsg_type) {
	case NLMSG_NOOP:
		return 0;
	case NLMSG_DONE:
		if (resync_sa_seq != 0 && nlh->nlmsg_seq == resync_sa_seq) {
			resync_sa_seq = 0;
			return 0;
		}
		if (resync_spd_seq != 0 && nlh->nlmsg_seq == resync_spd_seq) {
			resync_spd_seq = 0;
			return 0;
		}
		/*
		 * Dump terminator: clear dump tracking, but only clear
		 * the op-pending slot if it still belongs to the dump —
		 * a live op issued mid-dump owns it now (M2).
		 */
		if (pending_type == XFRM_MSG_GETPOLICY
		    && pending_seq == pending_dump_seq)
			pending_clear();
		pending_dump_seq = 0;
		return 0;
	case NLMSG_ERROR:
		if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
			goto shortmsg;
		err = NLMSG_DATA(nlh);
		rc->seq = err->msg.nlmsg_seq;
		if (resync_sa_seq != 0 && rc->seq == resync_sa_seq) {
			resync_sa_seq = 0;
			return 0;
		}
		if (resync_spd_seq != 0 && rc->seq == resync_spd_seq) {
			resync_spd_seq = 0;
			return 0;
		}
		if (err->error != 0) {
			int ours = pending_type != 0 && pending_seq == rc->seq;
			int e = -err->error;

			if (ours && e == EBUSY &&
			    pending_retries < XFRM_EBUSY_RETRIES) {
				pending_retries++;
				xfrm_stat_ebusy_retry++;
				plog(PLOG_DEBUG, PLOGLOC, NULL,
				    "xfrm: EBUSY on seq %u, retry %d\n",
				    rc->seq, pending_retries);
				if (xfrm_resend_pending() == 0)
					return 0;
			}
			if (ours && xfrm_classify_error(e, pending_type) == 0) {
				xfrm_stat_idempotent++;
				plog(PLOG_DEBUG, PLOGLOC, NULL,
				    "xfrm: %s on seq %u type %d treated as "
				    "success\n", strerror(e), rc->seq,
				    pending_type);
				goto ack_ok;
			}
			if (rc->seq == pending_dump_seq)
				pending_dump_seq = 0;
			if (ours || pending_type == 0)
				pending_clear();
			xfrm_seterror(rc, e, "xfrm netlink: %s", strerror(e));
			return -1;
		}
	ack_ok:
		/* success ACK: ALLOCSPI/GETSA still need the NEWSA body. */
		if (pending_type == 0 || pending_seq != rc->seq)
			return 0;
		ptype = pending_type;
		switch (ptype) {
		case XFRM_MSG_ALLOCSPI:
		case XFRM_MSG_GETSA:
			return 0;
		case XFRM_MSG_UPDSA:
			pending_fill_rc(rc);
			pending_clear();
			if (cb && cb->cb_update)
				return cb->cb_update(rc);
			return 0;
		case XFRM_MSG_NEWSA:
			pending_fill_rc(rc);
			pending_clear();
			if (cb && cb->cb_add)
				return cb->cb_add(rc);
			return 0;
		case XFRM_MSG_DELSA:
			pending_fill_rc(rc);
			pending_clear();
			if (cb && cb->cb_delete)
				return cb->cb_delete(rc);
			return 0;
		case XFRM_MSG_DELPOLICY:
			pending_clear();
			if (cb && cb->cb_spddelete)
				return cb->cb_spddelete(rc);
			return 0;
		case XFRM_MSG_NEWPOLICY:
			pending_clear();
			if (cb && cb->cb_spdadd)
				return cb->cb_spdadd(rc);
			return 0;
		case XFRM_MSG_UPDPOLICY:
			pending_clear();
			if (cb && cb->cb_spdupdate)
				return cb->cb_spdupdate(rc);
			return 0;
		default:
			pending_clear();
			return 0;
		}
	case XFRM_MSG_NEWSA:
		if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)))
			goto shortmsg;
		return handle_newsa(NLMSG_DATA(nlh), rc, nlh->nlmsg_seq);
	case XFRM_MSG_DELSA:
		if (pending_type == XFRM_MSG_DELSA &&
		    nlh->nlmsg_seq == pending_seq)
			pending_fill_rc(rc);
		pending_clear();
		if (cb && cb->cb_delete)
			return cb->cb_delete(rc);
		return 0;
	case XFRM_MSG_EXPIRE:
		if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_user_expire)))
			goto shortmsg;
		return handle_expire(NLMSG_DATA(nlh), rc);
	case XFRM_MSG_ACQUIRE:
		if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_user_acquire)))
			goto shortmsg;
		return handle_acquire(nlh, rc);
	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_UPDPOLICY:
		if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_info)))
			goto shortmsg;
		/* dumps arrive as NEWPOLICY + NLM_F_MULTI, then NLMSG_DONE;
		 * classify by the dump's own seq so a live op issued
		 * mid-dump cannot misroute the remaining frames (M2) */
		return handle_policy(NLMSG_DATA(nlh), rc,
		    (pending_dump_seq != 0 &&
		     nlh->nlmsg_seq == pending_dump_seq) ||
		    (resync_spd_seq != 0 && nlh->nlmsg_seq == resync_spd_seq),
		    pending_type != 0 && pending_seq == nlh->nlmsg_seq,
		    nlh->nlmsg_type);
	case XFRM_MSG_POLEXPIRE:
		if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_user_polexpire)))
			goto shortmsg;
		{
			struct xfrm_user_polexpire *pe = NLMSG_DATA(nlh);

			userpol_to_rc(&pe->pol, rc);
			if (cb && cb->cb_spdexpire)
				return cb->cb_spdexpire(rc);
		}
		return 0;
	case XFRM_MSG_DELPOLICY:
		pending_clear();
		if (cb && cb->cb_spddelete)
			return cb->cb_spddelete(rc);
		return 0;
	case XFRM_MSG_MAPPING:
		if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_user_mapping)))
			goto shortmsg;
		return handle_mapping(NLMSG_DATA(nlh), rc);
	case XFRM_MSG_MIGRATE:
		if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_userpolicy_id)))
			goto shortmsg;
		return handle_migrate(nlh, rc);
	default:
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "ignoring xfrm nlmsg type %u\n", nlh->nlmsg_type);
		return 0;
	}
shortmsg:
	xfrm_seterror(rc, EINVAL, "short xfrm netlink message type %u",
	    nlh->nlmsg_type);
	return -1;
}

/*
 * Is this message from the notify socket the multicast echo of one of our
 * own requests?  The kernel copies the requester's nlmsg_pid into the
 * event; kernel-originated events (EXPIRE, ACQUIRE, MAPPING) carry 0.
 */
static int
xfrm_is_echo(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_pid != 0 && nlh->nlmsg_pid == (uint32_t)pid;
}

static int
xfrm_dispatch(struct nlmsghdr *nlh, struct rcpfk_msg *rc, int from_req)
{
	if (from_req) {
		/* unicast replies: must be addressed to us and to a request
		 * we are still waiting for; anything else is stale */
		uint32_t seq = nlh->nlmsg_seq;

		if (nlh->nlmsg_type == NLMSG_ERROR &&
		    nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)))
			seq = ((struct nlmsgerr *)NLMSG_DATA(nlh))->msg.nlmsg_seq;
		if ((nlh->nlmsg_pid != 0 && nlh->nlmsg_pid != (uint32_t)pid) ||
		    seq == 0 ||
		    !((pending_type != 0 && seq == pending_seq) ||
		      (pending_dump_seq != 0 && seq == pending_dump_seq) ||
		      (resync_spd_seq != 0 && seq == resync_spd_seq) ||
		      (resync_sa_seq != 0 && seq == resync_sa_seq))) {
			int e = 0;

			if (nlh->nlmsg_type == NLMSG_ERROR &&
			    nlh->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)))
				e = -((struct nlmsgerr *)NLMSG_DATA(nlh))->error;
			if (e != 0 && (nlh->nlmsg_pid == 0 ||
			    nlh->nlmsg_pid == (uint32_t)pid)) {
				/*
				 * A failure for one of OUR requests that is no
				 * longer the awaited one (a second request was
				 * sent before its reply came back).  Before the
				 * reply matching such an error reached sadb_poll
				 * as "xfrm netlink: ..."; never let it vanish at
				 * DEBUG level.  It cannot complete the current
				 * wait, so it is logged and counted, not returned.
				 */
				xfrm_stat_late_error++;
				plog(PLOG_INTERR, PLOGLOC, NULL,
				    "xfrm netlink: request seq %u failed: %s\n",
				    seq, strerror(e));
				return 0;
			}
			xfrm_stat_stale_reply++;
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			    "xfrm: dropping unmatched reply type %u seq %u "
			    "pid %u\n", nlh->nlmsg_type, seq, nlh->nlmsg_pid);
			return 0;
		}
		return handle_nlmsg(nlh, rc);
	}
	if (xfrm_is_echo(nlh)) {
		/*
		 * Our own SA op's echo still completes the pending op when it
		 * wins the race with the ACK (it carries the full SA, which
		 * is what the single-socket code always delivered).  Policy
		 * and migrate echoes are never delivered: the ACK on the
		 * request socket already completed them.
		 */
		switch (nlh->nlmsg_type) {
		case XFRM_MSG_NEWSA:
		case XFRM_MSG_UPDSA:
		case XFRM_MSG_DELSA:
			if (pending_type != 0 && nlh->nlmsg_seq == pending_seq)
				return handle_nlmsg(nlh, rc);
			return 0;
		default:
			return 0;
		}
	}
	return handle_nlmsg(nlh, rc);
}

/*
 * Read one datagram from fd and dispatch every message in it.
 * Returns 1 if a datagram was handled, 0 on EAGAIN, -1 on error
 * (rc->eno/estr set; remaining messages in the datagram are still
 * dispatched).  With fresh != 0 every message is parsed into its own
 * zeroed container, so no pointer or field set by one message (e.g.
 * sa2_src from a MAPPING) leaks into the callback for the next.
 */
static int
xfrm_read_one(int fd, struct rcpfk_msg *rc, int flags, int fresh)
{
	struct rcpfk_msg scratch;

	ssize_t len;
	unsigned int ulen;
	size_t alnoff;
	struct nlmsghdr *nlh;
	int ret = 1, from_req = (fd == xfrm_req_fd);
	struct rcpfk_msg err;

	if (xfrm_alnbuf == NULL) {
		/* each copied message gains at most 4 bytes of padding */
		xfrm_alnbuf = malloc(2 * XFRM_RCVBUFLEN);
		if (xfrm_alnbuf == NULL) {
			xfrm_seterror(rc, ENOMEM, "out of memory");
			return -1;
		}
	}
	if (xfrm_rcvbuf == NULL) {
		xfrm_rcvbuf = malloc(XFRM_RCVBUFLEN);
		if (xfrm_rcvbuf == NULL) {
			xfrm_seterror(rc, ENOMEM, "xfrm recv buffer");
			return -1;
		}
	}
	len = xfrm_recv(fd, xfrm_rcvbuf, XFRM_RCVBUFLEN, flags);
	if (len < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return 0;
		if (errno == ENOBUFS) {
			xfrm_stat_enobufs++;
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			    "xfrm: %s socket overflowed (ENOBUFS); kernel "
			    "messages were lost, resyncing SAD/SPD\n",
			    from_req ? "request" : "notification");
			if (from_req)
				pending_clear();	/* its reply is gone */
			xfrm_need_resync = 1;
			return 1;
		}
		xfrm_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}
	if (len == 0) {
		xfrm_seterror(rc, EPIPE, "netlink socket closed");
		return -1;
	}
	if ((size_t)len < sizeof(struct nlmsghdr)) {
		xfrm_seterror(rc, EINVAL, "short netlink read");
		return -1;
	}
	memset(&err, 0, sizeof(err));
	ulen = (unsigned int)len;
	alnoff = 0;
	for (nlh = (struct nlmsghdr *)xfrm_rcvbuf;
	     NLMSG_OK(nlh, ulen);
	     nlh = NLMSG_NEXT(nlh, ulen)) {
		struct rcpfk_msg *t = rc;
		struct nlmsghdr *m = nlh;

		/*
		 * Netlink only aligns messages to 4 bytes (NLMSG_ALIGNTO), so
		 * the 2nd, 4th ... message of a multipart batch can sit at
		 * 4 mod 8, and xfrm_userpolicy_info / xfrm_usersa_info hold
		 * __u64 lifetimes: every member access through them is then
		 * misaligned (UBSan on the live ASan rows, a SIGBUS on strict
		 * alignment CPUs).  Copy such a message to an 8-byte aligned
		 * slot.  The slots of one recv stay valid together, like
		 * xfrm_rcvbuf itself, so a reply's pointers survive the
		 * messages that follow it.
		 */
		if (((uintptr_t)nlh & 7) != 0 &&
		    alnoff + NLMSG_ALIGN(nlh->nlmsg_len) + 8 <=
		    2 * XFRM_RCVBUFLEN) {
			m = (struct nlmsghdr *)(xfrm_alnbuf + alnoff);
			memcpy(m, nlh, nlh->nlmsg_len);
			alnoff += (NLMSG_ALIGN(nlh->nlmsg_len) + 7) & ~(size_t)7;
		}

		if (fresh) {
			memset(&scratch, 0, sizeof(scratch));
			scratch.so = rc->so;
			t = &scratch;
		}
		if (xfrm_dispatch(m, t, from_req) && ret == 1) {
			ret = -1;
			err.eno = t->eno;
			memcpy(err.estr, t->estr, sizeof(err.estr));
		}
	}
	if (ret == -1) {
		rc->eno = err.eno;
		memcpy(rc->estr, err.estr, sizeof(rc->estr));
	}
	return ret;
}

static int
xfrm_wait_req(int timeout_ms)
{
	struct pollfd pfd;
	int r;

	pfd.fd = xfrm_req_fd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	do {
		r = poll(&pfd, 1, timeout_ms);
	} while (r < 0 && errno == EINTR);
	return r;
}

static int
xfrm_send_dump(uint16_t type, uint32_t seq)
{
	char buf[NLMSG_SPACE(sizeof(struct xfrm_usersa_info))];
	struct nlmsghdr *n = (void *)buf;

	memset(buf, 0, sizeof(buf));
	/* GETSA/GETPOLICY dumps take an empty (zeroed) filter body */
	n->nlmsg_len = NLMSG_LENGTH(type == XFRM_MSG_GETSA ?
	    sizeof(struct xfrm_usersa_info) : 0);
	n->nlmsg_type = type;
	n->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	n->nlmsg_seq = seq;
	n->nlmsg_pid = (uint32_t)pid;
	if (send(xfrm_req_fd, buf, n->nlmsg_len, 0) != (ssize_t)n->nlmsg_len)
		return -1;
	return 0;
}

/*
 * Re-read the kernel state after lost notifications.  The dumps go out
 * on the request socket and are consumed synchronously; replies to an
 * op that is still pending are dispatched normally on the way.
 */
static int
xfrm_resync(struct rcpfk_msg *rc)
{
	struct rcpfk_msg tmp;
	int r, ret = 0;
	/* Iterative restart, depth-bounded: a request socket that keeps
	 * overflowing during the resync dump (sustained event storm) must
	 * not recurse without bound. */
	int restart = 0;

restart_resync:
	xfrm_need_resync = 0;
	xfrm_stat_resync++;
	resync_count++;
	resync_spd_seq = 0;
	if (cb && cb->cb_spddump) {
		resync_spd_seq = XFRM_RESYNC_SEQ_BASE + 2 * resync_count - 1;
		if (xfrm_send_dump(XFRM_MSG_GETPOLICY, resync_spd_seq) == -1)
			resync_spd_seq = 0;
	}
	resync_sa_seq = XFRM_RESYNC_SEQ_BASE + 2 * resync_count;
	if (xfrm_send_dump(XFRM_MSG_GETSA, resync_sa_seq) == -1) {
		xfrm_seterror(rc, errno, "resync SA dump: %s", strerror(errno));
		resync_sa_seq = 0;
		resync_spd_seq = 0;
		return -1;
	}
	while (resync_sa_seq != 0 || resync_spd_seq != 0) {
		r = xfrm_wait_req(XFRM_REPLY_TIMEOUT_MS);
		if (r <= 0) {
			xfrm_seterror(rc, r == 0 ? ETIMEDOUT : errno,
			    "resync dump %s", r == 0 ? "timed out" :
			    strerror(errno));
			resync_sa_seq = resync_spd_seq = 0;
			return -1;
		}
		memset(&tmp, 0, sizeof(tmp));
		tmp.so = rc->so;
		if (xfrm_read_one(xfrm_req_fd, &tmp, MSG_DONTWAIT, 1) < 0)
			ret = -1;	/* keep going: the dump must finish */
		if (xfrm_need_resync) {
			/* the request socket itself overflowed mid-dump */
			plog(PLOG_INTWARN, PLOGLOC, NULL,
			    "xfrm: resync dump overflowed, restarting\n");
			resync_sa_seq = resync_spd_seq = 0;
			if (++restart > XFRM_RESYNC_MAX_RETRY) {
				xfrm_seterror(rc, EAGAIN,
				    "resync dump restart exceeded retry cap");
				return -1;
			}
			goto restart_resync;
		}
	}
	plog(PLOG_INFO, PLOGLOC, NULL, "xfrm: SAD/SPD resync %u complete\n",
	    resync_count);
	if (cb && cb->cb_resync) {
		memset(&tmp, 0, sizeof(tmp));
		tmp.so = rc->so;
		tmp.eno = ENOBUFS;
		tmp.flags = PFK_FLAG_RESYNC;
		if (cb->cb_resync(&tmp) < 0)
			ret = -1;
	}
	(void)ret;
	return 0;
}

int
rcpfk_handler(struct rcpfk_msg *rc)
{
	int r, ret = 0, n;
	uint32_t want;

	if (xfrm_req_fd < 0 || xfrm_ntf_fd < 0) {
		xfrm_seterror(rc, EBADF, "xfrm sockets not open");
		return -1;
	}
	if (rc->flags & PFK_FLAG_WAITREPLY) {
		/*
		 * Send-then-read caller: only the request socket can hold the
		 * reply, so a queued multicast event can never be parsed into
		 * rc as if it were the answer (the old single-socket spmd
		 * SPDGET bug).  Events wait for the next select() round.
		 */
		want = pending_seq;
		if (pending_type == 0)
			return 0;	/* already completed (or failed) */
		while (pending_type != 0 && pending_seq == want) {
			r = xfrm_wait_req(XFRM_REPLY_TIMEOUT_MS);
			if (r <= 0) {
				xfrm_seterror(rc, r == 0 ? ETIMEDOUT : errno,
				    "no reply to xfrm request seq %u", want);
				pending_clear();
				return -1;
			}
			r = xfrm_read_one(xfrm_req_fd, rc, MSG_DONTWAIT, 0);
			if (r < 0)
				return -1;
			if (xfrm_need_resync) {
				xfrm_seterror(rc, ENOBUFS,
				    "reply to seq %u lost (ENOBUFS)", want);
				return -1;
			}
		}
		return 0;
	}
	/* events first: the echo of our own op precedes its ACK */
	for (n = 0; n < 256; n++) {
		r = xfrm_read_one(xfrm_ntf_fd, rc, MSG_DONTWAIT, 1);
		if (r == 0)
			break;
		if (r < 0)
			ret = -1;
	}
	for (n = 0; n < 256; n++) {
		r = xfrm_read_one(xfrm_req_fd, rc, MSG_DONTWAIT, 1);
		if (r == 0)
			break;
		if (r < 0)
			ret = -1;
	}
	if (xfrm_need_resync) {
		struct rcpfk_msg tmp;

		memset(&tmp, 0, sizeof(tmp));
		tmp.so = rc->so;
		if (xfrm_resync(&tmp) < 0) {
			rc->eno = tmp.eno;
			memcpy(rc->estr, tmp.estr, sizeof(rc->estr));
			return -1;
		}
	}
	return ret;
}
