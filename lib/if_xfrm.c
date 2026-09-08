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

#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#ifdef ENABLE_NATT
#include <linux/udp.h>
#endif

#include <netinet/in.h>

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
#ifndef XFRMGRP_ACQUIRE
#define XFRMGRP_ACQUIRE 1
#define XFRMGRP_EXPIRE  2
#define XFRMGRP_SA      4
#define XFRMGRP_POLICY  8
#endif

#define XFRM_BUFLEN		4096
#define XFRM_RCVBUFLEN		(128 * 1024)

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
static uint32_t pending_spi;
static uint8_t pending_satype;
static uint8_t pending_samode;
static struct sockaddr_storage pending_src, pending_dst;
static int pending_has_addrs;
static char *xfrm_rcvbuf;

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

struct xfrm_aeadmap {
	int rct;
	const char *name;
	unsigned int icv_bits;
};

static const struct xfrm_aeadmap aead_map[] = {
	{ RCT_ALG_AES_GCM,	"rfc4106(gcm(aes))",	128 },
	{ RCT_ALG_AES_GCM8,	"rfc4106(gcm(aes))",	64 },
	{ RCT_ALG_AES_GCM12,	"rfc4106(gcm(aes))",	96 },
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
}

static void
pending_set(struct rcpfk_msg *rc, int type, uint32_t seq)
{
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
full_prefix(uint16_t family)
{
	return family == AF_INET6 ? 128 : 32;
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
xfrm_open(struct rcpfk_msg *rc)
{
	struct sockaddr_nl local;
	int rcv = XFRM_RCVBUFLEN;
	socklen_t alen;

	rc->so = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (rc->so == -1) {
		xfrm_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}
#if SOCK_CLOEXEC == 0
	{
		int fl = fcntl(rc->so, F_GETFD);
		if (fl >= 0)
			(void)fcntl(rc->so, F_SETFD, fl | FD_CLOEXEC);
	}
#endif
	if (setsockopt(rc->so, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv)) == -1 ||
	    setsockopt(rc->so, SOL_SOCKET, SO_SNDBUF, &rcv, sizeof(rcv)) == -1) {
		xfrm_seterror(rc, errno, "%s", strerror(errno));
		close(rc->so);
		rc->so = -1;
		return -1;
	}
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = XFRMGRP_ACQUIRE | XFRMGRP_EXPIRE |
	    XFRMGRP_SA | XFRMGRP_POLICY;
	if (bind(rc->so, (struct sockaddr *)&local, sizeof(local)) == -1) {
		xfrm_seterror(rc, errno, "%s", strerror(errno));
		close(rc->so);
		rc->so = -1;
		return -1;
	}
	alen = sizeof(local);
	if (getsockname(rc->so, (struct sockaddr *)&local, &alen) == 0)
		pid = (pid_t)local.nl_pid;
	else
		pid = getpid();
	return 0;
}

static int
xfrm_nl_send(struct rcpfk_msg *rc, struct nlmsghdr *n)
{
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg;
	ssize_t nsent;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	iov.iov_base = n;
	iov.iov_len = n->nlmsg_len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	nsent = sendmsg(rc->so, &msg, 0);
	if (nsent < 0 || (size_t)nsent != n->nlmsg_len) {
		xfrm_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}
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
		    full_prefix(family), full_prefix(family),
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
			    add_encap_attr(n, sizeof(buf), rc))
				return -1;
		} else if (add_enc_attr(n, sizeof(buf), rc) ||
		    add_auth_attr(n, sizeof(buf), rc) ||
		    add_encap_attr(n, sizeof(buf), rc))
			return -1;
	}
	pending_set(rc, nltype, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
}

int
rcpfk_init(struct rcpfk_msg *rc, struct rcpfk_cb *cb0)
{
	struct rcpfk_cb null_cb = { 0 };

	pid = getpid();
	if (rc->flags & PFK_FLAG_NOHARM)
		f_noharm++;
	if (xfrm_open(rc))
		return -1;
	cb = &null_cb;
	cb = cb0;
	pending_clear();
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
	}
	if (rc->so >= 0 && close(rc->so) == -1) {
		xfrm_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}
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
	return xfrm_nl_send(rc, n);
}

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
	if (xfrm_addattr(n, sizeof(buf), XFRMA_MIGRATE, &m, sizeof(m)))
		return -1;
	pending_set(rc, XFRM_MSG_MIGRATE, n->nlmsg_seq);
	return xfrm_nl_send(rc, n);
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

static void
usersa_to_rc(const struct xfrm_usersa_info *sa, struct rcpfk_msg *rc)
{
	rc->spi = sa->id.spi;
	rc->satype = proto_to_satype(sa->id.proto);
	rc->samode = x_to_mode(sa->mode);
	rc->reqid = sa->reqid;
	rc->wsize = (uint8_t)sa->replay_window;
	rc->lft_hard_time = sa->lft.hard_add_expires_seconds == XFRM_INF ? 0 :
	    sa->lft.hard_add_expires_seconds;
	rc->lft_soft_time = sa->lft.soft_add_expires_seconds == XFRM_INF ? 0 :
	    sa->lft.soft_add_expires_seconds;
	rc->lft_hard_bytes = sa->lft.hard_byte_limit == XFRM_INF ? 0 :
	    sa->lft.hard_byte_limit;
	rc->lft_soft_bytes = sa->lft.soft_byte_limit == XFRM_INF ? 0 :
	    sa->lft.soft_byte_limit;
	rc->lft_current_bytes = sa->curlft.bytes;
	rc->lft_current_alloc = sa->curlft.use_time ? 1 : sa->curlft.packets;
	rc->lft_current_add = sa->curlft.add_time;
	rc->lft_current_use = sa->curlft.use_time;
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
handle_policy(struct xfrm_userpolicy_info *xp, struct rcpfk_msg *rc, int dumped)
{
	int (*fn)(struct rcpfk_msg *) = NULL;

	userpol_to_rc(xp, rc);
	if (dumped)
		fn = cb && cb->cb_spddump ? cb->cb_spddump : NULL;
	else if (pending_type == XFRM_MSG_UPDPOLICY)
		fn = cb && cb->cb_spdupdate ? cb->cb_spdupdate : NULL;
	else if (pending_type == XFRM_MSG_GETPOLICY)
		fn = cb && cb->cb_spdget ? cb->cb_spdget : NULL;
	else
		fn = cb && cb->cb_spdadd ? cb->cb_spdadd : NULL;
	if (!dumped)
		pending_clear();
	if (fn && fn(rc) < 0)
		return -1;
	return 0;
}

static int
handle_nlmsg(struct nlmsghdr *nlh, struct rcpfk_msg *rc)
{
	struct nlmsgerr *err;
	int ptype;

	rc->seq = nlh->nlmsg_seq;
	switch (nlh->nlmsg_type) {
	case NLMSG_NOOP:
		return 0;
	case NLMSG_DONE:
		pending_clear();
		return 0;
	case NLMSG_ERROR:
		err = NLMSG_DATA(nlh);
		rc->seq = err->msg.nlmsg_seq;
		if (err->error != 0) {
			pending_clear();
			xfrm_seterror(rc, -err->error, "xfrm netlink: %s",
			    strerror(-err->error));
			return -1;
		}
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
		/* dumps arrive as NEWPOLICY + NLM_F_MULTI, then NLMSG_DONE */
		return handle_policy(NLMSG_DATA(nlh), rc,
		    pending_type == XFRM_MSG_GETPOLICY);
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

int
rcpfk_handler(struct rcpfk_msg *rc)
{
	ssize_t len;
	unsigned int ulen;
	struct nlmsghdr *nlh;

	if (xfrm_rcvbuf == NULL) {
		xfrm_rcvbuf = malloc(XFRM_RCVBUFLEN);
		if (xfrm_rcvbuf == NULL) {
			xfrm_seterror(rc, ENOMEM, "xfrm recv buffer");
			return -1;
		}
	}
	len = recv(rc->so, xfrm_rcvbuf, XFRM_RCVBUFLEN, 0);
	if (len < 0) {
		xfrm_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}
	if ((size_t)len < sizeof(struct nlmsghdr)) {
		xfrm_seterror(rc, EINVAL, "short netlink read");
		return -1;
	}
	ulen = (unsigned int)len;
	for (nlh = (struct nlmsghdr *)xfrm_rcvbuf;
	     NLMSG_OK(nlh, ulen);
	     nlh = NLMSG_NEXT(nlh, ulen)) {
		if (handle_nlmsg(nlh, rc))
			return -1;
	}
	return 0;
}
