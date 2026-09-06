/* $Id$ */
/*
 * Userspace SAD/SPD backend (DPDK / appliance dataplane).
 * Same rcpfk_* ABI as if_pfkeyv2.c / if_xfrm.c (XOR via --with-km-backend).
 * Loopback socketpair drives iked callbacks; optional unix datagram
 * to RACOON2_DATAPLANE_SOCK mirrors SA/SPD to a consumer.
 *
 * Not a second vtable — rcpfk_* is the southbound plugin.
 * No XFRMA_OFFLOAD_DEV / if_id / eBPF here.
 *
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "if_pfkeyv2.h"

#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

#define US_MAGIC	0x52324450u	/* 'R2DP' */
#define US_VER		1
#define US_GETSPI	1
#define US_UPDSA	2
#define US_NEWSA	3
#define US_DELSA	4
#define US_SPDADD	5
#define US_SPDDEL	6
#define US_REGISTER	7
#define US_GET		8
#define US_BUFLEN	2048

uint32_t rc_spirange_min = 0x00000100;
uint32_t rc_spirange_max = 0x0fffffff;

static struct rcpfk_cb *cb;
static int reply_fd = -1;
static int dp_fd = -1;
static uint32_t next_spi;

struct us_hdr {
	uint32_t magic;
	uint32_t ver;
	uint32_t type;
	uint32_t seq;
	uint32_t spi;
	uint32_t reqid;
	uint32_t status;
	uint8_t satype;
	uint8_t samode;
	uint8_t dir;
	uint8_t natt_type;
	uint16_t natt_sport;
	uint16_t natt_dport;
	uint16_t src_len;
	uint16_t dst_len;
	uint16_t enckeylen;
	uint16_t authkeylen;
	uint8_t enctype;
	uint8_t authtype;
	uint8_t wsize;
	uint8_t pad;
	uint64_t lft_hard_time;
	uint64_t lft_hard_bytes;
	uint64_t lft_soft_time;
	uint64_t lft_soft_bytes;
};

static void
us_seterror(struct rcpfk_msg *rc, int eno, const char *fmt, ...)
{
	va_list ap;

	rc->eno = eno;
	va_start(ap, fmt);
	vsnprintf(rc->estr, sizeof(rc->estr), fmt, ap);
	va_end(ap);
}

static void
cloexec(int fd)
{
#ifdef F_SETFD
	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
	(void)fd;
}

static uint16_t
salen(struct sockaddr *sa)
{
	if (sa == NULL)
		return 0;
	if (sa->sa_family == AF_INET)
		return sizeof(struct sockaddr_in);
#ifdef AF_INET6
	if (sa->sa_family == AF_INET6)
		return sizeof(struct sockaddr_in6);
#endif
	return sizeof(struct sockaddr_storage);
}

static int
us_pack(char *buf, size_t buflen, uint32_t type, struct rcpfk_msg *rc)
{
	struct us_hdr *h;
	char *p;
	uint16_t sl, dl, el, al;
	size_t need;

	sl = salen(rc->sa_src);
	dl = salen(rc->sa_dst);
	el = (uint16_t)rc->enckeylen;
	al = (uint16_t)rc->authkeylen;
	need = sizeof(*h) + sl + dl + el + al;
	if (need > buflen)
		return -1;
	h = (struct us_hdr *)buf;
	memset(h, 0, sizeof(*h));
	h->magic = US_MAGIC;
	h->ver = US_VER;
	h->type = type;
	h->seq = rc->seq;
	h->spi = rc->spi;
	h->reqid = rc->reqid;
	h->satype = rc->satype;
	h->samode = rc->samode;
	h->dir = rc->dir;
	h->natt_type = rc->natt_type;
	h->natt_sport = rc->natt_sport;
	h->natt_dport = rc->natt_dport;
	h->src_len = sl;
	h->dst_len = dl;
	h->enckeylen = el;
	h->authkeylen = al;
	h->enctype = rc->enctype;
	h->authtype = rc->authtype;
	h->wsize = rc->wsize;
	h->lft_hard_time = rc->lft_hard_time;
	h->lft_hard_bytes = rc->lft_hard_bytes;
	h->lft_soft_time = rc->lft_soft_time;
	h->lft_soft_bytes = rc->lft_soft_bytes;
	p = buf + sizeof(*h);
	if (sl && rc->sa_src) {
		memcpy(p, rc->sa_src, sl);
		p += sl;
	}
	if (dl && rc->sa_dst) {
		memcpy(p, rc->sa_dst, dl);
		p += dl;
	}
	if (el && rc->enckey) {
		memcpy(p, rc->enckey, el);
		p += el;
	}
	if (al && rc->authkey)
		memcpy(p, rc->authkey, al);
	return (int)need;
}

static int
us_post(struct rcpfk_msg *rc, uint32_t type)
{
	char buf[US_BUFLEN];
	int n;

	n = us_pack(buf, sizeof(buf), type, rc);
	if (n < 0) {
		us_seterror(rc, ENOMEM, "userspace message too large");
		return -1;
	}
	if (reply_fd >= 0 && write(reply_fd, buf, (size_t)n) != n) {
		us_seterror(rc, errno, "loopback write: %s", strerror(errno));
		return -1;
	}
	if (dp_fd >= 0)
		(void)write(dp_fd, buf, (size_t)n);
	return 0;
}

static int
us_open_dataplane(void)
{
	const char *path;
	struct sockaddr_un un;
	int fd;

	path = getenv("RACOON2_DATAPLANE_SOCK");
	if (path == NULL || *path == '\0')
		return 0;
	if (strlen(path) >= sizeof(un.sun_path))
		return 0;
	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return 0;
	cloexec(fd);
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strncpy(un.sun_path, path, sizeof(un.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		close(fd);
		return 0;
	}
	dp_fd = fd;
	return 0;
}

int
rcpfk_init(struct rcpfk_msg *rc, struct rcpfk_cb *cb0)
{
	int sp[2];
	int type = SOCK_DGRAM | SOCK_CLOEXEC;

	cb = cb0;
	reply_fd = -1;
	dp_fd = -1;
	next_spi = rc_spirange_min;
	rc->so = -1;
	if (socketpair(AF_UNIX, type, 0, sp) < 0 &&
	    socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) < 0 &&
	    socketpair(AF_UNIX, SOCK_STREAM, 0, sp) < 0) {
		us_seterror(rc, errno, "socketpair: %s", strerror(errno));
		return -1;
	}
	cloexec(sp[0]);
	cloexec(sp[1]);
	rc->so = sp[0];
	reply_fd = sp[1];
	(void)us_open_dataplane();
	return 0;
}

int
rcpfk_clean(struct rcpfk_msg *rc)
{
	cb = NULL;
	if (reply_fd >= 0)
		close(reply_fd);
	reply_fd = -1;
	if (dp_fd >= 0)
		close(dp_fd);
	dp_fd = -1;
	if (rc->so >= 0)
		close(rc->so);
	rc->so = -1;
	return 0;
}

int
rcpfk_send_getspi(struct rcpfk_msg *rc)
{
	if (rc->spi == 0) {
		if (next_spi < rc_spirange_min || next_spi > rc_spirange_max)
			next_spi = rc_spirange_min;
		rc->spi = htonl(next_spi++);
		if (next_spi > rc_spirange_max)
			next_spi = rc_spirange_min;
	}
	return us_post(rc, US_GETSPI);
}

int
rcpfk_send_update(struct rcpfk_msg *rc)
{
	return us_post(rc, US_UPDSA);
}

int
rcpfk_send_add(struct rcpfk_msg *rc)
{
	return us_post(rc, US_NEWSA);
}

int
rcpfk_send_delete(struct rcpfk_msg *rc)
{
	return us_post(rc, US_DELSA);
}

int
rcpfk_send_get(struct rcpfk_msg *rc)
{
	return us_post(rc, US_GET);
}

int
rcpfk_send_acquire(struct rcpfk_msg *rc)
{
	(void)rc;
	return 0;
}

int
rcpfk_send_register(struct rcpfk_msg *rc)
{
	return us_post(rc, US_REGISTER);
}

int
rcpfk_send_spdupdate(struct rcpfk_msg *rc)
{
	return us_post(rc, US_SPDADD);
}

int
rcpfk_send_spdadd(struct rcpfk_msg *rc)
{
	return us_post(rc, US_SPDADD);
}

int
rcpfk_send_spddelete(struct rcpfk_msg *rc)
{
	return us_post(rc, US_SPDDEL);
}

int
rcpfk_send_spddelete2(struct rcpfk_msg *rc)
{
	return us_post(rc, US_SPDDEL);
}

int
rcpfk_send_spdget(struct rcpfk_msg *rc)
{
	(void)rc;
	return 0;
}

int
rcpfk_send_spddump(struct rcpfk_msg *rc)
{
	(void)rc;
	return 0;
}

int
rcpfk_send_migrate(struct rcpfk_msg *rc)
{
	us_seterror(rc, EOPNOTSUPP, "userspace migrate not implemented");
	return -1;
}

int
rcpfk_supported_auth(int algtype)
{
	(void)algtype;
	return 1;
}

int
rcpfk_supported_enc(int algtype)
{
	(void)algtype;
	return 1;
}

int
rcpfk_handler(struct rcpfk_msg *rc)
{
	char buf[US_BUFLEN];
	struct us_hdr *h;
	ssize_t n;
	int r = 0;

	n = recv(rc->so, buf, sizeof(buf), 0);
	if (n < 0) {
		us_seterror(rc, errno, "%s", strerror(errno));
		return -1;
	}
	if ((size_t)n < sizeof(*h)) {
		us_seterror(rc, EINVAL, "short userspace message");
		return -1;
	}
	h = (struct us_hdr *)buf;
	if (h->magic != US_MAGIC || h->ver != US_VER) {
		us_seterror(rc, EINVAL, "bad userspace magic/ver");
		return -1;
	}
	if (h->status != 0) {
		us_seterror(rc, (int)h->status, "dataplane status %u", h->status);
		return -1;
	}
	rc->seq = h->seq;
	rc->spi = h->spi;
	rc->reqid = h->reqid;
	rc->satype = h->satype;
	rc->samode = h->samode;
	rc->dir = h->dir;
	rc->enctype = h->enctype;
	rc->authtype = h->authtype;
	rc->wsize = h->wsize;
	rc->lft_hard_time = h->lft_hard_time;
	rc->lft_hard_bytes = h->lft_hard_bytes;
	rc->lft_soft_time = h->lft_soft_time;
	rc->lft_soft_bytes = h->lft_soft_bytes;
	{
		char *p = buf + sizeof(*h);
		size_t left = (size_t)n - sizeof(*h);

		if (h->src_len) {
			if (h->src_len > left ||
			    h->src_len > sizeof(rc->sa_src_storage)) {
				us_seterror(rc, EINVAL, "bad src_len");
				return -1;
			}
			memcpy(&rc->sa_src_storage, p, h->src_len);
			rc->sa_src = (struct sockaddr *)&rc->sa_src_storage;
			p += h->src_len;
			left -= h->src_len;
		}
		if (h->dst_len) {
			if (h->dst_len > left ||
			    h->dst_len > sizeof(rc->sa_dst_storage)) {
				us_seterror(rc, EINVAL, "bad dst_len");
				return -1;
			}
			memcpy(&rc->sa_dst_storage, p, h->dst_len);
			rc->sa_dst = (struct sockaddr *)&rc->sa_dst_storage;
		}
	}
	if (cb == NULL)
		return 0;
	switch (h->type) {
	case US_GETSPI:
		if (cb->cb_getspi)
			r = cb->cb_getspi(rc);
		break;
	case US_GET:
		if (cb->cb_get)
			r = cb->cb_get(rc);
		break;
	case US_UPDSA:
		if (cb->cb_update)
			r = cb->cb_update(rc);
		break;
	case US_NEWSA:
		if (cb->cb_add)
			r = cb->cb_add(rc);
		break;
	case US_DELSA:
		if (cb->cb_delete)
			r = cb->cb_delete(rc);
		break;
	case US_SPDADD:
		if (cb->cb_spdadd)
			r = cb->cb_spdadd(rc);
		else if (cb->cb_spdupdate)
			r = cb->cb_spdupdate(rc);
		break;
	case US_SPDDEL:
		if (cb->cb_spddelete)
			r = cb->cb_spddelete(rc);
		break;
	default:
		break;
	}
	return r;
}
