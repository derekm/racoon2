/*	$NetBSD: admin.c,v 1.41 2018/05/19 20:14:56 maxv Exp $	*/

/* Id: admin.c,v 1.25 2006/04/06 14:31:04 manubsd Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Unix admin socket for ikedctl. Not a KM backend: kernel SAD/SPD
 * on Linux is ip xfrm. IKE dump/flush/initiate live here.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>

#include "racoon.h"
#include "plog.h"
#include "gcmalloc.h"
#include "admin.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "oakley.h"
#include "ikev1/handler.h"
#include "ikev1/isakmp_inf.h"
#include "ikev1_impl.h"

const char *adminsock_path = ADMINSOCK_PATH;
uid_t adminsock_owner = 0;
gid_t adminsock_group = 0;
mode_t adminsock_mode = 0600;

static struct sockaddr_un sunaddr;
static int sock_admin = -1;

static int admin_dispatch(int, char *);
static int admin_reply(int, int, struct admin_com *, rc_vchar_t *);
static rc_vchar_t *admin_dump_isakmp(void);
static void admin_flush_one_ph1(struct ph1handle *);

int
admin_socket(void)
{
	return sock_admin;
}

int
admin_open(void)
{
	int flags;

	if (adminsock_path == NULL) {
		sock_admin = -1;
		return 0;
	}

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path),
		 "%s", adminsock_path);

	sock_admin = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_admin == -1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "socket: %s\n", strerror(errno));
		return -1;
	}
	flags = fcntl(sock_admin, F_GETFD, 0);
	if (flags >= 0)
		(void)fcntl(sock_admin, F_SETFD, flags | FD_CLOEXEC);

	unlink(sunaddr.sun_path);
	if (bind(sock_admin, (struct sockaddr *)&sunaddr,
		 sizeof(sunaddr)) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "bind(sockname:%s): %s\n",
		     sunaddr.sun_path, strerror(errno));
		(void)close(sock_admin);
		sock_admin = -1;
		return -1;
	}
	if (chown(sunaddr.sun_path, adminsock_owner, adminsock_group) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "chown(%s, %d, %d): %s\n",
		     sunaddr.sun_path, adminsock_owner, adminsock_group,
		     strerror(errno));
		(void)close(sock_admin);
		sock_admin = -1;
		return -1;
	}
	if (chmod(sunaddr.sun_path, adminsock_mode) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "chmod(%s, 0%03o): %s\n",
		     sunaddr.sun_path, adminsock_mode, strerror(errno));
		(void)close(sock_admin);
		sock_admin = -1;
		return -1;
	}
	if (listen(sock_admin, 5) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "listen(sockname:%s): %s\n",
		     sunaddr.sun_path, strerror(errno));
		(void)close(sock_admin);
		sock_admin = -1;
		return -1;
	}
	plog(PLOG_DEBUG, PLOGLOC, NULL,
	     "open %s as iked admin\n", sunaddr.sun_path);
	return 0;
}

int
admin_close(void)
{
	if (sock_admin >= 0) {
		(void)close(sock_admin);
		sock_admin = -1;
	}
	if (adminsock_path)
		unlink(adminsock_path);
	return 0;
}

void
admin_process(void)
{
	int so2;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	struct admin_com hdr;
	char *combuf = NULL;
	ssize_t n;
	int flags;

	so2 = accept(sock_admin, (struct sockaddr *)&from, &fromlen);
	if (so2 < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to accept admin command: %s\n",
			     strerror(errno));
		return;
	}
	flags = fcntl(so2, F_GETFD, 0);
	if (flags >= 0)
		(void)fcntl(so2, F_SETFD, flags | FD_CLOEXEC);
	{
		struct timeval tv;

		tv.tv_sec = 2;
		tv.tv_usec = 0;
		/* Cap recv, not O_NONBLOCK: accept then recv races connect-then-send. */
		(void)setsockopt(so2, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		(void)setsockopt(so2, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	}

	n = recv(so2, (char *)&hdr, sizeof(hdr), MSG_PEEK);
	if (n < 0 || (size_t)n < sizeof(hdr)) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "invalid header length of admin command\n");
		goto end;
	}
	if (hdr.ac_len < sizeof(hdr) || hdr.ac_len > 65535) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "invalid admin command length %u\n", hdr.ac_len);
		goto end;
	}
	combuf = racoon_malloc(hdr.ac_len);
	if (combuf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to alloc buffer for admin command\n");
		goto end;
	}
	n = recv(so2, combuf, hdr.ac_len, 0);
	if (n < 0 || (size_t)n < hdr.ac_len) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to recv admin command: %s\n",
		     n < 0 ? strerror(errno) : "short read");
		goto end;
	}
	(void)admin_dispatch(so2, combuf);
end:
	(void)close(so2);
	if (combuf)
		racoon_free(combuf);
}

static void
admin_ph1dump_from_v2(struct ph1dump *pd, struct ikev2_sa *sa)
{
	size_t slen;

	memset(pd, 0, sizeof(*pd));
	memcpy(&pd->index, &sa->index, sizeof(sa->index));
	pd->status = sa->state;
	pd->side = sa->is_initiator ? INITIATOR : RESPONDER;
	if (sa->remote) {
		slen = sysdep_sa_len(sa->remote);
		if (slen > sizeof(pd->remote))
			slen = sizeof(pd->remote);
		memcpy(&pd->remote, sa->remote, slen);
	}
	if (sa->local) {
		slen = sysdep_sa_len(sa->local);
		if (slen > sizeof(pd->local))
			slen = sizeof(pd->local);
		memcpy(&pd->local, sa->local, slen);
	}
	pd->version = 0x20;
	pd->etype = 0;
	pd->created = 0;
	pd->ph2cnt = sa->child_created;
}

static rc_vchar_t *
admin_dump_isakmp(void)
{
	rc_vchar_t *v1 = NULL, *out;
	struct ikev2_sa *sa;
	struct ph1dump *pd;
	int n2 = 0;
	size_t l1 = 0, l2;

	TAILQ_FOREACH(sa, &ikev2_sa_list, link) {
		if (sa->state == IKEV2_STATE_DYING ||
		    sa->state == IKEV2_STATE_DEAD)
			continue;
		n2++;
	}
#ifdef IKEV1
	v1 = dumpph1();
	if (v1)
		l1 = v1->l;
#endif
	l2 = (size_t)n2 * sizeof(struct ph1dump);
	if (l1 + l2 == 0) {
		if (v1)
			rc_vfree(v1);
		out = rc_vmalloc(1);
		if (out)
			out->l = 0;
		return out;
	}
	out = rc_vmalloc(l1 + l2);
	if (out == NULL) {
		if (v1)
			rc_vfree(v1);
		return NULL;
	}
	if (l1)
		memcpy(out->v, v1->v, l1);
	pd = (struct ph1dump *)(out->s + l1);
	TAILQ_FOREACH(sa, &ikev2_sa_list, link) {
		if (sa->state == IKEV2_STATE_DYING ||
		    sa->state == IKEV2_STATE_DEAD)
			continue;
		admin_ph1dump_from_v2(pd, sa);
		pd++;
	}
	if (v1)
		rc_vfree(v1);
	return out;
}

static void
admin_flush_one_ph1(struct ph1handle *p)
{
	struct ph2handle *p2;

	if (p->status == PHASE1ST_ESTABLISHED)
		isakmp_info_send_d1(p);
	while ((p2 = LIST_FIRST(&p->ph2tree)) != NULL) {
		if (p2->status == PHASE2ST_ESTABLISHED)
			isakmp_info_send_d2(p2);
		delete_spd(p2);
		destroy_ph2(p2);
	}
	remph1(p);
	delph1(p);
}

static int
admin_dispatch(int so2, char *combuf)
{
	struct admin_com *com = (struct admin_com *)combuf;
	rc_vchar_t *buf = NULL;
	int l_ac_errno = 0;
	uint16_t cmd;

	cmd = com->ac_cmd;
	if (cmd & ADMIN_FLAG_VERSION)
		cmd &= ~ADMIN_FLAG_VERSION;
	else
		com->ac_version = 0;

	switch (cmd) {
	case ADMIN_RELOAD_CONF:
		(void)kill(getpid(), SIGHUP);
		break;

	case ADMIN_SHOW_SA:
		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
			buf = admin_dump_isakmp();
			if (buf == NULL)
				l_ac_errno = ENOMEM;
			break;
		case ADMIN_PROTO_IPSEC:
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			l_ac_errno = ENOTSUP;
			plog(PLOG_INFO, PLOGLOC, NULL,
			     "kernel SAD is ip xfrm state, not admin show-sa\n");
			break;
		default:
			l_ac_errno = ENOTSUP;
			break;
		}
		break;

	case ADMIN_FLUSH_SA:
		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
#ifdef IKEV1
			flushph1();
#endif
#ifdef IKEV2
			ikev2_shutdown();
#endif
			break;
		case ADMIN_PROTO_IPSEC:
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			l_ac_errno = ENOTSUP;
			plog(PLOG_INFO, PLOGLOC, NULL,
			     "kernel SAD is ip xfrm state flush, not admin flush-sa\n");
			break;
		default:
			l_ac_errno = ENOTSUP;
			break;
		}
		break;

	case ADMIN_ESTABLISH_SA:
	case ADMIN_ESTABLISH_SA_PSK: {
		struct admin_com_indexes *ndx;
		struct sockaddr *dst;
		char host[NI_MAXHOST];
		char *name = NULL;

		if (com->ac_len < sizeof(*com) + sizeof(*ndx)) {
			l_ac_errno = EINVAL;
			break;
		}
		ndx = (struct admin_com_indexes *)(com + 1);
		dst = (struct sockaddr *)&ndx->dst;
		if (cmd == ADMIN_ESTABLISH_SA &&
		    com->ac_len > sizeof(*com) + sizeof(*ndx))
			name = (char *)(ndx + 1);
		if (com->ac_proto != ADMIN_PROTO_ISAKMP) {
			l_ac_errno = ENOTSUP;
			break;
		}
		if (getnameinfo(dst, sysdep_sa_len(dst), host, sizeof(host),
				NULL, 0, NI_NUMERICHOST) != 0) {
			l_ac_errno = EINVAL;
			break;
		}
		plog(PLOG_INFO, PLOGLOC, NULL,
		     "admin establish-sa %s%s%s\n", host,
		     name ? " selector " : "", name ? name : "");
		l_ac_errno = isakmp_force_initiate(name, host);
		break;
	}

	case ADMIN_DELETE_ALL_SA_DST: {
		struct admin_com_indexes *ndx;
		struct sockaddr *dst;
#ifdef IKEV1
		struct ph1handle *iph1;
#endif

		if (com->ac_len < sizeof(*com) + sizeof(*ndx)) {
			l_ac_errno = EINVAL;
			break;
		}
		ndx = (struct admin_com_indexes *)(com + 1);
		dst = (struct sockaddr *)&ndx->dst;
#ifdef IKEV1
		while ((iph1 = getph1bydstaddrwop(dst)) != NULL)
			admin_flush_one_ph1(iph1);
#endif
#ifdef IKEV2
		{
			struct ikev2_sa *sa, *next;

			for (sa = IKEV2_SA_LIST_FIRST(&ikev2_sa_list); sa;
			     sa = next) {
				next = IKEV2_SA_LIST_NEXT(sa);
				if (!sa->remote ||
				    rcs_cmpsa_wop(sa->remote, dst) != 0)
					continue;
				if (sa->state == IKEV2_STATE_DYING ||
				    sa->state == IKEV2_STATE_DEAD)
					continue;
				ikev2_sa_delete(sa);
			}
		}
#endif
		break;
	}

	case ADMIN_SHOW_SCHED:
	case ADMIN_SHOW_EVT:
	case ADMIN_GET_SA_CERT:
	case ADMIN_DELETE_SA:
	default:
		l_ac_errno = ENOTSUP;
		break;
	}

	return admin_reply(so2, l_ac_errno, com, buf);
}

static int
admin_reply(int so, int l_ac_errno, struct admin_com *req, rc_vchar_t *buf)
{
	size_t tlen;
	struct admin_com *combuf;
	char *retbuf;
	size_t sent = 0;
	ssize_t n;

	tlen = sizeof(*combuf) + (buf ? buf->l : 0);
	retbuf = racoon_calloc(1, tlen);
	if (retbuf == NULL) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "failed to allocate admin buffer\n");
		if (buf)
			rc_vfree(buf);
		return -1;
	}
	combuf = (struct admin_com *)retbuf;
	combuf->ac_len = (u_int16_t)tlen;
	combuf->ac_cmd = req->ac_cmd & ~ADMIN_FLAG_VERSION;
	if (tlen != (u_int32_t)combuf->ac_len && l_ac_errno == 0) {
		combuf->ac_len_high = tlen >> 16;
		combuf->ac_cmd |= ADMIN_FLAG_LONG_REPLY;
	} else {
		combuf->ac_errno = l_ac_errno;
	}
	combuf->ac_proto = req->ac_proto;
	if (buf != NULL)
		memcpy(retbuf + sizeof(*combuf), buf->v, buf->l);

	/*
	 * Send the whole reply; retry on EINTR, fail on short
	 * writes. Ported from racoon (ipsec-tools) admin_reply()
	 * (6892e96d-shaped).
	 */
	while (sent < tlen) {
		n = send(so, retbuf + sent, tlen - sent, 0);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to send admin command: %s\n",
			     strerror(errno));
			racoon_free(retbuf);
			if (buf)
				rc_vfree(buf);
			return -1;
		}
		if (n == 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "failed to send admin command: sent %zu of %zu bytes\n",
			     sent, tlen);
			racoon_free(retbuf);
			if (buf)
				rc_vfree(buf);
			return -1;
		}
		sent += (size_t)n;
	}
	racoon_free(retbuf);
	if (buf)
		rc_vfree(buf);
	return 0;
}

int
admin2pfkey_proto(u_int proto)
{
	(void)proto;
	return -1;
}
