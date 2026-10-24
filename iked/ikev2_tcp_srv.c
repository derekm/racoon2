/* $Id$ */
/*
 * iked/ikev2_tcp_srv.c -- RFC 9329 TCP listener + stream registry.
 *
 * See ikev2_tcp_srv.h.  Single-threaded; a plain linked list is enough.  The
 * responder registry only ever ACCEPTS (fully connected) streams, so write
 * readiness is purely "outbound bytes pending" -- connect-completion wake
 * belongs to the initiator path and is driven separately with evloop_wait_rw.
 */
#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "racoon.h"
#include "ikev2_tcp_stream.h"
#include "ikev2_tcp_srv.h"

struct tcp_conn {
	struct tcp_conn *next;
	struct tcp_stream *st;
};

static struct tcp_conn *conns;
static int listener_fd = -1;
static tcp_stream_dispatch g_dispatch;
static void *g_arg;

static int
sa_len(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		return 0;
	}
}

static int
set_nonblock(int fd)
{
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl < 0)
		return -1;
	return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void
tcp_srv_init(tcp_stream_dispatch dispatch, void *arg)
{
	conns = NULL;
	listener_fd = -1;
	g_dispatch = dispatch;
	g_arg = arg;
}

void
tcp_srv_fini(void)
{
	while (conns) {
		struct tcp_conn *c = conns;
		conns = c->next;
		tcp_stream_free(c->st);
		free(c);
	}
	if (listener_fd >= 0) {
		close(listener_fd);
		listener_fd = -1;
	}
}

int
tcp_srv_open_listener(const struct sockaddr *local, int port)
{
	struct sockaddr_storage la;
	int fd = -1, on = 1;
	int len;

	if (local == NULL) {
		errno = EINVAL;
		return -1;
	}
	len = sa_len(local);
	if (len == 0) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	memcpy(&la, local, len);
	if (port != 0) {
		switch (la.ss_family) {
		case AF_INET:
			((struct sockaddr_in *)&la)->sin_port = htons(port);
			break;
		case AF_INET6:
			((struct sockaddr_in6 *)&la)->sin6_port = htons(port);
			break;
		}
	}
	fd = socket(la.ss_family, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
		goto fail;
	if (set_nonblock(fd) < 0)
		goto fail;
	if (bind(fd, (struct sockaddr *)&la, len) < 0)
		goto fail;
	if (listen(fd, 32) < 0)
		goto fail;
	listener_fd = fd;
	return fd;
      fail:
	close(fd);
	listener_fd = -1;
	return -1;
}

int
tcp_srv_listener_fd(void)
{
	return listener_fd;
}

int
tcp_srv_accept_pending(void)
{
	int n = 0;

	if (listener_fd < 0)
		return 0;
	for (;;) {
		struct tcp_stream *st;
		struct tcp_conn *c;

		st = tcp_stream_accept(listener_fd, g_dispatch, g_arg);
		if (st == NULL) {
			/* EAGAIN: no more pending; any other errno: stop
			 * accepting this round (listener stays open). */
			break;
		}
		c = calloc(1, sizeof(*c));
		if (c == NULL) {
			tcp_stream_free(st);
			break;
		}
		c->st = st;
		c->next = conns;
		conns = c;
		++n;
	}
	return n;
}

int
tcp_srv_fdset(fd_set *rfds, fd_set *wfds)
{
	int max = -1;
	struct tcp_conn *c;

	if (rfds && listener_fd >= 0 && listener_fd < FD_SETSIZE) {
		FD_SET(listener_fd, rfds);
		if (listener_fd > max)
			max = listener_fd;
	}
	for (c = conns; c; c = c->next) {
		int fd = c->st->fd;

		if (fd >= 0 && fd < FD_SETSIZE) {
			if (rfds)
				FD_SET(fd, rfds);
			/* Write readiness only when outbound bytes are queued
			 * (an accepted stream is already fully connected). */
			if (wfds && c->st->obuf_off < c->st->obuf_len)
				FD_SET(fd, wfds);
			if (fd > max)
				max = fd;
		}
	}
	return max + 1;
}

void
tcp_srv_process(const fd_set *rfds, const fd_set *wfds)
{
	struct tcp_conn **pp = &conns;

	/* A ready listener means there are queued connections: accept them. */
	if (rfds && listener_fd >= 0 && FD_ISSET(listener_fd, rfds))
		tcp_srv_accept_pending();

	while (*pp) {
		struct tcp_conn *c = *pp;
		struct tcp_stream *st = c->st;
		int dead = 0;

		if (rfds && st->fd >= 0 && FD_ISSET(st->fd, rfds)) {
			if (tcp_stream_on_readable(st) < 0)
				dead = 1;	/* framing-fatal / FIN / error */
		}
		if (!dead && wfds && st->fd >= 0 && FD_ISSET(st->fd, wfds) &&
		    st->obuf_off < st->obuf_len) {
			if (tcp_stream_flush(st) < 0)
				dead = 1;
		}
		if (dead) {
			*pp = c->next;
			tcp_stream_free(st);
			free(c);
		} else {
			pp = &c->next;
		}
	}
}

int
tcp_srv_count(void)
{
	int n = 0;
	struct tcp_conn *c;

	for (c = conns; c; c = c->next)
		++n;
	return n;
}
