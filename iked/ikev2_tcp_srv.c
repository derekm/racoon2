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
	int connecting;		/* outbound (initiator) stream, not yet connected */
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
	/* IPsec bypass on the listener: accepted sockets inherit it, so the
	 * responder's SYN-ACK and stream bytes are not captured by the tunnel
	 * SPD either. */
	if (tcp_stream_sock_hook && tcp_stream_sock_hook(fd, la.ss_family) < 0)
		goto fail;
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
			if (c->connecting) {
				/* Not yet connected: wait on write/ERR only (a
				 * read on an unfinished socket errors). */
				if (wfds)
					FD_SET(fd, wfds);
			} else {
				if (rfds)
					FD_SET(fd, rfds);
				if (wfds && c->st->obuf_off < c->st->obuf_len)
					FD_SET(fd, wfds);
			}
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

		/* A connecting (initiator) stream completes on a write/ERR
		 * wake: ask SO_ERROR only then. */
		if (c->connecting && wfds && st->fd >= 0 &&
		    FD_ISSET(st->fd, wfds)) {
			if (tcp_stream_connect_done(st) < 0)
				dead = 1;	/* refused/reset connect */
			else
				c->connecting = 0;
		}
		if (!dead && !c->connecting && rfds && st->fd >= 0 &&
		    FD_ISSET(st->fd, rfds)) {
			if (tcp_stream_on_readable(st) < 0)
				dead = 1;	/* framing-fatal / FIN / error */
		}
		if (!dead && !c->connecting && wfds && st->fd >= 0 &&
		    FD_ISSET(st->fd, wfds) && st->obuf_off < st->obuf_len) {
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

/* RFC 9329 (M5): forcibly remove a stream from the registry and free it.
 * Used to tear down a stream that hit a fatal send error (r<0 from
 * tcp_stream_send/tcp_stream_flush), whose contract says the caller MUST
 * close a stream once it returns -1.  Plain tcp_stream_free() would leave a
 * dangling conns entry (use-after-free on the next loop pass), so unlink the
 * conn first, exactly as tcp_srv_process does.  Safe from the send path: the
 * event loop is single-threaded and never iterates conns concurrently.  If
 * the stream is already gone from the registry (double teardown) this is a
 * no-op -- never free it twice. */
void
tcp_srv_teardown(struct tcp_stream *ts)
{
	struct tcp_conn **pp;

	if (ts == NULL)
		return;
	for (pp = &conns; *pp; pp = &(*pp)->next) {
		if ((*pp)->st == ts) {
			struct tcp_conn *c = *pp;

			*pp = c->next;
			tcp_stream_free(c->st);
			free(c);
			return;
		}
	}
}

/* Append an OUTBOUND (initiator) stream to the registry.  It is still
 * connecting until the loop observes a writable/ERR wake; the initiator path
 * calls this right after tcp_stream_connect() returns EINPROGRESS, then the
 * registry drives connect completion and (via tcp_srv_find) routes replies
 * back over it. */
int
tcp_srv_register_connecting(struct tcp_stream *st)
{
	struct tcp_conn *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return -1;
	c->st = st;
	c->connecting = 1;
	c->next = conns;
	conns = c;
	return 0;
}

/* RFC 9329: the TCP transport is keyed per peer ADDRESS, not per port.
 * The stream's remote endpoint is the peer's IKE-over-TCP socket (:4500)
 * while the SA's IKE destination carries the normal IKE port (:500); the
 * local side differs likewise (TCP ephemeral src vs :500).  Comparing
 * addresses only lets tcp_srv_find() route any IKE message for that peer
 * over its stream -- both the initiator's outbound stream (remote=peer,
 * local=us) and the responder's accepted stream (remote=peer, local=us). */
static int
sa_addr_only_equal(const struct sockaddr *a, const struct sockaddr *b)
{
	if (a->sa_family != b->sa_family)
		return 0;
	switch (a->sa_family) {
	case AF_INET:
	{
		const struct sockaddr_in *x = (const struct sockaddr_in *)a;
		const struct sockaddr_in *y = (const struct sockaddr_in *)b;

		return x->sin_addr.s_addr == y->sin_addr.s_addr;
	}
	case AF_INET6:
	{
		const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)b;

		return memcmp(&x->sin6_addr, &y->sin6_addr,
			      sizeof(x->sin6_addr)) == 0 &&
		    x->sin6_scope_id == y->sin6_scope_id;
	}
	}
	return 0;
}

struct tcp_stream *
tcp_srv_find(const struct sockaddr *remote, const struct sockaddr *local)
{
	struct tcp_conn *c;

	for (c = conns; c; c = c->next)
		if (sa_addr_only_equal((const struct sockaddr *)&c->st->remote,
				       remote) &&
		    sa_addr_only_equal((const struct sockaddr *)&c->st->local,
				       local))
			return c->st;
	return NULL;
}

static int
sa_same_port(const struct sockaddr *a, const struct sockaddr *b)
{
	if (a->sa_family != b->sa_family)
		return 0;
	switch (a->sa_family) {
	case AF_INET:
		return ((const struct sockaddr_in *)a)->sin_port ==
		       ((const struct sockaddr_in *)b)->sin_port;
	case AF_INET6:
		return ((const struct sockaddr_in6 *)a)->sin6_port ==
		       ((const struct sockaddr_in6 *)b)->sin6_port;
	}
	return 0;
}

/* RFC 9329 (H3): the SA-bound stream lookup.  Once an IKE_SA is established
 * it must ride the specific TCP stream it was built over.  For a responder,
 * several RFC 9329 clients behind one NAT each present the same public
 * address on :4500 and differ only by their TCP source port; the SA's live
 * remote carries that source port.  Match the stream on the remote
 * ADDRESS:PORT plus the local ADDRESS -- an address-only match here would
 * cross-wire two such clients' replies over each other's streams for want
 * of the SPI, which only the remote port (per-peer client source) can tell
 * apart.  The local port is intentionally ignored: an SA's local may be the
 * IKE port (:500) rather than the stream's TCP port. */
struct tcp_stream *
tcp_srv_find_bound(const struct sockaddr *remote, const struct sockaddr *local)
{
	struct tcp_conn *c;

	for (c = conns; c; c = c->next)
		if (sa_addr_only_equal((const struct sockaddr *)&c->st->remote,
				       remote) &&
		    sa_same_port((const struct sockaddr *)&c->st->remote,
				 remote) &&
		    sa_addr_only_equal((const struct sockaddr *)&c->st->local,
				       local))
			return c->st;
	return NULL;
}
