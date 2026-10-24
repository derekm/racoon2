/* $Id$ */
/*
 * iked/ikev2_tcp_stream.c -- per-connection RFC 9329 IKE-over-TCP stream.
 *
 * See ikev2_tcp_stream.h.  This unit owns the socket, the framing de-framer,
 * and the non-blocking send buffer; the iked main loop will hold these
 * streams and drive them.  Framing-fatal (bad prefix, Len 0/1, malformed)
 * returns -1 from on_readable() so the caller closes the stream; a non-zero
 * IKE dispatch return is NOT stream-fatal (RFC 9329 s6.1 handles IKE errors
 * with INVALID_SYNTAX over the same stream) and is deliberately not conflated
 * here.
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
#include "vmbuf.h"

#include "ikev2_tcp_stream.h"

/* Originator prefix (6) + record overhead (6) + max payload. */
#define TCP_STREAM_OBUF_CAP	(IKEV2_TCP_PREFIX_LEN + 6 + IKEV2_TCP_MAXLEN)

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

/* Called for each de-framed record.  IKE messages are dispatched (marker
 * already stripped by the codec); ESP frames (ESP-in-TCP) are out of scope
 * for this slice and dropped.  Returns 0 always so a dispatch's decision
 * never aborts the stream; only a hard allocation failure is fatal. */
static int
stream_frame_cb(const unsigned char *pkt, size_t len, int is_esp, void *arg)
{
	struct tcp_stream *ts = arg;
	rc_vchar_t *v;
	int r;

	if (is_esp != TCP_FRAME_IKE)
		return 0;	/* ESP-in-TCP: not this slice */
	v = rc_vnew(pkt, len);
	if (v == NULL)
		return -1;
	r = ts->dispatch(v, (struct sockaddr *)&ts->remote,
			 (struct sockaddr *)&ts->local, ts->arg);
	(void)r;	/* IKE-layer decision; not a stream-fatal condition */
	return 0;
}

static struct tcp_stream *
stream_new(int fd, const struct sockaddr *remote, int expect_prefix,
	   tcp_stream_dispatch dispatch, void *arg)
{
	struct tcp_stream *ts;
	socklen_t sl;

	if (set_nonblock(fd) < 0)
		goto fail;

	ts = calloc(1, sizeof(*ts));
	if (ts == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	ts->obuf = malloc(TCP_STREAM_OBUF_CAP);
	if (ts->obuf == NULL) {
		free(ts);
		errno = ENOMEM;
		goto fail;
	}
	ts->fd = fd;
	if (remote)
		memcpy(&ts->remote, remote, sa_len(remote));
	sl = sizeof(ts->local);
	if (getsockname(fd, (struct sockaddr *)&ts->local, &sl) < 0) {
		free(ts->obuf);
		free(ts);
		goto fail;
	}
	tcp_decap_init(&ts->decap, expect_prefix);
	/*
	 * Outbound "IKETCP" is written by the TCP connection originator
	 * only: that is us when the peer is expected NOT to send it
	 * (expect_prefix==0).  The responder (expect_prefix==1) never writes
	 * it, so it is considered already sent.
	 */
	ts->prefix_sent = expect_prefix == 1;
	ts->dispatch = dispatch;
	ts->arg = arg;
	return ts;
      fail:
	close(fd);
	return NULL;
}

struct tcp_stream *
tcp_stream_accept(int lfd, tcp_stream_dispatch dispatch, void *arg)
{
	int fd;
	struct sockaddr_storage remote;
	socklen_t rl = sizeof(remote);

	fd = accept(lfd, (struct sockaddr *)&remote, &rl);
	if (fd < 0)
		return NULL;
	/* Accepted connection: we are the responder, the peer sent the prefix. */
	return stream_new(fd, (struct sockaddr *)&remote, 1, dispatch, arg);
}

struct tcp_stream *
tcp_stream_connect(const struct sockaddr *remote, const struct sockaddr *local,
		   int nonblock_port, tcp_stream_dispatch dispatch, void *arg)
{
	int fd = -1;
	int len;

	len = sa_len(remote);
	if (len == 0) {
		errno = EAFNOSUPPORT;
		return NULL;
	}
	fd = socket(remote->sa_family, SOCK_STREAM, 0);
	if (fd < 0)
		return NULL;
	if (local && bind(fd, local, sa_len(local)) < 0)
		goto fail;
	if (set_nonblock(fd) < 0)
		goto fail;
	if (connect(fd, remote, len) < 0 && errno != EINPROGRESS)
		goto fail;
	/*
	 * We originated the TCP connection: send the one-time "IKETCP"
	 * prefix; our peer does not.  `nonblock_port` is a placeholder for a
	 * future SO_REUSEPORT knob and is otherwise unused.
	 */
	(void)nonblock_port;
	return stream_new(fd, remote, 0, dispatch, arg);
      fail:
	if (fd >= 0)
		close(fd);
	return NULL;
}

int
tcp_stream_connect_done(struct tcp_stream *ts)
{
	int err = 0;
	socklen_t elen = sizeof(err);

	if (getsockopt(ts->fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0)
		return -1;
	if (err != 0) {
		errno = err;
		return -1;
	}
	return 0;
}

int
tcp_stream_on_readable(struct tcp_stream *ts)
{
	unsigned char buf[4096];
	int ret = 0;

	for (;;) {
		ssize_t n = read(ts->fd, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return ret;
			return -1;	/* error: close the stream */
		}
		if (n == 0)
			return -1;	/* peer FIN: close the stream */
		ret = 1;
		if (tcp_decap_feed(&ts->decap, buf, (size_t)n,
				   stream_frame_cb, ts) != 0)
			return -1;	/* framing-fatal: close the stream */
	}
}

int
tcp_stream_send(struct tcp_stream *ts, const unsigned char *ike, size_t n)
{
	size_t add, at;
	uint32_t len;
	unsigned char *p;

	if (n > IKEV2_TCP_MAXLEN - IKEV2_TCP_NON_ESP_MARKER_LEN - 2)
		return -1;	/* Len = 2 + 4 + n would not fit 16 bits */
	/* Compact any fully-sent tail before appending. */
	if (ts->obuf_off != 0) {
		if (ts->obuf_off == ts->obuf_len) {
			ts->obuf_off = ts->obuf_len = 0;
		} else {
			memmove(ts->obuf, ts->obuf + ts->obuf_off,
				ts->obuf_len - ts->obuf_off);
			ts->obuf_len -= ts->obuf_off;
			ts->obuf_off = 0;
		}
	}
	add = 6 + n;			/* Len + marker + message */
	if (ts->prefix_sent == 0)
		add += IKEV2_TCP_PREFIX_LEN;
	if (ts->obuf_len + add > TCP_STREAM_OBUF_CAP)
		return -1;
	at = ts->obuf_len;
	if (ts->prefix_sent == 0) {
		memcpy(ts->obuf + at, IKEV2_TCP_PREFIX, IKEV2_TCP_PREFIX_LEN);
		at += IKEV2_TCP_PREFIX_LEN;
		ts->prefix_sent = 1;
	}
	len = (uint32_t)n + IKEV2_TCP_NON_ESP_MARKER_LEN + 2;	/* includes Len */
	p = ts->obuf + at;
	p[0] = (uint8_t)(len >> 8);
	p[1] = (uint8_t)(len & 0xff);
	p[2] = p[3] = p[4] = p[5] = 0;
	memcpy(p + 6, ike, n);
	ts->obuf_len += add;
	return tcp_stream_flush(ts);
}

int
tcp_stream_flush(struct tcp_stream *ts)
{
	while (ts->obuf_off < ts->obuf_len) {
		ssize_t n = write(ts->fd, ts->obuf + ts->obuf_off,
				  ts->obuf_len - ts->obuf_off);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 1;	/* still pending -> want EPOLLOUT */
			return -1;
		}
		ts->obuf_off += (size_t)n;
	}
	ts->obuf_off = ts->obuf_len = 0;
	return 0;
}

void
tcp_stream_free(struct tcp_stream *ts)
{
	if (ts == NULL)
		return;
	if (ts->fd >= 0)
		close(ts->fd);
	free(ts->obuf);
	free(ts);
}
