/* $Id$ */
/*
 * iked/ikev2_tcp_stream.c -- per-connection RFC 9329 IKE-over-TCP stream.
 *
 * See ikev2_tcp_stream.h.  This unit owns the socket, the framing de-framer,
 * and the non-blocking send buffer; the iked main loop will hold these
 * streams and drive them.  Framing-fatal (bad prefix, Len 0/1, malformed)
 * returns -1 from on_readable() so the caller closes the stream; an IKE
 * dispatch return is NEVER stream-fatal -- the IKE layer itself sends
 * INVALID_SYNTAX (RFC 9329 s6.1) over this same stream -- and is deliberately
 * not conflated here.
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
#include "isakmp.h"		/* isakmp_cookie_t */
#include "ikev2.h"		/* struct ikev2_header */

#include "ikev2_tcp_stream.h"

/* TCP_ULP (kernel TCP Upper Layer Protocol selector, setsockopt(IPPROTO_TCP)).
 * Standard on Linux >= 4.3; 31 is the stable value. */
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

/* ESP-in-TCP ULP name the kernel registers (linux net/ipv4/espintcp.c). */
#define IKEV2_TCP_ULP_ESPINTCP	"espintcp"

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
 * for this slice and dropped.  A record shorter than an IKEv2 header has no
 * SPI or msgid to route a reply to, so it is dropped -- a transport rule,
 * NOT the RFC 9329 s6.1 INVALID_SYNTAX path (the IKE layer owns that on full
 * messages): it never reaches dispatch and NEVER closes the stream.  Returns
 * 0 always so a dispatch's decision also never aborts the stream; only a
 * hard allocation failure is fatal. */
static int
stream_frame_cb(const unsigned char *pkt, size_t len, int is_esp, void *arg)
{
	struct tcp_stream *ts = arg;
	rc_vchar_t *v;
	int r;

	if (is_esp != TCP_FRAME_IKE)
		return 0;	/* ESP-in-TCP: not this slice */
	if (len < sizeof(struct ikev2_header)) {
		/* Sub-header record: no SPI/msgid to route a reply to.  Count
		 * it so the IKE layer can send INVALID_SYNTAX (RFC 9329 s6.1)
		 * -- never closing the stream. */
		++ts->short_drops;
		return 0;
	}
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
	ts->tb = malloc(sizeof(struct tcp_record));	/* heap, never stack */
	if (ts->obuf == NULL || ts->tb == NULL) {
		free(ts->obuf);
		free(ts->tb);
		free(ts);
		errno = ENOMEM;
		goto fail;
	}
#ifdef SO_NOSIGPIPE
	/* A peer RST on a write would otherwise SIGPIPE-kill the daemon. */
	{
		int on = 1;
		(void)setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
	}
#endif
	ts->fd = fd;
	if (remote)
		memcpy(&ts->remote, remote, sa_len(remote));
	sl = sizeof(ts->local);
	if (getsockname(fd, (struct sockaddr *)&ts->local, &sl) < 0) {
		free(ts->obuf);
		free(ts->tb);
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

int (*tcp_stream_sock_hook)(int fd, int family) = NULL;

struct tcp_stream *
tcp_stream_connect(const struct sockaddr *remote, const struct sockaddr *local,
		   tcp_stream_dispatch dispatch, void *arg)
{
	int fd = -1;
	int len;
	struct tcp_stream *st;

	len = sa_len(remote);
	if (len == 0) {
		errno = EAFNOSUPPORT;
		return NULL;
	}
	fd = socket(remote->sa_family, SOCK_STREAM, 0);
	if (fd < 0)
		return NULL;
	/* Must precede connect(): the SYN's policy lookup happens there. */
	if (tcp_stream_sock_hook && tcp_stream_sock_hook(fd, remote->sa_family) < 0)
		goto fail;
	if (local && bind(fd, local, sa_len(local)) < 0)
		goto fail;
	if (set_nonblock(fd) < 0)
		goto fail;
	if (connect(fd, remote, len) < 0 && errno != EINPROGRESS)
		goto fail;
	/*
	 * We originated the TCP connection: send the one-time "IKETCP"
	 * prefix; our peer does not.
	 */
	st = stream_new(fd, remote, 0, dispatch, arg);
	if (st != NULL)
		st->connecting = 1;	/* connect in flight (may be async) */
	return st;
      fail:
	if (fd >= 0)
		close(fd);
	return NULL;
}

int
tcp_stream_connect_done(struct tcp_stream *ts)
{
	/*
	 * Must only be called once the fd was reported writable (or
	 * EPOLLERR/EPOLLHUP): SO_ERROR is 0 both before the handshake
	 * completes and after it succeeds.
	 */
	int err = 0;
	socklen_t elen = sizeof(err);

	if (getsockopt(ts->fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0)
		return -1;
	if (err != 0) {
		errno = err;
		return -1;
	}
	ts->connecting = 0;	/* connected; queued writes may now flush */
	return 0;
}

static int
ts_ulp_apply(struct tcp_stream *ts)
{
	if (ts->espintcp_ulp)
		return 0;
	if (setsockopt(ts->fd, IPPROTO_TCP, TCP_ULP,
		       IKEV2_TCP_ULP_ESPINTCP, sizeof(IKEV2_TCP_ULP_ESPINTCP)) != 0)
		return -1;
	ts->espintcp_ulp = 1;
	return 0;
}

int
tcp_stream_enable_espintcp(struct tcp_stream *ts)
{
	/* Mark the stream espintcp.  The kernel ULP setsockopt is deferred to
	 * the prefix boundary: for the ORIGINATOR it is applied in flush()
	 * right after the plain "IKETCP" prefix is written; for the RESPONDER
	 * (which never writes the prefix, prefix_sent==1) it is applied here,
	 * once the IKE layer knows this peer is espintcp. */
	ts->espintcp = 1;
	if (ts->prefix_sent == 1)
		return ts_ulp_apply(ts);
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
		if (ts->espintcp) {
			/* ESP-in-TCP mode: the kernel espintcp ULP strips the
			 * 2-byte Len and returns one complete frame per
			 * read():
			 *   4-octet marker | payload
			 * (marker 0 = IKE; non-zero = an ESP SPI that the
			 * kernel with an espintcp SA decaps itself and never
			 * surfaces here).  Strip the marker and hand the
			 * payload to the same dispatch as a manual-framing
			 * IKE record; ESP frames are dropped. */
			const unsigned char *mk = buf;
			if (n < (ssize_t)IKEV2_TCP_NON_ESP_MARKER_LEN)
				return 0;
			if ((mk[0] | mk[1] | mk[2] | mk[3]) != 0)
				continue;	/* ESP frame: kernel-owned, drop */
			if (stream_frame_cb(buf + IKEV2_TCP_NON_ESP_MARKER_LEN,
					    (size_t)n - IKEV2_TCP_NON_ESP_MARKER_LEN,
					    TCP_FRAME_IKE, ts) != 0)
				return -1;
		} else {
			if (tcp_decap_feed(&ts->decap, buf, (size_t)n,
					   stream_frame_cb, ts) != 0)
				return -1;	/* framing-fatal: close the stream */
		}
	}
}

int
tcp_stream_send(struct tcp_stream *ts, const unsigned char *ike, size_t n)
{
	struct tcp_record *rec = ts->tb;
	size_t rl;
	int have_prefix;

	/* Build the record through the codec (Prefix + Len|marker|message);
	 * tcp_record_ike enforces the 16-bit inclusive-Length cap.  Encoded
	 * into the heap record (ts->tb), never a 64KB stack array. */
	memset(rec, 0, sizeof(*rec));
	have_prefix = 0;
	if (ts->espintcp) {
		/* ESP-in-TCP mode: the kernel espintcp ULP owns the wire
		 * framing (Len|marker).  Queue the BARE IKE message.  For the
		 * originator, the one-time "IKETCP" prefix is NOT queued
		 * here -- flush() writes it PLAIN and enables the ULP first
		 * (the kernel must never wrap the prefix). */
		if (ts->prefix_sent == 0) {
			ts->prefix_pending = 1;
			ts->prefix_sent = 1;
		}
		if (rec->stream_len + n > sizeof(rec->stream))
			return 2;
		memcpy(rec->stream + rec->stream_len, ike, n);
		rec->stream_len += n;
	} else {
		/* RFC 9329 manual framing: Prefix + Len|marker|message.
		 * tcp_record_ike enforces the 16-bit inclusive-Length cap.
		 * Encoded into the heap record (ts->tb), never a 64KB stack
		 * array. */
		if (ts->prefix_sent == 0) {
			/* We are the TCP connection originator: one-time prefix. */
			if (tcp_stream_begin(rec) != 0)
				return 2;	/* not queued; nothing lost, not fatal */
			have_prefix = 1;
		}
		if (tcp_record_ike(rec, ike, n) != 0)
			return 2;	/* oversized (n > 65529): not queued, not fatal */
	}
	rl = rec->stream_len;

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
	if (ts->obuf_len + rl > TCP_STREAM_OBUF_CAP) {
		/* Move queued bytes out first.  If still full, report "not
		 * queued": NOTHING is lost and the caller flushes + retries. */
		int fr = tcp_stream_flush(ts);

		if (fr < 0)
			return -1;	/* hard write error */
		if (ts->obuf_len + rl > TCP_STREAM_OBUF_CAP)
			return 2;	/* not queued; nothing lost */
	}
	memcpy(ts->obuf + ts->obuf_len, rec->stream, rl);
	ts->obuf_len += rl;
	if (have_prefix)
		ts->prefix_sent = 1;	/* the prefix bytes are now in obuf */
	return tcp_stream_flush(ts);
}

int
tcp_stream_flush(struct tcp_stream *ts)
{
	/* While an outbound connect is in flight the socket is not yet
	 * established: sending now would fail with ENOTCONN.  Defer -- the
	 * event loop completes the connect (tcp_stream_connect_done clears
	 * ts->connecting) and then flushes the queued obuf. */
	if (ts->connecting)
		return 1;
	/* espintcp originator: write the "IKETCP" prefix PLAIN, then enable the
	 * kernel ULP, before any bare-IKE bytes hit the socket (the ULP must
	 * never wrap the prefix). */
	if (ts->espintcp && ts->prefix_pending && !ts->espintcp_ulp) {
		ssize_t pw = send(ts->fd, IKEV2_TCP_PREFIX, IKEV2_TCP_PREFIX_LEN,
				  0);
		if (pw < 0) {
			if (errno == EINTR)
				return 1;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 1;	/* retry on EPOLLOUT */
			return -1;
		}
		if (pw != (ssize_t)IKEV2_TCP_PREFIX_LEN)
			return 1;	/* partial prefix: defer the rest */
		if (ts_ulp_apply(ts) < 0)
			return -1;
		ts->prefix_pending = 0;
	}
	while (ts->obuf_off < ts->obuf_len) {
		/* An espintcp ULP socket rejects MSG_NOSIGNAL with EOPNOTSUPP,
		 * so plain send(2) must be used there; SIGPIPE is globally
		 * ignored in iked (see main()).  Manual RFC 9329 streams keep
		 * MSG_NOSIGNAL for extra safety. */
		ssize_t n = send(ts->fd, ts->obuf + ts->obuf_off,
				 ts->obuf_len - ts->obuf_off,
				 ts->espintcp ? 0 : MSG_NOSIGNAL
#ifdef MSG_NOSIGNAL
				 ); /* just the flag above */
#else
				 );
#endif
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 1;	/* still pending -> want EPOLLOUT */
			if (errno == ENOTCONN && ts->connecting)
				return 1;	/* connecting: defer the write */
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
	free(ts->tb);
	free(ts->obuf);
	free(ts);
}
