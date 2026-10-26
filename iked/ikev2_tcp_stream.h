/* $Id$ */
/*
 * iked/ikev2_tcp_stream.h -- per-connection RFC 9329 IKE-over-TCP stream.
 *
 * A tcp_stream wraps one accepted-connected TCP socket with the framing
 * codec (iked/ikev2_tcp.c), the local/remote addresses the IKE engine needs,
 * and a non-blocking send buffer.  It is the unit the iked main loop will
 * drive (river a couple of extra fds into isakmp_fdset/isset in step 3):
 *
 *   - tcp_stream_accept(): the ACCEPTED (responder) side, expect_prefix=1.
 *   - tcp_stream_connect(): the CONNECTING (originator) side, expect_prefix=0.
 *   - tcp_stream_on_readable(): read(); a complete IKE record (marker
 *     stripped) becomes an rc_vchar_t handed to the dispatch callback.  This
 *     is where iked plugs in ikev2_input().
 *   - tcp_stream_send()/flush(): encode + non-blocking write with EAGAIN
 *     backpressure (partial-write buffering).  The TCP path must NOT go
 *     through isakmp_transmit_noretry (that adds the UDP NAT-T marker).
 *
 * Framing-fatal (bad prefix, Len 0/1, malformed, peer FIN, hard I/O error)
 * returns -1 from on_readable()/send()/flush() and the caller MUST close the
 * stream -- once any returns -1 the stream is dead and must not be retried.
 * A record shorter than an IKEv2 header has no SPI or msgid to route a
 * response to: it is DROPPED (never reaches dispatch, never closes the
 * stream) and counted in st->short_drops, so the IKE layer can later emit
 * INVALID_SYNTAX (RFC 9329 s6.1) on this same stream.  The counter is the
 * distinct signal the daemon path uses for that.
 *
 * All buffers are heap-allocated (they are 64KB); destroy with
 * tcp_stream_free().
 */
#ifndef _IKEV2_TCP_STREAM_H_
#define _IKEV2_TCP_STREAM_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "vmbuf.h"
#include "ikev2_tcp.h"

/*
 * dispatch is invoked with a completed, marker-stripped IKE message and the
 * stream's remote/local addresses.  It owns and frees pkt (like ikev2_input
 * does).  Its return value is IKE-layer bookkeeping only (e.g. an RFC 9329
 * s6.1 INVALID_SYNTAX is sent over this same stream) and NEVER terminates
 * the stream; only a framing-fatal error (bad prefix, Len 0/1, malformed)
 * closes the stream, surfaced as -1 from tcp_stream_on_readable().
 */
typedef int (*tcp_stream_dispatch)(rc_vchar_t *pkt, struct sockaddr *remote,
				   struct sockaddr *local, void *arg);

struct tcp_stream {
	int fd;				/* non-blocking stream socket */
	int connecting;			/* outbound connect in flight (async):
					   write()/flush() defer until
					   tcp_stream_connect_done() clears it */
	struct sockaddr_storage local;	/* our bound address */
	struct sockaddr_storage remote;	/* peer address */
	struct tcp_decap_state decap;	/* inbound de-framer */
	unsigned char *obuf;		/* outbound record buffer */
	size_t obuf_len;		/* bytes queued in obuf */
	size_t obuf_off;		/* bytes of obuf already written */
	int prefix_sent;		/* originator's one-time "IKETCP" done */
	unsigned long short_drops;	/* sub-IKEv2-header records dropped (for
					   the IKE layer to emit INVALID_SYNTAX) */
	struct tcp_record *tb;		/* heap-encoded outbound record (not stack) */
	tcp_stream_dispatch dispatch;	/* the IKE receive entry (ikev2_input) */
	void *arg;
};

/*
 * Accept one connection off the (non-blocking) listener into a responder
 * stream (expect_prefix=1).  Returns NULL with errno == EAGAIN when there is
 * simply no pending connection -- the loop must treat EAGAIN as "try later",
 * not as a dead listener.
 */
struct tcp_stream *tcp_stream_accept(int lfd, tcp_stream_dispatch, void *);
/*
 * Non-blocking outbound connect.  remote is required; local may be NULL
 * (let the kernel pick the source).  EINPROGRESS is success.  The returned
 * stream is the TCP connection originator (expect_prefix=0) and queues the
 * one-time "IKETCP" prefix before its first record.
 */
struct tcp_stream *tcp_stream_connect(const struct sockaddr *remote,
				      const struct sockaddr *local,
				      tcp_stream_dispatch, void *);
/*
 * Ask whether a non-blocking connect finished.  MUST be called only after
 * the fd was reported writable (or EPOLLERR/EPOLLHUP) by evloop_wait_rw:
 * SO_ERROR is 0 both before the handshake completes and after it succeeds,
 * so blind polling cannot distinguish "in progress" from "done".  Returns 0
 * once connected, -1 on a refused/reset connect (errno set from SO_ERROR)
 * or any socket error.
 */
int tcp_stream_connect_done(struct tcp_stream *);

/* Returns >0 activity, 0 nothing ready (EAGAIN), -1 FATAL (close the stream). */
int tcp_stream_on_readable(struct tcp_stream *);
/* Queue + flush an IKE message on the stream (takes a copy of ike,n).
 * Returns: 0 fully written, 1 queued but still writing (want EPOLLOUT, call
 * flush() again), 2 NOT queued -- send buffer full, nothing lost -- flush()
 * first then retry, -1 FATAL hard write error (close; do not retry). */
int tcp_stream_send(struct tcp_stream *, const unsigned char *ike, size_t n);
/* Write more of any queued partial record; 0 written, 1 still pending, -1 fatal. */
int tcp_stream_flush(struct tcp_stream *);

void tcp_stream_free(struct tcp_stream *);

/*
 * Per-socket hook run on every IKE-over-TCP socket (outbound connect and the
 * listener; accepted sockets inherit the listener's socket policy) right
 * after socket() and BEFORE bind/connect/listen.  iked installs
 * setsockopt_bypass() here, exactly as for its UDP IKE sockets: without a
 * per-socket IPsec bypass the TCP SYN to the peer's :4500 matches the
 * tunnel SPD (selectors covering the IKE endpoints), the kernel parks it on
 * an ACQUIRE and the stream never leaves SYN-SENT.  NULL = no hook (unit
 * tests).  A hook failure fails the socket.
 */
extern int (*tcp_stream_sock_hook)(int fd, int family);

#endif /* _IKEV2_TCP_STREAM_H_ */
