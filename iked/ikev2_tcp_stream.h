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
 * Framing-fatal (bad prefix, Len 0/1, malformed) returns -1 from
 * on_readable() and the caller MUST close the stream.  A non-zero return
 * from the dispatch callback is the IKE layer's decision (e.g. RFC 9329
 * s6.1 INVALID_SYNTAX tears down the IKE SA) and is NOT itself fatal to the
 * TCP stream -- so the two are deliberately separated here.
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
	struct sockaddr_storage local;	/* our bound address */
	struct sockaddr_storage remote;	/* peer address */
	struct tcp_decap_state decap;	/* inbound de-framer */
	unsigned char *obuf;		/* outbound record buffer */
	size_t obuf_len;		/* bytes queued in obuf */
	size_t obuf_off;		/* bytes of obuf already written */
	int prefix_sent;		/* originator's one-time "IKETCP" done */
	tcp_stream_dispatch dispatch;	/* the IKE receive entry (ikev2_input) */
	void *arg;
};

struct tcp_stream *tcp_stream_accept(int lfd, tcp_stream_dispatch, void *);
struct tcp_stream *tcp_stream_connect(const struct sockaddr *remote,
				      const struct sockaddr *local,
				      int nonblock_port, tcp_stream_dispatch,
				      void *);
/* True once an outbound connect() has completed (checked on write/ERR). */
int tcp_stream_connect_done(struct tcp_stream *);

/* Returns >0 activity, 0 nothing ready (EAGAIN), -1 fatal (close the stream); */
int tcp_stream_on_readable(struct tcp_stream *);
/* Queue + flush an IKE message on the stream (takes a copy of ike,n). */
int tcp_stream_send(struct tcp_stream *, const unsigned char *ike, size_t n);
/* Write more of any queued partial record; returns 1 if still pending. */
int tcp_stream_flush(struct tcp_stream *);

void tcp_stream_free(struct tcp_stream *);

#endif /* _IKEV2_TCP_STREAM_H_ */
