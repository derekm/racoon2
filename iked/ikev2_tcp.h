/* $Id$ */
/*
 * iked/ikev2_tcp.h -- RFC 8229 / RFC 9329 IKE-over-TCP framing codec.
 */
#ifndef _IKEV2_TCP_H_
#define _IKEV2_TCP_H_

#include <stdint.h>
#include <stddef.h>

#define IKEV2_TCP_PREFIX	"IKETCP"
#define IKEV2_TCP_PREFIX_LEN	6
#define IKEV2_TCP_SEP_ESP	0x00	/* 0x00: ESP packet */
#define IKEV2_TCP_SEP_IKE	0x01	/* 0x01: non-ESP (IKE message) */
#define IKEV2_TCP_MAXLEN	65535	/* 16-bit record length */

/*
 * Outbound: accumulate the stream in this buffer.  tcp_stream_begin() writes
 * the one-time "IKETCP" prefix; tcp_record_build() appends a [len][sep][pkt]
 * record for each IKE message.  stream is linear and ready for a single
 * write/SSL_write of stream_len octets.
 */
struct tcp_record {
	unsigned char stream[IKEV2_TCP_PREFIX_LEN + 3 + IKEV2_TCP_MAXLEN];
	size_t stream_len;
};

typedef int (*tcp_record_cb)(const unsigned char *pkt, size_t len,
			     unsigned char sep, void *arg);

/* Inbound de-framer phases. */
enum {
	TCAP_PREFIX = 0,	/* expecting the one-time "IKETCP" prefix */
	TCAP_HEADER,		/* expecting 2-byte length + 1-byte separator */
	TCAP_PAYLOAD			/* expecting the message body */
};

struct tcp_decap_state {
	unsigned char buf[IKEV2_TCP_MAXLEN];	/* payload frame buffer */
	unsigned int pos;		/* bytes buffered for the current phase */
	unsigned int reclen;	/* payload length of the current record */
	unsigned char sep;	/* separator of the current record */
	int phase;
};

void tcp_decap_init(struct tcp_decap_state *);
int tcp_decap_feed(struct tcp_decap_state *, const unsigned char *, size_t,
		   tcp_record_cb, void *);
int tcp_stream_begin(struct tcp_record *);
int tcp_record_build(struct tcp_record *, const unsigned char *, size_t);

#endif /* _IKEV2_TCP_H_ */
