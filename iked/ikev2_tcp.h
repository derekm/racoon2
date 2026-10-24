/* $Id$ */
/*
 * iked/ikev2_tcp.h -- RFC 9329 / RFC 8229 IKE-over-TCP framing codec.
 *
 * Wire format (RFC 9329 s3.1/s3.2, which obsoletes RFC 8229 s3):
 *
 *   The TCP connection ORIGINATOR only ("IKETCP", once) writes the 6-octet
 *   prefix "IKETCP", then records.  The responder writes records only, no
 *   prefix.  Each record:
 *
 *     +------+----------------+-----------+
 *     | Len  |  Discriminator |   data    |
 *     +------+----------------+-----------+
 *
 *   Len (16 bits, network order) INCLUDES the 2 Len octets themselves.
 *     - IKE message : Len | 4 zero octets | IKE message
 *         Len = 2 + 4 + ike_len; the 4 zero octets are the same non-ESP
 *         marker the UDP/NAT-T path already strips via NON_ESP_MARKER_LEN.
 *     - ESP packet  : Len | ESP packet; the discriminator's first 32 bits
 *         are non-zero (SPI must not be 0).
 *     - NAT keepalive: Len=3 | 0xFF  (00 03 FF) -- silently dropped.
 *   Len 0 or 1 -> protocol error, close the connection.
 *   Len 2 -> silently ignore (no data).
 *
 *   Because Len includes itself, an n-octet IKE message encodes as
 *   Len = 2 + 4 + n and n is capped at 65535 - 6 = 65529.
 */
#ifndef _IKEV2_TCP_H_
#define _IKEV2_TCP_H_

#include <stdint.h>
#include <stddef.h>

#define IKEV2_TCP_PREFIX	"IKETCP"
#define IKEV2_TCP_PREFIX_LEN	6
#define IKEV2_TCP_MAXLEN	65535	/* 16-bit Len; Len includes itself */
#define IKEV2_TCP_NON_ESP_MARKER_LEN 4	/* zero octets preceding an IKE msg */
#define IKEV2_TCP_KEEPALIVE_LEN	3	/* 00 03 FF: NAT keepalive record */

/* The de-framed payload handed to tcp_decap_feed's callback. */
enum { TCP_FRAME_IKE = 0, TCP_FRAME_ESP = 1 };

/* Inbound de-framer phases. */
enum {
	TCAP_PREFIX = 0,	/* expecting the one-time "IKETCP" prefix */
	TCAP_LEN,		/* expecting the 2-octet Len */
	TCAP_PAYLOAD		/* expecting Len - 2 payload octets */
};

typedef int (*tcp_record_cb)(const unsigned char *pkt, size_t len, int is_esp,
			     void *arg);

/*
 * Outbound (TCP connection ORIGINATOR only): a stream assembled in this
 * buffer.  tcp_stream_begin() writes the one-time "IKETCP" prefix;
 * tcp_record_ike() appends an IKE record.  `stream` is linear for a single
 * write(2) of stream_len octets.  A responder builds records WITHOUT the
 * prefix by simply not calling tcp_stream_begin().
 */
struct tcp_record {
	unsigned char stream[IKEV2_TCP_PREFIX_LEN + 6 + IKEV2_TCP_MAXLEN];
	size_t stream_len;
};

/* Inbound de-framer.  `expect_prefix` tells whether the peer is the TCP
 * connection originator (so IT would have written "IKETCP" first): true for
 * an accepted (responder) connection, false for an outbound (originator)
 * connection whose peer reply carries no prefix. */
struct tcp_decap_state {
	unsigned char buf[IKEV2_TCP_MAXLEN];
	uint32_t pos;		/* bytes buffered for the current phase */
	uint32_t reclen;	/* the Len field of the current record */
	int phase;
	int expect_prefix;
};

void tcp_decap_init(struct tcp_decap_state *, int expect_prefix);
/*
 * Feed stream bytes.  Each complete IKE/ESP record is handed to cb with the
 * 4-octet marker STRIPPED for IKE (pkt = the bare IKE message ikev2_input
 * wants) and the payload after Len for ESP.  cb returns 0 to continue,
 * nonzero to abort after this record.  Silent-ignore records (Len 2, NAT
 * keepalive) never call cb.  Returns 0 on success, -1 on a fatal stream
 * error (bad prefix, Len 0/1, malformed payload) -- the caller must drop the
 * connection.
 */
int tcp_decap_feed(struct tcp_decap_state *, const unsigned char *, size_t,
		   tcp_record_cb, void *);
int tcp_stream_begin(struct tcp_record *);
int tcp_record_ike(struct tcp_record *, const unsigned char *, size_t);

#endif /* _IKEV2_TCP_H_ */
