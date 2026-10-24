/* $Id$ */
/*
 * iked/ikev2_tcp.c -- RFC 8229 / RFC 9329 IKE-over-TCP framing.
 *
 * RFC 8229 s3: a TCP stream carrying IKE messages begins with the 6-octet
 * ASCII prefix "IKETCP", followed by one or more records:
 *
 *   +------+--------+------+
 *   | len  |  sep   | data |     len (16 bits) : data length
 *   ~~~~~~ ~~~~~~~~  ~~~~~~     sep  (8 bits)  : 0x00 ESP / 0x01 non-ESP (IKE)
 *                                data          : the ESP packet or IKE message
 *
 * iked only ever sends non-ESP (IKE) records, so the encoder emits sep=0x01.
 * The prefix appears ONCE at stream start, not per record.
 *
 * The decoder is an incremental, stream-fed state machine (TCP reads may
 * deliver any byte count, including splits inside a field), so callers feed
 * read() results into it and receive whole de-framed messages via a callback
 * without their own buffering.
 */
#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "racoon.h"
#include "isakmp.h"

#include "ikev2_tcp.h"

int
tcp_record_build(struct tcp_record *out, const unsigned char *pkt, size_t len)
{
	uint8_t hdr[3];

	if (len == 0 || len > IKEV2_TCP_MAXLEN) {
		/* RFC 8229 s3: a record with a zero-length message is invalid
		 * (a "0 byte" ESP packet is still a valid uint16); the 16-bit
		 * header caps a record at 65535 octets. */
		errno = EINVAL;
		return -1;
	}
	if (out->stream_len + 3 + len > sizeof(out->stream)) {
		errno = EMSGSIZE;
		return -1;
	}
	hdr[0] = (uint8_t)(len >> 8);
	hdr[1] = (uint8_t)(len & 0xff);
	hdr[2] = IKEV2_TCP_SEP_IKE;	/* non-ESP: an IKE message */
	memcpy(out->stream + out->stream_len, hdr, 3);
	memcpy(out->stream + out->stream_len + 3, pkt, len);
	out->stream_len += 3 + len;
	return 0;
}

int
tcp_stream_begin(struct tcp_record *out)
{
	if (out->stream_len != 0)
		return -1;	/* prefix must be the very first bytes */
	memcpy(out->stream, IKEV2_TCP_PREFIX, IKEV2_TCP_PREFIX_LEN);
	out->stream_len = IKEV2_TCP_PREFIX_LEN;
	return 0;
}

void
tcp_decap_init(struct tcp_decap_state *s)
{
	s->pos = 0;
	s->phase = TCAP_PREFIX;
	s->reclen = 0;
	s->sep = 0;
}

/*
 * Feed n bytes into the de-framer.  Whole records are handed to cb(pkt,len,
 * sep,arg); cb must not depend on pkt staying valid after it returns (pkt
 * aliases s->buf).  Returns 0 on success, -1 on a malformed stream (bad
 * prefix, bad separator, or a length that cannot fit).  On -1 the stream
 * state is undefined; the caller must drop the connection.
 */
int
tcp_decap_feed(struct tcp_decap_state *s, const unsigned char *p, size_t n,
	       tcp_record_cb cb, void *arg)
{
	size_t i = 0;
	unsigned int want;

	while (i < n) {
		switch (s->phase) {
		case TCAP_PREFIX:
			want = IKEV2_TCP_PREFIX_LEN - s->pos;
			if (want > n - i)
				want = (unsigned int)(n - i);
			memcpy(s->buf + s->pos, p + i, want);
			s->pos += want; i += want;
			if (s->pos < IKEV2_TCP_PREFIX_LEN)
				continue;
			if (memcmp(s->buf, IKEV2_TCP_PREFIX,
				   IKEV2_TCP_PREFIX_LEN) != 0)
				return -1;	/* bad stream prefix */
			s->pos = 0;
			s->phase = TCAP_HEADER;
			break;
		case TCAP_HEADER:
			want = 3 - s->pos;
			if (want > n - i)
				want = (unsigned int)(n - i);
			memcpy(s->buf + s->pos, p + i, want);
			s->pos += want; i += want;
			if (s->pos < 3)
				continue;
			s->reclen = ((unsigned int)s->buf[0] << 8) | s->buf[1];
			s->sep = s->buf[2];
			if (s->reclen == 0 || s->reclen > IKEV2_TCP_MAXLEN)
				return -1;	/* bad length */
			if (s->sep != IKEV2_TCP_SEP_ESP &&
			    s->sep != IKEV2_TCP_SEP_IKE)
				return -1;	/* bad separator */
			s->pos = 0;
			s->phase = TCAP_PAYLOAD;
			break;
		case TCAP_PAYLOAD:
			want = s->reclen - s->pos;
			if (want > n - i)
				want = (unsigned int)(n - i);
			memcpy(s->buf + s->pos, p + i, want);
			s->pos += want; i += want;
			if (s->pos < s->reclen)
				continue;
			if (cb(s->buf, s->reclen, s->sep, arg) != 0)
				return -1;
			s->pos = 0;
			s->phase = TCAP_HEADER;
			break;
		}
	}
	return 0;
}
