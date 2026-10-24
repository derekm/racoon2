/* $Id$ */
/*
 * iked/ikev2_tcp.c -- RFC 9329 / RFC 8229 IKE-over-TCP framing.
 *
 * Wire format (RFC 9329 s3.1/s3.2): the TCP connection ORIGINATOR writes the
 * 6-octet prefix "IKETCP" once, then records; the responder writes records
 * only.  Each record is:
 *
 *     Len(16, includes itself) | 4 zero octets | IKE message   (IKE)
 *     Len(16, includes itself) | ESP packet                    (ESP)
 *     Len=3 | 0xFF                                              (keepalive)
 *
 *   Len 0/1 -> fatal, close the connection; Len 2 -> silently ignore.
 *
 * The DECODER is an incremental, stream-fed state machine (a TCP read() may
 * deliver any byte count, including a split inside the 2-byte Len or inside
 * the non-ESP marker), so callers feed read() results in and receive whole
 * de-framed messages back, without their own buffering.  For IKE the 4-octet
 * non-ESP marker is stripped, so the callback's pkt is the bare IKE header
 * (which is exactly what the UDP/NAT-T receive path hands to ikev2_input).
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

/* An IKE message of n octets encodes as Len = 2 + 4 + n (must fit 16 bits). */
#define IKE_RECORD_OVERHEAD	(IKEV2_TCP_NON_ESP_MARKER_LEN + 2)

int
tcp_record_ike(struct tcp_record *out, const unsigned char *ike, size_t n)
{
	uint32_t len;
	uint8_t *p;

	if (n > IKEV2_TCP_MAXLEN - IKE_RECORD_OVERHEAD) {
		/* Len = 2 + 4 + n would not fit in 16 bits. */
		errno = EMSGSIZE;
		return -1;
	}
	len = (uint32_t)n + IKE_RECORD_OVERHEAD;	/* includes the Len field */
	if (out->stream_len + len > sizeof(out->stream)) {
		errno = EMSGSIZE;
		return -1;
	}
	p = out->stream + out->stream_len;
	p[0] = (uint8_t)(len >> 8);
	p[1] = (uint8_t)(len & 0xff);
	/* 4 zero octets: the non-ESP marker (NON_ESP_MARKER_LEN). */
	p[2] = p[3] = p[4] = p[5] = 0;
	memcpy(p + 6, ike, n);
	out->stream_len += len;
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
tcp_decap_init(struct tcp_decap_state *s, int expect_prefix)
{
	s->pos = 0;
	s->reclen = 0;
	s->expect_prefix = expect_prefix;
	/* The peer that did NOT originate the TCP connection sends no prefix. */
	s->phase = expect_prefix ? TCAP_PREFIX : TCAP_LEN;
}

/*
 * Feed n bytes into the de-framer.  Each complete IKE/ESP record is handed
 * to cb; LEN 2 and keepalive records are silently consumed.  cb must not
 * depend on pkt staying valid after it returns (pkt aliases s->buf).
 * Returns 0 on success, -1 on a fatal protocol error (bad prefix, Len 0/1,
 * malformed payload); on -1 the stream state is undefined and the caller
 * must drop the connection.
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
			s->phase = TCAP_LEN;
			break;
		case TCAP_LEN:
			want = 2 - s->pos;
			if (want > n - i)
				want = (unsigned int)(n - i);
			memcpy(s->buf + s->pos, p + i, want);
			s->pos += want; i += want;
			if (s->pos < 2)
				continue;
			s->reclen = ((uint32_t)s->buf[0] << 8) | s->buf[1];
			if (s->reclen == 0 || s->reclen == 1)
				return -1;	/* RFC 9329 s3.1: fatal, close */
			if (s->reclen == 2) {
				/* Silent-ignore record: no data (RFC 9329 s3.2). */
				s->pos = 0;
				s->phase = TCAP_LEN;
				continue;
			}
			s->pos = 0;
			s->phase = TCAP_PAYLOAD;
			break;
		case TCAP_PAYLOAD:
			/* s->reclen includes the 2 Len octets. */
			want = s->reclen - 2 - s->pos;
			if (want > n - i)
				want = (unsigned int)(n - i);
			memcpy(s->buf + s->pos, p + i, want);
			s->pos += want; i += want;
			if (s->pos < s->reclen - 2)
				continue;
			{
				uint32_t plen = s->reclen - 2;
				int is_esp;
				const unsigned char *pkt;
				size_t pl;

				/* NAT keepalive 00 03 FF: silently drop. */
				if (plen == 1 && s->buf[0] == 0xff) {
					s->pos = 0;
					s->phase = TCAP_LEN;
					continue;
				}
				/* Need a 4-octet discriminator to classify. */
				if (plen < IKEV2_TCP_NON_ESP_MARKER_LEN)
					return -1;	/* malformed payload */
				if (s->buf[0] == 0 && s->buf[1] == 0 &&
				    s->buf[2] == 0 && s->buf[3] == 0) {
					/* Non-ESP marker: an IKE message. */
					is_esp = TCP_FRAME_IKE;
					pkt = s->buf + 4;
					pl = plen - 4;
				} else {
					/* Non-zero first 32 bits: an ESP packet. */
					is_esp = TCP_FRAME_ESP;
					pkt = s->buf;
					pl = plen;
				}
				if (cb(pkt, pl, is_esp, arg) != 0)
					return -1;
			}
			s->pos = 0;
			s->phase = TCAP_LEN;
			break;
		}
	}
	return 0;
}
