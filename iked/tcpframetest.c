/* $Id$ */
/*
 * Tests for the RFC 9329 (obsoletes RFC 8229) IKE-over-TCP framing codec
 * (iked/ikev2_tcp.c).  Byte-exact on-wire vectors.  Standalone main() like
 * the other iked test binaries: printf + exit status.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ikev2_tcp.h"

static int n_frame;
static unsigned char got[8][65535];
static uint32_t glen[8];
static int        gesp[8];

static int
collect(const unsigned char *pkt, size_t len, int is_esp, void *arg)
{
	(void)arg;
	if (n_frame < 8) {
		glen[n_frame] = (uint32_t)len;
		gesp[n_frame] = is_esp;
		memcpy(got[n_frame], pkt, len);
	}
	++n_frame;
	return 0;
}

static int
feed_all(struct tcp_decap_state *s, const unsigned char *d, size_t n)
{
	return tcp_decap_feed(s, d, n, collect, NULL);
}

static int fails = 0;
#define CHECK(cond, why) do { if (!(cond)) { \
	printf("FAIL: %s\n", why); ++fails; } else { \
	printf("ok: %s\n", why); } } while (0)

int
main(void)
{
	struct tcp_decap_state s;
	struct tcp_record r;
	unsigned char m, esp[5];
	const unsigned char *w;
	size_t wlen, k;

	/* --- 1. originator round-trip: IKETCP | Len(=7) | 00000000 | 42 --- */
	m = 0x42;
	memset(&r, 0, sizeof(r));
	tcp_decap_init(&s, 1);			/* expect prefix */
	CHECK(tcp_stream_begin(&r) == 0, "begin: originator prefix written");
	CHECK(tcp_record_ike(&r, &m, 1) == 0, "build: 1-byte IKE message");
	CHECK(r.stream_len == 13 &&
	      memcmp(r.stream, "IKETCP", 6) == 0 && r.stream[6] == 0 &&
	      r.stream[7] == 7 && r.stream[8] == 0 && r.stream[9] == 0 &&
	      r.stream[10] == 0 && r.stream[11] == 0 && r.stream[12] == 0x42,
	      "wire: IKETCP + Len=7 + 4-zero marker + 0x42");
	n_frame = 0;
	CHECK(feed_all(&s, r.stream, r.stream_len) == 0 && n_frame == 1,
	      "round-trip: one IKE frame decoded");
	CHECK(n_frame == 1 && gesp[0] == TCP_FRAME_IKE && glen[0] == 1 &&
	      got[0][0] == 0x42, "round-trip: marker stripped, payload+type right");

	/* --- 2. responder reply has NO prefix (expect_prefix=0) --- */
	{
		const unsigned char reply[] = { 0, 7, 0, 0, 0, 0, 0x42 };
		n_frame = 0;
		tcp_decap_init(&s, 0);
		CHECK(feed_all(&s, reply, sizeof(reply)) == 0 && n_frame == 1 &&
		      gesp[0] == TCP_FRAME_IKE && glen[0] == 1 && got[0][0] == 0x42,
		      "reply: no-prefix stream decodes one IKE frame");
	}

	/* --- 3. bad prefix is fatal --- */
	{
		const unsigned char bad[] = "IKETCQ\0\7\0\0\0\0\x42";
		tcp_decap_init(&s, 1);
		CHECK(feed_all(&s, bad, sizeof(bad) - 1) == -1,
		      "prefix: 'IKETCQ' is a fatal protocol error");
	}

	/* --- 4. Len 0 and Len 1 are fatal (RFC 9329 s3.1) --- */
	{
		const unsigned char l0[] = { 0, 0 };
		const unsigned char l1[] = { 0, 1 };
		tcp_decap_init(&s, 0);
		CHECK(feed_all(&s, l0, sizeof(l0)) == -1, "len: 0 is fatal");
		tcp_decap_init(&s, 0);
		CHECK(feed_all(&s, l1, sizeof(l1)) == -1, "len: 1 is fatal");
	}

	/* --- 5. Len 2 is silently ignored (RFC 9329 s3.2) --- */
	{
		const unsigned char stream[] = { 0, 2,     /* ignore */
						0, 7, 0, 0, 0, 0, 0x42 }; /* IKE */
		n_frame = 0;
		tcp_decap_init(&s, 0);
		CHECK(feed_all(&s, stream, sizeof(stream)) == 0 && n_frame == 1 &&
		      got[0][0] == 0x42,
		      "len: 2 silently ignored, following IKE record delivered");
	}

	/* --- 6. NAT keepalive 00 03 FF is silently dropped --- */
	{
		const unsigned char stream[] = { 0, 3, 0xff,   /* keepalive */
						0, 7, 0, 0, 0, 0, 0x42 };
		n_frame = 0;
		tcp_decap_init(&s, 0);
		CHECK(feed_all(&s, stream, sizeof(stream)) == 0 && n_frame == 1,
		      "keepalive: 00 03 FF dropped, following IKE delivered");
	}

	/* --- 7. ESP record: Len=2+n, non-zero first 32 bits, delivered whole --- */
	{
		const unsigned char esprec[] = { 0, 7, 0x11, 0x22, 0x33,
						  0x44, 0x55 };
		n_frame = 0;
		tcp_decap_init(&s, 0);
		CHECK(feed_all(&s, esprec, sizeof(esprec)) == 0 && n_frame == 1 &&
		      gesp[0] == TCP_FRAME_ESP && glen[0] == 5 &&
		      got[0][4] == 0x55, "esp: packet delivered after Len");
	}

	/* --- 8. mixed IKE + ESP in one originator stream --- */
	{
		unsigned char ike1 = 0x99, ike2 = 0x7a;
		memset(&r, 0, sizeof(r));
		esp[0] = 0x01; esp[1] = 0x00; esp[2] = 0x00; esp[3] = 0x00; esp[4] = 0x02;
		tcp_stream_begin(&r);
		tcp_record_ike(&r, &ike1, 1);
		/* build ESP by hand: Len=7 | esp(5 bytes) */
		r.stream[r.stream_len++] = 0; r.stream[r.stream_len++] = 7;
		memcpy(r.stream + r.stream_len, esp, 5); r.stream_len += 5;
		tcp_record_ike(&r, &ike2, 1);
		n_frame = 0;
		tcp_decap_init(&s, 1);
		CHECK(feed_all(&s, r.stream, r.stream_len) == 0 && n_frame == 3 &&
		      gesp[0] == TCP_FRAME_IKE && gesp[1] == TCP_FRAME_ESP &&
		      gesp[2] == TCP_FRAME_IKE && glen[1] == 5,
		      "coalesce: IKE + ESP + IKE decoded in order");
	}

	/* --- 9. split at EVERY byte boundary (incl. inside Len and marker) --- */
	{
		unsigned char ike1 = 0x11, ike2 = 0x22;
		memset(&r, 0, sizeof(r));
		tcp_stream_begin(&r);
		tcp_record_ike(&r, &ike1, 1);
		tcp_record_ike(&r, &ike2, 1);
		wlen = r.stream_len; w = r.stream;
	}
	{
		int ok = 1;
		for (k = 0; k < wlen; k++) {
			n_frame = 0;
			tcp_decap_init(&s, 1);
			if (feed_all(&s, w, k) != 0 || feed_all(&s, w + k, wlen - k) != 0 ||
			    n_frame != 2 || glen[0] != 1 || glen[1] != 1) {
				ok = 0; break;
			}
		}
		CHECK(ok, "split: every byte boundary (Len+marker+payload) decodes");
	}

	/* --- 10. malformed payload (< 4 discriminator, not keepalive) fatal --- */
	{
		const unsigned char bad[] = { 0, 3, 0xaa };
		tcp_decap_init(&s, 0);
		CHECK(feed_all(&s, bad, sizeof(bad)) == -1,
		      "malformed: 1-byte non-FF payload is fatal");
	}

	/* --- 11. encoder caps IKE message at 65529 octets --- */
	{
		struct tcp_record bs;
		unsigned char big[65530];

		memset(&bs, 0, sizeof(bs));
		CHECK(tcp_record_ike(&bs, big, 65529) == 0,
		      "encode: 65529-octet IKE message accepted (Len=65535)");
		memset(&bs, 0, sizeof(bs));
		CHECK(tcp_record_ike(&bs, big, 65530) == -1,
		      "encode: 65530-octet IKE message rejected (Len would overflow)");
	}

	/* --- 12. empty prefix-only stream: no frames, header state --- */
	tcp_decap_init(&s, 1);
	CHECK(feed_all(&s, (const unsigned char *)"IKETCP", 6) == 0 &&
	      s.phase == TCAP_LEN, "prefix: exact 'IKETCP' alone, awaiting Len");

	if (!fails)
		printf("all tcp-framing checks passed\n");
	return fails ? 1 : 0;
}
