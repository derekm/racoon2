/* $Id$ */
/*
 * Tests for the RFC 8229 IKE-over-TCP framing codec (iked/ikev2_tcp.c).
 * Standalone main() like the other iked test binaries: printf + exit status.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ikev2_tcp.h"

static int n_frames;
static unsigned char got[16][65535];
static unsigned int got_len[16];
static int got_sep[16];

static int
collect(const unsigned char *pkt, size_t len, unsigned char sep, void *arg)
{
	(void)arg;
	if (n_frames < 16) {
		got_len[n_frames] = (unsigned int)len;
		got_sep[n_frames] = sep;
		memcpy(got[n_frames], pkt, len);
	}
	++n_frames;
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
	unsigned char buf[32];
	unsigned char badprefix[] = "IKETCQ";
	size_t i;

	memset(&r, 0, sizeof(r));	/* tcp_record_build validates stream_len */

	/* --- 1. prefix must be exactly "IKETCP" --- */
	tcp_decap_init(&s);
	CHECK(feed_all(&s, (const unsigned char *)"IKET", 4) == 0,
	      "prefix: partial 'IKET' accepted");
	CHECK(feed_all(&s, (const unsigned char *)"CP", 2) == 0,
	      "prefix: 'IKETCP' completed across feeds");
	CHECK(s.phase == TCAP_HEADER, "prefix: state is TCAP_HEADER after it");
	tcp_decap_init(&s);
	CHECK(feed_all(&s, (const unsigned char *)"IKETCP" "\0\0" "\x01" "\x00",
		       6) == 0, "prefix: exact 'IKETCP' ok");

	/* --- 2. bad prefix rejected --- */
	tcp_decap_init(&s);
	CHECK(feed_all(&s, badprefix, 6) == -1, "prefix: bad prefix rejected");

	/* --- 3. a single IKE record (len=1, sep=0x01) round-trips --- */
	n_frames = 0;
	tcp_decap_init(&s);
	tcp_stream_begin(&r);
	{
		unsigned char m = 0x42;
		CHECK(tcp_record_build(&r, &m, 1) == 0, "build: 1-byte record");
	}
	CHECK(r.stream_len == IKEV2_TCP_PREFIX_LEN + 3 + 1,
	      "build: stream length 10");
	CHECK(feed_all(&s, r.stream, r.stream_len) == 0 && n_frames == 1,
	      "round-trip: one frame decoded");
	CHECK(n_frames == 1 && got_len[0] == 1 && got_sep[0] == IKEV2_TCP_SEP_IKE &&
	      got[0][0] == 0x42, "round-trip: payload+sep correct");

	/* --- 4. length bound: zero-length record rejected --- */
	tcp_decap_init(&s);
	{
		unsigned char rec[] = "IKETCP" "\0\0" "\x01";
		CHECK(feed_all(&s, rec, sizeof(rec) - 1) == -1,
		      "length: zero-length record rejected");
	}

	/* --- 5. length bound: >65535 rejected (0xffff allowed) --- */
	tcp_decap_init(&s);
	{
		unsigned char rec1[] = "IKETCP" "\xff\xff" "\x01";
		CHECK(feed_all(&s, rec1, sizeof(rec1) - 1) == 0,
		      "length: 65535 header accepted (waits for payload)");
	}
	{
		unsigned char rec2[] = "IKETCP" "\x01\x00" "\x01";
		tcp_decap_init(&s);
		CHECK(feed_all(&s, rec2, sizeof(rec2) - 1) == 0 &&
		      s.phase == TCAP_PAYLOAD && s.reclen == 256,
		      "length: 256 header with no payload yet is a wait, not malformed");
	}

	/* --- 6. separators: ESP (0x00) and IKE (0x01) routed; 0x02 rejected --- */
	n_frames = 0;
	tcp_decap_init(&s);
	{
		unsigned char rec[] = "IKETCP" "\0\1" "\x00" "\xaa" "\0\1" "\x01" "\xbb";
		CHECK(feed_all(&s, rec, sizeof(rec) - 1) == 0 && n_frames == 2,
		      "sep: ESP + IKE both decoded");
		CHECK(n_frames == 2 && got_sep[0] == IKEV2_TCP_SEP_ESP &&
		      got_sep[1] == IKEV2_TCP_SEP_IKE, "sep: sep values recorded");
	}
	tcp_decap_init(&s);
	{
		unsigned char rec[] = "IKETCP" "\0\1" "\x02" "\xaa";
		CHECK(feed_all(&s, rec, sizeof(rec) - 1) == -1,
		      "sep: separator 0x02 rejected");
	}

	/* --- 7. partial feed at every byte boundary still decodes --- */
	{
		int ok = 1, k;
		unsigned char pkt[16];
		for (k = 0; k < 16; k++)
			pkt[k] = (unsigned char)k;
		for (i = 0; i < 16; i++) {
			n_frames = 0;
			tcp_decap_init(&s);
			feed_all(&s, (const unsigned char *)"IKETCP", 6);
			feed_all(&s, (const unsigned char*)"\x00\x10" "\x01", 3);
			if (i > 0) feed_all(&s, pkt, i);
			if (i < 16) feed_all(&s, pkt + i, 16 - i);
			if (n_frames != 1 || got_len[0] != 16 || got[0][i] != i) {
				ok = 0;
				break;
			}
		}
		CHECK(ok, "partial: split at every boundary decodes");
	}

	/* --- 8. multi-record coalescing in one feed --- */
	n_frames = 0;
	tcp_decap_init(&s);
	r.stream_len = 0;	/* fresh stream */
	tcp_stream_begin(&r);
	{
		unsigned char m1 = 0x01, m2 = 0x02;
		tcp_record_build(&r, &m1, 1);
		tcp_record_build(&r, &m2, 1);
	}
	CHECK(feed_all(&s, r.stream, r.stream_len) == 0 && n_frames == 2,
	      "coalesce: two records in one stream feed");

	if (!fails)
		printf("all tcp-framing checks passed\n");
	return fails ? 1 : 0;
}
