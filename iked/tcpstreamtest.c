/* $Id$ */
/*
 * End-to-end test of the RFC 9329 framing codec over a real TCP stream.
 *
 * RFC 9329 s4: the TCP connection ORIGINATOR writes the one-time "IKETCP"
 * prefix then records; the RESPONDER writes records with no prefix.  This
 * test runs two endpoints over a socketpair and verifies:
 *   - originator write(prefix + records) -> responder decodes (expect_prefix=1)
 *   - responder writes records (no prefix) -> originator decodes (expect_prefix=0)
 *   - real read() results are fed in whatever chunking the kernel delivers,
 *     including byte-at-a-time to force a split inside every field.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>

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

/* Drain a fd fully: read() until EAGAIN/EOF, feeding bytes as read into the
 * de-framer.  Drives the chunking exactly as a daemon loop read would. */
static int
drain(struct tcp_decap_state *s, int fd, int onebyte)
{
	unsigned char b;
	ssize_t n;

	for (;;) {
		if (onebyte) {
			/* force a split inside every field */
			n = read(fd, &b, 1);
			if (n == 1 && tcp_decap_feed(s, &b, 1, collect, NULL) != 0)
				return -1;
		} else {
			unsigned char chunk[4096];
			size_t i, got = 0;

			n = read(fd, chunk, sizeof(chunk));
			if (n > 0) {
				for (i = 0; i < (size_t)n; i++)
					got += (size_t)chunk[i];
				(void)got;
				if (tcp_decap_feed(s, chunk, (size_t)n,
						   collect, NULL) != 0)
					return -1;
			}
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -1;
		}
		if (n == 0)
			return 0;	/* peer shutdown */
	}
}

int
main(void)
{
	int sv[2];			/* sv[0]=originator, sv[1]=responder */
	struct tcp_decap_state os, rs;	/* originator/responder decoders */
	struct tcp_record ob, rb;	/* originator/responder outbound */
	unsigned char ike_a[] = { 0x10, 0x20, 0x30 }, ike_b[] = { 0xaa, 0xbb };
	int fails = 0;

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("FAIL: socketpair: %s\n", strerror(errno));
		return 1;
	}
	if (fcntl(sv[0], F_SETFL, O_NONBLOCK) < 0 ||
	    fcntl(sv[1], F_SETFL, O_NONBLOCK) < 0) {
		printf("FAIL: fcntl nonblock\n");
		return 1;
	}

	/* --- originator -> responder (RFC 9329 s4: prefix + records) --- */
	memset(&ob, 0, sizeof(ob));
	tcp_stream_begin(&ob);
	if (tcp_record_ike(&ob, ike_a, sizeof(ike_a)) != 0) {
		printf("FAIL: originator build\n");
		return 1;
	}
	if (tcp_record_ike(&ob, ike_b, sizeof(ike_b)) != 0) {
		printf("FAIL: originator build\n");
		return 1;
	}
	if (write(sv[0], ob.stream, ob.stream_len) != (ssize_t)ob.stream_len) {
		printf("FAIL: originator write\n");
		return 1;
	}
	/* responder is the ACCEPTING side: peer is originator -> expect prefix */
	tcp_decap_init(&rs, 1);
	n_frame = 0;
	if (drain(&rs, sv[1], 0) != 0 || n_frame != 2) {
		printf("FAIL: responder decode (got %d frames)\n", n_frame);
		++fails;
	} else if (gesp[0] != TCP_FRAME_IKE || glen[0] != 3 ||
		   got[0][2] != 0x30 || gesp[1] != TCP_FRAME_IKE ||
		   glen[1] != 2 || got[1][1] != 0xbb) {
		printf("FAIL: responder frame contents\n");
		++fails;
	} else {
		printf("ok: originator prefix stream decoded by responder\n");
	}

	/* --- responder -> originator (no prefix) --- */
	memset(&rb, 0, sizeof(rb));	/* NO tcp_stream_begin: responder's reply */
	if (tcp_record_ike(&rb, ike_a, sizeof(ike_a)) != 0) {
		printf("FAIL: responder build\n");
		return 1;
	}
	if (write(sv[1], rb.stream, rb.stream_len) != (ssize_t)rb.stream_len) {
		printf("FAIL: responder write\n");
		return 1;
	}
	/* originator is the CONNECTING side: peer reply has no prefix */
	tcp_decap_init(&os, 0);
	n_frame = 0;
	if (drain(&os, sv[0], 0) != 0 || n_frame != 1 ||
	    glen[0] != 3 || gesp[0] != TCP_FRAME_IKE || got[0][0] != 0x10) {
		printf("FAIL: originator decode of no-prefix reply\n");
		++fails;
	} else {
		printf("ok: responder no-prefix reply decoded by originator\n");
	}

	/* --- both directions again with real byte-at-a-time kernel writes --- */
	{
		struct tcp_decap_state d;
		unsigned char payload[] = { 0xde, 0xad, 0xbe, 0xef };
		int k;

		/* originator writes a fresh prefix+record stream one byte at a
		 * time AND reads each byte back individually, so every field
		 * byte arrives as its own read(): a split falls inside the Len
		 * and the 4-octet marker, not just between records. */
		memset(&ob, 0, sizeof(ob)); tcp_stream_begin(&ob);
		tcp_record_ike(&ob, payload, sizeof(payload));
		tcp_decap_init(&d, 1); n_frame = 0;
		for (k = 0; k < (int)ob.stream_len && !fails; k++) {
			unsigned char b;

			if (write(sv[0], ob.stream + k, 1) != 1) {
				printf("FAIL: byte-at-a-time write\n"); ++fails; break;
			}
			if (read(sv[1], &b, 1) != 1) {
				printf("FAIL: byte-at-a-time read\n"); ++fails; break;
			}
			if (tcp_decap_feed(&d, &b, 1, collect, NULL) != 0) {
				printf("FAIL: byte-at-a-time feed\n"); ++fails; break;
			}
		}
		if (!fails && (n_frame != 1 || glen[0] != 4 ||
			       gesp[0] != TCP_FRAME_IKE || got[0][3] != 0xef))
			{ printf("FAIL: byte-at-a-time decode\n"); ++fails; }
		if (!fails)
			printf("ok: byte-at-a-time stream decoded (split in every field)\n");
	}

	close(sv[0]); close(sv[1]);
	if (!fails)
		printf("all tcp-stream checks passed\n");
	return fails ? 1 : 0;
}
