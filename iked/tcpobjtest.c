/* $Id$ */
/*
 * Test for the per-connection tcp_stream transport object
 * (iked/ikev2_tcp_stream.c) over real loopback TCP: one side accepts
 * (responder, expect_prefix=1), the other connects (originator,
 * expect_prefix=0).  Verifies:
 *   - non-blocking outbound connect that completes;
 *   - the originator emits the one-time "IKETCP" prefix, the responder does
 *     not;
 *   - an IKE record sent by the originator is received (marker-stripped) by
 *     the responder's dispatch callback;
 *   - a no-prefix reply from the responder is received by the originator's
 *     dispatch callback.
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "racoon.h"
#include "vmbuf.h"
#include "ikev2_tcp_stream.h"

static int nrecv;
static unsigned char cap[8][256];
static size_t capl[8];

static int
capture(rc_vchar_t *pkt, struct sockaddr *remote, struct sockaddr *local,
	void *arg)
{
	(void)remote; (void)local; (void)arg;
	if (nrecv < 8 && pkt->l < sizeof(cap[0])) {
		memcpy(cap[nrecv], pkt->v, pkt->l);
		capl[nrecv] = pkt->l;
	}
	++nrecv;
	rc_vfree(pkt);		/* dispatch owns/frees the packet */
	return 0;
}

static int
wait_done(struct tcp_stream *ts, int tries)
{
	while (tries-- > 0) {
		if (tcp_stream_connect_done(ts) == 0)
			return 0;
		usleep(2000);
	}
	return -1;
}

static int
fails = 0;
#define CHECK(cond, why) do { if (!(cond)) { \
	printf("FAIL: %s\n", why); ++fails; } else { \
	printf("ok: %s\n", why); } } while (0)

int
main(void)
{
	struct sockaddr_in la, lr;
	struct tcp_stream *origin = NULL, *resp = NULL;
	int lfd = -1, on = 1, tries;
	socklen_t sl = sizeof(la);
	const unsigned char msg[] = { 0x01, 0x02, 0x03, 0x04 };

	memset(&la, 0, sizeof(la));
	la.sin_family = AF_INET;
	la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	la.sin_port = 0;
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0 || setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on,
				 sizeof(on)) < 0 ||
	    bind(lfd, (struct sockaddr *)&la, sizeof(la)) < 0 ||
	    getsockname(lfd, (struct sockaddr *)&la, &sl) < 0 ||
	    listen(lfd, 8) < 0) {
		printf("FAIL: listener setup: %s\n", strerror(errno));
		return 1;
	}

	/* originator: non-blocking connect to the listener */
	memset(&lr, 0, sizeof(lr));
	lr.sin_family = AF_INET;
	lr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	lr.sin_port = la.sin_port;
	origin = tcp_stream_connect((struct sockaddr *)&lr, NULL, 0, capture, NULL);
	CHECK(origin != NULL, "connect: stream created (EINPROGRESS)");
	if (origin == NULL) {
		printf("FAIL: connect: %s\n", strerror(errno));
		return 1;
	}
	/* responder: accept the connection (peer is the originator) */
	resp = tcp_stream_accept(lfd, capture, NULL);
	CHECK(resp != NULL, "accept: responder stream created");
	if (resp == NULL) {
		printf("FAIL: accept: %s\n", strerror(errno));
		return 1;
	}

	CHECK(wait_done(origin, 5000) == 0, "connect: non-blocking connect completed");

	/* originator sends an IKE message; the one-time prefix must precede it */
	nrecv = 0;
	CHECK(tcp_stream_send(origin, msg, sizeof(msg)) == 0, "send: originator queues+flushes");
	for (tries = 5000; tries > 0 && nrecv == 0; tries--)
		if (tcp_stream_on_readable(resp) < 0)
			break;
	CHECK(nrecv == 1 && capl[0] == 4 && cap[0][0] == 0x01 && cap[0][3] == 0x04,
	      "recv: responder dispatch got the IKE message (marker stripped)");

	/* responder replies with no prefix; originator must decode it */
	nrecv = 0;
	CHECK(tcp_stream_send(resp, msg, sizeof(msg)) == 0, "reply: responder queues+flushes");
	for (tries = 5000; tries > 0 && nrecv == 0; tries--)
		if (tcp_stream_on_readable(origin) < 0)
			break;
	CHECK(nrecv == 1 && capl[0] == 4 && cap[0][0] == 0x01,
	      "recv: originator dispatch got the no-prefix reply");

	tcp_stream_free(origin);
	tcp_stream_free(resp);
	close(lfd);
	if (!fails)
		printf("all tcp-stream-object checks passed\n");
	return fails ? 1 : 0;
}
