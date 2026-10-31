/* $Id$ */
/*
 * Test for the TCP listener + stream registry (iked/ikev2_tcp_srv.c) over
 * real loopback TCP, mimicking the iked main loop: build the fdset, wait
 * with select(), then drive tcp_srv_process().  Verifies:
 *   - a non-blocking listener accepts queued connections into streams;
 *   - tcp_srv_fdset covers the listener and every accepted stream;
 *   - a client message is handed to the dispatch callback (marker stripped);
 *   - a client FIN removes the stream (count drops) -- framing-fatal teardown
 *     follows the same path.
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
#include <poll.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "racoon.h"
#include "vmbuf.h"
#include "ikev2_tcp_stream.h"
#include "ikev2_tcp_srv.h"
#include <sys/queue.h>
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_tcp_route.h"

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
	rc_vfree(pkt);
	return 0;
}

static int
wait_connect(struct tcp_stream *ts, int ms)
{
	struct pollfd pfd;

	pfd.fd = ts->fd;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	if (poll(&pfd, 1, ms) > 0 &&
	    (pfd.revents & (POLLOUT | POLLERR | POLLHUP)))
		return tcp_stream_connect_done(ts);
	return -1;
}


/* Fatal-send-inside-dispatch probe: the reply to the first record fails
 * (our write side is shut, so tcp_stream_send returns -1 just as on a peer
 * RST) through the production ikev2_tcp_send(), which retires the stream
 * while tcp_stream_on_readable is still de-framing the same read. */
static int kill_calls, kill_r = 99, kill_handled, kill_after_dead;
static int
send_fail_dispatch(rc_vchar_t *pkt, struct sockaddr *remote,
		   struct sockaddr *local, void *arg)
{
	struct tcp_stream *ts;

	(void)arg;
	++kill_calls;
	ts = tcp_srv_find(remote, local);
	if (ts == NULL) {
		++kill_after_dead;	/* dispatched on a retired stream */
		rc_vfree(pkt);
		return 0;
	}
	(void)shutdown(ts->fd, SHUT_WR);
	kill_handled = ikev2_tcp_send(NULL, 0, remote, local,
	    (const unsigned char *)pkt->v, pkt->l, &kill_r, NULL);
	rc_vfree(pkt);
	return 0;
}

static int fails;

/* Socket-hook probe: iked installs setsockopt_bypass() here.  The hook has
 * to run on a fresh socket, before bind/listen/connect; otherwise the
 * kernel has already done the SYN's policy lookup and the bypass comes
 * too late. */
static int hook_calls, hook_fresh = 1, hook_fail;
static int
probe_hook(int fd, int family)
{
	struct sockaddr_storage ss;
	socklen_t l = sizeof(ss);
	int acc = 0;
	socklen_t al = sizeof(acc);

	++hook_calls;
	if (family != AF_INET)
		hook_fresh = 0;
	if (getsockname(fd, (struct sockaddr *)&ss, &l) == 0 &&
	    ((struct sockaddr_in *)&ss)->sin_port != 0)
		hook_fresh = 0;		/* already bound */
	if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &acc, &al) == 0 && acc)
		hook_fresh = 0;		/* already listening */
	if (getpeername(fd, (struct sockaddr *)&ss, &l) == 0)
		hook_fresh = 0;		/* already connected */
	if (hook_fail) {
		errno = EPERM;
		return -1;
	}
	return 0;
}
#define CHECK(cond, why) do { if (!(cond)) { \
	printf("FAIL: %s\n", why); ++fails; } else { \
	printf("ok: %s\n", why); } } while (0)

int
main(void)
{
	struct sockaddr_in la, ca;
	struct tcp_stream *cli1 = NULL, *cli2 = NULL;
	fd_set rfds, wfds;
	struct timeval tv;
	int lfd = -1, tries, spins;
	socklen_t sl = sizeof(la);
	unsigned char msg[32] = { 0 };
	int i;

	for (i = 0; i < 32; i++)
		msg[i] = (unsigned char)i;

	memset(&la, 0, sizeof(la));
	la.sin_family = AF_INET;
	la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	la.sin_port = 0;

	tcp_srv_init(capture, NULL);
	tcp_stream_sock_hook = probe_hook;
	lfd = tcp_srv_open_listener((struct sockaddr *)&la, 0);
	CHECK(lfd >= 0 && tcp_srv_listener_fd() == lfd, "listener: opened");
	if (lfd < 0) {
		printf("FAIL: listener: %s\n", strerror(errno));
		return 1;
	}
	if (getsockname(lfd, (struct sockaddr *)&la, &sl) < 0) {
		printf("FAIL: getsockname %s\n", strerror(errno));
		return 1;
	}

	/* two originator clients connect to the listener */
	memset(&ca, 0, sizeof(ca));
	ca.sin_family = AF_INET;
	ca.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ca.sin_port = la.sin_port;
	cli1 = tcp_stream_connect((struct sockaddr *)&ca, NULL, capture, NULL);
	cli2 = tcp_stream_connect((struct sockaddr *)&ca, NULL, capture, NULL);
	CHECK(cli1 && cli2, "connect: two clients");
	CHECK(hook_calls == 3 && hook_fresh,
	      "hook: run once per listener/connect socket, before bind/listen/connect");
	if (!cli1 || !cli2)
		return 1;
	CHECK(wait_connect(cli1, 3000) == 0 && wait_connect(cli2, 3000) == 0,
	      "connect: both completed");

	CHECK(tcp_srv_accept_pending() == 2 && tcp_srv_count() == 2,
	      "accept: 2 streams registered");

	/* find: the registered stream resolves by (client src, listener local) */
	{
		struct sockaddr_storage csrc;
		struct sockaddr_in bogus, bogus2;
		struct tcp_stream *f;
		socklen_t cl = sizeof(csrc);

		memset(&csrc, 0, sizeof(csrc));
		CHECK(getsockname(cli1->fd, (struct sockaddr *)&csrc, &cl) == 0,
		      "find: got client source addr");
		f = tcp_srv_find((struct sockaddr *)&csrc,
				 (struct sockaddr *)&la);
		CHECK(f != NULL, "find: stream found by (client src, listener local)");
		/* RFC 9329 address-only keying: the transport is matched on the peer
		 * ADDRESS, not its port (the stream's remote is :4500 while the SA's
		 * IKE dest is :500; the local side differs likewise).  A bogus PORT on
		 * the same loopback address is therefore NOT a mismatch under
		 * address-only semantics -- it must still resolve.  The negative case
		 * has to differ by ADDRESS (a non-loopback local), which address-only
		 * correctly rejects.  One stream per peer-address pair is the design
		 * (RFC 9329 keeps a single IKE-over-TCP connection per peer). */
		memset(&bogus, 0, sizeof(bogus));
		bogus.sin_family = AF_INET;
		bogus.sin_addr.s_addr = htonl(0xc0000201); /* 192.0.2.1, not loopback */
		bogus.sin_port = htons(9999);
		CHECK(tcp_srv_find((struct sockaddr *)&csrc,
				   (struct sockaddr *)&bogus) == NULL,
		      "find: no match on wrong local addr");
		/* and the port-agnostic contract: a different IKE port on the SAME
		 * loopback address still resolves to the stream. */
		memset(&bogus2, 0, sizeof(bogus2));
		bogus2.sin_family = AF_INET;
		bogus2.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		bogus2.sin_port = htons(4500);
		CHECK(tcp_srv_find((struct sockaddr *)&csrc,
				   (struct sockaddr *)&bogus2) != NULL,
		      "find: same-peer different-port still resolves (address-only)");
	}

	/* RFC 9329 / H3: two clients behind one NAT present the same address
	 * and differ only by TCP source port.  The SA-bound lookup matches on
	 * the stream's remote ADDRESS:PORT, so it must tell them apart where
	 * the address-only tcp_srv_find() cannot. */
	{
		struct sockaddr_storage csrc1, csrc2;
		struct sockaddr_in wrongport;
		struct tcp_stream *fb1, *fb2;
		socklen_t l1 = sizeof(csrc1), l2 = sizeof(csrc2);

		CHECK(getsockname(cli1->fd, (struct sockaddr *)&csrc1, &l1) == 0 &&
		      getsockname(cli2->fd, (struct sockaddr *)&csrc2, &l2) == 0,
		      "bound: got both client source addrs");
		fb1 = tcp_srv_find_bound((struct sockaddr *)&csrc1,
					 (struct sockaddr *)&la);
		fb2 = tcp_srv_find_bound((struct sockaddr *)&csrc2,
					 (struct sockaddr *)&la);
		CHECK(fb1 != NULL && fb2 != NULL,
		      "bound: each client resolves a stream");
		CHECK(fb1 != fb2,
		      "bound: distinct streams for distinct source ports");
		memset(&wrongport, 0, sizeof(wrongport));
		wrongport.sin_family = AF_INET;
		wrongport.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		wrongport.sin_port = htons(39999);	/* matches no client */
		CHECK(tcp_srv_find_bound((struct sockaddr *)&wrongport,
					 (struct sockaddr *)&la) == NULL,
		      "bound: no stream for an unknown source port");
	}

	/* RFC 9329 / H3 through the production send selection
	 * (ikev2_tcp_route, used by isakmp_try_tcp_send): two IKE_SAs whose
	 * peers share one address (same NAT) and differ by port and SPI.  Each
	 * SA's message must go out on its own bound stream and arrive at its
	 * own client; a UDP SA to a peer that has a stream stays on UDP. */
	{
		struct sockaddr_storage r1, r2, ikeport;
		socklen_t l1 = sizeof(r1), l2 = sizeof(r2);
		struct ikev2_sa sa1, sa2, sau;
		struct tcp_stream *t1, *t2;
		static const uint8_t m1[16] = { 0xa1 }, m2[16] = { 0xb2 };
		uint8_t buf[64];

		getsockname(cli1->fd, (struct sockaddr *)&r1, &l1);
		getsockname(cli2->fd, (struct sockaddr *)&r2, &l2);
		/* the IKE dest an SA would hand the send path: same peer
		 * address, IKE port, so only the SA binding can disambiguate */
		memcpy(&ikeport, &r1, sizeof(ikeport));
		((struct sockaddr_in *)&ikeport)->sin_port = htons(500);
		memset(&sa1, 0, sizeof(sa1));
		memset(&sa2, 0, sizeof(sa2));
		sa1.remote = (struct sockaddr *)&r1;
		sa1.local = (struct sockaddr *)&la;
		memset(sa1.index.i_ck, 0x11, sizeof(sa1.index.i_ck));
		sa2.remote = (struct sockaddr *)&r2;
		sa2.local = (struct sockaddr *)&la;
		memset(sa2.index.i_ck, 0x22, sizeof(sa2.index.i_ck));
		t1 = ikev2_tcp_route(&sa1, 1, (struct sockaddr *)&ikeport,
				     (struct sockaddr *)&la);
		t2 = ikev2_tcp_route(&sa2, 1, (struct sockaddr *)&ikeport,
				     (struct sockaddr *)&la);
		CHECK(t1 != NULL && t2 != NULL && t1 != t2,
		      "route: same-NAT SAs pick distinct streams");
		CHECK(t1 == tcp_srv_find_bound((struct sockaddr *)&r1,
					       (struct sockaddr *)&la) &&
		      t2 == tcp_srv_find_bound((struct sockaddr *)&r2,
					       (struct sockaddr *)&la),
		      "route: each SA picks the stream bound to its own port");
		if (t1 && t2 && t1 != t2) {
			struct pollfd pf;
			ssize_t n1, n2;

			tcp_stream_send(t1, m1, sizeof(m1));
			tcp_stream_send(t2, m2, sizeof(m2));
			pf.fd = cli1->fd; pf.events = POLLIN; pf.revents = 0;
			poll(&pf, 1, 1000);
			pf.fd = cli2->fd; pf.revents = 0;
			poll(&pf, 1, 1000);
			/* RFC 9329 frame: 2-byte length, then the IKE bytes
			 * (non-ESP marker included); last byte of m1/m2 is 0 */
			n1 = recv(cli1->fd, buf, sizeof(buf), MSG_DONTWAIT);
			CHECK(n1 > 0 && memchr(buf, 0xa1, n1) &&
			      !memchr(buf, 0xb2, n1),
			      "route: SA1's message reached client1 only");
			n2 = recv(cli2->fd, buf, sizeof(buf), MSG_DONTWAIT);
			CHECK(n2 > 0 && memchr(buf, 0xb2, n2) &&
			      !memchr(buf, 0xa1, n2),
			      "route: SA2's message reached client2 only");
		}
		sau = sa1;
		CHECK(ikev2_tcp_route(&sau, 0, (struct sockaddr *)&r1,
				      (struct sockaddr *)&la) == NULL,
		      "route: a UDP SA stays on UDP despite a stream to its peer");
		CHECK(ikev2_tcp_route(NULL, 1, (struct sockaddr *)&r1,
				      (struct sockaddr *)&la) != NULL,
		      "route: pre-SA IKE_SA_INIT uses the address-only lookup");
	}

	FD_ZERO(&rfds); FD_ZERO(&wfds);
	CHECK(tcp_srv_fdset(&rfds, &wfds) > lfd &&
	      FD_ISSET(lfd, &rfds), "fdset: listener is readable");
	{
		int nrf = 0;
		FD_ZERO(&rfds); FD_ZERO(&wfds);
		tcp_srv_fdset(&rfds, &wfds);
		for (tries = 0; tries < FD_SETSIZE; tries++)
			if (FD_ISSET(tries, &rfds))
				++nrf;
		CHECK(nrf == 3, "fdset: listener + 2 streams cover 3 fds");
	}

	/* client 1 sends an IKE message; the registry loop delivers it */
	nrecv = 0;
	CHECK(tcp_stream_send(cli1, msg, sizeof(msg)) == 0, "send: client1 IKE");
	tv.tv_sec = 1; tv.tv_usec = 0;
	{
		int maxfd;

		FD_ZERO(&rfds); FD_ZERO(&wfds);
		maxfd = tcp_srv_fdset(&rfds, &wfds);
		/* like the daemon loop: wait on both directions, then drive */
		select(maxfd < 1 ? 1 : maxfd, &rfds, &wfds, NULL, &tv);
		tcp_srv_process(&rfds, &wfds);
	}
	CHECK(nrecv == 1 && capl[0] == 32 && cap[0][0] == 0x00 && cap[0][31] == 0x1f,
	      "process: delivered client1 IKE (marker stripped)");
	CHECK(tcp_srv_count() == 2, "process: stream count unchanged after delivery");

	/* client 1 FIN -> its stream is removed by the loop */
	tcp_stream_free(cli1);
	cli1 = NULL;
	spins = 0;
	while (tcp_srv_count() == 2 && spins < 50) {
		int maxfd;

		FD_ZERO(&rfds); FD_ZERO(&wfds);
		maxfd = tcp_srv_fdset(&rfds, &wfds);
		tv.tv_sec = 0; tv.tv_usec = 200000;
		select(maxfd < 1 ? 1 : maxfd, &rfds, &wfds, NULL, &tv);
		tcp_srv_process(&rfds, &wfds);
		++spins;
	}
	CHECK(tcp_srv_count() == 1, "teardown: client1 FIN removed its stream");

	hook_fail = 1;
	CHECK(tcp_stream_connect((struct sockaddr *)&ca, NULL, capture, NULL) == NULL,
	      "hook: a failing socket hook fails the connect (no unprotected SYN)");
	hook_fail = 0;
	tcp_stream_sock_hook = NULL;

	tcp_stream_free(cli2);

	/* RFC 9329 (M5): tcp_srv_teardown removes a registry stream and frees it
	 * (the fatal-send-error path), so it no longer resolves.  The initiator
	 * path registers a connecting stream right after tcp_stream_connect
	 * returns EINPROGRESS; do the same here so tmp is a registry member. */
	{
		struct tcp_stream *tmp;
		struct sockaddr_in tca;
		int before;

		memset(&tca, 0, sizeof(tca));
		tca.sin_family = AF_INET;
		tca.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		tca.sin_port = la.sin_port;
		tmp = tcp_stream_connect((struct sockaddr *)&tca, NULL, capture, NULL);
		CHECK(tmp != NULL, "teardown: temp stream created");
		CHECK(tcp_srv_register_connecting(tmp) == 0,
		      "teardown: temp stream registered");
		before = tcp_srv_count();
		tcp_srv_teardown(tmp);
		CHECK(tcp_srv_count() == before - 1,
		      "teardown: stream removed from registry");
	}

	/* RFC 9329 (M5): a fatal send from INSIDE a stream's own dispatch must
	 * not free the stream under the read loop (use-after-free; ASan builds
	 * abort on it).  Two records arrive in one read; the first's reply
	 * fails.  The stream must be marked dead at once (no lookup, no second
	 * dispatch, no UDP fallback), freed exactly once by the next
	 * tcp_srv_process pass, and a second teardown must be a no-op. */
	{
		struct tcp_stream *kc;
		static struct tcp_record rec1, rec2;
		static unsigned char wire[2 * sizeof(rec1.stream)];
		size_t wl = 0;
		int base, k;

		/* Settle earlier connections first so counts are exact. */
		for (k = 0; k < 10; k++) {
			FD_ZERO(&rfds); FD_ZERO(&wfds);
			tcp_srv_fdset(&rfds, &wfds);
			tv.tv_sec = 0; tv.tv_usec = 20000;
			select(FD_SETSIZE, &rfds, &wfds, NULL, &tv);
			tcp_srv_process(&rfds, &wfds);
		}
		base = tcp_srv_count_all();
		CHECK(base == tcp_srv_count(), "send-fail: registry settled");

		signal(SIGPIPE, SIG_IGN);
		kc = tcp_stream_connect((struct sockaddr *)&ca, NULL, capture,
		    NULL);
		CHECK(kc != NULL && wait_connect(kc, 2000) == 0,
		      "send-fail: client connected");
		for (k = 0; k < 50 && tcp_srv_count() == base; k++) {
			FD_ZERO(&rfds); FD_ZERO(&wfds);
			tcp_srv_fdset(&rfds, &wfds);
			tv.tv_sec = 0; tv.tv_usec = 20000;
			select(FD_SETSIZE, &rfds, &wfds, NULL, &tv);
			tcp_srv_process(&rfds, &wfds);
		}
		CHECK(tcp_srv_count_all() == base + 1,
		      "send-fail: stream accepted");
		{
			struct sockaddr_storage cs;
			socklen_t csl = sizeof(cs);
			struct tcp_stream *ss;

			getsockname(kc->fd, (struct sockaddr *)&cs, &csl);
			ss = tcp_srv_find((struct sockaddr *)&cs,
			    (struct sockaddr *)&ca);
			CHECK(ss != NULL, "send-fail: server stream found");
			if (ss != NULL)
				ss->dispatch = send_fail_dispatch;
		}
		/* "IKETCP" prefix + two whole records in one write(). */
		memset(&rec1, 0, sizeof(rec1));
		memset(&rec2, 0, sizeof(rec2));
		tcp_stream_begin(&rec1);
		CHECK(tcp_record_ike(&rec1, msg, sizeof(msg)) == 0 &&
		      tcp_record_ike(&rec2, msg, sizeof(msg)) == 0,
		      "send-fail: records built");
		memcpy(wire, rec1.stream, rec1.stream_len);
		wl = rec1.stream_len;
		memcpy(wire + wl, rec2.stream, rec2.stream_len);
		wl += rec2.stream_len;
		CHECK(write(kc->fd, wire, wl) == (ssize_t)wl,
		      "send-fail: two records written in one burst");
		usleep(50000);
		FD_ZERO(&rfds); FD_ZERO(&wfds);
		tcp_srv_fdset(&rfds, &wfds);
		tv.tv_sec = 1; tv.tv_usec = 0;
		select(FD_SETSIZE, &rfds, &wfds, NULL, &tv);
		tcp_srv_process(&rfds, &wfds);
		CHECK(kill_calls == 1, "send-fail: exactly one dispatch "
		      "(second record not delivered on a dead stream)");
		CHECK(kill_after_dead == 0, "send-fail: no dispatch after death");
		CHECK(kill_r == -1, "send-fail: tcp_stream_send reported fatal");
		CHECK(kill_handled == 1, "send-fail: handled on TCP, no UDP "
		      "fallback for a failed stream send");
		CHECK(tcp_srv_count_all() == base && tcp_srv_count() == base,
		      "send-fail: dead stream reaped by tcp_srv_process");
		tcp_stream_free(kc);
	}

	/* Deferred teardown outside dispatch + double teardown: marked dead at
	 * once, invisible to lookups, freed once on the next pass. */
	{
		struct tcp_stream *tmp2;
		int before;

		tmp2 = tcp_stream_connect((struct sockaddr *)&ca, NULL, capture,
		    NULL);
		CHECK(tmp2 != NULL && tcp_srv_register_connecting(tmp2) == 0,
		      "double-teardown: temp stream registered");
		before = tcp_srv_count_all();
		tcp_srv_teardown(tmp2);
		tcp_srv_teardown(tmp2);
		CHECK(tcp_srv_count() == before - 1 &&
		      tcp_srv_count_all() == before,
		      "double-teardown: marked dead, not yet freed");
		CHECK(tcp_stream_send(tmp2, msg, sizeof(msg)) == -1,
		      "double-teardown: no writes on a dead stream");
		FD_ZERO(&rfds); FD_ZERO(&wfds);
		tcp_srv_process(&rfds, &wfds);	/* frees once (ASan: no DF) */
		CHECK(tcp_srv_count_all() == before - 1,
		      "double-teardown: freed once by the next pass");
	}
	tcp_srv_fini();
	if (!fails)
		printf("all tcp-srv checks passed\n");
	return fails ? 1 : 0;
}
