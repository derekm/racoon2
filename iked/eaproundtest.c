/*
 * iked/eaproundtest.c - hermetic test of the responder EAP worker-round
 * bridge (ikev2_eap_round.c), focused on the SA-lifetime and pin bookkeeping
 * that the operator harnesses (radworkertest / relayworkertest) cannot prove
 * because they run without an ike_sa.
 *
 * ikev2_eap_round_submit() pins ike_sa->crypto_pending, runs the exchange on
 * a worker, and done() re-finds the SA by serial on the main thread:
 *   - a live SA has the pin cleared and resume() is called once;
 *   - a gone / recycled / DYING / DEAD SA has the pin cleared (when still
 *     findable) and resume() is NOT called (mirror of
 *     ikev2_createchild_initiator_dh_done) - the round is just released.
 *
 * Cases:
 *   1. live, inserted SA: pin cleared, resume called once.
 *   2. not-on-list SA (find_sa_by_serial == NULL): resume NOT called, no
 *      touch of the SA (no use-after-free).
 *   3. inserted DEAD SA: pin cleared, resume NOT called.
 *   4. inserted SA freed while the worker is away: resume NOT called, no
 *      crash (unlink + dispose + drain).
 *
 * The exchange runs against 127.0.0.1:1 (nothing listens) so it fails fast
 * with a transport error; what matters here is the done() path (SA re-find,
 * pin clear, resume-or-drop), which runs regardless of the exchange rc.
 *
 * Returns 0 iff all pass.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_radius.h"
#include "crypto_workers.h"
#include "ikev2_eap_round.h"
#include <getopt.h>
#include "test_util.h"

TEST_MAIN_STUBS()

static int fails;
static int resume_count;
static int resume_had_sa;

static void
on_resume(struct ikev2_eap_round *r, int rc)
{
	resume_count++;
	if (ikev2_eap_round_sa(r) != NULL)
		resume_had_sa = 1;
	(void)rc;
}

/* run the main-loop select+drain until the worker round completes.
 * Returns 0 once a drain ran, -1 if the round never completed (timeout). */
static int
drain_until_done(void)
{
	int i;
	for (i = 0; i < 400; i++) {
		fd_set rfd; struct timeval tv;
		FD_ZERO(&rfd);
		FD_SET(crypto_workers_fd(), &rfd);
		tv.tv_sec = 0; tv.tv_usec = 10000;
		if (select(crypto_workers_fd() + 1, &rfd, NULL, NULL, &tv) > 0 &&
		    FD_ISSET(crypto_workers_fd(), &rfd)) {
			crypto_workers_drain();
			return 0;
		}
	}
	return -1;
}

int
main(void)
{
	rc_vchar_t secret, eap;
	struct sockaddr_in server;
	struct ikev2_radius_opt opt;
	uint8_t id = 7;
	uint8_t eapwire[5] = { 2, 7, 0, 5, 1 };	/* Response/Identity */
	struct ikev2_sa *sa;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;
	if (crypto_workers_init(2) < 0)
		return 2;
	if (!crypto_workers_enabled()) {
		printf("eaproundtest: FAIL no worker pool\n");
		return 1;
	}
	ikev2_sa_init();
	sched_init();

	secret.v = malloc(4); secret.l = 4; memcpy(secret.v, "ABCD", 4);
	eap.v = eapwire; eap.l = 5;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(1);	/* nothing listening: fast error path */
	inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);
	memset(&opt, 0, sizeof(opt));
	opt.secret = &secret;
	opt.nas_ip = "127.0.0.1";
	opt.retries = 1;
	opt.timeout_ms = 50;

	/* ---- 1. live, inserted SA: pin cleared + resume once ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->crypto_pending = 0;
	resume_count = 0; resume_had_sa = 0;
	id = 7;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		printf("eaproundtest: FAIL 1 submit\n");
		fails++;
	} else if (sa->crypto_pending == 0) {
		printf("eaproundtest: FAIL 1 pin not set during round\n");
		fails++;
	} else {
		drain_until_done();
		if (resume_count == 1 && sa->crypto_pending == 0 &&
		    resume_had_sa) {
			printf("eaproundtest: PASS 1 live SA resumed once, "
			       "pin cleared\n");
		} else {
			printf("eaproundtest: FAIL 1 resume=%d pending=%d"
			       " sa=%d\n", resume_count, sa->crypto_pending,
			       resume_had_sa);
			fails++;
		}
	}
	TAILQ_REMOVE(&ikev2_sa_list, sa, link);
	ikev2_dispose_sa(sa);

	/* ---- 2. not-on-list SA: resume NOT called, no touch ----
	 * allocates a real SA but does NOT put it on the serial list, so
	 * find_sa_by_serial(serial) is NULL in done() -> release the round
	 * without calling resume (no use-after-free). */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	sa->crypto_pending = 0;
	resume_count = 0; resume_had_sa = 0;
	id = 8;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		printf("eaproundtest: FAIL 2 submit\n");
		fails++;
	} else {
		/* pin may or may not still be set if inline; either way
		 * resume must NOT run */
		drain_until_done();
		if (resume_count == 0) {
			printf("eaproundtest: PASS 2 not-on-list SA not "
			       "resumed\n");
		} else {
			printf("eaproundtest: FAIL 2 resume_count=%d "
			       "(want 0)\n", resume_count);
			fails++;
		}
	}
	ikev2_dispose_sa(sa);

	/* ---- 3. inserted DEAD SA: pin cleared, resume NOT called ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->crypto_pending = 0;
	sa->state = IKEV2_STATE_DEAD;
	resume_count = 0; resume_had_sa = 0;
	id = 9;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		printf("eaproundtest: FAIL 3 submit\n");
		fails++;
	} else {
		drain_until_done();
		if (resume_count == 0 && sa->crypto_pending == 0) {
			printf("eaproundtest: PASS 3 DEAD SA not resumed, "
			       "pin cleared\n");
		} else {
			printf("eaproundtest: FAIL 3 resume=%d pending=%d\n",
			       resume_count, sa->crypto_pending);
			fails++;
		}
	}
	TAILQ_REMOVE(&ikev2_sa_list, sa, link);
	ikev2_dispose_sa(sa);

	/* ---- 4. SA freed while worker away: no resume, no crash ----
	 * submit pins + queues; then the caller frees its opt.state and the SA
	 * BEFORE drain.  done() finds no SA by serial -> releases the round
	 * without touching the freed SA.  Freeing caller-owned opt.state right
	 * after submit is only sound because submit deep-copies every
	 * worker-read opt member (user_name/nas_ip/nas_id/state/secret):
	 * if it shallow-copied, the worker would read freed memory (ASan
	 * crash).  A use-after-free of the SA would crash or resume. */
	rc_vchar_t sbuf;
	uint8_t statewire[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	sbuf.v = malloc(sizeof(statewire)); sbuf.l = sizeof(statewire);
	memcpy(sbuf.v, statewire, sizeof(statewire));
	opt.state = &sbuf;
	opt.user_name = "alice@example.test";	/* non-NULL: deep-copied */
	opt.nas_id = "nas-test";
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->crypto_pending = 0;
	resume_count = 0; resume_had_sa = 0;
	id = 10;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		printf("eaproundtest: FAIL 4 submit\n");
		fails++;
	} else {
		/* caller frees its opt.state + SA right after submit; the worker
		 * must already hold its own deep copies */
		free(sbuf.v); sbuf.v = NULL;
		TAILQ_REMOVE(&ikev2_sa_list, sa, link);
		ikev2_dispose_sa(sa);
		opt.state = NULL;	/* drop the alias so later cases are clean */
		if (drain_until_done() != 0) {
			printf("eaproundtest: FAIL 4 drain timeout\n");
			fails++;
		} else if (resume_count == 0) {
			printf("eaproundtest: PASS 4 freed-SA round not "
			       "resumed (no UAF, opt deep-copied)\n");
		} else {
			printf("eaproundtest: FAIL 4 freed-SA WAS resumed "
			       "count=%d (use-after-free!)\n", resume_count);
			fails++;
		}
	}

	if (secret.v) free(secret.v);
	printf("eaproundtest: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
