/*
 * iked/eaproundtest.c - hermetic test of the responder EAP worker-round
 * bridge (ikev2_eap_round.c), focused on the SA-lifetime guard.
 *
 * The operator harnesses (radworkertest / relayworkertest) prove the
 * worker+drain+relay path but run WITHOUT an ike_sa, so they cannot test
 * the one property this bridge exists to guarantee: between the worker
 * starting and the main loop draining, the IKE_SA may disappear, and
 * done() must NOT resume (or touch) an SA it cannot re-find as the same,
 * live SA (use-after-free guard; same discipline as
 * ikev2_createchild_initiator_dh_done).
 *
 * This test creates REAL ike_sa structs and exercises the bridge's
 * revalidate/done path hermetically:
 *
 *   1. a live, inserted SA is resumed (done() runs; crypto_pending cleared).
 *   2. an SA that is not on the serial list (not inserted) is NOT resumed:
 *      find_sa_by_serial returns NULL and the round is dropped cleanly.
 *   3. an inserted, IKEV2_STATE_DEAD SA is NOT resumed (state check).
 *
 * The worker's exchange runs against 127.0.0.1:1 (nothing listens) so it
 * returns fast with a transport error - the point here is the done() path
 * (SA re-find + resume-or-drop), which runs regardless of the exchange rc.
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

static void
on_resume(struct ikev2_eap_round *r, int rc)
{
	resume_count++;
	(void)rc;
	(void)r;
}

/* run the main-loop select+drain until the worker round completes */
static void
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
			return;
		}
	}
}

int
main(void)
{
	rc_vchar_t secret, eap;
	struct sockaddr_in server;
	struct ikev2_radius_opt opt;
	struct ikev2_eap_round *round = NULL;
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

	/* ---- 1. live, inserted SA is resumed ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->crypto_pending = 1;
	resume_count = 0;
	round = NULL;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume, &round) != 0) {
		printf("eaproundtest: FAIL 1 submit\n");
		fails++;
	} else {
		drain_until_done();
		if (resume_count == 1 && sa->crypto_pending == 0) {
			printf("eaproundtest: PASS 1 live SA resumed, "
			       "crypto_pending cleared\n");
		} else {
			printf("eaproundtest: FAIL 1 resume_count=%d"
			       " pending=%d\n", resume_count, sa->crypto_pending);
			fails++;
		}
	}
	/* dispose the live SA (round already completed and freed).  dispose_sa
	 * does not unlink (iked/ike_sa.c:1080), so remove it from the list
	 * ourselves first - otherwise the freed block keeps a stale list entry
	 * that malloc can later reuse, making a later "not on the list" check
	 * nondeterministic. */
	TAILQ_REMOVE(&ikev2_sa_list, sa, link);
	ikev2_dispose_sa(sa);

	/* ---- 2. non-inserted SA (not findable by serial) is NOT resumed ----
	 * allocates a real SA but does NOT put it on the serial list, so
	 * find_sa_by_serial(serial) is NULL -> done() must drop the round
	 * without calling on_resume (no use-after-free). */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	sa->crypto_pending = 1;
	resume_count = 0;
	round = NULL;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume, &round) != 0) {
		printf("eaproundtest: FAIL 2 submit\n");
		fails++;
	} else {
		drain_until_done();
		if (resume_count == 0) {
			printf("eaproundtest: PASS 2 non-findable SA round "
			       "not resumed\n");
		} else {
			printf("eaproundtest: FAIL 2 resume_count=%d (want 0: "
			       "SA not on serial list)\n", resume_count);
			fails++;
		}
	}
	/* dispose our reference (SA is not on the serial list; disposing it
	 * here is safe: no worker round will find it by serial) */
	ikev2_dispose_sa(sa);

	/* ---- 3. inserted but DEAD SA is NOT resumed ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->crypto_pending = 1;
	sa->state = IKEV2_STATE_DEAD;
	resume_count = 0;
	round = NULL;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume, &round) != 0) {
		printf("eaproundtest: FAIL 3 submit\n");
		fails++;
	} else {
		drain_until_done();
		if (resume_count == 0) {
			printf("eaproundtest: PASS 3 DEAD SA not resumed\n");
		} else {
			printf("eaproundtest: FAIL 3 DEAD SA resumed count=%d\n",
			       resume_count);
			fails++;
		}
	}
	/* dispose the DEAD SA (round already dropped); unlink first so the
	 * freed block doesn't leave a reusable stale list entry */
	TAILQ_REMOVE(&ikev2_sa_list, sa, link);
	ikev2_dispose_sa(sa);

	if (secret.v) free(secret.v);
	printf("eaproundtest: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
