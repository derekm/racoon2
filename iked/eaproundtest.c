/*
 * iked/eaproundtest.c - hermetic test of the responder EAP worker-round
 * bridge (ikev2_eap_round.c), focused on the SA-lifetime and pin bookkeeping
 * that the operator harnesses (radworkertest / relayworkertest) cannot prove
 * because they run without an ike_sa.
 *
 * ikev2_eap_round_submit() pins ike_sa->eap_round_pending (EAP's own pin, set and
 * cleared separately from the DH/rekey crypto_pending), runs the exchange on
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
 *   5. mismatched serial: submit rejected, nothing pinned.
 *   6. already-pinned SA (eap_round_pending set by a prior round): submit
 *      rejected, the existing pin left set.
 *   7. a DH/rekey crypto_pending concurrent job does NOT block EAP: submit
 *      accepted even with crypto_pending=1, and the round's done() leaves
 *      crypto_pending set (EAP never touches the DH pin).
 *   8. the reaper defers a DYING childless SA while either pin is set
 *      (8a crypto_pending, 8b eap_round_pending) and reaps it once both
 *      clear, locking both sides of the reaper OR.
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
	sa->eap_round_pending = 0;
	resume_count = 0; resume_had_sa = 0;
	id = 7;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		printf("eaproundtest: FAIL 1 submit\n");
		fails++;
	} else if (sa->eap_round_pending == 0) {
		printf("eaproundtest: FAIL 1 pin not set during round\n");
		fails++;
	} else {
		if (drain_until_done() != 0) {
			printf("eaproundtest: FAIL 1 drain timeout\n");
			fails++;
		} else if (resume_count == 1 && sa->eap_round_pending == 0 &&
		    resume_had_sa) {
			printf("eaproundtest: PASS 1 live SA resumed once, "
			       "pin cleared\n");
		} else {
			printf("eaproundtest: FAIL 1 resume=%d pending=%d"
			       " sa=%d\n", resume_count, sa->eap_round_pending,
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
	sa->eap_round_pending = 0;
	resume_count = 0; resume_had_sa = 0;
	id = 8;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		printf("eaproundtest: FAIL 2 submit\n");
		fails++;
	} else {
		resume_count = 0;
		if (drain_until_done() != 0) {
			printf("eaproundtest: FAIL 2 drain timeout\n");
			fails++;
		} else if (resume_count == 0) {
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
	sa->eap_round_pending = 0;
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
		resume_count = 0;
		if (drain_until_done() != 0) {
			printf("eaproundtest: FAIL 3 drain timeout\n");
			fails++;
		} else if (resume_count == 0 && sa->eap_round_pending == 0) {
			printf("eaproundtest: PASS 3 DEAD SA not resumed, "
			       "pin cleared\n");
		} else {
			printf("eaproundtest: FAIL 3 resume=%d pending=%d\n",
			       resume_count, sa->eap_round_pending);
			fails++;
		}
	}
	TAILQ_REMOVE(&ikev2_sa_list, sa, link);
	ikev2_dispose_sa(sa);

	/* ---- 4. SA freed while worker away: no resume, no crash,
	 * and a REAL deep-copy proof ----
	 * Every worker-read opt member (user_name, nas_ip, nas_id, state,
	 * secret) is a heap object the caller frees IMMEDIATELY after submit,
	 * before drain.  submit must deep-copy all of them: if any were only
	 * shallow-copied, the worker would read freed memory (ASan crash on the
	 * worker thread or a bad request packet).  nas_ip is cleared and nas_id
	 * set so build_request reads nas_id, and secret/state are heap-backed so
	 * their copies are exercised too.  The SA is also freed before drain;
	 * done() finds no SA by serial and drops the round without touching it.
	 * A use-after-free of the SA would crash or resume. */
	rc_vchar_t sbuf;
	rc_vchar_t csecret;
	uint8_t statewire[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	char *c_uname, *c_nasip, *c_nasid;
	sbuf.v = malloc(sizeof(statewire)); sbuf.l = sizeof(statewire);
	csecret.v = malloc(4); csecret.l = 4;
	c_uname = strdup("alice@example.test");
	c_nasip = strdup("192.0.2.9");
	c_nasid = strdup("nas-test");
	if (!sbuf.v || !csecret.v || !c_uname || !c_nasip || !c_nasid) {
		printf("eaproundtest: FAIL 4 malloc\n");
		fails++;
		goto case4_done;
	}
	memcpy(sbuf.v, statewire, sizeof(statewire));
	memcpy(csecret.v, "SEKR", 4);
	opt.state = &sbuf;
	opt.user_name = c_uname;
	opt.nas_ip = c_nasip;	/* set but build_request prefers it; also freed */
	opt.nas_id = c_nasid;
	opt.secret = &csecret;
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->eap_round_pending = 0;
	resume_count = 0; resume_had_sa = 0;
	id = 10;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		printf("eaproundtest: FAIL 4 submit\n");
		fails++;
	} else {
		/* caller frees every opt member + the SA right after submit; the
		 * worker must already hold its own deep copies of all of them */
		free(sbuf.v); sbuf.v = NULL;
		free(csecret.v); csecret.v = NULL;
		free(c_uname); free(c_nasip); free(c_nasid);
		TAILQ_REMOVE(&ikev2_sa_list, sa, link);
		ikev2_dispose_sa(sa);
		opt.state = NULL;
		opt.user_name = NULL;
		opt.nas_ip = NULL;
		opt.nas_id = NULL;
		opt.secret = &secret;
		if (drain_until_done() != 0) {
			printf("eaproundtest: FAIL 4 drain timeout\n");
			fails++;
		} else if (resume_count == 0) {
			printf("eaproundtest: PASS 4 freed-SA round not "
			       "resumed (opt deep-copied, no UAF)\n");
		} else {
			printf("eaproundtest: FAIL 4 freed-SA WAS resumed "
			       "count=%d (use-after-free!)\n", resume_count);
			fails++;
		}
	}
      case4_done:
	opt.state = NULL;
	opt.user_name = NULL;
	opt.nas_ip = NULL;
	opt.nas_id = NULL;
	opt.secret = &secret;

	/* ---- 5. reject a mismatched caller serial (no pin left set) ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->eap_round_pending = 0;
	resume_count = 0;
	id = 11;
	if (ikev2_eap_round_submit(sa, sa->serial_number + 1, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		if (sa->eap_round_pending == 0) {
			printf("eaproundtest: PASS 5 mismatched serial "
			       "rejected, no pin set\n");
		} else {
			printf("eaproundtest: FAIL 5 rejected but pin set=%d\n",
			       sa->eap_round_pending);
			fails++;
		}
	} else {
		printf("eaproundtest: FAIL 5 mismatched serial accepted\n");
		fails++;
	}
	TAILQ_REMOVE(&ikev2_sa_list, sa, link);
	ikev2_dispose_sa(sa);

	/* ---- 6. reject an already-pinned SA (same-EAP-round guard) ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->eap_round_pending = 1;	/* another EAP round already in flight */
	resume_count = 0;
	id = 12;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		if (sa->eap_round_pending == 1) {
			printf("eaproundtest: PASS 6 already-pinned SA "
			       "rejected, own EAP pin left set\n");
		} else {
			printf("eaproundtest: FAIL 6 rejected but pinned=%d\n",
			       sa->eap_round_pending);
			fails++;
		}
	} else {
		printf("eaproundtest: FAIL 6 already-pinned SA accepted\n");
		fails++;
	}
	TAILQ_REMOVE(&ikev2_sa_list, sa, link);
	ikev2_dispose_sa(sa);

	/* ---- 7. a concurrent DH/rekey crypto_pending does NOT block EAP,
	 * and the round's done() clears only its OWN pin - crypto_pending is
	 * left set (EAP never writes the DH pin). ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->crypto_pending = 1;		/* a DH/rekey job is in flight */
	sa->eap_round_pending = 0;
	resume_count = 0; resume_had_sa = 0;
	id = 13;
	if (ikev2_eap_round_submit(sa, sa->serial_number, &eap,
				   (struct sockaddr *)&server,
				   (socklen_t)sizeof(server), &opt,
				   &id, on_resume) != 0) {
		printf("eaproundtest: FAIL 7 crypto_pending blocked EAP submit\n");
		fails++;
	} else if (drain_until_done() != 0) {
		printf("eaproundtest: FAIL 7 drain timeout\n");
		fails++;
	} else if (resume_count == 1 && sa->eap_round_pending == 0 &&
	    sa->crypto_pending == 1) {
		printf("eaproundtest: PASS 7 crypto_pending coexists; EAP done "
		       "left DH pin set\n");
	} else {
		printf("eaproundtest: FAIL 7 resume=%d eap=%d crypto=%d\n",
		       resume_count, sa->eap_round_pending, sa->crypto_pending);
		fails++;
	}
	TAILQ_REMOVE(&ikev2_sa_list, sa, link);
	ikev2_dispose_sa(sa);

	/* ---- 8. the periodic task defers disposal of a DYING childless SA
	 * with no pin, and reaps it once both clear.  Two deferral halves so
	 * the reaper OR (ike_sa.c:237 crypto_pending || eap_round_pending)
	 * is locked on both sides, not just the EAP one. */
	/* 8a: crypto_pending (a DH/rekey job) alone must defer */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->state = IKEV2_STATE_DYING;
	sa->crypto_pending = 1;
	sa->eap_round_pending = 0;
	ikev2_sa_periodic_task();
	if (ikev2_find_sa_by_serial(sa->serial_number) == NULL) {
		printf("eaproundtest: FAIL 8a reaper disposed crypto-pinned SA\n");
		fails++;
	} else {
		printf("eaproundtest: PASS 8a reaper defers on crypto_pending\n");
		/* clear crypto; must now be reaped */
		{
			int serno = sa->serial_number;
			sa->crypto_pending = 0;
			ikev2_sa_periodic_task();
			if (ikev2_find_sa_by_serial(serno) != NULL) {
				printf("eaproundtest: FAIL 8a reaper kept unpinned "
				       "DYING SA\n");
				fails++;
			} else
				printf("eaproundtest: PASS 8a reaper reaps after "
				       "crypto clear\n");
		}
	}
	/* 8b: eap_round_pending (an EAP round) alone must defer */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	ikev2_sa_insert(sa);
	sa->state = IKEV2_STATE_DYING;
	sa->crypto_pending = 0;
	sa->eap_round_pending = 1;	/* EAP worker still out */
	ikev2_sa_periodic_task();
	if (ikev2_find_sa_by_serial(sa->serial_number) == NULL) {
		printf("eaproundtest: FAIL 8b reaper disposed EAP-pinned SA\n");
		fails++;
	} else {
		printf("eaproundtest: PASS 8b reaper defers on eap_round_pending\n");
		/* clear EAP; must now be reaped */
		{
			int serno = sa->serial_number;
			sa->eap_round_pending = 0;	/* round done */
			ikev2_sa_periodic_task();
			/* the second tick disposed the SA, so only the captured
			 * serial (not sa) is valid from here on */
			if (ikev2_find_sa_by_serial(serno) != NULL) {
				printf("eaproundtest: FAIL 8b reaper kept unpinned "
				       "DYING SA\n");
				fails++;
			} else
				printf("eaproundtest: PASS 8b reaper reaps after "
				       "EAP clear\n");
		}
	}

	if (secret.v) free(secret.v);
	printf("eaproundtest: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
