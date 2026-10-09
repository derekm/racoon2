/*
 * iked/ikev2_eap_round.c - responder EAP RADIUS round on the worker pool.
 *
 * RFC 7296 s2.16: the responder terminates a road-warrior EAP by proxying
 * each EAP message to RADIUS.  The blocking ikev2_radius_exchange() MUST
 * run off iked's single-threaded main loop, so each round is submitted to
 * the existing worker pool (crypto_job_submit) and the result is handled
 * on the main thread after crypto_workers_drain().
 *
 * SA-lifetime: between the worker starting select() and the main loop
 * draining, the IKE_SA may have been freed.  This bridge therefore re-finds
 * the SA by serial and verifies the pointer on the MAIN thread BEFORE
 * resuming the caller (the same discipline as
 * ikev2_createchild_initiator_dh_done).  A done() callback that kept a raw
 * SA pointer across the worker hop would be a use-after-free.  The worker
 * thread never touches the SA; the resume runs on the main thread with the
 * SA re-found and confirmed live.  This is the one property the operator
 * harnesses (radworkertest / relayworkertest) cannot prove, because they
 * run without an ike_sa.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

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

struct ikev2_eap_round {
	int serial;			/* SA serial to re-find after the hop */
	struct ikev2_sa *ike_sa;	/* expected pointer (same-serial check) */
	int *sa_crypto_pending;		/* -> ike_sa->crypto_pending */
	uint8_t id;			/* RADIUS Identifier */
	int rv;				/* exchange result (worker) */
	struct ikev2_radius_response *resp;	/* decoded result (worker) */
	ikev2_eap_round_resume_t resume;	/* caller, main thread */
	/* owned round I/O */
	struct sockaddr_in server;
	rc_vchar_t secret, eap;
	struct ikev2_radius_opt opt;
	struct ikev2_sa *resume_sa;	/* re-found live SA at resume */
};

/* worker thread: run the blocking RADIUS exchange.  Does NOT touch the SA. */
static void
eap_round_run(void *arg)
{
	struct ikev2_eap_round *r = arg;
	r->rv = ikev2_radius_exchange(
		(struct sockaddr *)&r->server, (socklen_t)sizeof(r->server),
		&r->eap, &r->opt, &r->id, &r->resp);
}

/* Re-find the SA by serial and verify it is the same, live SA (not
 * DYING/DEAD, not replaced).  Returns the live SA or NULL. */
static struct ikev2_sa *
eap_round_revalidate(struct ikev2_eap_round *r)
{
	struct ikev2_sa *sa;

	if (!r)
		return NULL;
	sa = ikev2_find_sa_by_serial(r->serial);
	if (sa == NULL || sa != r->ike_sa)
		return NULL;	/* freed or recycled */
	if (sa->state == IKEV2_STATE_DYING ||
	    sa->state == IKEV2_STATE_DEAD)
		return NULL;
	return sa;
}

/* main thread after drain: re-find the SA, then resume (or drop on dead). */
static void
eap_round_done(void *arg)
{
	struct ikev2_eap_round *r = arg;
	struct ikev2_sa *sa;
	ikev2_eap_round_resume_t resume;
	int rv;

	if (!r)
		return;
	sa = eap_round_revalidate(r);
	if (sa == NULL) {
		/* SA freed while the worker was in select(); drop the round
		 * without touching the SA.  Nothing on this round references
		 * the relay/MSK now (they live on the freed SA). */
		if (r->resp)
			ikev2_radius_response_free(r->resp);
		racoon_free(r->eap.v);
		racoon_free(r->secret.v);
		racoon_free(r);
		return;
	}
	/* only now may the result touch the SA */
	if (r->sa_crypto_pending)
		*r->sa_crypto_pending = 0;
	r->resume_sa = sa;
	resume = r->resume;
	rv = r->rv;
	if (resume)
		resume(r, rv);
	if (r->resp)
		ikev2_radius_response_free(r->resp);
	racoon_free(r->eap.v);
	racoon_free(r->secret.v);
	racoon_free(r);
}

int
ikev2_eap_round_submit(struct ikev2_sa *ike_sa, int serial,
		       rc_vchar_t *eap, const struct sockaddr *server,
		       socklen_t servlen, const struct ikev2_radius_opt *opt,
		       uint8_t *id, ikev2_eap_round_resume_t resume,
		       struct ikev2_eap_round **round_out)
{
	struct ikev2_eap_round *r;
	static const rc_vchar_t empty = { 0, NULL };

	if (!ike_sa || !eap || !eap->v || !server || !opt || !opt->secret ||
	    !opt->secret->v || servlen < (socklen_t)sizeof(struct sockaddr_in))
		return -1;

	r = racoon_calloc(1, sizeof(*r));
	if (!r)
		return -1;
	r->serial = serial;
	r->ike_sa = ike_sa;
	r->sa_crypto_pending = &ike_sa->crypto_pending;
	r->id = *id;
	r->resume = resume;
	r->server = *((struct sockaddr_in *)server);

	/* self-contained copies: the round frees its own at done() */
	r->opt = *opt;
	r->secret = (opt->secret ? *opt->secret : empty);
	r->secret.v = NULL;	/* set below */
	r->eap = *eap;
	r->eap.v = NULL;
	if (r->secret.l) {
		r->secret.v = racoon_malloc(r->secret.l);
		if (!r->secret.v) {
			racoon_free(r);
			return -1;
		}
		memcpy(r->secret.v, opt->secret->v, r->secret.l);
	}
	r->eap.v = racoon_malloc(r->eap.l);
	if (!r->eap.v) {
		if (r->secret.v)
			racoon_free(r->secret.v);
		racoon_free(r);
		return -1;
	}
	memcpy(r->eap.v, eap->v, r->eap.l);
	r->opt.secret = &r->secret;	/* opt copy -> OUR secret copy */

	if (crypto_job_submit(eap_round_run, eap_round_done, r) != 0) {
		if (r->eap.v)
			racoon_free(r->eap.v);
		if (r->secret.v)
			racoon_free(r->secret.v);
		racoon_free(r);
		return -1;
	}
	if (round_out)
		*round_out = r;
	return 0;
}

struct ikev2_radius_response *
ikev2_eap_round_response(struct ikev2_eap_round *r)
{
	return r ? r->resp : NULL;
}

struct ikev2_sa *
ikev2_eap_round_sa(struct ikev2_eap_round *r)
{
	return r ? r->resume_sa : NULL;
}
