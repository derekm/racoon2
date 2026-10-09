/*
 * iked/ikev2_eap_round.c - responder EAP RADIUS round on the worker pool.
 *
 * RFC 7296 s2.16: the responder terminates a road-warrior EAP by proxying
 * each EAP message to RADIUS.  The blocking ikev2_radius_exchange() MUST
 * run off iked's single-threaded main loop, so each round is submitted to
 * the existing worker pool (crypto_job_submit) and the result is handled on
 * the main thread after crypto_workers_drain().
 *
 * SA-lifetime: between the worker starting select() and the main loop
 * draining, the IKE_SA may be freed or moved to DYING/DEAD.  The bridge
 * therefore sets ike_sa->crypto_pending before submitting (the pin that
 * stops ikev2_sa_periodic_task disposing the SA while the worker is away)
 * and clears it in done() on the re-found SA - ALWAYS, even for a
 * DYING/DEAD SA, so the periodic task can reap it and release the eap_msk.
 * done() runs on the main thread and is the ONLY place the RADIUS result
 * may touch the SA; a gone/dead SA is NOT resumed, but its pin is still
 * cleared first.  The worker thread never touches the SA.
 *
 * This bridge exists because the operator harnesses (radworkertest /
 * relayworkertest) cannot prove the SA-lifetime + pin bookkeeping: they run
 * without an ike_sa.
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
	uint8_t *id_out;		/* -> caller's id (advanced id) */
	uint8_t id;			/* RADIUS Identifier */
	int rv;				/* exchange result (worker) */
	struct ikev2_radius_response *resp;	/* decoded result (worker) */
	ikev2_eap_round_resume_t resume;	/* caller, main thread */
	/* owned round I/O (freed in release; deep copies for the worker) */
	struct sockaddr_storage server;
	socklen_t servlen;
	rc_vchar_t secret, eap;
	char *user_name, *nas_ip, *nas_id;
	rc_vchar_t state;
	struct ikev2_radius_opt opt;
};

/* worker thread: run the blocking RADIUS exchange.  Does NOT touch the SA. */
static void
eap_round_run(void *arg)
{
	struct ikev2_eap_round *r = arg;
	r->rv = ikev2_radius_exchange((struct sockaddr *)&r->server, r->servlen,
				      &r->eap, &r->opt, &r->id, &r->resp);
}

/* Copy a NUL-terminated string into the round; NULL-safe. */
static int
eap_round_strdup(char **dst, const char *src)
{
	if (src == NULL) {
		*dst = NULL;
		return 0;
	}
	*dst = strdup(src);
	return (*dst != NULL) ? 0 : -1;
}

/* Release the round and everything it owns (main thread only).
 * NOTE: r->eap/.secret/.state are EMBEDDED rc_vchar_t members of the round,
 * not separately heap-allocated vchars, so we must NOT use rc_vfreez() on
 * them (rc_vfreez frees the rc_vchar_t itself, i.e. the round struct - a
 * use-after-return of the whole round).  Zero and free just the .v buffers. */
static void
eap_round_release(struct ikev2_eap_round *r)
{
	if (!r)
		return;
	if (r->resp)
		ikev2_radius_response_free(r->resp);
	/* cleanse before freeing the key/shared-secret/EAP bytes */
	if (r->eap.v) { memset(r->eap.v, 0, r->eap.l); rc_free(r->eap.v); }
	if (r->secret.v) { memset(r->secret.v, 0, r->secret.l); rc_free(r->secret.v); }
	if (r->state.v) { memset(r->state.v, 0, r->state.l); rc_free(r->state.v); }
	if (r->user_name) racoon_free(r->user_name);
	if (r->nas_ip) racoon_free(r->nas_ip);
	if (r->nas_id) racoon_free(r->nas_id);
	racoon_free(r);
}

/*
 * main thread after drain: re-find the SA, clear the pin, and either resume
 * or drop.  Mirror of iked/ikev2.c ikev2_createchild_initiator_dh_done:
 * on a gone / recycled / DYING / DEAD SA the continuation is NOT called -
 * the round is just released - because the SA teardown is already handling
 * the EAP relay and MSK.  resume() runs only with a confirmed-live SA.
 */
static void
eap_round_done(void *arg)
{
	struct ikev2_eap_round *r = arg;
	struct ikev2_sa *sa;
	ikev2_eap_round_resume_t resume;
	int rv;

	if (!r)
		return;
	sa = ikev2_find_sa_by_serial(r->serial);
	if (sa == NULL || sa != r->ike_sa) {
		/* freed or recycled: nothing to unpin, do not resume */
		eap_round_release(r);
		return;
	}
	/* clear the pin ALWAYS, even for a DYING/DEAD SA, so the periodic
	 * task can dispose it (and the eap_msk) */
	sa->crypto_pending = 0;
	if (sa->state == IKEV2_STATE_DYING ||
	    sa->state == IKEV2_STATE_DEAD) {
		/* teardown owns the SA; do not resume into a dying SA */
		eap_round_release(r);
		return;
	}

	/* only now, with a live, unpinned SA, resume the caller */
	if (r->id_out)
		*r->id_out = r->id;
	resume = r->resume;
	rv = r->rv;
	if (resume)
		resume(r, rv);
	eap_round_release(r);
}

int
ikev2_eap_round_submit(struct ikev2_sa *ike_sa, int serial,
		       rc_vchar_t *eap, const struct sockaddr *server,
		       socklen_t servlen, const struct ikev2_radius_opt *opt,
		       uint8_t *id, ikev2_eap_round_resume_t resume)
{
	struct ikev2_eap_round *r;

	if (!ike_sa || !eap || !eap->v || !server || !opt || !opt->secret ||
	    !opt->secret->v || !id || servlen <= 0 ||
	    servlen > (socklen_t)sizeof(r->server))
		return -1;

	r = racoon_calloc(1, sizeof(*r));
	if (!r)
		return -1;
	r->serial = serial;
	r->ike_sa = ike_sa;
	r->id = *id;
	r->id_out = id;
	r->resume = resume;
	r->servlen = servlen;
	memcpy(&r->server, server, servlen);

	/* deep-copy every worker-read option member */
	r->opt = *opt;
	r->opt.secret = &r->secret;	/* repoint to our owned copy */
	memset(&r->state, 0, sizeof(r->state));
	r->opt.state = &r->state;
	if (opt->secret->l) {
		/* rc_calloc: pairs with rc_vfreez()/rc_free (plain malloc
		 * family); racoon_malloc is the GC allocator under -DGC and
		 * must not be freed with plain free(). */
		r->secret.v = rc_calloc(1, opt->secret->l);
		if (!r->secret.v) { racoon_free(r); return -1; }
		memcpy(r->secret.v, opt->secret->v, opt->secret->l);
		r->secret.l = opt->secret->l;
	}
	if (opt->state && opt->state->l) {
		r->state.v = rc_calloc(1, opt->state->l);
		if (!r->state.v) {
			rc_vfreez(&r->secret);
			racoon_free(r);
			return -1;
		}
		memcpy(r->state.v, opt->state->v, opt->state->l);
		r->state.l = opt->state->l;
	}
	if (eap_round_strdup(&r->user_name, opt->user_name) < 0 ||
	    eap_round_strdup(&r->nas_ip, opt->nas_ip) < 0 ||
	    eap_round_strdup(&r->nas_id, opt->nas_id) < 0) {
		eap_round_release(r);
		return -1;
	}
	r->opt.user_name = r->user_name;
	r->opt.nas_ip = r->nas_ip;
	r->opt.nas_id = r->nas_id;

	/* EAP bytes copy */
	r->eap.l = eap->l;
	r->eap.v = rc_calloc(1, eap->l);
	if (!r->eap.v) {
		eap_round_release(r);
		return -1;
	}
	memcpy(r->eap.v, eap->v, eap->l);

	/* pin the SA so it is not disposed while the worker is away */
	ike_sa->crypto_pending = 1;

	if (crypto_job_submit(eap_round_run, eap_round_done, r) != 0) {
		ike_sa->crypto_pending = 0;
		eap_round_release(r);
		return -1;
	}
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
	/* the caller already has the SA it submitted with; this accessor
	 * exists so a resume callback that only holds r can confirm the SA. */
	return r ? r->ike_sa : NULL;
}
