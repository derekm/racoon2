/*
 * iked/ikev2_eap_round.h - responder EAP RADIUS round on the worker pool.
 *
 * Bridge between the IKE_AUTH responder's EAP relay (ikev2_eap_relay.c)
 * and the worker pool: submit one blocking ikev2_radius_exchange() to a
 * worker; on the main thread after crypto_workers_drain(), re-find the SA by
 * serial, clear the crypto_pending pin it set, and resume the caller's
 * callback only if that SA is still live (or drop the round - pin already
 * cleared - if the SA is gone or DYING/DEAD).
 *
 * See ikev2_eap_round.c for the lifetime rationale.  The relay's per-SE
 * state and the MSK live on the caller-owned ike_sa; this module never
 * touches the SA from the worker thread.
 */

#ifndef __IKEV2_EAP_ROUND_H_
#define __IKEV2_EAP_ROUND_H_

#include "vmbuf.h"
#include "ikev2_radius.h"

struct ikev2_sa;	/* forward: the round never needs the full SA here */
struct ikev2_eap_round;

/*
 * Caller resume on the main thread after a round.  rc is the exchange result
 * (IKEV2_RADIUS_OK etc.); ikev2_eap_round_response() gives the decoded
 * response (or NULL on a transport error) and ikev2_eap_round_sa() the
 * re-found live SA (or NULL if the SA was freed / went DYING/DEAD).
 *
 * r is valid ONLY during this callback: the bridge frees r AND the response
 * after this returns, so the caller must not retain either past the
 * callback.  This mirrors the DH/rekey done() discipline.
 */
typedef void (*ikev2_eap_round_resume_t)(struct ikev2_eap_round *r, int rc);

/*
 * Submit one round.  eap is the RFC 3748 EAP message to send to RADIUS;
 * server/servlen the endpoint (AF_INET or AF_INET6); opt the per-round
 * options; id[in/out] the RADIUS Identifier to stamp on the request and the
 * advanced id is written back to *id on the main thread at resume.
 *
 * ike_sa->crypto_pending is set here and cleared in done() on the re-found
 * SA - even for a DYING/DEAD SA, so the periodic task can reap it.  All
 * worker-read input (eap, server, every opt string/state/secret) is
 * deep-copied into the round up front, so the caller may free its own copies
 * right after submit returns.
 *
 * Returns 0 on submit (resume() will be called exactly once, on the main
 * thread after crypto_workers_drain(); if the pool is disabled the round
 * runs inline and resume() is called before submit returns), -1 on failure
 * (nothing submitted, nothing pinned, resume() never called).  On failure
 * the caller keeps ownership of all its inputs.
 */
extern int ikev2_eap_round_submit(
	struct ikev2_sa *ike_sa, int serial,
	rc_vchar_t *eap, const struct sockaddr *server, socklen_t servlen,
	const struct ikev2_radius_opt *opt, uint8_t *id,
	ikev2_eap_round_resume_t resume);

/* Accessors, valid only inside a resume() callback. */
extern struct ikev2_radius_response *ikev2_eap_round_response(
	struct ikev2_eap_round *r);
extern struct ikev2_sa *ikev2_eap_round_sa(struct ikev2_eap_round *r);

#endif /* __IKEV2_EAP_ROUND_H_ */
