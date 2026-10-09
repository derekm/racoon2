/*
 * iked/ikev2_eap_round.h - responder EAP RADIUS round on the worker pool.
 *
 * Bridge between the IKE_AUTH responder's EAP relay (ikev2_eap_relay.c)
 * and the worker pool: submit one blocking ikev2_radius_exchange() to a
 * worker; on the main thread after crypto_workers_drain(), re-find the SA by
 * serial (SA-lifetime guard - the SA may have been freed while the worker
 * was in select()), and resume the caller's callback only if the SA is
 * still live.
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

/* Caller resume on the main thread after a round: rc is the exchange result
 * (IKEV2_RADIUS_OK etc.); r holds resp (decoded), serial, and the re-found
 * live SA.  The caller owns resp and must free it; the round is released by
 * the bridge after this returns. */
typedef void (*ikev2_eap_round_resume_t)(struct ikev2_eap_round *r, int rc);

/* Submit one round.  server/opt/eap are borrowed and copied into the round.
 * *id is copied; the relay advances it across rounds.  Returns 0 on submit,
 * -1 on failure (nothing submitted, round released).  On 0, the caller's
 * resume() runs on the main thread after drain. */
extern int ikev2_eap_round_submit(
	struct ikev2_sa *ike_sa, int serial,
	rc_vchar_t *eap, const struct sockaddr *server, socklen_t servlen,
	const struct ikev2_radius_opt *opt, uint8_t *id,
	ikev2_eap_round_resume_t resume,
	struct ikev2_eap_round **round_out);

/* Accessors for a resumed round (main thread only). */
extern struct ikev2_radius_response *ikev2_eap_round_response(
	struct ikev2_eap_round *r);
extern struct ikev2_sa *ikev2_eap_round_sa(struct ikev2_eap_round *r);

#endif /* __IKEV2_EAP_ROUND_H_ */
