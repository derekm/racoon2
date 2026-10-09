/*
 * iked/ikev2_eap_round.h - responder EAP RADIUS round on the worker pool.
 *
 * Bridge between the IKE_AUTH responder's EAP relay (ikev2_eap_relay.c)
 * and the worker pool: submit one blocking ikev2_radius_exchange() to a
 * worker; on the main thread after crypto_workers_drain(), re-find the SA by
 * serial, clear the EAP pin (sa->eap_round_pending) it set, and resume the caller's
 * callback only if that SA is still live.  A gone / DYING / DEAD SA drops
 * the round without resuming: for a findable DYING/DEAD SA the pin is
 * cleared first so the periodic task can reap it; a gone SA has no pin left
 * to clear.
 *
 * The EAP round uses its OWN pin (ike_sa->eap_round_pending), orthogonal to the
 * DH/rekey crypto_pending that other worker jobs pin.  An EAP round can
 * therefore be in flight on the same SA as a DH/rekey job without the pin-clear
 * race: one done() releases only its own pin, never the other's, so the
 * periodic task cannot reap the SA (and its relay/MSK) under a still-running
 * worker.
 *
 * Memory-safety of that overlap rests on the caller invariant: the EAP worker
 * never touches the SA - it runs ikev2_radius_exchange() on round-owned copies
 * only (see eap_round_run).  A DH abort() during an in-flight EAP round only
 * marks the SA DYING; the round's done() treats a re-found DYING/DEAD SA as a
 * drop, so the caller must treat that outcome as the exchange ending with no
 * AUTH rather than as a successful continuation.
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
 * Caller resume on the main thread after a round, called exactly once when
 * done() re-finds the SA by serial and it is still live.  rc is the exchange
 * result (IKEV2_RADIUS_OK etc.) and ikev2_eap_round_response() gives the
 * decoded response (or NULL on a transport error).  The SA is the live,
 * unpinned SA the round was submitted around; it is never NULL here because
 * resume() does NOT run for a gone / recycled / DYING / DEAD SA - done()
 * drops the round in that case (mirror of ikev2_createchild_initiator_dh_done)
 * and the caller is not re-entered.
 *
 * *id (the caller's RADIUS Identifier pointer) is written with the advanced
 * identifier BEFORE resume() runs, and *id must stay valid until resume()
 * returns (or until done() drops the round without resuming).
 *
 * r is valid ONLY during this callback: the bridge frees r AND the response
 * after this returns, so the caller must not retain either past the
 * callback.
 */
typedef void (*ikev2_eap_round_resume_t)(struct ikev2_eap_round *r, int rc);

/*
 * Submit one round.  eap is the RFC 3748 EAP message to send to RADIUS;
 * server/servlen the endpoint (AF_INET or AF_INET6); opt the per-round
 * options; id[in/out] the RADIUS Identifier to stamp on the request.
 *
 * serial MUST equal ike_sa->serial_number (done() looks the SA up by serial
 * to unpin it; a mismatched caller serial would never unpin).
 *
 * ike_sa->eap_round_pending (EAP's own pin, orthogonal to the DH/rekey
 * crypto_pending) is set here and cleared in done() on the SA found by
 * serial - even for a DYING/DEAD SA, so the periodic task can reap it.
 * eap_round_pending is a boolean: submit FAILS (returns -1) if it is already set
 * (an EAP round already in flight on this SA).  A concurrent DH/rekey job
 * pins crypto_pending, its own field, so EAP and DH/rekey can be in flight
 * together without one done() releasing the other's pin.  For an SA that
 * disappears before done() runs there is no pin to clear (nothing is set on
 * the freed SA): that path just drops the round.
 *
 * All worker-read input (eap, server, every opt string/state/secret) is
 * deep-copied into the round up front, so the caller may free its own copies
 * right after submit returns.  *id is NOT deep-copied - it must stay live
 * until resume() returns.
 *
 * Returns 0 on submit (resume() will be called exactly once, on the main
 * thread after crypto_workers_drain(), only for a live SA; if the pool is
 * disabled the round runs inline and resume() is called before submit
 * returns), -1 on failure (nothing submitted, nothing pinned, resume() never
 * called, caller keeps ownership of all inputs).
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
