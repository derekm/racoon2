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
 * race: one done() releases only its own pin, never the other's.
 *
 * What the pin guards: it keeps this SA findable (on the list, not unlinked
 * and freed) until the round's done() has run and cleared it.  The EAP worker
 * never touches the SA or eap_msk - it runs ikev2_radius_exchange() on
 * round-owned copies only (see eap_round_run) - so the pin is NOT protecting
 * SA memory a worker writes.  Rather, done() runs on the main loop after
 * crypto_workers_drain() and must be able to re-find the SA by serial so it
 * can clear its own pin and either resume a live SA or drop a DYING/DEAD one;
 * the pin must stay set until that happens, so a DH/rekey done() setting
 * crypto_pending=0 can never release an in-flight EAP round (nor vice versa)
 * and let this tick dispose the SA first.
 *
 * The caller invariant: the pin makes overlap memory-safe, but the caller of
 * ikev2_eap_round_submit() must treat EACH round as possibly ending in either
 * path at done() time, depending on where the SA is then standing:
 *   - live SA: done() clears the pin and calls resume() exactly once;
 *   - findable DYING/DEAD SA: done() clears the pin and does NOT call
 *     resume() - the round is released.  eap_msk is still alive here:
 *     disposal (which frees it) happens on a LATER reaper tick, so the
 *     caller must never free it (teardown owns it).
 *   - gone (already unlinked/freed) SA: done() just releases the round; the
 *     SA and its eap_msk were already freed by whoever unlinked it.
 * In the drop cases the caller is not re-entered, so it must not retain the
 * SA pointer across a submit expecting a later cleanup - teardown owns the
 * relay and eap_msk in both drop paths.
 * No DH worker shares the IKE_AUTH window with an EAP round.  In this tree
 * the responder creates the AUTH child with g_i=n_i=0 -- responder_ike_sa_auth_cont
 * hardcodes the 0,0 at ikev2.c responder_ike_sa_auth_cont (the
 * ikev2_create_child_responder call that passes sa_i2,ts_i,ts_r,cfg,0,0),
 * which
 * only submits a child DH exchange inside `if (g_i)` (ikev2_child.c:1351) -- so
 * no child DH runs at IKE_AUTH (the AUTH child is keyed from SK_d per the RFC
 * 7296 2.17 no-PFS formula; an optional KE in IKE_AUTH is allowed by 1.2 but this
 * responder never passes one).  CREATE_CHILD_SA / rekey DH (ikev2_child.c /
 * ikev2_rekey.c) runs only on an ESTABLISHED (or DYING, which forwards to the
 * established handler) SA, and IKE_SA_INIT / IKE_INTERMEDIATE finish before
 * IKE_AUTH.  This statement depends on the g_i=0 call site - if that 0,0 later
 * becomes the peer's KE, re-check it.  The round's pin
 * (eap_round_pending) is therefore orthogonal to crypto_pending because no
 * crypto_pending job is in flight during IKE_AUTH EAP anyway - the DH/rekey
 * done()-clears-the-other-pin hazard this design guards cannot actually arise
 * while the round runs.  Still, IKE_AUTH failure does call ikev2_abort()
 * (DYING then DEAD, expires children, no dispose), and the SA can be torn
 * down independently, so the drop path is real and not the EAP worker's
 * doing.  The caller must therefore not condition on which worker failed; it
 * either gets resume() with a confirmed-live SA or no callback at all.
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
 * called, caller keeps ownership of all inputs), or 1 when a round is already
 * in flight on this SA (a retransmit of an in-flight round - the caller should
 * drop the duplicate, not treat it as a failure), nothing more is submitted.
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
extern const rc_vchar_t *ikev2_eap_round_secret(struct ikev2_eap_round *r);

#endif /* __IKEV2_EAP_ROUND_H_ */
