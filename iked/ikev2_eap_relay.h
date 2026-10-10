/*
 * iked/ikev2_eap_relay.h - responder-side EAP relay state machine.
 *
 * RFC 7296 s2.16: a responder that authenticates a road-warrior client
 * with EAP opens the exchange by replying to an IKE_AUTH that carries IDi
 * but no AUTH with an EAP-Request (Identity).  Each subsequent EAP
 * Response from the client is proxied to the RADIUS server as an
 * Access-Request; the RADIUS Access-Challenge carries the next EAP-Request
 * to send back to the client; an Access-Accept ends the exchange with the
 * MSK that the responder AUTH is computed from.
 *
 * This module is that relay, shaped as a pure state machine over DECODED
 * RADIUS responses so the round logic is unittestable hermetically
 * (relaytest.c) without a socket or a live server.  The transport
 * (ikev2_radius_exchange on the worker pool) is owned by the caller - the
 * IKE_AUTH wiring drives one round trip, then feeds the decoded response
 * to ikev2_eap_relay_consume(), which says what to send the client next.
 *
 * Per-SE state is a struct ikev2_eap_relay.  Lifecycle:
 *
 *   ikev2_eap_relay_start()   -> Identity Request to send the client
 *   [loop] caller runs one exchange(round eap) on a worker, decodes the
 *          response, then:
 *   ikev2_eap_relay_consume() -> next EAP Request, or SUCCESS (MSK ready)
 *                                or FAILURE.
 *
 * The relay owns all buffers it allocates; free with
 * ikev2_eap_relay_free().  secret / identity / server / nas config live in
 * the caller-owned ikev2_radius_opt the caller passes to each exchange;
 * the relay only needs the decoded response here.
 */

#ifndef __IKEV2_EAP_RELAY_H_
#define __IKEV2_EAP_RELAY_H_

#include "vmbuf.h"	/* rc_vchar_t */
#include "ikev2_radius.h"

/* Outcome of one consume() round. */
enum ikev2_eap_relay_result {
	IKEV2_EAP_RELAY_CONTINUE = 0,	/* *out_eap is the next Request */
	IKEV2_EAP_RELAY_SUCCESS,	/* *out_msk set (64 octets) */
	IKEV2_EAP_RELAY_FAILURE,	/* Access-Reject / malformed */
	IKEV2_EAP_RELAY_ERROR		/* internal: no secret/response */
};

struct ikev2_eap_relay {
	uint8_t radius_id;	/* current RADIUS Identifier, advanced per round */
	rc_vchar_t *state;	/* echoed Access-Challenge State (owned) */
	rc_vchar_t *eap_pending;/* the EAP packet we most recently sent the
				   client (owned); NULL before start / after
				   success */
	int started;		/* start() ran */
	int finished;		/* consume() reached SUCCESS or FAILURE */
};

/* Open the exchange: return a freshly allocated EAP Identity Request the
 * caller transmits to the client as an IKE_AUTH EAP payload, and prime the
 * relay.  NULL on alloc failure.  Caller frees the returned vchar. */
extern rc_vchar_t *ikev2_eap_relay_start(struct ikev2_eap_relay *relay,
					 u_int8_t identifier);

/* Advance one round with the decoded RADIUS response to the Access-Request
 * that carried the client's latest EAP Response.
 *
 *  - code Access-Challenge: *out_eap is set to a NEW vchar the caller must
 *    transmit to the client and then free; returns CONTINUE.
 *  - code Access-Accept:    *out_msk is set to a NEW 64-octet MSK the caller
 *    uses to compute AUTH; *out_eap MAY additionally be set to a NEW vchar
 *    (whatever EAP-Message attribute the Accept carried - often the server's
 *    EAP-Success, whose Identifier is authoritative for RFC 3748 s4.2).  The
 *    caller validates it (Code==3, Len>=4, Identifier matching the proxied
 *    Response) before forwarding and frees it either way.
 *    Returns SUCCESS, relay finished.
 *  - code Access-Reject:    returns FAILURE, relay finished.
 *  - any other / missing EAP on a Challenge: returns ERROR (no output).
 *
 * The returned response must carry req_auth (set by
 * ikev2_radius_verify_response) so the MSK schedule can be keyed; if a
 * caller constructed the response by hand in a unit test it must fill
 * ->req_auth.  On SUCCESS / FAILURE / ERROR nothing is written to the
 * out params that were not documented above.
 */
extern enum ikev2_eap_relay_result
ikev2_eap_relay_consume(struct ikev2_eap_relay *relay,
			struct ikev2_radius_response *resp,
			const rc_vchar_t *secret,
			rc_vchar_t **out_eap, rc_vchar_t **out_msk);

extern void ikev2_eap_relay_free(struct ikev2_eap_relay *relay);

#endif /* __IKEV2_EAP_RELAY_H_ */
