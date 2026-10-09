/*
 * iked/ikev2_eap_relay.c - responder-side EAP relay state machine.
 *
 * See ikev2_eap_relay.h for the contract and lifecycle.  The relay owns no
 * sockets and runs no threads: the caller performs the RADIUS round trip
 * (on the worker pool) and hands the decoded response to
 * ikev2_eap_relay_consume().  This keeps the round logic pure and
 * unit-testable (relaytest.c), and keeps the blocking exchange off iked's
 * main thread - the routing of consume() output back to the client and the
 * MSK into AUTH is the IKE_AUTH wiring's job (doc/eap-wiring-plan.md).
 */

#include <config.h>

#include <string.h>
#include <sys/types.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "ikev2_radius.h"
#include "ikev2_eap.h"
#include "ikev2_eap_relay.h"

rc_vchar_t *
ikev2_eap_relay_start(struct ikev2_eap_relay *relay, u_int8_t identifier)
{
	rc_vchar_t *req;

	if (!relay || relay->started || relay->finished)
		return NULL;

	/* the RFC 3748 s5.1 Identity Request opener (also the IKE_AUTH
	 * pre-EAP trigger in practice sends the same packet). */
	req = ikev2_eap_build_identity_request(identifier);
	if (!req)
		return NULL;

	relay->eap_pending = rc_vdup(req);
	if (!relay->eap_pending) {
		rc_vfree(req);
		return NULL;
	}
	relay->started = 1;
	return req;
}

static void
relay_discard_pending(struct ikev2_eap_relay *relay)
{
	if (relay->eap_pending) {
		rc_vfree(relay->eap_pending);
		relay->eap_pending = NULL;
	}
}

enum ikev2_eap_relay_result
ikev2_eap_relay_consume(struct ikev2_eap_relay *relay,
			struct ikev2_radius_response *resp,
			const rc_vchar_t *secret,
			rc_vchar_t **out_eap, rc_vchar_t **out_msk)
{
	enum ikev2_eap_relay_result r;
	rc_vchar_t *state;

	if (!relay || !relay->started || relay->finished ||
	    !resp || !secret || secret->l == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "EAP relay: bad consume() arguments\n");
		return IKEV2_EAP_RELAY_ERROR;
	}

	switch (resp->code) {
	case IKEV2_RADIUS_CODE_ACCESS_CHALLENGE:
		/* carry the next EAP-Request back to the client; remember
		 * the State attr to echo on the next Access-Request (the
		 * caller does the echoing by passing it in opt->state). */
		*out_eap = ikev2_radius_eap_message(resp);
		if (!*out_eap) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "EAP relay: Challenge without EAP-Message\n");
			return IKEV2_EAP_RELAY_ERROR;
		}
		state = ikev2_radius_find_attr(resp, IKEV2_RADIUS_ATTR_STATE);
		if (state) {
			if (relay->state)
				rc_vfree(relay->state);
			relay->state = rc_vdup(state);
		}
		relay_discard_pending(relay);
		relay->eap_pending = rc_vdup(*out_eap);
		r = IKEV2_EAP_RELAY_CONTINUE;
		break;

	case IKEV2_RADIUS_CODE_ACCESS_ACCEPT:
		/* the MSK (RFC 3079 s3.3 / [MS-CHAP] 3.1.5.1) is the AUTH
		 * seed.  It must key off the Request Authenticator that drew
		 * this Accept; ikev2_radius_verify_response captured it in
		 * resp->req_auth. */
		*out_msk = ikev2_radius_msk(resp, resp->req_auth, (rc_vchar_t *)secret);
		if (!*out_msk) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "EAP relay: Accept without decryptable MSK\n");
			return IKEV2_EAP_RELAY_ERROR;
		}
		relay->finished = 1;
		relay_discard_pending(relay);
		r = IKEV2_EAP_RELAY_SUCCESS;
		break;

	case IKEV2_RADIUS_CODE_ACCESS_REJECT:
		relay->finished = 1;
		relay_discard_pending(relay);
		r = IKEV2_EAP_RELAY_FAILURE;
		break;

	default:
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "EAP relay: unexpected RADIUS code %u\n", resp->code);
		r = IKEV2_EAP_RELAY_ERROR;
		break;
	}
	return r;
}

void
ikev2_eap_relay_free(struct ikev2_eap_relay *relay)
{
	if (!relay)
		return;
	if (relay->state)
		rc_vfree(relay->state);
	if (relay->eap_pending)
		rc_vfree(relay->eap_pending);
	relay->started = relay->finished = 0;
}
