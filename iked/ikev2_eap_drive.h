/*
 * iked/ikev2_eap_drive.h - responder EAP round driver interface.
 *
 * Glue between the worker-round bridge (ikev2_eap_round.c) and the per-SE
 * relay (ikev2_eap_relay.c): a main-thread resume() callback calls
 * ikev2_eap_drive_advance() with the decoded round response to feed the
 * relay and, on Acceptance, store the 64-octet MSK on the SA.  See
 * ikev2_eap_drive.c for ownership and rationale.
 */

#ifndef __IKEV2_EAP_DRIVE_H_
#define __IKEV2_EAP_DRIVE_H_

#include "vmbuf.h"
#include "ikev2_radius.h"

struct ikev2_sa;
struct ikev2_eap_relay;

/* Outcome of driving one round. */
enum ikev2_eap_drive_result {
	IKEV2_EAP_DRIVE_CONTINUE = 0,	/* *out_eap is the next EAP Request */
	IKEV2_EAP_DRIVE_SUCCESS,	/* ike_sa->eap_msk set (64 octets);
					   * *out_eap MAY be set to the
					   * server's EAP-Message (e.g. an
					   * EAP-Success forwarded from the
					   * Accept) - caller must free it */
	IKEV2_EAP_DRIVE_FAILURE,	/* Access-Reject */
	IKEV2_EAP_DRIVE_ERROR		/* transport error / malformed / no SA */
};

extern enum ikev2_eap_drive_result
ikev2_eap_drive_advance(struct ikev2_sa *ike_sa,
			struct ikev2_eap_relay *relay,
			struct ikev2_radius_response *resp,
			const rc_vchar_t *secret,
			rc_vchar_t **out_eap);

#endif /* __IKEV2_EAP_DRIVE_H_ */
