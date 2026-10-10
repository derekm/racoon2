/*
 * iked/ikev2_eap_drive.c - responder EAP round driver: bridge -> relay ->
 * MSK-on-SA.
 *
 * Milestone-3 responder wiring glue.  The worker-round bridge
 * (ikev2_eap_round.c, ikev2_eap_round_submit) runs one blocking
 * ikev2_radius_exchange() on the worker pool and delivers the decoded
 * response to a main-thread resume() callback with the SA re-found and live.
 * This driver is the resume() continue-path: given the decoded response, the
 * shared RADIUS secret, and the per-SE relay, it feeds
 * ikev2_eap_relay_consume() and - crucially - on an Acceptance stores the
 * 64-octet MSK on ike_sa->eap_msk, the field the fail-closed AUTH arm
 * (ikev2_auth.c ikev2_auth_shared_secret / ikev2_auth_method) requires.
 * Until this runs, an eap remote cannot authenticate; ikev2_auth_method
 * returns 0 for RCT_ALG_EAP without sa->eap_msk (fail closed).
 *
 * This exists so the Accept->MSK->stored-on-SA link is proven with a real
 * ike_sa (no prior harness ran the relay against an SA; relaytest has no SA
 * and authdertest does not touch ikev2_auth.c).
 *
 * Ownership: the bridge frees r->resp after resume() returns (see
 * ikev2_eap_round.h), so this driver does NOT free resp and the caller must
 * not retain it past the callback.  The IKE_AUTH transmission of the resulting
 * EAP Request / AUTH to the client is owned by the caller (ikev2.c), which
 * also frees *out_eap after transmitting.
 */

#include <config.h>

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
#include "ikev2_eap_relay.h"
#include "ikev2_eap_drive.h"

/*
 * Drive one decoded round into the relay and, on SUCCESS, store the MSK on
 * the SA.  resp is the round's decoded RADIUS response (the bridge frees it
 * after resume returns; we do not).  secret is the round's deep-copied shared
 * secret.  On CONTINUE, *out_eap is set to a new vchar the caller transmits to
 * the client and frees; on SUCCESS, ike_sa->eap_msk holds a 64-octet MSK
 * (replacing any prior), the relay is finished, and *out_eap MAY hold the
 * server's EAP-Message (e.g. the EAP-Success forwarded from the Accept, which
 * the caller chooses whether to forward and must free either way).
 */
enum ikev2_eap_drive_result
ikev2_eap_drive_advance(struct ikev2_sa *ike_sa,
			struct ikev2_eap_relay *relay,
			struct ikev2_radius_response *resp,
			const rc_vchar_t *secret,
			rc_vchar_t **out_eap)
{
	rc_vchar_t *out_msk = NULL;
	enum ikev2_eap_relay_result rr;
	enum ikev2_eap_drive_result dr = IKEV2_EAP_DRIVE_ERROR;

	*out_eap = NULL;
	if (ike_sa == NULL || relay == NULL || secret == NULL)
		return IKEV2_EAP_DRIVE_ERROR;

	/* transport error / no reply: nothing to consume */
	if (resp == NULL)
		return IKEV2_EAP_DRIVE_ERROR;

	rr = ikev2_eap_relay_consume(relay, resp, secret, out_eap, &out_msk);
	switch (rr) {
	case IKEV2_EAP_RELAY_CONTINUE:
		dr = (*out_eap != NULL) ? IKEV2_EAP_DRIVE_CONTINUE
					: IKEV2_EAP_DRIVE_ERROR;
		break;
	case IKEV2_EAP_RELAY_SUCCESS:
		/* store the MSK on the SA: unlocks the fail-closed AUTH arm */
		if (ike_sa->eap_msk)
			rc_vfreez(ike_sa->eap_msk);
		ike_sa->eap_msk = out_msk;
		out_msk = NULL;
		dr = IKEV2_EAP_DRIVE_SUCCESS;
		break;
	case IKEV2_EAP_RELAY_FAILURE:
		dr = IKEV2_EAP_DRIVE_FAILURE;
		break;
	case IKEV2_EAP_RELAY_ERROR:
	default:
		dr = IKEV2_EAP_DRIVE_ERROR;
		break;
	}
	if (out_msk)
		rc_vfreez(out_msk);
	return dr;
}
