/*
 * iked/ikev2_eap_emit.c - responder EAP IKE_AUTH response composition.
 *
 * Milestone-3 responder wiring, factored for hermetic testing.
 *
 * During EAP (RFC 7296 s2.16 / RFC 5998 s2), the responder's IKE_AUTH
 * response to a peer's IKE_AUTH carrying IDi (and no final AUTH) is:
 *   IDr + EAP Request (payload 48, the first being EAP-Identity)  [no AUTH]
 * and, on each later round while EAP continues, IDr + the next EAP Request
 * again with no AUTH.  Only after the peer's EAP exchange reaches Success
 * (the relay returns an MSK) does the responder send its real AUTH.
 *
 * This module builds the *plaintext payload list* for the EAP form.  It is
 * kept separate from ikev2.c's sender so the exact composition (IDr first,
 * exactly one EAP payload 48, NO AUTH payload) can be unit-tested without a
 * live socket, and so the same composition can be reused by a later
 * IKE_FOLLOWUP_KE / multi-round continuation without duplicating logic.
 *
 * Ownership: the returned rc_vchar_t is newly allocated (the serialized
 * payload blob); ikev2_eap_emit_request() does NOT take ownership of eap_req
 * (the caller retains it).  id_r is read from ike_sa->id_r or generated from
 * ike_sa->rmconf, owned as the rest of the SA does.
 */

#include <config.h>

#include <string.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "ikev2_eap_emit.h"

/*
 * Build the plaintext IKE_AUTH payload list for an EAP round response:
 * IDr then exactly one EAP payload, NO AUTH.  On success *first_np receives
 * the first payload type (IDr) for the IKE header / Encrypted header and the
 * returned blob is the serialized payload chain (caller frees it).  Returns
 * NULL on failure.  eap_req is NOT consumed.
 */
rc_vchar_t *
ikev2_eap_emit_request(struct ikev2_sa *ike_sa, rc_vchar_t *eap_req,
		       uint8_t *first_np)
{
	struct ikev2_payloads payl;
	rc_vchar_t *id_r = 0, *blob = 0;
	struct rc_idlist *my_id;

	if (!ike_sa || !eap_req || !eap_req->v || !first_np)
		return NULL;

	ikev2_payloads_init(&payl);

	if (ike_sa->id_r) {
		id_r = ike_sa->id_r;
	} else {
		my_id = ikev2_my_id(ike_sa->rmconf);
		if (!my_id)
			goto fail;
		id_r = ikev2_identifier(my_id);
		if (!id_r)
			goto fail;
		ike_sa->id_r = id_r;
	}

	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_R, id_r, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_EAP, eap_req, FALSE);

	blob = ikev2_payloads_to_blob(&payl, first_np);
	if (!blob)
		goto fail;

	ikev2_payloads_destroy(&payl);
	return blob;

      fail:
	if (blob)
		rc_vfree(blob);
	ikev2_payloads_destroy(&payl);
	return NULL;
}
