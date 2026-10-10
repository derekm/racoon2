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
 * This module raises IDr and chains it with exactly one EAP payload (48) and
 * NO AUTH into the caller's ikev2_payloads list.  That list is the shape
 * ikev2_packet_construct() serializes, so the same composition serves both
 * the ikev2.c responder sender (which hands &payl to packet_construct) and
 * the hermetic test (which runs ikev2_payloads_to_blob to verify the shape
 * without a live socket).
 *
 * Ownership: the caller owns the payloads list (init and destroy) and both
 * id_r and eap_req.  This module pushes with need_free=0 and takes nothing.
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
 * Raise IDr (from ike_sa->id_r if present, else from ike_sa->rmconf) and
 * chain exactly one EAP payload (48) with NO AUTH into the caller's payloads
 * list.  Returns 0 on success, -1 on failure (the list may be partially
 * filled on failure; the caller destroys it either way).  eap_req is NOT
 * consumed.
 */
int
ikev2_eap_emit_request(struct ikev2_sa *ike_sa, struct ikev2_payloads *payl,
		       rc_vchar_t *eap_req)
{
	rc_vchar_t *id_r = 0;
	struct rc_idlist *my_id;

	if (!ike_sa || !payl || !eap_req || !eap_req->v)
		return -1;

	if (ike_sa->id_r) {
		id_r = ike_sa->id_r;
	} else {
		my_id = ikev2_my_id(ike_sa->rmconf);
		if (!my_id)
			return -1;
		id_r = ikev2_identifier(my_id);
		if (!id_r)
			return -1;
		ike_sa->id_r = id_r;
	}

	/* IDr then exactly one EAP Request; NO AUTH (RFC 7296 s2.16 +
	 * RFC 5998 s2).  need_free=0: id_r is SA-owned, eap_req caller-owned. */
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_ID_R, id_r, FALSE);
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_EAP, eap_req, FALSE);
	return 0;
}
