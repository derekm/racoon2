/*
 * iked/ikev2_eap_emit.h - responder EAP IKE_AUTH response composition.
 *
 * Raises IDr and chains exactly one EAP payload (48) with NO AUTH into a
 * caller-owned ikev2_payloads list, so the shape is testable hermetically
 * and reusable by the ikev2.c responder sender.  See ikev2_eap_emit.c for
 * rationale and ownership.  struct ikev2_payloads is declared in
 * ikev2_impl.h (included by callers that already handle IKE_AUTH).
 */

#ifndef __IKEV2_EAP_EMIT_H_
#define __IKEV2_EAP_EMIT_H_

#include "vmbuf.h"

struct ikev2_sa;
struct ikev2_payloads;

/* Returns 0 on success (IDr + EAP pushed into payl), -1 on failure.
 * eap_req is NOT consumed; the caller owns payl + id_r + eap_req. */
extern int
ikev2_eap_emit_request(struct ikev2_sa *ike_sa, struct ikev2_payloads *payl,
		       rc_vchar_t *eap_req);

#endif /* __IKEV2_EAP_EMIT_H_ */
