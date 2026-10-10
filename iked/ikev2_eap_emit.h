/*
 * iked/ikev2_eap_emit.h - responder EAP IKE_AUTH response composition.
 *
 * Facts the plaintext payload list for an EAP round response (IDr + exactly
 * one EAP payload 48, NO AUTH) so it can be unit-tested hermetically and
 * reused by the sender / future continuation.  See ikev2_eap_emit.c for
 * rationale and ownership.
 */

#ifndef __IKEV2_EAP_EMIT_H_
#define __IKEV2_EAP_EMIT_H_

#include "vmbuf.h"

struct ikev2_sa;

/* Returns a newly allocated serialized payload blob (the IKE_AUTH plaintext
 * body: IDr then EAP payload), *first_np = first payload type (IDr), or NULL
 * on failure.  eap_req is NOT consumed.  Caller frees the returned blob. */
extern rc_vchar_t *
ikev2_eap_emit_request(struct ikev2_sa *ike_sa, rc_vchar_t *eap_req,
		       uint8_t *first_np);

#endif /* __IKEV2_EAP_EMIT_H_ */
