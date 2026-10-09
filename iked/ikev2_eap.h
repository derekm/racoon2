/*
 * iked/ikev2_eap.h - EAP (RFC 3748) framing interface for iked IKEv2.
 *
 * See ikev2_eap.c for the codec and the roadmap in doc/eap-wiring-plan.md.
 */

#ifndef __IKEV2_EAP_H_
#define __IKEV2_EAP_H_

#include "vmbuf.h"	/* rc_vchar_t */

struct ikev2_eap_packet;

/* Parse a wire EAP message into a packet; NULL on malformed input. */
extern struct ikev2_eap_packet *ikev2_eap_decode(rc_vchar_t *);

/* Serialize a packet back to wire bytes (caller frees the returned vchar). */
extern rc_vchar_t *ikev2_eap_encode_packet(struct ikev2_eap_packet *);

/* Build an RFC 3748 s5.1 Identity Request (the exchange opener). */
extern rc_vchar_t *ikev2_eap_build_identity_request(u_int8_t identifier);

/* Return the Type of a Response, or -1 if not a Response (Nak detection). */
extern int ikev2_eap_response_type(rc_vchar_t *);

/* Free a packet returned by ikev2_eap_decode(). */
extern void ikev2_eap_packet_free(struct ikev2_eap_packet *);

#endif /* __IKEV2_EAP_H_ */
