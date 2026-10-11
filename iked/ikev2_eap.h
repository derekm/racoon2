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

/* Build an RFC 3748 s5.2 EAP-Success (Code=3, no Type octet). */
extern rc_vchar_t *ikev2_eap_build_success(u_int8_t identifier);

/* Build an RFC 3748 s4.2 EAP-Failure (Code=4, no Type octet); answers the
 * outstanding IKE_AUTH when EAP/RADIUS rejects the client. */
extern rc_vchar_t *ikev2_eap_build_failure(u_int8_t identifier);

/* Extract the EAP Identity (RFC 3748 s5.1) from a wire Response; returns a
 * NUL-terminated duplicate (rc_free) or NULL. */
extern char *ikev2_eap_identity_string(rc_vchar_t *);

/* Return the Type of a Response, or -1 if not a Response (Nak detection). */
extern int ikev2_eap_response_type(rc_vchar_t *);

/* RFC 5998 s4: nonzero iff EAP Type is in the RFC's list of methods that
 * are mutual, key-generating and dictionary-attack resistant.  Only such a
 * method may complete an exchange in which the responder omitted AUTH. */
extern int ikev2_eap_rfc5998_safe_method(int type);

/* RFC 5998 s3 responder decision for the first IKE_AUTH response.
 *   rmethod        responder signature method (0 = none resolved)
 *   sig_configured a non-EAP method is listed in kmp_auth_method
 *   peer_eap_only  the initiator sent N(EAP_ONLY_AUTHENTICATION)
 * EAP-only (omit AUTH) is honored only when BOTH the operator configured
 * an EAP-only responder (kmp_auth_method { eap; }) AND the initiator asked
 * for it; otherwise RFC 7296 s2.16 requires the responder's AUTH. */
enum ikev2_eap_only_decision {
	IKEV2_EAPONLY_SIGN = 0,	/* send IDr + [CERT] + AUTH + EAP */
	IKEV2_EAPONLY_HONOR,	/* send IDr + EAP; method must be RFC 5998 safe */
	IKEV2_EAPONLY_REFUSE,	/* EAP-only config, peer did not ask: AUTH_FAILED */
	IKEV2_EAPONLY_SIGFAIL	/* signature configured but unresolvable: abort */
};
extern enum ikev2_eap_only_decision
ikev2_eap_only_policy(int rmethod, int sig_configured, int peer_eap_only);

/* Free a packet returned by ikev2_eap_decode(). */
extern void ikev2_eap_packet_free(struct ikev2_eap_packet *);

#endif /* __IKEV2_EAP_H_ */
