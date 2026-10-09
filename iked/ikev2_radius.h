/*
 * iked/ikev2_radius.h - RADIUS client (RFC 2865/RFC 3579) interface for
 * iked IKEv2 EAP.
 *
 * iked terminates a road-warrior client's EAP by proxying each EAP message
 * to a RADIUS server (see ikev2_eap.c + doc/eap-wiring-plan.md).  This
 * module is the RADIUS *client* wire layer: it builds Access-Request
 * packets carrying the EAP-Message (79) attribute with a correct
 * Message-Authenticator (80), sends them to the RADIUS server over UDP
 * (1812), and decodes/verifies the Access-Accept / Access-Challenge /
 * Access-Reject response (checking the Response-Authenticator and its
 * Message-Authenticator).  The EAP method itself lives on FreeRADIUS.
 *
 * A packet is:  Code(1) Identifier(1) Length(2) Authenticator(16) then a
 * sequence of Type(1) Length(1) Value attributes.
 */
#ifndef __IKEV2_RADIUS_H_
#define __IKEV2_RADIUS_H_

#include "vmbuf.h"	/* rc_vchar_t */

/* RFC 2865 codes */
#define IKEV2_RADIUS_CODE_ACCESS_REQUEST	1
#define IKEV2_RADIUS_CODE_ACCESS_ACCEPT		2
#define IKEV2_RADIUS_CODE_ACCESS_REJECT		3
#define IKEV2_RADIUS_CODE_ACCESS_CHALLENGE	11

/* RADIUS attributes we carry (RFC 2865 + RFC 3579) */
#define IKEV2_RADIUS_ATTR_USER_NAME		1
#define IKEV2_RADIUS_ATTR_NAS_IP_ADDRESS	4
#define IKEV2_RADIUS_ATTR_NAS_PORT		5
#define IKEV2_RADIUS_ATTR_SERVICE_TYPE		6
#define IKEV2_RADIUS_ATTR_FRAMED_PROTOCOL	7
#define IKEV2_RADIUS_ATTR_STATE			24
#define IKEV2_RADIUS_ATTR_CLASS			25
#define IKEV2_RADIUS_ATTR_EAP_MESSAGE		79
#define IKEV2_RADIUS_ATTR_MESSAGE_AUTH		80

#define IKEV2_RADIUS_AUTH_LEN	16	/* Request/Response Authenticator */
#define IKEV2_RADIUS_HEADER_LEN	20	/* Code+ID+Len+Auth */

/*
 * Codec-level entry points (no socket) so the authenticator math is
 * unit-tested (radiustest.c) and the IKE_AUTH responder can drive a
 * single round trip without the transport.  Both operate on the raw
 * EAP-Message attribute bytes the same way ikev2_radius_exchange() does.
 *
 * ikev2_radius_build_request() returns a signed Access-Request vchar
 * (fresh Request Authenticator + Message-Authenticator(80)).  The caller
 * frees it.
 *
 * ikev2_radius_verify_response() checks id + Response-Authenticator and
 * decodes attributes; returns a response the caller frees, or NULL.
 */
extern rc_vchar_t *ikev2_radius_build_request(uint8_t id, rc_vchar_t *eap,
					      const char *user_name,
					      uint16_t nas_port,
					      const struct sockaddr *nas,
					      rc_vchar_t *secret);
extern struct ikev2_radius_response *
ikev2_radius_verify_response(uint8_t id, const uint8_t *req_auth,
			     rc_vchar_t *resp_raw, rc_vchar_t *secret);

/* Transport result from a RADIUS round trip. */
#define IKEV2_RADIUS_OK		0
#define IKEV2_RADIUS_TIMEOUT	-1	/* all retries exhausted/no reply */
#define IKEV2_RADIUS_IOERR	-2	/* socket/send/recv failure */
#define IKEV2_RADIUS_BADVERIFY	-3	/* reply failed authenticator check */
#define IKEV2_RADIUS_TOOLONG	-4	/* reply longer than the buffer */

/*
 * Options for a single Access-Request.  server/proto point at stack
 * sockaddr storage the caller owns; the module copies what it needs.
 */
struct ikev2_radius_opt {
	const char *user_name;		/* EAP Identity (attr 1), optional */
	const char *nas_ip;		/* our address presented as NAS, may be "" */
	uint16_t nas_port;		/* attr 5, optional (0 = omit) */
	rc_vchar_t *secret;		/* shared RADIUS secret (never in cfg) */
	unsigned retries;		/* total transmit attempts (>= 1) */
	unsigned timeout_ms;		/* wait per attempt */
};

/*
 * A decoded RADIUS response.  attrs is an array of (type, vchar) pairs;
 * use ikev2_radius_find_attr() to pull the EAP-Message / State / Class.
 */
struct ikev2_radius_response {
	uint8_t code;
	uint8_t identifier;
	uint8_t authenticator[IKEV2_RADIUS_AUTH_LEN];	/* Response Auth */
	unsigned nattrs;
	struct ikev2_radius_attr *attrs;
};

struct ikev2_radius_attr {
	uint8_t type;
	rc_vchar_t *value;
};

/*
 * ikev2_radius_exchange(server, port, eap, opt, id[in/out], resp)
 *
 * Send one EAP message (already the 4-byte RFC 3748 packet in `eap`) to
 * the RADIUS server as an Access-Request, wait for the response, verify
 * its authentics, and return the decoded response in *resp (caller frees
 * with ikev2_radius_response_free()).
 *
 * id[in] is the RADIUS Identifier to stamp (monotonic per SA); it is
 * updated to the next value on return so successive round trips within
 * the same IKE_SA do not reuse it.
 *
 * Returns IKEV2_RADIUS_*; on OK, *resp->code is Accept/Reject/Challenge
 * and the EAP-Message attribute(s) are in the attr list.
 *
 * server/proto: caller-owned sockaddr storage for the RADIUS endpoint
 * (AF_INET/AF_INET6 both accepted).
 */
extern int ikev2_radius_exchange(struct sockaddr *server, socklen_t servlen,
				 rc_vchar_t *eap,
				 const struct ikev2_radius_opt *opt,
				 uint8_t *id,
				 struct ikev2_radius_response **resp);

/* Find the first attribute of a given type; NULL if absent. */
extern rc_vchar_t *ikev2_radius_find_attr(struct ikev2_radius_response *,
					  uint8_t type);

/* Free a response returned by ikev2_radius_exchange(). */
extern void ikev2_radius_response_free(struct ikev2_radius_response *);

#endif /* __IKEV2_RADIUS_H_ */
