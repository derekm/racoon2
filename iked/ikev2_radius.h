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
 * Message-Authenticator).
 *
 * Rock-solid authenticator handling is the point of the module:
 *  - Response-Authenticator (RFC 2865 s3) proves the reply came from the
 *    holder of the shared secret.
 *  - Message-Authenticator (RFC 2869 s3.2 / RFC 3579 s3.5) is computed
 *    over the packet with the Authenticator field replaced by the Request
 *    Authenticator and the attribute value zeroed; requiring it on EAP
 *    responses closes Blast-RADIUS (CVE-2024-3596) style forgery, where
 *    an on-path attacker who only knows Code/ID/Length/ReqAuth could
 *    forge the MD5 Response-Authenticator for Access-Reject.
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
#define IKEV2_RADIUS_ATTR_NAS_IDENTIFIER	32
#define IKEV2_RADIUS_ATTR_EAP_MESSAGE		79
#define IKEV2_RADIUS_ATTR_MESSAGE_AUTH		80

/* Microsoft VSA (RFC 2548): vendor-id 311, in attr 26 (Vendor-Specific). */
#define IKEV2_RADIUS_VSA_MICROSOFT	311
#define IKEV2_RADIUS_ATTR_VENDOR_SPECIFIC	26
#define IKEV2_RADIUS_VSA_MS_MPPE_SEND_KEY	16
#define IKEV2_RADIUS_VSA_MS_MPPE_RECV_KEY	17

#define IKEV2_RADIUS_AUTH_LEN	16	/* Request/Response Authenticator */
#define IKEV2_RADIUS_HEADER_LEN	20	/* Code+ID+Len+Auth */
#define IKEV2_RADIUS_MAX_VALUE	253	/* max octets in one Attr Value */

struct ikev2_radius_opt;	/* forward decl: used in the codec prototypes */

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
 * ikev2_radius_verify_response() checks id + Response-Authenticator +
 * Message-Authenticator and decodes attributes; returns a response the
 * caller frees, or NULL.
 */
extern rc_vchar_t *ikev2_radius_build_request(uint8_t id, rc_vchar_t *eap,
					      const struct ikev2_radius_opt *);
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
	const char *nas_ip;		/* NAS-IP-Address dotted quad, may be "" */
	const char *nas_id;		/* NAS-Identifier, optional */
	uint32_t nas_port;		/* attr 5 (4-octet), optional (0=omit) */
	rc_vchar_t *state;		/* prior Access-Challenge State to echo */
	rc_vchar_t *secret;		/* shared RADIUS secret (never in cfg) */
	unsigned retries;		/* total transmit attempts (>= 1) */
	unsigned timeout_ms;		/* wait per attempt */
};

/*
 * A decoded RADIUS response.  attrs is an array of (type, vchar) pairs;
 * use ikev2_radius_find_attr() to pull State / Class, and
 * ikev2_radius_eap_message() to get the reassembled EAP message.
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
 * ikev2_radius_exchange(server, servlen, eap, opt, id[in/out], resp)
 *
 * Send one EAP message (already the 4-byte RFC 3748 packet in `eap`) to
 * the RADIUS server as an Access-Request, wait for the response, verify
 * its authentics, and return the decoded response in *resp (caller frees
 * with ikev2_radius_response_free()).
 *
 * id[in] is the RADIUS Identifier to stamp.  On a SUCCESSFUL round trip it
 * is incremented so the next EAP exchange uses a fresh id; on timeout /
 * verify failure it is left unchanged.  That is safe because every call
 * opens a fresh UDP socket (new source port), which together with the id
 * is what RFC 2865 s2.5 duplicate detection keys on - a retried call is
 * not a duplicate of a timed-out one.
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

/* Reassemble EAP-Message (79) attributes across RFC 3579 fragmentation
 * into a single vchar the caller frees; NULL if none present. */
extern rc_vchar_t *ikev2_radius_eap_message(struct ikev2_radius_response *);

/*
 * Extract the EAP-derived MSK from an Access-Accept: the MS-MPPE-Recv-Key
 * (RFC 2548 s2.4.3, vendor 311 sub-attr 17, carried in a Vendor-Specific
 * attr) is the EAP-MSCHAPv2 session key iked folds into Ka = prf+(SK_d,
 * N(p)||MSK...) per RFC 7296 s2.16 / doc/eap-wiring-plan.md s7.  The key
 * is encrypted with a per-packet protocol ("recv" from the user; "send"
 * is the NAS->user direction and is not the MSK for IKE EAP).  Returns a
 * freshly allocated vchar with the decrypted master key the caller frees,
 * or NULL if the response lacks it / decrypt fails.
 *
 * req_auth is the Request Authenticator of the Access-Request that drew
 * this Access-Accept (their exchange's authenticator feeds the RC4 key
 * schedule, RFC 2548 s2.4.3).
 */
extern rc_vchar_t *ikev2_radius_msk(struct ikev2_radius_response *,
				    const uint8_t req_auth[IKEV2_RADIUS_AUTH_LEN],
				    rc_vchar_t *secret);

/* Free a response returned by ikev2_radius_exchange(). */
extern void ikev2_radius_response_free(struct ikev2_radius_response *);

#endif /* __IKEV2_RADIUS_H_ */
