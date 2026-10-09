/*
 * iked/ikev2_eap.c - EAP (RFC 3748) framing for racoon2 iked IKEv2.
 *
 * Road-warrior EAP is tunneled per RFC 7296 s2.16 inside IKE_AUTH, with
 * each EAP message proxied to a RADIUS server (see ikev2_radius.c).  That
 * responder path is NOT yet wired (see the Status note below); this module
 * is the EAP *wire* codec: it encodes and decodes RFC 3748 EAP packets
 * (the 4-byte Code/Identifier/Length header plus the single-byte Type and
 * method data), and provides the small set of method-agnostic skeleton
 * operations (Identity request/response, Nak) that any method must handle
 * before the method-specific exchange runs inside the RADIUS
 * Access-Challenge round trips.
 *
 * The EAP method itself is never implemented here: method types
 * (EAP-MSCHAPv2, EAP-TLS) are opaque to this module and live on the remote
 * FreeRADIUS server.  iked only frames and carries them.
 *
 * Status: milestone 1 - framing codec + skeleton.  NOT YET wired into the
 * IKE_AUTH responder: IKEV2_PAYLOAD_EAP (48) appears in ikev2.c only as
 * the top of the critical-payload type range (ikev2.c:1229); the responder
 * EAP path that would intercept an IDi-without-AUTH message and proxy the
 * exchange via ikev2_radius.c is still to be written per
 * doc/eap-wiring-plan.md (milestone 3, responder wiring).
 */

#include <config.h>

#include <assert.h>
#include <string.h>
#include <sys/types.h>

#include "racoon.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_eap.h"

/* RFC 3748 s4.1: EAP packet Code. */
#define	IKEV2_EAP_CODE_REQUEST	1
#define	IKEV2_EAP_CODE_RESPONSE	2
#define	IKEV2_EAP_CODE_SUCCESS	3
#define	IKEV2_EAP_CODE_FAILURE	4

/* RFC 3748 s5: EAP Type (after the 4-byte header on Request/Response). */
#define	IKEV2_EAP_TYPE_IDENTITY	1
#define	IKEV2_EAP_TYPE_NOTIFY	2
#define	IKEV2_EAP_TYPE_NAK	3
#define	IKEV2_EAP_TYPE_MD5	4
#define	IKEV2_EAP_TYPE_EXPANDED	254
#define	IKEV2_EAP_TYPE_EXPERIMENTAL 255

/* A parsed EAP packet: the 4-byte header plus optional Type. */
struct ikev2_eap_packet {
	u_int8_t code;
	u_int8_t identifier;
	u_int16_t length;	/* total including header */
	u_int8_t type;		/* valid when code is Request/Response */
	rc_vchar_t *data;	/* Type+Data for Req/Resp; empty for Success/Failure */
};

/*
 * ikev2_eap_decode(rc_vchar_t *raw) -> struct ikev2_eap_packet *
 *
 * Parse a wire EAP packet.  raw is exactly one EAP message (the IKEv2 EAP
 * payload body).  Returns a newly allocated packet that the caller must
 * free with ikev2_eap_packet_free().  NULL on a malformed or short packet.
 */
struct ikev2_eap_packet *
ikev2_eap_decode(rc_vchar_t *raw)
{
	struct ikev2_eap_packet *p;
	u_int8_t *v;

	if (!raw || raw->l < 4)
		return NULL;

	p = racoon_calloc(1, sizeof(*p));
	if (!p)
		return NULL;

	v = (u_int8_t *)raw->v;
	p->code = v[0];
	p->identifier = v[1];
	p->length = ((u_int16_t)v[2] << 8) | v[3];

	/* Length must span the packet we were given and be >= 4 (header). */
	if (p->length < 4 || p->length > raw->l) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "EAP: bad length %u (pkt %zd)\n", p->length, raw->l);
		racoon_free(p);
		return NULL;
	}

	/* Only Request/Response carry a Type octet; Data excludes it so
	 * encode (which re-emits p->type then data) round-trips exactly.
	 */
	if (p->code == IKEV2_EAP_CODE_REQUEST ||
	    p->code == IKEV2_EAP_CODE_RESPONSE) {
		if (p->length < 5) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "EAP: Request/Response shorter than Type octet\n");
			racoon_free(p);
			return NULL;
		}
		p->type = v[4];
	}

	if (p->length > 4) {
		size_t dlen = p->length - 4;
		u_int8_t *src = v + 4;
		/* Request/Response: data is after the type octet; Success/
		 * Failure: the whole body (pad/retransmit) is data. */
		if (p->code == IKEV2_EAP_CODE_REQUEST ||
		    p->code == IKEV2_EAP_CODE_RESPONSE) {
			if (p->length < 5)
				goto bad_data;
			dlen = p->length - 5;
			src = v + 5;
		}
		p->data = rc_vmalloc(dlen);
		if (!p->data) {
			racoon_free(p);
			return NULL;
		}
		memcpy(p->data->v, src, dlen);
		p->data->l = dlen;
	} else
		p->data = rc_vmalloc(0);

	return p;

      bad_data:
	plog(PLOG_PROTOERR, PLOGLOC, NULL,
	     "EAP: Request/Response shorter than Type octet\n");
	racoon_free(p);
	return NULL;
}

/*
 * ikev2_eap_encode_packet(struct ikev2_eap_packet *p) -> rc_vchar_t *
 *
 * Serialize a parsed EAP packet back to wire bytes (Code/Identifier/Length/
 * Type+Data).  Returns a new vchar; caller frees it.
 */
rc_vchar_t *
ikev2_eap_encode_packet(struct ikev2_eap_packet *p)
{
	rc_vchar_t *out;
	u_int16_t len;
	size_t dlen;
	u_int8_t *v;

	if (!p)
		return NULL;

	dlen = (p->data ? p->data->l : 0);
	/* Success/Failure have no Type octet; Req/Resp do. */
	len = (p->code == IKEV2_EAP_CODE_REQUEST ||
	       p->code == IKEV2_EAP_CODE_RESPONSE)
	    ? (u_int16_t)(4 + 1 + dlen) : (u_int16_t)(4 + dlen);

	out = rc_vmalloc(len);
	if (!out)
		return NULL;
	v = (u_int8_t *)out->v;
	v[0] = p->code;
	v[1] = p->identifier;
	v[2] = (u_int8_t)(len >> 8);
	v[3] = (u_int8_t)(len & 0xff);
	if (p->code == IKEV2_EAP_CODE_REQUEST ||
	    p->code == IKEV2_EAP_CODE_RESPONSE) {
		v[4] = p->type;
		if (dlen)
			memcpy(v + 5, p->data->v, dlen);
	} else if (dlen) {
		memcpy(v + 4, p->data->v, dlen);
	}
	out->l = len;
	return out;
}

/*
 * ikev2_eap_build_identity_request(identifier) -> rc_vchar_t *
 *
 * RFC 3748 s5.1: the first Request is an Identity request (empty Data).
 * FreeRADIUS will respond with an Access-Challenge carrying the method's
 * real first Request; the Identity round is what starts the exchange.
 */
rc_vchar_t *
ikev2_eap_build_identity_request(u_int8_t identifier)
{
	struct ikev2_eap_packet p;
	rc_vchar_t *enc;

	memset(&p, 0, sizeof(p));
	p.code = IKEV2_EAP_CODE_REQUEST;
	p.identifier = identifier;
	p.type = IKEV2_EAP_TYPE_IDENTITY;
	p.data = NULL;
	enc = ikev2_eap_encode_packet(&p);
	return enc;
}

/*
 * ikev2_eap_type_from_response(rc_vchar_t *resp)
 *
 * Return the EAP Type carried by a Response, or -1 if it is not a Request/
 * Response.  Used to detect RFC 3748 s5.2 Nak responses (type 3) without
 * decoding the full 3-byte NAIS list.
 */
int
ikev2_eap_response_type(rc_vchar_t *resp)
{
	struct ikev2_eap_packet *p;
	int type;

	p = ikev2_eap_decode(resp);
	if (!p)
		return -1;
	type = (p->code == IKEV2_EAP_CODE_RESPONSE) ? (int)p->type : -1;
	ikev2_eap_packet_free(p);
	return type;
}

void
ikev2_eap_packet_free(struct ikev2_eap_packet *p)
{
	if (!p)
		return;
	if (p->data)
		rc_vfree(p->data);
	racoon_free(p);
}
