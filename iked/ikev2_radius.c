/*
 * iked/ikev2_radius.c - RADIUS client (RFC 2865 / RFC 3579) for iked IKEv2.
 *
 * iked proxies a road-warrior client's EAP to a RADIUS server (see
 * ikev2_eap.c + doc/eap-wiring-plan.md).  This module is the RADIUS
 * *client* wire layer: it builds an Access-Request carrying the framed
 * EAP-Message (79) attribute, signs it with the Message-Authenticator
 * (80, RFC 2869 s3.2: HMAC-MD5 of the whole packet with the attr value
 * zeroed, under the shared secret), sends it over UDP 1812, and decodes +
 * authenticator-verifies the reply (Access-Accept / Access-Challenge /
 * Access-Reject: Response-Authenticator = MD5(Code+ID+Len+ReqAuth+Attrs+
 * Secret), RFC 2865 s3).
 *
 * Self-contained: only lib allocators (racoon_malloc/rc_vmalloc), the
 * daemon's OpenSSL MD5/HMAC wrappers (eay_md5_one/eay_hmacmd5_one) and
 * the RAND_bytes DRBG are used, so a unit test (radiustest.c) exercises
 * the authenticator math without a live server.
 *
 * Status: milestone 2 (doc/eap-wiring-plan.md).  Not yet wired into the
 * IKE_AUTH responder; builds into iked via IKEV2_SRC.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/rand.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "crypto_impl.h"	/* eay_md5_one / eay_hmacmd5_one */
#include "vmbuf.h"
#include "ikev2_radius.h"

#define	RADIUS_PKT_GROW	256

/* Append one Type/Length/Value attribute to *pktp at *off (grows pkt). */
static int
radius_put_attr(rc_vchar_t **pktp, size_t *off, uint8_t type,
		const uint8_t *val, size_t vlen)
{
	rc_vchar_t *pkt = *pktp, *nb;
	size_t alen = vlen + 2;
	uint8_t *v;

	if (vlen > 253) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RADIUS attr %u value too long (%zu)\n", type, vlen);
		return -1;
	}
	if (*off + alen > pkt->l) {
		nb = rc_vmalloc(pkt->l + RADIUS_PKT_GROW);
		if (!nb)
			return -1;
		memcpy(nb->v, pkt->v, pkt->l);
		rc_vfree(pkt);
		*pktp = nb;
		pkt = nb;
	}
	v = (uint8_t *)pkt->v + *off;
	v[0] = type;
	v[1] = (uint8_t)alen;
	if (vlen)
		memcpy(v + 2, val, vlen);
	*off += alen;
	return 0;
}

/* Parse Attributes out of a raw response body into resp->attrs. */
static int
radius_parse_attrs(struct ikev2_radius_response *resp, const uint8_t *v,
		   size_t len)
{
	size_t off = 0;

	while (off < len) {
		uint8_t type, alen;
		size_t vlen;
		rc_vchar_t *val;
		struct ikev2_radius_attr *na;

		if (off + 2 > len) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "RADIUS: truncated attr header\n");
			return -1;
		}
		type = v[off];
		alen = v[off + 1];
		if (alen < 2) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "RADIUS: attr %u bad length %u\n", type, alen);
			return -1;
		}
		vlen = alen - 2;
		if (off + alen > len) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "RADIUS: attr %u overruns packet\n", type);
			return -1;
		}
		val = rc_vmalloc(vlen);
		if (!val)
			return -1;
		if (vlen)
			memcpy(val->v, v + off + 2, vlen);

		na = racoon_realloc(resp->attrs,
				    sizeof(*na) * (resp->nattrs + 1));
		if (!na) {
			rc_vfree(val);
			return -1;
		}
		resp->attrs = na;
		resp->attrs[resp->nattrs].type = type;
		resp->attrs[resp->nattrs].value = val;
		resp->nattrs++;
		off += alen;
	}
	return 0;
}

/*
 * Build a signed Access-Request with a fresh Request Authenticator and a
 * correct Message-Authenticator(80).  Returns a vchar the caller frees.
 */
rc_vchar_t *
ikev2_radius_build_request(uint8_t id, rc_vchar_t *eap, const char *user_name,
			   uint16_t nas_port, const struct sockaddr *nas,
			   rc_vchar_t *secret)
{
	rc_vchar_t *pkt;
	size_t off;
	static const uint8_t zauth[IKEV2_RADIUS_AUTH_LEN] = { 0 };
	uint8_t *reqauth;

	pkt = rc_vmalloc(IKEV2_RADIUS_HEADER_LEN + RADIUS_PKT_GROW);
	if (!pkt)
		return NULL;

	/* header: code/id/len filled at the end; Request Authenticator now */
	reqauth = (uint8_t *)pkt->v + 4;
	if (RAND_bytes(reqauth, IKEV2_RADIUS_AUTH_LEN) != 1) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RADIUS: RAND_bytes failed\n");
		rc_vfree(pkt);
		return NULL;
	}
	off = IKEV2_RADIUS_HEADER_LEN;

	if (user_name && user_name[0])
		if (radius_put_attr(&pkt, &off, IKEV2_RADIUS_ATTR_USER_NAME,
				   (const uint8_t *)user_name,
				   strlen(user_name)) < 0)
			goto fail;

	/* NAS-IP-Address (4) - only meaningful for AF_INET. */
	if (nas && nas->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const void *)nas;
		if (radius_put_attr(&pkt, &off, IKEV2_RADIUS_ATTR_NAS_IP_ADDRESS,
				   (const uint8_t *)&sin->sin_addr.s_addr, 4) < 0)
			goto fail;
	}

	if (nas_port) {
		uint8_t p16[2];
		p16[0] = (uint8_t)(nas_port >> 8);
		p16[1] = (uint8_t)(nas_port & 0xff);
		if (radius_put_attr(&pkt, &off, IKEV2_RADIUS_ATTR_NAS_PORT,
				   p16, 2) < 0)
			goto fail;
	}

	if (radius_put_attr(&pkt, &off, IKEV2_RADIUS_ATTR_EAP_MESSAGE,
			   (const uint8_t *)eap->v, eap->l) < 0)
		goto fail;

	/* Message-Authenticator(80) slot, zeroed first (RFC 2869 s3.2). */
	if (radius_put_attr(&pkt, &off, IKEV2_RADIUS_ATTR_MESSAGE_AUTH,
			   zauth, IKEV2_RADIUS_AUTH_LEN) < 0)
		goto fail;

	/* header: Code, Id, Length */
	((uint8_t *)pkt->v)[0] = IKEV2_RADIUS_CODE_ACCESS_REQUEST;
	((uint8_t *)pkt->v)[1] = id;
	((uint8_t *)pkt->v)[2] = (uint8_t)(off >> 8);
	((uint8_t *)pkt->v)[3] = (uint8_t)(off & 0xff);

	/* Message-Authenticator = HMAC-MD5(secret, whole packet).  The value
	 * slot is the last 16 bytes of the packet (off - 16). */
	{
		rc_vchar_t key, mac;
		rc_vchar_t *dig;
		uint8_t *maslot = (uint8_t *)pkt->v + off - IKEV2_RADIUS_AUTH_LEN;

		key.v = secret->v; key.l = secret->l;
		mac.v = pkt->v;    mac.l = off;
		dig = eay_hmacmd5_one(&key, &mac);
		if (!dig) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "RADIUS: HMAC-MD5 failed\n");
			goto fail;
		}
		memcpy(maslot, dig->v, IKEV2_RADIUS_AUTH_LEN);
		rc_vfree(dig);
	}

	pkt->l = off;
	return pkt;

      fail:
	rc_vfree(pkt);
	return NULL;
}

/*
 * Verify a response against the Request Authenticator we sent and decode
 * it.  Returns NULL on any failure (id/authenticator mismatch, short
 * packet, malformed attrs); caller frees the result.
 */
struct ikev2_radius_response *
ikev2_radius_verify_response(uint8_t id, const uint8_t *req_auth,
			     rc_vchar_t *resp_raw, rc_vchar_t *secret)
{
	struct ikev2_radius_response *resp;
	const uint8_t *v = (const uint8_t *)resp_raw->v;
	size_t len = resp_raw->l;
	rc_vchar_t *dig;
	uint8_t calc[IKEV2_RADIUS_AUTH_LEN];

	if (len < IKEV2_RADIUS_HEADER_LEN) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RADIUS: response too short (%zu)\n", len);
		return NULL;
	}
	if (v[1] != id) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RADIUS: response id %u != request id %u\n", v[1], id);
		return NULL;
	}

	resp = racoon_calloc(1, sizeof(*resp));
	if (!resp)
		return NULL;
	resp->code = v[0];
	resp->identifier = v[1];
	memcpy(resp->authenticator, v + 4, IKEV2_RADIUS_AUTH_LEN);

	/* Response-Authenticator = MD5(Code+ID+Len+ReqAuth+Attrs+Secret).
	 * The response header's first 4 bytes are its Code/Id/Len; the
	 * 16-byte Request Authenticator we sent follows, then attrs + secret. */
	{
		size_t attrl = len - IKEV2_RADIUS_HEADER_LEN;
		size_t blen = 4 + IKEV2_RADIUS_AUTH_LEN + attrl + secret->l;
		size_t bo = 0;
		uint8_t *b = racoon_malloc(blen);
		rc_vchar_t buf;
		if (!b) {
			racoon_free(resp);
			return NULL;
		}
		memcpy(b + bo, v, 4);				   bo += 4;
		memcpy(b + bo, req_auth, IKEV2_RADIUS_AUTH_LEN);   bo += IKEV2_RADIUS_AUTH_LEN;
		memcpy(b + bo, v + IKEV2_RADIUS_HEADER_LEN, attrl); bo += attrl;
		memcpy(b + bo, secret->v, secret->l);		   bo += secret->l;
		buf.v = b; buf.l = blen;
		dig = eay_md5_one(&buf);
		racoon_free(b);
		if (!dig) {
			racoon_free(resp);
			return NULL;
		}
		memcpy(calc, dig->v, IKEV2_RADIUS_AUTH_LEN);
		rc_vfree(dig);
		if (CRYPTO_memcmp(calc, resp->authenticator,
				  IKEV2_RADIUS_AUTH_LEN) != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "RADIUS: response authenticator mismatch\n");
			racoon_free(resp);
			return NULL;
		}
	}

	if (radius_parse_attrs(resp, v + IKEV2_RADIUS_HEADER_LEN,
			       len - IKEV2_RADIUS_HEADER_LEN) < 0) {
		ikev2_radius_response_free(resp);
		return NULL;
	}
	return resp;
}

rc_vchar_t *
ikev2_radius_find_attr(struct ikev2_radius_response *resp, uint8_t type)
{
	unsigned i;
	if (!resp)
		return NULL;
	for (i = 0; i < resp->nattrs; i++)
		if (resp->attrs[i].type == type)
			return resp->attrs[i].value;
	return NULL;
}

void
ikev2_radius_response_free(struct ikev2_radius_response *resp)
{
	unsigned i;
	if (!resp)
		return;
	for (i = 0; i < resp->nattrs; i++)
		rc_vfree(resp->attrs[i].value);
	racoon_free(resp->attrs);
	racoon_free(resp);
}

int
ikev2_radius_exchange(struct sockaddr *server, socklen_t servlen,
		      rc_vchar_t *eap, const struct ikev2_radius_opt *opt,
		      uint8_t *id, struct ikev2_radius_response **resp_out)
{
	int s = -1;
	int rv = IKEV2_RADIUS_IOERR;
	unsigned attempt, max;
	struct sockaddr_storage nas;
	socklen_t naslen = (socklen_t)sizeof(nas);
	uint8_t req_auth[IKEV2_RADIUS_AUTH_LEN];
	rc_vchar_t *req = NULL, *rbuf = NULL;

	*resp_out = NULL;
	if (!server || !eap || !opt || !opt->secret || opt->secret->l == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RADIUS: missing server/eap/secret\n");
		return IKEV2_RADIUS_IOERR;
	}

	max = opt->retries ? opt->retries : 1;
	memset(&nas, 0, sizeof(nas));

	s = socket(server->sa_family, SOCK_DGRAM, 0);
	if (s < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RADIUS: socket: %s\n", strerror(errno));
		return IKEV2_RADIUS_IOERR;
	}

	for (attempt = 0; attempt < max; attempt++) {
		ssize_t n;
		fd_set rfd;
		struct timeval ts;
		struct ikev2_radius_response *rr;

		/* fresh Request Authenticator + MAC per transmit (RFC 2865
		 * requires a unique authenticator per Access-Request). */
		req = ikev2_radius_build_request(*id, eap, opt->user_name,
						 opt->nas_port,
						 (struct sockaddr *)&nas,
						 opt->secret);
		if (!req) {
			rv = IKEV2_RADIUS_IOERR;
			goto out;
		}
		memcpy(req_auth, (const uint8_t *)req->v + 4,
		       IKEV2_RADIUS_AUTH_LEN);

		if (sendto(s, req->v, req->l, 0, server, servlen) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "RADIUS: sendto: %s\n", strerror(errno));
			rv = IKEV2_RADIUS_IOERR;
			goto out;
		}

		ts.tv_sec = opt->timeout_ms / 1000;
		ts.tv_usec = (opt->timeout_ms % 1000) * 1000;
		FD_ZERO(&rfd);
		FD_SET(s, &rfd);
		if (select(s + 1, &rfd, NULL, NULL, &ts) <= 0) {
			/* timeout (or EINTR) -> retry with a fresh auth */
			rc_vfree(req);
			req = NULL;
			continue;
		}

		rbuf = rc_vmalloc(4096);
		if (!rbuf) {
			rv = IKEV2_RADIUS_IOERR;
			goto out;
		}
		n = recvfrom(s, rbuf->v, 4096, 0,
			     (struct sockaddr *)&nas, &naslen);
		if (n < 0) {
			rc_vfree(rbuf);
			rbuf = NULL;
			rc_vfree(req);
			req = NULL;
			continue;	/* transient: retry */
		}
		rbuf->l = n;

		if (((uint8_t *)rbuf->v)[0] != IKEV2_RADIUS_CODE_ACCESS_ACCEPT &&
		    ((uint8_t *)rbuf->v)[0] != IKEV2_RADIUS_CODE_ACCESS_REJECT &&
		    ((uint8_t *)rbuf->v)[0] != IKEV2_RADIUS_CODE_ACCESS_CHALLENGE) {
			/* not a reply to our request; ignore + retry */
			rc_vfree(rbuf);
			rbuf = NULL;
			rc_vfree(req);
			req = NULL;
			continue;
		}
		rr = ikev2_radius_verify_response(*id, req_auth, rbuf,
						 opt->secret);
		if (rr) {
			*resp_out = rr;
			rv = IKEV2_RADIUS_OK;
			rc_vfree(rbuf);
			rc_vfree(req);
			goto out;
		}
		/* auth mismatch / malformed -> treat as lost and retry */
		rc_vfree(rbuf);
		rbuf = NULL;
		rc_vfree(req);
		req = NULL;
	}
	rv = IKEV2_RADIUS_TIMEOUT;

      out:
	if (s >= 0)
		close(s);
	if (req)
		rc_vfree(req);
	if (rbuf)
		rc_vfree(rbuf);
	if (rv == IKEV2_RADIUS_OK)
		*id = (uint8_t)(*id + 1);
	return rv;
}
