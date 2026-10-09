/*
 * iked/ikev2_radius.c - RADIUS client (RFC 2865 / RFC 3579) for iked IKEv2.
 *
 * iked proxies a road-warrior client's EAP to a RADIUS server (see
 * ikev2_eap.c + doc/eap-wiring-plan.md).  This module is the RADIUS
 * *client* wire layer: it builds an Access-Request carrying the framed
 * EAP-Message (79) attribute, signs it with the Message-Authenticator
 * (80), sends it over UDP 1812, and decodes + authenticator-verifies the
 * reply (Access-Accept / Access-Challenge / Access-Reject).
 *
 * Both response authenticators are checked (and required on EAP):
 *  - Response-Authenticator (RFC 2865 s3):
 *      MD5(Code+ID+Len+ReqAuth+Attrs+Secret)
 *  - Message-Authenticator (RFC 2869 s3.2, RFC 3579 s3.5):
 *      HMAC-MD5(Secret, packet with Authenticator <- RequestAuthenticator
 *               and MA value zeroed)
 * The MA requirement defeats Blast-RADIUS (CVE-2024-3596): an on-path
 * attacker who knows only Code/ID/Length/ReqAuth can forge the MD5
 * Response-Authenticator, but cannot forge the HMAC-MD5 MA.  A response
 * that lacks attr 80 or whose HMAC fails is dropped.
 *
 * RFC 2865 robustness:
 *  - retransmits resend the IDENTICAL request bytes (RFC 2865 s2.5
 *    duplicate detection) - a fresh Request Authenticator only on a new
 *    round trip.
 *  - the reply source must match the server, and the response Length must
 *    match the datagram.
 *  - Access-Challenge State (RFC 2865 s5.24) is echoed on the next
 *    Access-Request via opt->state for multi-round EAP.
 *  - EAP-Message longer than 253 octets is fragmented (RFC 3579 s2.2) and
 *    reassembled across attributes on receipt.
 *
 * Self-contained: only lib allocators, the daemon's OpenSSL MD5/HMAC
 * wrappers, and the RAND_bytes DRBG - so a unit test (radiustest.c)
 * exercises the authenticator math without a live server.
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
#include <openssl/crypto.h>	/* CRYPTO_memcmp */

#include "racoon.h"
#include "gcmalloc.h"
#include "crypto_impl.h"	/* eay_md5_one / eay_hmacmd5_one */
#include "vmbuf.h"
#include "ikev2_radius.h"

#define	RADIUS_PKT_GROW	256
#define	RADIUS_RECV_MAX	4096	/* RADIUS packets cap at 4096 octets */

/* Append one Type/Length/Value attribute to *pktp at *off (grows pkt). */
static int
radius_put_attr(rc_vchar_t **pktp, size_t *off, uint8_t type,
		const uint8_t *val, size_t vlen)
{
	rc_vchar_t *pkt = *pktp, *nb;
	size_t alen = vlen + 2;
	uint8_t *v;

	if (vlen > IKEV2_RADIUS_MAX_VALUE) {
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

/*
 * Append an EAP-Message attribute, splitting `data` across consecutive
 * type-79 attributes when it exceeds 253 octets (RFC 3579 s2.2).  Returns
 * the number of attributes appended, or -1 on alloc failure.
 */
static int
radius_put_eap(rc_vchar_t **pktp, size_t *off, const uint8_t *data,
	       size_t len)
{
	size_t done = 0;
	int n = 0;

	while (len - done > IKEV2_RADIUS_MAX_VALUE) {
		if (radius_put_attr(pktp, off, IKEV2_RADIUS_ATTR_EAP_MESSAGE,
				   data + done, IKEV2_RADIUS_MAX_VALUE) < 0)
			return -1;
		done += IKEV2_RADIUS_MAX_VALUE;
		n++;
	}
	if (radius_put_attr(pktp, off, IKEV2_RADIUS_ATTR_EAP_MESSAGE,
			   data + done, len - done) < 0)
		return -1;
	return n + 1;
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
 * Given a parsed response, locate the Message-Authenticator(80) attribute
 * and return its value length position markers: sets *ma_pos to the byte
 * offset of the MA value within the packet and *ma_len to its length (16).
 * Returns 0 if present (and 16), -1 if absent or malformed.
 */
static int
radius_locate_ma(const struct ikev2_radius_response *resp, const uint8_t *pkt,
		 size_t len, size_t *ma_pos)
{
	size_t off = IKEV2_RADIUS_HEADER_LEN;
	size_t i;
	int found = -1;

	/*
	 * Walk the packet attributes in step with resp->attrs (which were
	 * parsed from the same bytes, in order) to find the MA appending
	 * offset.  We need the byte position because the HMAC covers the
	 * raw zerod MA value, not the parsed copy.
	 */
	for (i = 0; i < resp->nattrs; i++) {
		size_t alen;
		if (off + 2 > len)
			return -1;
		alen = pkt[off + 1];
		if (off + alen > len)
			return -1;
		if (resp->attrs[i].type == IKEV2_RADIUS_ATTR_MESSAGE_AUTH) {
			/* exactly one MA, exactly 16 octets (RFC 5080 s2.2: a
			 * second Message-Authenticator is a protocol error). */
			if (found == 0 || resp->attrs[i].value->l != IKEV2_RADIUS_AUTH_LEN)
				return -1;
			*ma_pos = off + 2;	/* value starts here */
			found = 0;
		}
		off += alen;
	}
	return found;
}

/*
 * Build a signed Access-Request with a fresh Request Authenticator and a
 * correct Message-Authenticator(80).  Returns a vchar the caller frees.
 */
rc_vchar_t *
ikev2_radius_build_request(uint8_t id, rc_vchar_t *eap,
			   const struct ikev2_radius_opt *opt)
{
	rc_vchar_t *pkt;
	size_t off;
	static const uint8_t zauth[IKEV2_RADIUS_AUTH_LEN] = { 0 };
	uint8_t *reqauth;

	if (!opt || !eap)
		return NULL;
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

	if (opt->user_name && opt->user_name[0])
		if (radius_put_attr(&pkt, &off, IKEV2_RADIUS_ATTR_USER_NAME,
				   (const uint8_t *)opt->user_name,
				   strlen(opt->user_name)) < 0)
			goto fail;

	/* NAS-IP-Address (4): the NAS's address, or NAS-Identifier (32)
	 * when only a name is configured.  RFC 2869 requires one of them
	 * on an Access-Request. */
	if (opt->nas_ip && opt->nas_ip[0]) {
		struct in_addr a;
		if (inet_pton(AF_INET, opt->nas_ip, &a) == 1)
			if (radius_put_attr(&pkt, &off,
					   IKEV2_RADIUS_ATTR_NAS_IP_ADDRESS,
					   (const uint8_t *)&a, 4) < 0)
				goto fail;
	} else if (opt->nas_id && opt->nas_id[0]) {
		if (radius_put_attr(&pkt, &off,
				   IKEV2_RADIUS_ATTR_NAS_IDENTIFIER,
				   (const uint8_t *)opt->nas_id,
				   strlen(opt->nas_id)) < 0)
			goto fail;
	}

	/* NAS-Port (5): 4-octet value (RFC 2865 s5.5). */
	if (opt->nas_port) {
		uint32_t p32 = htonl(opt->nas_port);
		if (radius_put_attr(&pkt, &off, IKEV2_RADIUS_ATTR_NAS_PORT,
				   (const uint8_t *)&p32, 4) < 0)
			goto fail;
	}

	/* echo prior Access-Challenge State (RFC 2865 s5.24) */
	if (opt->state && opt->state->l > 0)
		if (radius_put_attr(&pkt, &off, IKEV2_RADIUS_ATTR_STATE,
				   (const uint8_t *)opt->state->v,
				   opt->state->l) < 0)
			goto fail;

	/* EAP-Message (79, RFC 3579), fragmented if > 253 octets */
	if (radius_put_eap(&pkt, &off, (const uint8_t *)eap->v, eap->l) < 0)
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

		key.v = opt->secret->v; key.l = opt->secret->l;
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
 * Compute the RFC 3579 s3.5 Message-Authenticator for a response and
 * compare it (constant-time) with the attr-80 value in the packet.
 * req_auth is the Request Authenticator we sent.  Returns 0 if valid,
 * -1 if absent/wrong/malformed.
 */
static int
radius_check_msg_auth(const struct ikev2_radius_response *resp,
		      const uint8_t *pkt, size_t len,
		      const uint8_t *req_auth, rc_vchar_t *secret)
{
	size_t ma_pos = 0;
	uint8_t *work;
	rc_vchar_t key, mac, *dig;
	int ok;

	if (radius_locate_ma(resp, pkt, len, &ma_pos) < 0) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RADIUS: EAP response lacks Message-Authenticator(80)\n");
		return -1;
	}

	/* HMAC input: the response with Authenticator <- ReqAuth and the
	 * MA value zeroed.  Copy, patch both spots, hash. */
	work = racoon_malloc(len);
	if (!work)
		return -1;
	memcpy(work, pkt, len);
	memcpy(work + 4, req_auth, IKEV2_RADIUS_AUTH_LEN);	/* Auth <- ReqAuth */
	memset(work + ma_pos, 0, IKEV2_RADIUS_AUTH_LEN);	/* MA <- 0 */

	key.v = secret->v; key.l = secret->l;
	mac.v = work;      mac.l = len;
	dig = eay_hmacmd5_one(&key, &mac);
	if (!dig) {
		racoon_free(work);
		return -1;
	}
	/* compare the computed HMAC against the ORIGINAL attr-80 value (the
	 * packet, not the zeroed working copy). */
	ok = (dig->l == IKEV2_RADIUS_AUTH_LEN) &&
	     (CRYPTO_memcmp(dig->v, pkt + ma_pos, IKEV2_RADIUS_AUTH_LEN) == 0);
	rc_vfree(dig);
	racoon_free(work);
	if (!ok)
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RADIUS: response Message-Authenticator mismatch\n");
	return ok ? 0 : -1;
}

/*
 * Verify a response against the Request Authenticator we sent and decode
 * it.  Returns NULL on any failure (id/authenticator mismatch, short
 * packet, malformed attrs, missing/bad Message-Authenticator); caller
 * frees the result.
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
	size_t hlen;

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
	/* honor the RADIUS Length field; discard trailing padding (RFC
	 * 2865 s3: octets beyond Length are padding and MUST be ignored). */
	hlen = ((size_t)v[2] << 8) | v[3];
	if (hlen < IKEV2_RADIUS_HEADER_LEN || hlen > len) {
		plog(PLOG_PROTOERR, PLOGLOC, NULL,
		     "RADIUS: bad Length %zu (datagram %zu)\n", hlen, len);
		return NULL;
	}
	len = hlen;	/* attributes stop at Length */

	resp = racoon_calloc(1, sizeof(*resp));
	if (!resp)
		return NULL;
	resp->code = v[0];
	resp->identifier = v[1];
	memcpy(resp->authenticator, v + 4, IKEV2_RADIUS_AUTH_LEN);
	/* Record the Request Authenticator that drew this response: the EAP
	 * relay extracts the MS-MPPE MSK with ikev2_radius_msk(), which needs
	 * it (RFC 2548 key schedule).  Without this, the caller that runs the
	 * exchange on a worker could not recover the MSK from an Accept. */
	memcpy(resp->req_auth, req_auth, IKEV2_RADIUS_AUTH_LEN);

	/* parse attributes MUST happen before MA check (locate needs them) */
	if (radius_parse_attrs(resp, v + IKEV2_RADIUS_HEADER_LEN,
			       len - IKEV2_RADIUS_HEADER_LEN) < 0) {
		ikev2_radius_response_free(resp);
		return NULL;
	}

	/* Response-Authenticator = MD5(Code+ID+Len+ReqAuth+Attrs+Secret) */
	{
		size_t attrl = len - IKEV2_RADIUS_HEADER_LEN;
		size_t blen = 4 + IKEV2_RADIUS_AUTH_LEN + attrl + secret->l;
		size_t bo = 0;
		uint8_t *b = racoon_malloc(blen);
		rc_vchar_t buf;
		if (!b) {
			ikev2_radius_response_free(resp);
			return NULL;
		}
		memcpy(b + bo, v, 4);				   bo += 4;
		memcpy(b + bo, req_auth, IKEV2_RADIUS_AUTH_LEN);   bo += IKEV2_RADIUS_AUTH_LEN;
		memcpy(b + bo, v + IKEV2_RADIUS_HEADER_LEN, attrl); bo += attrl;
		memcpy(b + bo, secret->v, secret->l);		   bo += secret->l;
		buf.v = b; buf.l = blen;
		dig = eay_md5_one(&buf);
		memset(b, 0, blen);	/* wipe the secret-bearing buffer */
		racoon_free(b);
		if (!dig) {
			ikev2_radius_response_free(resp);
			return NULL;
		}
		memcpy(calc, dig->v, IKEV2_RADIUS_AUTH_LEN);
		rc_vfree(dig);
		if (CRYPTO_memcmp(calc, resp->authenticator,
				  IKEV2_RADIUS_AUTH_LEN) != 0) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "RADIUS: response authenticator mismatch\n");
			ikev2_radius_response_free(resp);
			return NULL;
		}
	}

	/* Message-Authenticator (RFC 3579): required on every EAP reply. */
	if (radius_check_msg_auth(resp, v, len, req_auth, secret) < 0) {
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

rc_vchar_t *
ikev2_radius_eap_message(struct ikev2_radius_response *resp)
{
	rc_vchar_t *out;
	size_t total = 0, off = 0;
	unsigned i, n = 0;

	if (!resp)
		return NULL;
	/* first pass: count attr-79 total bytes + fragment count */
	for (i = 0; i < resp->nattrs; i++)
		if (resp->attrs[i].type == IKEV2_RADIUS_ATTR_EAP_MESSAGE) {
			total += resp->attrs[i].value->l;
			n++;
		}
	if (n == 0)
		return NULL;
	out = rc_vmalloc(total);
	if (!out)
		return NULL;
	for (i = 0; i < resp->nattrs; i++)
		if (resp->attrs[i].type == IKEV2_RADIUS_ATTR_EAP_MESSAGE) {
			memcpy((uint8_t *)out->v + off,
			       resp->attrs[i].value->v,
			       resp->attrs[i].value->l);
			off += resp->attrs[i].value->l;
		}
	out->l = total;
	return out;
}

/*
 * RFC 2548 s2.4.3: decrypt an MS-MPPE key.  The sub-attribute value is
 * Salt(2) || ciphertext, where the plaintext Key-Length(1) || Key (padded
 * to a 16-multiple) is wrapped by the MD5-XOR schedule:
 *     b(1)=MD5(S+R+A); c(1)=p(1)^b(1)
 *     b(i)=MD5(S+c(i-1)); c(i)=p(i)^b(i)
 * S = shared secret, R = Request Authenticator, A = Salt.  (NOT the RC4
 * MPPE cipher - that is the MPPE session cipher, not this attribute wrap;
 * using real RC4 here would fail against FreeRADIUS.)  We reverse it:
 * p(1)=c(1)^b(1); for i>1 b(i)=MD5(S+c(i-1)) gives p(i) from c(i).
 */
static rc_vchar_t *
radius_decrypt_mppe(const uint8_t *val, size_t vlen,
		    const uint8_t *req_auth, rc_vchar_t *secret)
{
	size_t salt, clen, i, keylen;
	const uint8_t *c;
	uint8_t b[16];
	rc_vchar_t out;

	/* Salt is 2 octets, MSB of first set */
	if (vlen < 3 || !(val[0] & 0x80))
		return NULL;
	salt = 2;
	c = val + salt;
	clen = vlen - salt;
	if (clen == 0 || (clen % 16) != 0)
		return NULL;

	out.v = racoon_malloc(clen);
	if (!out.v)
		return NULL;

	/* p(1) = c(1) ^ MD5(S||R||A) */
	{
		uint8_t *m = racoon_malloc(secret->l + IKEV2_RADIUS_AUTH_LEN + 2);
		size_t mo = 0;
		rc_vchar_t md_in;
		rc_vchar_t *md;
		if (!m) {
			racoon_free(out.v);
			return NULL;
		}
		memcpy(m + mo, secret->v, secret->l);		mo += secret->l;
		memcpy(m + mo, req_auth, IKEV2_RADIUS_AUTH_LEN); mo += IKEV2_RADIUS_AUTH_LEN;
		memcpy(m + mo, val, 2);				 mo += 2;	/* salt */
		md_in.v = m; md_in.l = mo;
		md = eay_md5_one(&md_in);
		racoon_free(m);
		if (!md) {
			racoon_free(out.v);
			return NULL;
		}
		memcpy(b, md->v, IKEV2_RADIUS_AUTH_LEN);
		rc_vfree(md);
	}
	for (i = 0; i < clen; i += 16) {
		size_t o;
		for (o = 0; o < 16; o++)
			((uint8_t *)out.v)[i + o] = c[i + o] ^ b[o];
		if (i + 16 < clen) {
			/* b(i+1) = MD5(S || c(i)) for the next chunk */
			uint8_t *m = racoon_malloc(secret->l + 16);
			size_t mo;
			rc_vchar_t md_in;
			rc_vchar_t *md;
			if (!m) {
				racoon_free(out.v);
				return NULL;
			}
			memcpy(m, secret->v, secret->l);	  mo = secret->l;
			memcpy(m + mo, c + i, 16);		  mo += 16;
			md_in.v = m; md_in.l = mo;
			md = eay_md5_one(&md_in);
			racoon_free(m);
			if (!md) {
				racoon_free(out.v);
				return NULL;
			}
			memcpy(b, md->v, IKEV2_RADIUS_AUTH_LEN);
			rc_vfree(md);
		}
	}

	/* plaintext: Key-Length(1) then Key */
	keylen = ((uint8_t *)out.v)[0];
	if ((size_t)(1 + keylen) > clen) {
		racoon_free(out.v);
		return NULL;
	}
	if (keylen == 0) {
		/* an empty key is not a usable key - fail closed */
		racoon_free(out.v);
		return NULL;
	}
	{
		rc_vchar_t *key = rc_vmalloc(keylen);
		if (!key) {
			racoon_free(out.v);
			return NULL;
		}
		memcpy(key->v, (uint8_t *)out.v + 1, keylen);
		key->l = keylen;
		racoon_free(out.v);
		return key;
	}
}

rc_vchar_t *
ikev2_radius_msk(struct ikev2_radius_response *resp,
		 const uint8_t req_auth[IKEV2_RADIUS_AUTH_LEN],
		 rc_vchar_t *secret)
{
	unsigned i;
	rc_vchar_t *recv = NULL, *send = NULL, *msk = NULL;
	uint8_t zero32[32];

	if (!resp || !secret)
		return NULL;
	/* RFC 2548 s2.4: MS-MPPE-* keys appear ONLY in Access-Accept. */
	if (resp->code != IKEV2_RADIUS_CODE_ACCESS_ACCEPT)
		return NULL;

	/* Walk every Microsoft VSA and grab the Recv-Key (17) and the
	 * Send-Key (16).  The EAP-MSCHAPv2 MSK is 64 octets:
	 *     MSK = MasterReceiveKey || MasterSendKey || 32 zero octets
	 * (RFC 3079 s3.3 / [MS-CHAP] 3.1.5.1), where the RADIUS attributes
	 * carry those two 16-octet master keys.  Both must decrypt. */
	for (i = 0; i < resp->nattrs; i++) {
		const uint8_t *v;
		size_t vlen;
		rc_vchar_t *k;
		if (resp->attrs[i].type != IKEV2_RADIUS_ATTR_VENDOR_SPECIFIC)
			continue;
		v = (const uint8_t *)resp->attrs[i].value->v;
		vlen = resp->attrs[i].value->l;
		if (vlen < 8)
			continue;
		{
			uint32_t vendor = ((uint32_t)v[0] << 24) |
					  ((uint32_t)v[1] << 16) |
					  ((uint32_t)v[2] << 8) | v[3];
			size_t off = 4;
			if (vendor != IKEV2_RADIUS_VSA_MICROSOFT)
				continue;
			while (off + 2 <= vlen) {
				uint8_t st = v[off], sl = v[off + 1];
				if (sl < 2 || off + sl > vlen)
					break;
				if (st == IKEV2_RADIUS_VSA_MS_MPPE_RECV_KEY ||
				    st == IKEV2_RADIUS_VSA_MS_MPPE_SEND_KEY) {
					k = radius_decrypt_mppe(v + off + 2, sl - 2,
								req_auth, secret);
					if (!k)
						goto done;	/* fail closed */
					if (st == IKEV2_RADIUS_VSA_MS_MPPE_RECV_KEY) {
						if (recv) { rc_vfree(k); goto done; }
						recv = k;
					} else {
						if (send) { rc_vfree(k); goto done; }
						send = k;
					}
				}
				off += sl;
			}
		}
	}
	/* both keys are mandatory for a usable MSK */
	if (!recv || !send)
		goto done;

	memset(zero32, 0, sizeof(zero32));
	/* EAP-MSCHAPv2 master keys are 16 octets (RFC 3079 s3.3); truncate
	 * any longer attribute to the first 16, per RFC 2548 implementation
	 * note ("the RADIUS client is responsible for truncation"). */
	{
		size_t rl = recv->l < 16 ? recv->l : 16;
		size_t sl2 = send->l < 16 ? send->l : 16;
		msk = rc_vmalloc(64);
		if (!msk)
			goto done;
		memcpy((uint8_t *)msk->v, recv->v, rl);
		if (rl < 16)
			memset((uint8_t *)msk->v + rl, 0, 16 - rl);
		memcpy((uint8_t *)msk->v + 16, send->v, sl2);
		if (sl2 < 16)
			memset((uint8_t *)msk->v + 16 + sl2, 0, 16 - sl2);
		memcpy((uint8_t *)msk->v + 32, zero32, 32);
		msk->l = 64;
	}

      done:
	if (recv)
		rc_vfree(recv);
	if (send)
		rc_vfree(send);
	return msk;
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
	rc_vchar_t *req = NULL, *rbuf = NULL;
	uint8_t req_auth[IKEV2_RADIUS_AUTH_LEN];
	int got_bad = 0;

	*resp_out = NULL;
	if (!server || !eap || !opt || !opt->secret || opt->secret->l == 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RADIUS: missing server/eap/secret\n");
		return IKEV2_RADIUS_IOERR;
	}

	max = opt->retries ? opt->retries : 1;

	s = socket(server->sa_family, SOCK_DGRAM, 0);
	if (s < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RADIUS: socket: %s\n", strerror(errno));
		return IKEV2_RADIUS_IOERR;
	}
	/* bind the socket to the server so the kernel filters the source:
	 * a reply from anywhere else cannot be accepted. */
	if (connect(s, server, servlen) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "RADIUS: connect: %s\n", strerror(errno));
		close(s);
		return IKEV2_RADIUS_IOERR;
	}

	/* Build the request ONCE.  A retransmit resends the identical
	 * bytes (RFC 2865 s2.5) - same ID, same Request Authenticator. */
	req = ikev2_radius_build_request(*id, eap, opt);
	if (!req) {
		rv = IKEV2_RADIUS_IOERR;
		goto out;
	}
	memcpy(req_auth, (const uint8_t *)req->v + 4, IKEV2_RADIUS_AUTH_LEN);

	/*
	 * Per RFC 5080 s2.2.2, a responder must use the first datagram that
	 * carries a valid Response-Authenticator and discard every other
	 * datagram (bad code, bad id, bad MAC) as noise - never treat it as
	 * the final answer.  So for each transmit we wait out the FULL
	 * timeout window, draining the socket and keeping it readable until
	 * a valid reply arrives or the window expires.
	 */
	for (attempt = 0; attempt < max; attempt++) {
		struct timeval deadline, now, rem;
		int window_ms = opt->timeout_ms ? opt->timeout_ms : 1000;
		int first_send = 1;
		int bad_this_window = 0;

	      send_once:
		{
			ssize_t n;
			fd_set rfd;
			struct ikev2_radius_response *rr;

			if (first_send) {
				if (sendto(s, req->v, req->l, 0, NULL, 0) < 0) {
					plog(PLOG_INTERR, PLOGLOC, NULL,
					     "RADIUS: send: %s\n", strerror(errno));
					rv = IKEV2_RADIUS_IOERR;
					goto out;
				}
				first_send = 0;
				gettimeofday(&now, NULL);
				deadline.tv_sec = now.tv_sec + window_ms / 1000;
				deadline.tv_usec = now.tv_usec +
					(window_ms % 1000) * 1000;
				if (deadline.tv_usec >= 1000000) {
					deadline.tv_sec++;
					deadline.tv_usec -= 1000000;
				}
			}

			/* how much of the window is left? */
			gettimeofday(&now, NULL);
			rem.tv_sec = deadline.tv_sec - now.tv_sec;
			rem.tv_usec = deadline.tv_usec - now.tv_usec;
			if (rem.tv_usec < 0) {
				rem.tv_sec--;
				rem.tv_usec += 1000000;
			}
			if (rem.tv_sec < 0) {
				/* window expired: retransmit identical bytes */
				goto next_attempt;
			}

			FD_ZERO(&rfd);
			FD_SET(s, &rfd);
			if (select(s + 1, &rfd, NULL, NULL, &rem) <= 0)
				goto next_attempt;	/* EINTR/timeout */

			rbuf = rc_vmalloc(RADIUS_RECV_MAX);
			if (!rbuf) {
				rv = IKEV2_RADIUS_IOERR;
				goto out;
			}
			n = recvfrom(s, rbuf->v, RADIUS_RECV_MAX, 0, NULL, NULL);
			if (n < 0) {
				rc_vfree(rbuf);
				rbuf = NULL;
				goto send_once;	/* transient: keep waiting */
			}
			rbuf->l = n;

			if (((uint8_t *)rbuf->v)[0] == IKEV2_RADIUS_CODE_ACCESS_ACCEPT ||
			    ((uint8_t *)rbuf->v)[0] == IKEV2_RADIUS_CODE_ACCESS_REJECT ||
			    ((uint8_t *)rbuf->v)[0] == IKEV2_RADIUS_CODE_ACCESS_CHALLENGE) {
				rr = ikev2_radius_verify_response(*id, req_auth,
								 rbuf, opt->secret);
				if (rr) {
					*resp_out = rr;
					rv = IKEV2_RADIUS_OK;
					rc_vfree(rbuf);
					rbuf = NULL;
					goto out;
				}
			}
			/* discard the datagram, note we saw something, and keep
			 * waiting out the window for a VALID reply. */
			bad_this_window = 1;
			rc_vfree(rbuf);
			rbuf = NULL;
			goto send_once;
		}
	      next_attempt:
		if (bad_this_window)
			got_bad = 1;
		first_send = 1;	/* (per-attempt scope; resets each iteration) */
		(void)first_send;
	}
	rv = got_bad ? IKEV2_RADIUS_BADVERIFY : IKEV2_RADIUS_TIMEOUT;

      out:
	if (s >= 0)
		close(s);
	if (req) {
		rc_vfree(req);
		req = NULL;
	}
	if (rbuf) {
		rc_vfree(rbuf);
		rbuf = NULL;
	}
	if (rv == IKEV2_RADIUS_OK)
		*id = (uint8_t)(*id + 1);
	return rv;
}
