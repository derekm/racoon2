/*
 * iked/relaytest.c - hermetic unit test for the responder EAP relay
 * (ikev2_eap_relay.c).
 *
 * The relay is a pure state machine over decoded RADIUS responses, so this
 * test builds responses directly (no socket, no server) and drives the
 * full lifecycle that the IKE_AUTH wiring will perform:
 *
 *   1. start() emits an EAP Identity Request (RFC 3748 s5.1).
 *   2. An Access-Challenge carrying an EAP-PEAP-in-progress style Request
 *      (type 26, MSCHAPv2) is consumed: the relay returns CONTINUE with
 *      that EAP Request for the client, and remembers the State attr.
 *   3. An Access-Accept carrying independently encrypted MS-MPPE-Recv+Send
 *      keys is consumed: the relay returns SUCCESS with the 64-octet MSK
 *      (RFC 3079 s3.3), keyed off resp->req_auth.
 *   4. A challenge with no EAP-Message -> ERROR; an Access-Reject ->
 *      FAILURE; a consume after finish -> ERROR.
 *
 * The MSK fixture uses an INDEPENDENT RFC 2548 s2.4.3 encryptor (OpenSSL
 * MD5), not ikev2_radius_msk - a shared bug would pass anyway.
 *
 * Returns 0 iff all pass.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "ikev2_radius.h"
#include "ikev2_eap_relay.h"
#include "ikev2_eap.h"

#define AUTH_LEN	IKEV2_RADIUS_AUTH_LEN
#define CHAL_REQ	IKEV2_RADIUS_CODE_ACCESS_CHALLENGE
#define ACCEPT		IKEV2_RADIUS_CODE_ACCESS_ACCEPT
#define REJECT		IKEV2_RADIUS_CODE_ACCESS_REJECT
#define ATTR_EAP	IKEV2_RADIUS_ATTR_EAP_MESSAGE
#define ATTR_STATE	IKEV2_RADIUS_ATTR_STATE
#define ATTR_VSA	IKEV2_RADIUS_ATTR_VENDOR_SPECIFIC
#define VSA_MS		IKEV2_RADIUS_VSA_MICROSOFT
#define VSA_RECV	IKEV2_RADIUS_VSA_MS_MPPE_RECV_KEY
#define VSA_SEND	IKEV2_RADIUS_VSA_MS_MPPE_SEND_KEY

static int fails;

/* Independent MS-MPPE key encryption (RFC 2548 s2.4.3): plain Key-Length(1)
 * || Key, salted, MD5-XOR schedule, MSB of salt set. */
static size_t
mppe_encrypt(const uint8_t *key, size_t keylen, const uint8_t *req_auth,
	     const uint8_t *secret, size_t secretl, uint8_t out[64])
{
	uint8_t salt[2] = { 0x82, 0x11 };
	size_t plen = 1 + keylen;
	size_t padded = ((plen + 15) / 16) * 16;
	size_t i, o;
	uint8_t *p = malloc(padded), *c = out + 2;
	uint8_t b[16];

	if (!p) abort();
	memset(p, 0, padded);
	p[0] = (uint8_t)keylen;		/* Key-Length octet, then key */
	memcpy(p + 1, key, keylen);
	out[0] = salt[0]; out[1] = salt[1];

	for (i = 0; i < padded; i += 16) {
		uint8_t md_in[2048], md[16];
		size_t mo = 0;
		MD5_CTX cx;
		if (i == 0) {
			memcpy(md_in + mo, secret, secretl); mo += secretl;
			memcpy(md_in + mo, req_auth, AUTH_LEN);   mo += AUTH_LEN;
			memcpy(md_in + mo, salt, 2);              mo += 2;
		} else {
			memcpy(md_in + mo, secret, secretl); mo += secretl;
			memcpy(md_in + mo, c + i - 16, 16);       mo += 16;
		}
		MD5_Init(&cx); MD5_Update(&cx, md_in, mo); MD5_Final(md, &cx);
		for (o = 0; o < 16; o++)
			c[i + o] = p[i + o] ^ md[o];
	}
	free(p);
	return 2 + padded;	/* Salt(2) || ciphertext(padded) */
}

/* Build a decoded response with a list of (type, bytes) attributes. */
struct relattr { uint8_t type; const uint8_t *v; size_t l; };
static struct ikev2_radius_response *
mkresp(uint8_t code, const uint8_t *req_auth, unsigned n,
       const struct relattr *aa)
{
	struct ikev2_radius_response *r = calloc(1, sizeof(*r));
	unsigned i;
	if (!r) abort();
	r->code = code;
	r->identifier = 1;
	memcpy(r->req_auth, req_auth, AUTH_LEN);
	r->nattrs = n;
	r->attrs = calloc(n ? n : 1, sizeof(*r->attrs));
	if (!r->attrs) abort();
	for (i = 0; i < n; i++) {
		rc_vchar_t *w = rc_vmalloc(aa[i].l);
		if (!w) abort();
		memcpy(w->v, aa[i].v, aa[i].l);
		w->l = aa[i].l;
		r->attrs[i].type = aa[i].type;
		r->attrs[i].value = w;
	}
	return r;
}

static void
fresp(struct ikev2_radius_response *r)
{
	unsigned i;
	if (!r) return;
	for (i = 0; i < r->nattrs; i++)
		rc_vfree(r->attrs[i].value);
	free(r->attrs);
	free(r);
}

/* read wire EAP: byte0=code, byte1=identifier, byte4=type */
static int
eap_req(unsigned char *raw, size_t len, unsigned char *type, unsigned char *id)
{
	if (len < 5)
		return -1;
	if (type) *type = raw[4];
	if (id)   *id   = raw[1];
	return raw[0];
}

int
main(void)
{
	uint8_t req_auth[AUTH_LEN];
	rc_vchar_t secret;
	struct ikev2_eap_relay relay;
	rc_vchar_t *eap, *msk = NULL;
	enum ikev2_eap_relay_result res;
	int i;

	/* rbuf for plog (same requirement as the other iked tests). */
	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;

	memset(req_auth, 0xab, AUTH_LEN);
	secret.v = malloc(8); secret.l = 8;
	memcpy(secret.v, "RADIUSSS", 8);

	/* ---- 1. start() emits the Identity Request ---- */
	{
		unsigned char type = 0, id = 0;
		memset(&relay, 0, sizeof(relay));
		eap = ikev2_eap_relay_start(&relay, 7);
		if (!eap ||
		    eap_req((unsigned char *)eap->v, eap->l, &type, &id) != 1 ||
		    id != 7 || type != 1 /* IKEV2_EAP_TYPE_IDENTITY */) {
			printf("relaytest: FAIL 1 Identity Request opener\n");
			fails++;
		} else
			printf("relaytest: PASS 1 Identity Request opener (id=%u)\n", id);
		if (eap) rc_vfree(eap);
	}

	/* ---- 2. Access-Challenge -> CONTINUE with the EAP Request + State ---- */
	{
		/* wire EAP: Request(1), id=2, len=8, type=26, body 0123 */
		uint8_t eap_req_wire[8] = { 1, 2, 0, 8, 26, 1, 2, 3 };
		uint8_t state[4] = { 9, 9, 9, 9 };
		struct ikev2_radius_response *r;
		struct relattr aa[2];
		aa[0].type = ATTR_EAP;  aa[0].v = eap_req_wire; aa[0].l = 8;
		aa[1].type = ATTR_STATE; aa[1].v = state; aa[1].l = 4;
		r = mkresp(CHAL_REQ, req_auth, 2, aa);
		msk = NULL;
		res = ikev2_eap_relay_consume(&relay, r, &secret, &eap, &msk);
		if (res != IKEV2_EAP_RELAY_CONTINUE || !eap || msk) {
			printf("relaytest: FAIL 2 Challenge->continue\n");
			fails++;
		} else if (eap->l != 8 ||
			   memcmp(eap->v, eap_req_wire, 8) != 0) {
			printf("relaytest: FAIL 2 EAP Request not passed through\n");
			fails++;
		} else if (!relay.state || relay.state->l != 4) {
			printf("relaytest: FAIL 2 State not saved\n");
			fails++;
		} else
			printf("relaytest: PASS 2 Challenge->CONTINUE w/ EAP+State\n");
		if (eap) rc_vfree(eap);
		fresp(r);
	}

	/* ---- 3. Access-Accept -> SUCCESS with 64-octet MSK ---- */
	{
		uint8_t recv[16], send[16], ev_r[64], ev_s[64], vsa[200];
		size_t el_r, el_s, off = 0;
		struct ikev2_radius_response *r;
		struct relattr aa[1];
		for (i = 0; i < 16; i++) { recv[i]=0xa0+i; send[i]=0x50+i; }
		el_r = mppe_encrypt(recv, 16, req_auth, secret.v, secret.l, ev_r);
		el_s = mppe_encrypt(send, 16, req_auth, secret.v, secret.l, ev_s);
		vsa[0]=0;vsa[1]=0;vsa[2]=1;vsa[3]=0x37;		/* 311 BE */
		off = 4;
		vsa[off++]=VSA_RECV; vsa[off++]=(uint8_t)(2+el_r);
		memcpy(vsa+off, ev_r, el_r); off += el_r;
		vsa[off++]=VSA_SEND; vsa[off++]=(uint8_t)(2+el_s);
		memcpy(vsa+off, ev_s, el_s); off += el_s;
		aa[0].type = ATTR_VSA; aa[0].v = vsa; aa[0].l = off;
		r = mkresp(ACCEPT, req_auth, 1, aa);
		msk = NULL; eap = NULL;
		res = ikev2_eap_relay_consume(&relay, r, &secret, &eap, &msk);
		if (res != IKEV2_EAP_RELAY_SUCCESS || !msk || eap) {
			printf("relaytest: FAIL 3 Accept->MSK (res=%d, msk=%p)\n",
			       res, (void *)msk);
			fails++;
		} else if (msk->l != 64) {
			printf("relaytest: FAIL 3 MSK length %zu != 64\n", msk->l);
			fails++;
		} else if (memcmp(msk->v, recv, 16) != 0 ||
			   memcmp((uint8_t *)msk->v + 16, send, 16) != 0) {
			printf("relaytest: FAIL 3 MSK != Recv||Send||zeros\n");
			fails++;
		} else {
			int allz = 1;
			for (i = 32; i < 64; i++)
				if (((uint8_t *)msk->v)[i] != 0) allz = 0;
			if (!allz) {
				printf("relaytest: FAIL 3 MSK pad not zero\n");
				fails++;
			} else
				printf("relaytest: PASS 3 Accept->SUCCESS (64-octet MSK)\n");
		}
		if (msk) rc_vfree(msk);
		fresp(r);
	}

	/* ---- 4. consume after finish -> ERROR ---- */
	{
		uint8_t state[4] = { 0 };
		struct relattr aa[1];
		struct ikev2_radius_response *r;
		aa[0].type = ATTR_STATE; aa[0].v = state; aa[0].l = 4;
		r = mkresp(CHAL_REQ, req_auth, 1, aa);
		eap = NULL; msk = NULL;
		res = ikev2_eap_relay_consume(&relay, r, &secret, &eap, &msk);
		if (res != IKEV2_EAP_RELAY_ERROR || eap || msk) {
			printf("relaytest: FAIL 4 consume-after-finish\n");
			fails++;
		} else
			printf("relaytest: PASS 4 consume after SUCCESS -> ERROR\n");
		fresp(r);
	}

	/* ---- 5. Challenge without EAP-Message -> ERROR ---- */
	{
		struct ikev2_eap_relay r2;
		struct relattr aa[1];
		struct ikev2_radius_response *r;
		uint8_t state[4] = { 1, 2, 3, 4 };
		memset(&r2, 0, sizeof(r2));
		ikev2_eap_relay_start(&r2, 3);
		aa[0].type = ATTR_STATE; aa[0].v = state; aa[0].l = 4;
		r = mkresp(CHAL_REQ, req_auth, 1, aa);
		eap = NULL; msk = NULL;
		res = ikev2_eap_relay_consume(&r2, r, &secret, &eap, &msk);
		if (res != IKEV2_EAP_RELAY_ERROR || eap || msk) {
			printf("relaytest: FAIL 5 no-EAP Challenge\n");
			fails++;
		} else
			printf("relaytest: PASS 5 Challenge w/o EAP -> ERROR\n");
		ikev2_eap_relay_free(&r2);
		fresp(r);
	}

	/* ---- 6. Access-Reject -> FAILURE ---- */
	{
		struct ikev2_eap_relay r3;
		struct ikev2_radius_response *r;
		struct relattr aa[0];
		memset(&r3, 0, sizeof(r3));
		ikev2_eap_relay_start(&r3, 4);
		r = mkresp(REJECT, req_auth, 0, aa);
		eap = NULL; msk = NULL;
		res = ikev2_eap_relay_consume(&r3, r, &secret, &eap, &msk);
		if (res != IKEV2_EAP_RELAY_FAILURE || eap || msk) {
			printf("relaytest: FAIL 6 Reject\n");
			fails++;
		} else
			printf("relaytest: PASS 6 Access-Reject -> FAILURE\n");
		ikev2_eap_relay_free(&r3);
		fresp(r);
	}

	ikev2_eap_relay_free(&relay);
	free(secret.v);

	printf("relaytest: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
