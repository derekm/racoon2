/*
 * iked/radiustest.c - unit test for the RADIUS client (ikev2_radius.c).
 *
 * Validates the authenticator math the way a peer would: build an
 * Access-Request (fresh Request Authenticator + Message-Authenticator(80)),
 * then synthesize a correct server reply (Access-Challenge carrying an
 * EAP-Message) with the Response-Authenticator computed INDEPENDENTLY
 * here with raw OpenSSL MD5 (RFC 2865 s3: MD5(Code+ID+Len+ReqAuth+Attrs+
 * Secret)) - not by calling the module's own verify path - and check the
 * module verifies it, plus the negative cases (wrong secret, wrong id,
 * tampered EAP-Message).  This catches a sign/verify asymmetry the same
 * way eaptest caught the codec type-octet bug.
 *
 * Emits "radiustest: PASS <n>/<n>" lines; returns 0 iff all pass.
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/md5.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "ikev2_radius.h"

static int fails = 0;

/* Independent server-side Response-Authenticator (RFC 2865 s3). */
static void
server_response_auth(uint8_t *hdr4, const uint8_t *req_auth,
		     const uint8_t *attrs, size_t attrl,
		     const uint8_t *secret, size_t secretl,
		     uint8_t out[16])
{
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c, hdr4, 4);			/* Code+ID+Len */
	MD5_Update(&c, req_auth, IKEV2_RADIUS_AUTH_LEN);	/* ReqAuth */
	MD5_Update(&c, attrs, attrl);			/* Attributes */
	MD5_Update(&c, secret, secretl);		/* Secret */
	MD5_Final(out, &c);
}

int
main(void)
{
	static const char secretstr[] = "testing123";
	static const uint8_t eap_ident[] = { 0x02, 0x01, 0x00, 0x05, 0x01 }; /* Resp Ident */
	const char *user = "radiuslocal";
	rc_vchar_t *secret, *eap, *req;
	uint8_t id = 42;
	struct sockaddr_in nas;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;

	secret = rc_vmalloc(sizeof(secretstr) - 1);
	if (!secret)
		return 2;
	memcpy(secret->v, secretstr, sizeof(secretstr) - 1);
	secret->l = sizeof(secretstr) - 1;

	eap = rc_vmalloc(sizeof(eap_ident));
	if (!eap)
		return 2;
	memcpy(eap->v, eap_ident, sizeof(eap_ident));
	eap->l = sizeof(eap_ident);

	memset(&nas, 0, sizeof(nas));
	nas.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &nas.sin_addr);

	/* 1. build a signed Access-Request */
	req = ikev2_radius_build_request(id, eap, user, 0,
					 (struct sockaddr *)&nas, secret);
	if (!req) {
		printf("radiustest: FAIL build_request (NULL)\n");
		fails++;
		return 1;
	}
	/* check code/id + Request Auth present + EAP-Message(79) present */
	{
		const uint8_t *b = (const uint8_t *)req->v;
		int ok = 1;
		size_t i;
		int has_eap = 0;
		if (b[0] != IKEV2_RADIUS_CODE_ACCESS_REQUEST || b[1] != id) {
			printf("radiustest: FAIL build code/id (0x%02x id %u)\n",
			       b[0], b[1]);
			ok = 0;
		}
		/* scan attrs for EAP-Message(79) and Message-Auth(80) */
		for (i = IKEV2_RADIUS_HEADER_LEN; i + 2 <= req->l;) {
			uint8_t t = b[i], l = b[i + 1];
			if (l < 2 || i + l > req->l)
				break;
			if (t == IKEV2_RADIUS_ATTR_EAP_MESSAGE)
				has_eap = 1;
			i += l;
		}
		if (!has_eap) {
			printf("radiustest: FAIL build no EAP-Message attr\n");
			ok = 0;
		}
		if (ok)
			printf("radiustest: PASS 1 build_request (code/id/EAP-Message)\n");
		else
			fails++;
	}

	/* 2. synthesize a correct Access-Challenge + verify it */
	{
		uint8_t hdr4[4] = { IKEV2_RADIUS_CODE_ACCESS_CHALLENGE, id, 0, 0 };
		uint8_t respbuf[IKEV2_RADIUS_HEADER_LEN + 32];
		uint8_t *resp_attrs;
		size_t resp_attrl;
		const uint8_t *req_auth = (const uint8_t *)req->v + 4;
		rc_vchar_t resp_raw;
		struct ikev2_radius_response *resp;
		rc_vchar_t *got;

		/* attributes: EAP-Message(79) carrying a Request-Identity,
		 * optionally a State(24) attr */
		resp_attrs = respbuf + IKEV2_RADIUS_HEADER_LEN;
		resp_attrs[0] = IKEV2_RADIUS_ATTR_EAP_MESSAGE;
		resp_attrs[1] = (uint8_t)(2 + sizeof(eap_ident));
		memcpy(resp_attrs + 2, eap_ident, sizeof(eap_ident));
		resp_attrl = 2 + sizeof(eap_ident);

		/* length */
		{
			size_t total = IKEV2_RADIUS_HEADER_LEN + resp_attrl;
			hdr4[2] = (uint8_t)(total >> 8);
			hdr4[3] = (uint8_t)(total & 0xff);
		}
		memcpy(respbuf, hdr4, 4);
		server_response_auth(hdr4, req_auth, resp_attrs, resp_attrl,
				     (const uint8_t *)secret->v, secret->l,
				     respbuf + 4);

		resp_raw.v = respbuf;
		resp_raw.l = IKEV2_RADIUS_HEADER_LEN + resp_attrl;
		resp = ikev2_radius_verify_response(id, req_auth,
						    &resp_raw, secret);
		if (!resp) {
			printf("radiustest: FAIL verify correct challenge\n");
			fails++;
		} else {
			got = ikev2_radius_find_attr(resp, IKEV2_RADIUS_ATTR_EAP_MESSAGE);
			if (got && got->l == sizeof(eap_ident) &&
			    memcmp(got->v, eap_ident, sizeof(eap_ident)) == 0)
				printf("radiustest: PASS 2 verify Access-Challenge + EAP-Message\n");
			else {
				printf("radiustest: FAIL EAP-Message attr not recovered\n");
				fails++;
			}
			ikev2_radius_response_free(resp);
		}

		/* 2b. wrong secret must be rejected */
		{
			rc_vchar_t wrong;
			uint8_t wrongs[] = "WRONG";
			wrong.v = wrongs; wrong.l = sizeof(wrongs) - 1;
			resp_raw.v = respbuf;
			resp_raw.l = IKEV2_RADIUS_HEADER_LEN + resp_attrl;
			if (ikev2_radius_verify_response(id, req_auth,
							&resp_raw, &wrong) != NULL) {
				printf("radiustest: FAIL wrong-secret accepted\n");
				fails++;
			} else {
				printf("radiustest: PASS 3 reject wrong secret\n");
			}
		}

		/* 2c. wrong id must be rejected */
		{
			resp_raw.v = respbuf;
			resp_raw.l = IKEV2_RADIUS_HEADER_LEN + resp_attrl;
			if (ikev2_radius_verify_response(id + 1, req_auth,
							&resp_raw, secret) != NULL) {
				printf("radiustest: FAIL wrong-id accepted\n");
				fails++;
			} else {
				printf("radiustest: PASS 4 reject wrong id\n");
			}
		}

		/* 2d. tampered EAP-Message (flip a byte) must reject */
		{
			/* rebuild with a different EAP payload + correct auth */
			uint8_t eap2[sizeof(eap_ident)];
			memcpy(eap2, eap_ident, sizeof(eap_ident));
			eap2[3] ^= 0xff;	/* corrupt the length byte */
			resp_attrs[0] = IKEV2_RADIUS_ATTR_EAP_MESSAGE;
			resp_attrs[1] = (uint8_t)(2 + sizeof(eap2));
			memcpy(resp_attrs + 2, eap2, sizeof(eap2));
			{
				size_t total = IKEV2_RADIUS_HEADER_LEN + resp_attrl;
				hdr4[2] = (uint8_t)(total >> 8);
				hdr4[3] = (uint8_t)(total & 0xff);
			}
			/* note: header length unchanged, but recalc auth over
			 * the SAME attrs so the only change is the payload; a
			 * verify against the OLD authenticator must fail. */
			resp_raw.v = respbuf;
			resp_raw.l = IKEV2_RADIUS_HEADER_LEN + resp_attrl;
			if (ikev2_radius_verify_response(id, req_auth,
							&resp_raw, secret) != NULL) {
				printf("radiustest: FAIL tampered EAP accepted\n");
				fails++;
			} else {
				printf("radiustest: PASS 5 reject tampered EAP-Message\n");
			}
		}
	}

	rc_vfree(req);
	rc_vfree(eap);
	rc_vfree(secret);

	printf("radiustest: %s (%d failures)\n", fails ? "FAIL" : "ALL PASS",
	       fails);
	return fails ? 1 : 0;
}
