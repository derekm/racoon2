/*
 * iked/radiustest.c - unit test for the RADIUS client (ikev2_radius.c).
 *
 * Validates the authenticator math the way a peer would.  Every server
 * reply is synthesized HERE with raw OpenSSL MD5/HMAC - not by calling
 * the module's own sign/verify - so a sign/verify asymmetry fails.
 *
 * Checks:
 *   1. Access-Request build (code/id/EAP/NAS/MA present) and that the
 *      request's attr-80 INDEPENDENTLY matches HMAC-MD5(secret, req with
 *      MA value zeroed).
 *   2. A correct Access-Challenge (valid MA) verifies; EAP-Message is
 *      recovered.
 *   3. wrong secret -> reject.   4. wrong id -> reject.
 *   5. tampered EAP-Message -> reject.
 *   6. missing Message-Authenticator -> reject (RFC 3579 requires it).
 *   7. tampered Message-Authenticator -> reject (Blast-RADIUS against->
 *      does not pass an attacker-forged reply).
 *   8. State attribute is echoed in the next request.
 *   9. >253-octet EAP-Message fragments (RFC 3579 s2.2) and reassembles.
 *
 * Returns 0 iff all pass.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/md5.h>
#include <openssl/hmac.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "ikev2_radius.h"

static int fails = 0;

/* Independent Response-Authenticator (RFC 2865 s3). */
static void
resp_auth(uint8_t *hdr4, const uint8_t *req_auth,
	  const uint8_t *attrs, size_t attrl,
	  const uint8_t *secret, size_t secretl, uint8_t out[16])
{
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c, hdr4, 4);
	MD5_Update(&c, req_auth, IKEV2_RADIUS_AUTH_LEN);
	MD5_Update(&c, attrs, attrl);
	MD5_Update(&c, secret, secretl);
	MD5_Final(out, &c);
}

/* Independent Message-Authenticator for a response (RFC 3579 s3.5):
 * HMAC-MD5(secret, pkt with Authenticator <- req_auth and MA zeroed). */
static void
msg_auth(uint8_t *pkt, size_t len, const uint8_t *req_auth,
	 const uint8_t *secret, size_t secretl, size_t ma_val_off,
	 uint8_t out[16])
{
	uint8_t *work = malloc(len);
	unsigned ou = 0;
	if (!work)
		abort();
	memcpy(work, pkt, len);
	memcpy(work + 4, req_auth, IKEV2_RADIUS_AUTH_LEN);
	memset(work + ma_val_off, 0, IKEV2_RADIUS_AUTH_LEN);
	HMAC(EVP_md5(), secret, (int)secretl, work, len, out, &ou);
	free(work);
	if (ou != 16)
		abort();
}

/*
 * Build a valid Access-Challenge carrying the given attributes (type/len/
 * val triples; len is the full attribute length incl. type+len), plus a
 * correctly-signed Message-Authenticator and Response-Authenticator (both
 * computed independently).  Writes at most `cap` bytes; returns length.
 */
static size_t
build_challenge(uint8_t id, const uint8_t *req_auth,
		const uint8_t (*ta_type)[1], const uint8_t *ta_len,
		const uint8_t **ta_val, int nta,
		const uint8_t *secret, size_t secretl,
		uint8_t *out, size_t cap)
{
	uint8_t attrbuf[1024];
	size_t attrsl = 0, total, ma_val_off;
	int i;
	uint8_t hdr4[4], ra[16];

	/* attributes */
	for (i = 0; i < nta; i++) {
		attrbuf[attrsl] = ta_type[i][0];
		attrbuf[attrsl + 1] = ta_len[i];
		memcpy(attrbuf + attrsl + 2, ta_val[i], ta_len[i] - 2);
		attrsl += ta_len[i];
	}
	/* Message-Authenticator attr (80, len 18, value zeroed first) */
	ma_val_off = attrsl + 2;
	attrbuf[attrsl] = IKEV2_RADIUS_ATTR_MESSAGE_AUTH;
	attrbuf[attrsl + 1] = 2 + IKEV2_RADIUS_AUTH_LEN;
	memset(attrbuf + attrsl + 2, 0, IKEV2_RADIUS_AUTH_LEN);
	attrsl += 2 + IKEV2_RADIUS_AUTH_LEN;

	total = IKEV2_RADIUS_HEADER_LEN + attrsl;
	if (total > cap)
		abort();
	out[0] = IKEV2_RADIUS_CODE_ACCESS_CHALLENGE;
	out[1] = id;
	out[2] = (uint8_t)(total >> 8);
	out[3] = (uint8_t)(total & 0xff);
	memset(out + 4, 0, IKEV2_RADIUS_AUTH_LEN);	/* fill later */
	memcpy(out + IKEV2_RADIUS_HEADER_LEN, attrbuf, attrsl);

	/* MA is computed over packet with Auth<-req_auth and MA=0:
	 * do it in a scratch copy, then store the result into attrbuf so
	 * the final attributes (used for ResponseAuth) carry the real MA. */
	{
		uint8_t *scratch = malloc(total);
		uint8_t ma[16];
		if (!scratch)
			abort();
		memcpy(scratch, out, total);
		memcpy(scratch, out, 4);
		msg_auth(scratch, total, req_auth, secret, secretl,
			 IKEV2_RADIUS_HEADER_LEN + ma_val_off, ma);
		/* patch attrbuf + the output packet with the real MA */
		memcpy(attrbuf + ma_val_off, ma, IKEV2_RADIUS_AUTH_LEN);
		memcpy(out + IKEV2_RADIUS_HEADER_LEN + ma_val_off, ma,
		       IKEV2_RADIUS_AUTH_LEN);
		free(scratch);
	}

	/* ResponseAuth = MD5(code+id+len + req_auth + attrs(now w/real MA) + secret) */
	hdr4[0] = out[0]; hdr4[1] = out[1]; hdr4[2] = out[2]; hdr4[3] = out[3];
	resp_auth(hdr4, req_auth, attrbuf, attrsl, secret, secretl, ra);
	memcpy(out + 4, ra, IKEV2_RADIUS_AUTH_LEN);
	return total;
}

int
main(void)
{
	static const char secretstr[] = "testing123";
	static const uint8_t eap_ident[] = { 0x02, 0x01, 0x00, 0x05, 0x01 };
	rc_vchar_t *secret, *eap, *req;
	uint8_t id = 42;
	struct sockaddr_in nas;
	struct ikev2_radius_opt opt;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;

	memset(&opt, 0, sizeof(opt));
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

	/* ---- 1. build + independent request-MA oracle ---- */
	opt.secret = secret;
	opt.user_name = "radiuslocal";
	opt.nas_ip = "192.168.0.165";
	req = ikev2_radius_build_request(id, eap, &opt, (struct sockaddr *)&nas);
	if (!req) {
		printf("radiustest: FAIL build_request (NULL)\n");
		fails++;
		return 1;
	}
	{
		const uint8_t *b = (const uint8_t *)req->v;
		int ok = 1, has_eap = 0, has_ma = 0, has_nas = 0;
		size_t i, ma_off = 0;
		uint8_t oracle[16];
		for (i = IKEV2_RADIUS_HEADER_LEN; i + 2 <= req->l;) {
			uint8_t t = b[i], l = b[i + 1];
			if (l < 2 || i + l > req->l)
				break;
			if (t == IKEV2_RADIUS_ATTR_EAP_MESSAGE)
				has_eap = 1;
			if (t == IKEV2_RADIUS_ATTR_NAS_IP_ADDRESS)
				has_nas = (l == 6);
			if (t == IKEV2_RADIUS_ATTR_MESSAGE_AUTH) {
				has_ma = 1;
				ma_off = i + 2;
			}
			i += l;
		}
		if (b[0] != IKEV2_RADIUS_CODE_ACCESS_REQUEST || b[1] != id ||
		    !has_eap || !has_ma || !has_nas) {
			printf("radiustest: FAIL build code/id/EAP/MA/NAS\n");
			ok = 0;
		}
		if (ok) {
			uint8_t *work = malloc(req->l);
			unsigned ou = 0;
			memcpy(work, b, req->l);
			memset(work + ma_off, 0, IKEV2_RADIUS_AUTH_LEN);
			HMAC(EVP_md5(), secret->v, secret->l, work, req->l,
			     oracle, &ou);
			free(work);
			if (ou != 16 ||
			    CRYPTO_memcmp(oracle, b + ma_off,
					  IKEV2_RADIUS_AUTH_LEN) != 0) {
				printf("radiustest: FAIL request MA mismatch\n");
				ok = 0;
			}
		}
		if (ok)
			printf("radiustest: PASS 1 build + request-MA oracle\n");
		else
			fails++;
	}

	/* ---- 2..7 response verification ---- */
	{
		uint8_t respbuf[2048];
		size_t rlen;
		const uint8_t *req_auth = (const uint8_t *)req->v + 4;
		const uint8_t *eapval = eap_ident;
		uint8_t eaplen = (uint8_t)(2 + sizeof(eap_ident));
		rc_vchar_t resp_raw;
		struct ikev2_radius_response *resp;
		rc_vchar_t *got;

		rlen = build_challenge(id, req_auth, (const uint8_t (*)[1])&(uint8_t[]){IKEV2_RADIUS_ATTR_EAP_MESSAGE}, &eaplen, &eapval, 1, secret->v, secret->l, respbuf, sizeof(respbuf));

		/* 2. verifies + EAP recovered */
		resp_raw.v = respbuf; resp_raw.l = rlen;
		resp = ikev2_radius_verify_response(id, req_auth, &resp_raw, secret);
		if (!resp) {
			printf("radiustest: FAIL verify correct challenge\n");
			fails++;
		} else {
			got = ikev2_radius_eap_message(resp);
			if (got && got->l == sizeof(eap_ident) &&
			    memcmp(got->v, eap_ident, sizeof(eap_ident)) == 0)
				printf("radiustest: PASS 2 verify challenge + EAP-Message\n");
			else {
				printf("radiustest: FAIL EAP-Message not recovered\n");
				fails++;
			}
			if (got)
				rc_vfree(got);
			ikev2_radius_response_free(resp);
		}

		/* 3. wrong secret */
		{
			rc_vchar_t wrong;
			uint8_t wrongs[] = "WRONG";
			wrong.v = wrongs; wrong.l = sizeof(wrongs) - 1;
			resp_raw.v = respbuf; resp_raw.l = rlen;
			if (ikev2_radius_verify_response(id, req_auth,
							&resp_raw, &wrong) != NULL) {
				printf("radiustest: FAIL wrong-secret accepted\n");
				fails++;
			} else
				printf("radiustest: PASS 3 reject wrong secret\n");
		}

		/* 4. wrong id */
		{
			resp_raw.v = respbuf; resp_raw.l = rlen;
			if (ikev2_radius_verify_response(id + 1, req_auth,
							&resp_raw, secret) != NULL) {
				printf("radiustest: FAIL wrong-id accepted\n");
				fails++;
			} else
				printf("radiustest: PASS 4 reject wrong id\n");
		}

		/* 5. tampered EAP payload (corrupt one EAP byte, keep the
		 * ORIGINAL authenticators -> must fail) */
		{
			uint8_t respbuf2[2048];
			memcpy(respbuf2, respbuf, sizeof(respbuf2));
			respbuf2[IKEV2_RADIUS_HEADER_LEN + 2 + 1] ^= 0xff;
			resp_raw.v = respbuf2; resp_raw.l = rlen;
			if (ikev2_radius_verify_response(id, req_auth,
							&resp_raw, secret) != NULL) {
				printf("radiustest: FAIL tampered EAP accepted\n");
				fails++;
			} else
				printf("radiustest: PASS 5 reject tampered EAP-Message\n");
		}

		/* 6. missing MA -> reject (RFC 3579).  Rebuild the attr set
		 * WITHOUT the MA; sign only the Response-Authenticator (which
		 * alone is insufficient vs. MA requirement). */
		{
			uint8_t attrbuf[1024];
			size_t attrsl = 0, total;
			uint8_t hdr4[4], ra[16];
			attrsl = 0;
			attrbuf[attrsl] = IKEV2_RADIUS_ATTR_EAP_MESSAGE;
			attrbuf[attrsl + 1] = eaplen;
			memcpy(attrbuf + attrsl + 2, eapval, sizeof(eap_ident));
			attrsl += eaplen;
			total = IKEV2_RADIUS_HEADER_LEN + attrsl;
			respbuf[0] = IKEV2_RADIUS_CODE_ACCESS_CHALLENGE;
			respbuf[1] = id;
			respbuf[2] = (uint8_t)(total >> 8);
			respbuf[3] = (uint8_t)(total & 0xff);
			memset(respbuf + 4, 0, 16);
			memcpy(respbuf + IKEV2_RADIUS_HEADER_LEN, attrbuf, attrsl);
			hdr4[0]=respbuf[0];hdr4[1]=respbuf[1];hdr4[2]=respbuf[2];hdr4[3]=respbuf[3];
			resp_auth(hdr4, req_auth, attrbuf, attrsl,
				  secret->v, secret->l, ra);
			memcpy(respbuf + 4, ra, 16);
			resp_raw.v = respbuf; resp_raw.l = total;
			if (ikev2_radius_verify_response(id, req_auth,
							&resp_raw, secret) != NULL) {
				printf("radiustest: FAIL missing-MA accepted\n");
				fails++;
			} else
				printf("radiustest: PASS 6 reject missing MA\n");
		}

		/* 7. tampered MA -> reject: build a correct challenge, then
		 * flip one byte in the MA value (the ResponseAuth still
		 * covers the attrs, so only the MA check can catch it). */
		{
			/* rebuild the 2-pass signed packet */
			rlen = build_challenge(id, req_auth, (const uint8_t (*)[1])&(uint8_t[]){IKEV2_RADIUS_ATTR_EAP_MESSAGE}, &eaplen, &eapval, 1, secret->v, secret->l, respbuf, sizeof(respbuf));
			respbuf[rlen - 1] ^= 0xff;	/* last MA byte */
			resp_raw.v = respbuf; resp_raw.l = rlen;
			if (ikev2_radius_verify_response(id, req_auth,
							&resp_raw, secret) != NULL) {
				printf("radiustest: FAIL tampered-MA accepted\n");
				fails++;
			} else
				printf("radiustest: PASS 7 reject tampered MA\n");
		}
	}

	/* ---- 8. State echo ---- */
	{
		uint8_t st[5] = { 1, 2, 3, 4, 5 };
		rc_vchar_t stv;
		const uint8_t *b;
		rc_vchar_t *req2;
		size_t i;
		int has_state = 0;
		stv.v = st; stv.l = sizeof(st);
		opt.state = &stv;
		req2 = ikev2_radius_build_request(id, eap, &opt,
						 (struct sockaddr *)&nas);
		if (!req2) {
			printf("radiustest: FAIL State build (NULL)\n");
			fails++;
		} else {
			b = (const uint8_t *)req2->v;
			for (i = IKEV2_RADIUS_HEADER_LEN; i + 2 <= req2->l;) {
				uint8_t t = b[i], l = b[i + 1];
				if (l < 2 || i + l > req2->l)
					break;
				if (t == IKEV2_RADIUS_ATTR_STATE &&
				    l == 2 + (uint8_t)sizeof(st) &&
				    memcmp(b + i + 2, st, sizeof(st)) == 0)
					has_state = 1;
				i += l;
			}
			if (!has_state) {
				printf("radiustest: FAIL State not echoed\n");
				fails++;
			} else
				printf("radiustest: PASS 8 State echoed\n");
			rc_vfree(req2);
		}
		opt.state = NULL;
	}

	/* ---- 9. EAP-Message fragmentation + reassembly ---- */
	{
		uint8_t big[400];
		const uint8_t *req_auth = (const uint8_t *)req->v + 4;
		uint8_t respbuf[2048];
		size_t rlen;
		const uint8_t *vals[3];
		uint8_t lens[3];
		rc_vchar_t resp_raw, *got;
		struct ikev2_radius_response *resp;
		size_t i;
		for (i = 0; i < sizeof(big); i++)
			big[i] = (uint8_t)(0x80 + (i & 0x3f));
		/* two 253-byte fragments + remainder (RFC 3579 splits at
		 * 253; our EAP splits into 253+147) */
		vals[0] = big;
		lens[0] = 255;				/* 2 + 253 */
		vals[1] = big + 253;
		lens[1] = 2 + (sizeof(big) - 253);	/* 2 + 147 */
		(void)vals[2]; (void)lens[2];

		/* build with 2 EAP-Message attrs + a trailing Class */
		/* reuse build_challenge but it takes a generic array; pass
		 * the two EAP fragments + one Class attr for good measure */
		{
			const uint8_t *valsb[3];
			uint8_t lensb[3];
			valsb[0] = big;
			lensb[0] = 255;
			valsb[1] = big + 253;
			lensb[1] = 2 + (sizeof(big) - 253);
			valsb[2] = (const uint8_t *)"ABCDE";
			lensb[2] = 7;
			rlen = build_challenge(id, req_auth,
				(const uint8_t (*)[1])&(uint8_t[]){IKEV2_RADIUS_ATTR_EAP_MESSAGE,IKEV2_RADIUS_ATTR_EAP_MESSAGE,IKEV2_RADIUS_ATTR_CLASS},
				lensb, valsb, 3, secret->v, secret->l,
				respbuf, sizeof(respbuf));
		}
		resp_raw.v = respbuf; resp_raw.l = rlen;
		resp = ikev2_radius_verify_response(id, req_auth,
						    &resp_raw, secret);
		if (!resp) {
			printf("radiustest: FAIL fragmented challenge verify\n");
			fails++;
		} else {
			got = ikev2_radius_eap_message(resp);
			if (!got || got->l != sizeof(big) ||
			    memcmp(got->v, big, sizeof(big)) != 0) {
				printf("radiustest: FAIL EAP fragmentation reassembly\n");
				fails++;
			} else
				printf("radiustest: PASS 9 EAP fragmentation reassembly\n");
			if (got)
				rc_vfree(got);
			ikev2_radius_response_free(resp);
		}
	}

	rc_vfree(req);
	rc_vfree(eap);
	rc_vfree(secret);

	printf("radiustest: %s (%d failures)\n", fails ? "FAIL" : "ALL PASS",
	       fails);
	return fails ? 1 : 0;
}
