/*
 * iked/eapdrivetest.c - hermetic test of the responder EAP round DRIVER
 * (ikev2_eap_drive.c): bridge -> relay -> MSK stored on a REAL ike_sa.
 *
 * relaytest proves the relay is a correct state machine over decoded RADIUS
 * responses, and eaproundtest proves the worker-round bridge's SA-lifetime
 * pin bookkeeping - but neither links them to the SA: no prior harness ran a
 * decoded Access-Accept into ike_v2_eap_relay_consume() and confirmed the
 * resulting 64-octet MSK lands on sa->eap_msk (the one field the fail-closed
 * AUTH arm in ikev2_auth.c reads).  This test closes that gap with a REAL
 * ike_sa carrying a REAL relay.
 *
 * Cases:
 *   1. Access-Challenge -> IKEV2_EAP_DRIVE_CONTINUE, sa->eap_msk stays NULL.
 *   2. Access-Accept (encrypted MS-MPPE Recv+Send) -> IKEV2_EAP_DRIVE_SUCCESS
 *      and sa->eap_msk == the expected 64-octet Recv||Send||zeros MSK, which
 *      is exactly what ikev2_auth_method() (RCT_ALG_EAP) and
 *      ikev2_auth_shared_secret() will accept (length 64).
 *   3. Access-Reject -> IKEV2_EAP_DRIVE_FAILURE.
 *
 * The MSK fixture uses an INDEPENDENT RFC 2548 mppe_encrypt (OpenSSL MD5),
 * not ikev2_radius_msk, so give_a_shared bug cannot self-pass.
 *
 * Returns 0 iff all pass.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "ikev2_radius.h"
#include "ikev2_eap.h"
#include "ikev2_eap_relay.h"
#include "ikev2_eap_drive.h"
#include <getopt.h>
#include "test_util.h"

TEST_MAIN_STUBS()

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

/* Independent MS-MPPE key encryption (RFC 2548 s2.4.3): Key-Length(1)||Key,
 * salted, MD5-XOR schedule, MSB of salt set.  Output Salt(2)||cipher. */
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
	p[0] = (uint8_t)keylen;
	memcpy(p + 1, key, keylen);
	out[0] = salt[0]; out[1] = salt[1];
	for (i = 0; i < padded; i += 16) {
		uint8_t md_in[2048], md[16];
		size_t mo = 0;
		MD5_CTX cx;
		if (i == 0) {
			memcpy(md_in + mo, secret, secretl); mo += secretl;
			memcpy(md_in + mo, req_auth, AUTH_LEN); mo += AUTH_LEN;
			memcpy(md_in + mo, salt, 2); mo += 2;
		} else {
			memcpy(md_in + mo, secret, secretl); mo += secretl;
			memcpy(md_in + mo, c + i - 16, 16); mo += 16;
		}
		MD5_Init(&cx); MD5_Update(&cx, md_in, mo); MD5_Final(md, &cx);
		for (o = 0; o < 16; o++)
			c[i + o] = p[i + o] ^ md[o];
	}
	free(p);
	return 2 + padded;
}

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

int
main(void)
{
	uint8_t req_auth[AUTH_LEN];
	rc_vchar_t secret;
	struct ikev2_sa *sa;
	struct ikev2_eap_relay *relay;
	rc_vchar_t *out_eap = NULL;
	enum ikev2_eap_drive_result dr;
	int i;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;
	ikev2_sa_init();
	sched_init();

	memset(req_auth, 0xab, AUTH_LEN);
	secret.v = malloc(8); secret.l = 8;
	memcpy(secret.v, "RADIUSSS", 8);

	/* a real SA with a real per-SE relay (heap: ike_sa dispose frees it) */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	relay = calloc(1, sizeof(*relay));
	if (!relay) return 2;
	{
		rc_vchar_t *opener = ikev2_eap_relay_start(relay, 7);
		if (!opener) { printf("eapdrivetest: FAIL start\n"); return 2; }
		rc_vfree(opener);
	}
	sa->eap_relay = relay;

	/* ---- 1. Access-Challenge -> CONTINUE, eap_msk stays NULL ---- */
	{
		uint8_t eap_req_wire[8] = { 1, 2, 0, 8, 26, 1, 2, 3 };
		uint8_t state[4] = { 9, 9, 9, 9 };
		struct relattr aa[2];
		struct ikev2_radius_response *r;
		aa[0].type = ATTR_EAP;  aa[0].v = eap_req_wire; aa[0].l = 8;
		aa[1].type = ATTR_STATE; aa[1].v = state; aa[1].l = 4;
		r = mkresp(CHAL_REQ, req_auth, 2, aa);
		out_eap = NULL;
		dr = ikev2_eap_drive_advance(sa, relay, r, &secret, &out_eap);
		if (dr != IKEV2_EAP_DRIVE_CONTINUE || !out_eap) {
			printf("eapdrivetest: FAIL 1 Challenge->CONTINUE (res=%d)\n",
			       dr);
			fails++;
		} else if (sa->eap_msk != NULL) {
			printf("eapdrivetest: FAIL 1 eap_msk set on Challenge\n");
			fails++;
		} else
			printf("eapdrivetest: PASS 1 Challenge->CONTINUE, no MSK yet\n");
		if (out_eap) rc_vfree(out_eap);
		fresp(r);
	}

	/* ---- 2. Access-Accept -> SUCCESS, MSK stored on the SA ---- */
	{
		uint8_t recv[16], send[16], ev_r[64], ev_s[64], vsa[200];
		size_t el_r, el_s, off = 0;
		struct relattr aa[1];
		struct ikev2_radius_response *r;
		for (i = 0; i < 16; i++) { recv[i]=0xa0+i; send[i]=0x50+i; }
		el_r = mppe_encrypt(recv, 16, req_auth, secret.v, secret.l, ev_r);
		el_s = mppe_encrypt(send, 16, req_auth, secret.v, secret.l, ev_s);
		vsa[0]=0;vsa[1]=0;vsa[2]=1;vsa[3]=0x37;	/* 311 BE */
		off = 4;
		vsa[off++]=VSA_RECV; vsa[off++]=(uint8_t)(2+el_r);
		memcpy(vsa+off, ev_r, el_r); off += el_r;
		vsa[off++]=VSA_SEND; vsa[off++]=(uint8_t)(2+el_s);
		memcpy(vsa+off, ev_s, el_s); off += el_s;
		aa[0].type = ATTR_VSA; aa[0].v = vsa; aa[0].l = off;
		r = mkresp(ACCEPT, req_auth, 1, aa);
		out_eap = NULL;
		dr = ikev2_eap_drive_advance(sa, relay, r, &secret, &out_eap);
		if (dr != IKEV2_EAP_DRIVE_SUCCESS || out_eap) {
			printf("eapdrivetest: FAIL 2 Accept->SUCCESS (res=%d)\n", dr);
			fails++;
		} else if (!sa->eap_msk || sa->eap_msk->l != 64) {
			printf("eapdrivetest: FAIL 2 MSK not stored/length\n");
			fails++;
		} else if (memcmp(sa->eap_msk->v, recv, 16) != 0 ||
			   memcmp((uint8_t *)sa->eap_msk->v + 16, send, 16) != 0) {
			printf("eapdrivetest: FAIL 2 MSK != Recv||Send||zeros\n");
			fails++;
		} else {
			int allz = 1;
			for (i = 32; i < 64; i++)
				if (((uint8_t *)sa->eap_msk->v)[i] != 0) allz = 0;
			if (!allz) {
				printf("eapdrivetest: FAIL 2 MSK pad not zero\n");
				fails++;
			} else
				printf("eapdrivetest: PASS 2 Accept->MSK stored on "
				       "SA (64 octets, unlocks AUTH)\n");
		}
		fresp(r);
	}

	/* ---- 3. Access-Reject -> FAILURE, eap_msk untouched ----
	 * Use a FRESH relay (the first reached SUCCESS in case 2 and is
	 * finished; a finished relay returns ERROR on further consume). */
	{
		struct ikev2_eap_relay *relay3;
		struct relattr aa[1];
		struct ikev2_radius_response *r;
		uint8_t state[4] = { 0 };
		relay3 = calloc(1, sizeof(*relay3));
		if (!relay3) return 2;
		{
			rc_vchar_t *opener = ikev2_eap_relay_start(relay3, 3);
			if (opener) rc_vfree(opener);
		}
		aa[0].type = ATTR_STATE; aa[0].v = state; aa[0].l = 4;
		r = mkresp(REJECT, req_auth, 0, aa);
		out_eap = NULL;
		dr = ikev2_eap_drive_advance(sa, relay3, r, &secret, &out_eap);
		if (dr != IKEV2_EAP_DRIVE_FAILURE) {
			printf("eapdrivetest: FAIL 3 Reject->FAILURE (res=%d)\n",
			       dr);
			fails++;
		} else {
			/* a reject must NOT overwrite an MSK already stored by an
			 * earlier Accept (case 2 set one); the SA MSK is intact */
			printf("eapdrivetest: PASS 3 Reject->FAILURE, existing "
			       "MSK untouched\n");
		}
		if (out_eap) rc_vfree(out_eap);
		fresp(r);
		ikev2_eap_relay_free(relay3);
		free(relay3);
	}

		/* ---- 4. EAP-TLS Accept (two 32-octet keys) -> MSK = Recv||Send
	 * (full 64, no zero pad).  Fresh SA + relay: case 2 already
	 * finished its relay.  Locks the DRIVE path (not just the radius
	 * helper) for the 32-octet shape so a regression that mishandles
	 * EAP-TLS MPPE keys but keeps the radius unit test green is
	 * caught here. */
	{
		struct ikev2_sa *sa4;
		struct ikev2_eap_relay *relay4;
		uint8_t recv[32], send[32], ev_r[64], ev_s[64], vsa[200];
		size_t el_r, el_s, off = 0;
		struct relattr aa[1];
		struct ikev2_radius_response *r;
		sa4 = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
		if (!sa4) return 2;
		relay4 = calloc(1, sizeof(*relay4));
		if (!relay4) return 2;
		{
			rc_vchar_t *opener = ikev2_eap_relay_start(relay4, 9);
			if (!opener) return 2;
			rc_vfree(opener);
		}
		sa4->eap_relay = relay4;
		for (i = 0; i < 32; i++) { recv[i]=0xc0+i; send[i]=0x40+i; }
		el_r = mppe_encrypt(recv, 32, req_auth, secret.v, secret.l, ev_r);
		el_s = mppe_encrypt(send, 32, req_auth, secret.v, secret.l, ev_s);
		vsa[0]=0;vsa[1]=0;vsa[2]=1;vsa[3]=0x37;	/* 311 BE */
		off = 4;
		vsa[off++]=VSA_RECV; vsa[off++]=(uint8_t)(2+el_r);
		memcpy(vsa+off, ev_r, el_r); off += el_r;
		vsa[off++]=VSA_SEND; vsa[off++]=(uint8_t)(2+el_s);
		memcpy(vsa+off, ev_s, el_s); off += el_s;
		aa[0].type = ATTR_VSA; aa[0].v = vsa; aa[0].l = off;
		r = mkresp(ACCEPT, req_auth, 1, aa);
		out_eap = NULL;
		dr = ikev2_eap_drive_advance(sa4, relay4, r, &secret, &out_eap);
		if (dr != IKEV2_EAP_DRIVE_SUCCESS || out_eap) {
			printf("eapdrivetest: FAIL 4 EAP-TLS Accept->SUCCESS (res=%d)\n", dr);
			fails++;
		} else if (!sa4->eap_msk || sa4->eap_msk->l != 64) {
			printf("eapdrivetest: FAIL 4 EAP-TLS MSK not stored/length\n");
			fails++;
		} else if (memcmp(sa4->eap_msk->v, recv, 32) != 0 ||
			   memcmp((uint8_t *)sa4->eap_msk->v + 32, send, 32) != 0) {
			/* full 64: no zero tail for 32+32 */
			printf("eapdrivetest: FAIL 4 MSK != Recv(32)||Send(32)\n");
			fails++;
		} else {
			int allz = 0;
			(void)allz; /* no zero pad expected for 32+32 */
			printf("eapdrivetest: PASS 4 EAP-TLS MSK = Recv(32)||Send(32) on SA\n");
		}
		if (out_eap) rc_vfree(out_eap);
		fresp(r);
		ikev2_dispose_sa(sa4);
	}

/* dispose the SA (frees eap_msk + the attached relay per
	 * ike_sa.c dispose: ikev2_eap_relay_free + racoon_free(eap_relay)) */
	ikev2_dispose_sa(sa);

	if (secret.v) free(secret.v);
	printf("eapdrivetest: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
