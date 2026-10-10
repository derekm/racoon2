/*
 * iked/eaptest.c - unit test for the EAP (RFC 3748) framing codec.
 *
 * Drives ikev2_eap_decode/encode against known-good wire bytes and
 * malformed inputs.  Emits "eaptest: PASS <n>/<n> <name>" per group and a
 * final line; returns 0 iff all pass.  Linked with ikev2_eap.c + the lib
 * symbol stubs the codec needs (racoon_calloc/rc_vmalloc/plog live in lib).
 *
 * Wire reference (RFC 3748 s4.1/s5.1):
 *   Identity Request, id=1: 01 01 00 05 01
 *   Identity Response "joe": 02 01 00 08 01 6a 6f 65   (type 1 + "joe")
 *   Success (id=3):          03 03 00 04
 *   Failure (id=4):          04 04 00 04
 *   Nak (id=2), suggested MD5-Challenge(4)+Generic Token Card(6):
 *                            02 02 00 07 03 04 06
 */
#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "racoon.h"
#include "vmbuf.h"
#include "ikev2_eap.h"

static int fails = 0;

/* decode + re-encode must reproduce the exact input bytes. */
static void
t_roundtrip(const char *name, const u_int8_t *wire, size_t len)
{
	rc_vchar_t raw, *enc;
	struct ikev2_eap_packet *p;
	raw.v = (u_int8_t *)(uintptr_t)wire;
	raw.l = len;

	p = ikev2_eap_decode(&raw);
	if (!p) {
		printf("eaptest: FAIL %s (decode returned NULL)\n", name);
		fails++;
		return;
	}
	enc = ikev2_eap_encode_packet(p);
	if (!enc) {
		printf("eaptest: FAIL %s (encode returned NULL)\n", name);
		ikev2_eap_packet_free(p);
		fails++;
		return;
	}
	if (enc->l != len || memcmp(enc->v, wire, len) != 0) {
		printf("eaptest: FAIL %s (round-trip mismatch)\n", name);
		fails++;
	} else {
		printf("eaptest: PASS %s round-trip (%zu bytes)\n", name, len);
	}
	rc_vfree(enc);
	ikev2_eap_packet_free(p);
}

int
main(void)
{
	/* the codec's plog() on malformed input needs the log buffer live */
	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;
	/* Identity Request, id=1 */
	{
		u_int8_t w[] = { 0x01, 0x01, 0x00, 0x05, 0x01 };
		t_roundtrip("identity-request", w, sizeof(w));
	}
	/* Identity Response "joe" */
	{
		u_int8_t w[] = { 0x02, 0x01, 0x00, 0x08, 0x01, 'j', 'o', 'e' };
		t_roundtrip("identity-response", w, sizeof(w));
	}
	/* Success (no type octet) */
	{
		u_int8_t w[] = { 0x03, 0x03, 0x00, 0x04 };
		t_roundtrip("success", w, sizeof(w));
	}
	/* Failure */
	{
		u_int8_t w[] = { 0x04, 0x04, 0x00, 0x04 };
		t_roundtrip("failure", w, sizeof(w));
	}
	/* Nak (type 3) with NAIS list */
	{
		u_int8_t w[] = { 0x02, 0x02, 0x00, 0x07, 0x03, 0x04, 0x06 };
		t_roundtrip("nak", w, sizeof(w));
	}

	/* codec builders: identity request must be exactly RFC bytes. */
	{
		rc_vchar_t *enc = ikev2_eap_build_identity_request(7);
		u_int8_t want[] = { 0x01, 0x07, 0x00, 0x05, 0x01 };
		if (!enc || enc->l != 5 || memcmp(enc->v, want, 5) != 0) {
			printf("eaptest: FAIL build_identity_request\n");
			fails++;
		} else {
			printf("eaptest: PASS build_identity_request (id=7)\n");
		}
		if (enc)
			rc_vfree(enc);
	}

	/* EAP-Success builder: Code=3, echoed id, Len=4, no Type octet. */
	{
		rc_vchar_t *enc = ikev2_eap_build_success(3);
		u_int8_t want[] = { 0x03, 0x03, 0x00, 0x04 };
		if (!enc || enc->l != 4 || memcmp(enc->v, want, 4) != 0) {
			printf("eaptest: FAIL build_success\n");
			fails++;
		} else {
			printf("eaptest: PASS build_success (id=3, len=4)\n");
		}
		if (enc)
			rc_vfree(enc);
	}

	/* identity extraction: "joe" from a Response/Identity, and the
	 * empty / non-identity / short-Length-borderline rejections. */
	{
		u_int8_t w[] = { 0x02, 0x05, 0x00, 0x08, 0x01, 'j', 'o', 'e' };
		rc_vchar_t raw; char *s;
		raw.v = w; raw.l = sizeof(w);
		s = ikev2_eap_identity_string(&raw);
		if (!s || strcmp(s, "joe") != 0) {
			printf("eaptest: FAIL identity_string(joe)\n");
			fails++;
		} else {
			printf("eaptest: PASS identity_string(joe)\n");
		}
		if (s) rc_free(s);
	}
	/* short Length inside a longer payload: honor bytes 2-3, ignore tail.
	 * Length=6 => one data byte "j"; the trailing 'o'/0xff are padding in
	 * the larger IKEv2 payload and must NOT leak into the identity. */
	{
		u_int8_t w[] = { 0x02, 0x05, 0x00, 0x06, 0x01, 'j', 'o', 0xff };
		rc_vchar_t raw; char *s;
		raw.v = w; raw.l = sizeof(w);
		s = ikev2_eap_identity_string(&raw);
		if (!s || strcmp(s, "j") != 0) {
			printf("eaptest: FAIL identity_string short-length\n");
			fails++;
		} else {
			printf("eaptest: PASS identity_string short-length\n");
		}
		if (s) rc_free(s);
	}
	/* empty identity: Len=5, no data */
	{
		u_int8_t w[] = { 0x02, 0x05, 0x00, 0x05, 0x01 };
		rc_vchar_t raw; char *s;
		raw.v = w; raw.l = sizeof(w);
		s = ikev2_eap_identity_string(&raw);
		if (s != NULL) {
			printf("eaptest: FAIL identity_string empty\n");
			if (s) rc_free(s);
			fails++;
		} else {
			printf("eaptest: PASS identity_string empty rejected\n");
		}
	}
	/* non-identity Response: Type=MSCHAPv2(26) -> NULL */
	{
		u_int8_t w[] = { 0x02, 0x07, 0x00, 0x06, 26, 0x01, 0x02 };
		rc_vchar_t raw; char *s;
		raw.v = w; raw.l = sizeof(w);
		s = ikev2_eap_identity_string(&raw);
		if (s != NULL) {
			printf("eaptest: FAIL identity_string non-identity\n");
			if (s) rc_free(s);
			fails++;
		} else {
			printf("eaptest: PASS identity_string non-identity rejected\n");
		}
	}

	/* Nak detection: a Response carrying type 3 must report type 3. */
	{
		u_int8_t w[] = { 0x02, 0x09, 0x00, 0x07, 0x03, 0x04, 0x06 };
		rc_vchar_t raw;
		raw.v = w; raw.l = sizeof(w);
		if (ikev2_eap_response_type(&raw) != 3) {
			printf("eaptest: FAIL response_type(nak)\n");
			fails++;
		} else {
			printf("eaptest: PASS response_type(nak)=3\n");
		}
	}

	/* malformed: short header, length overrun, truncated type. */
	{
		rc_vchar_t raw;
		raw.v = (u_int8_t *)"\x01\x01\x00"; raw.l = 3;	/* len<4 */
		if (ikev2_eap_decode(&raw) != NULL) {
			printf("eaptest: FAIL malformed-short accepted\n");
			fails++;
		} else {
			printf("eaptest: PASS malformed-short rejected\n");
		}
	}
	{
		u_int8_t w[] = { 0x01, 0x01, 0x01, 0x00, 0x01 }; /* len=0x0100>5 */
		rc_vchar_t raw;
		raw.v = w; raw.l = sizeof(w);
		if (ikev2_eap_decode(&raw) != NULL) {
			printf("eaptest: FAIL length-overrun accepted\n");
			fails++;
		} else {
			printf("eaptest: PASS length-overrun rejected\n");
		}
	}
	{
		u_int8_t w[] = { 0x02, 0x01, 0x00, 0x04 }; /* Request len=4: no type */
		rc_vchar_t raw;
		raw.v = w; raw.l = sizeof(w);
		if (ikev2_eap_decode(&raw) != NULL) {
			printf("eaptest: FAIL missing-type accepted\n");
			fails++;
		} else {
			printf("eaptest: PASS missing-type rejected\n");
		}
	}

	printf("eaptest: %s (%d failures)\n", fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
