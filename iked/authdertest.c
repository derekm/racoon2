/*
 * iked/authdertest.c - hermetic test of the EAP responder AUTH derivation.
 *
 * RFC 7296 s2.16 substitutes the EAP MSK for the shared secret of s2.15:
 * the responder's AUTH over SignedOctets is
 *
 *     AUTH = prf(prf(MSK, "Key Pad for IKEv2"), SignedOctets)
 *
 * which is exactly the pre-shared-key MAC in ikev2_auth.c (IKEV2_AUTH_
 * SHARED_KEY), with the MSK in place of the PSK.  This test computes that
 * value with the daemon's own one-shot HMAC primitive (eay_hmacsha2_256_one,
 * i.e. the negotiated prf in iked's hmac_sha2_256 case) and re-derives it
 * INDEPENDENTLY with raw OpenSSL HMAC(EVP_sha256,...), so a shared bug in
 * the wrapper cannot make it pass.
 *
 * It also checks the length/skew on short and empty SignedOctets, so a
 * future ikev2_auth.c EAP arm that feeds ikev2_auth_input() produces the
 * same bytes the relay/exchange already validated.
 *
 * Returns 0 iff all pass.
 */

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "crypto_impl.h"

#define KEYPAD "Key Pad for IKEv2"
#define KEYPADLEN (sizeof(KEYPAD) - 1)

static int fails;

/* daemon path: HMAC( HMAC(msk, keypad), octets ) via eay_hmacsha2_256_one */
static rc_vchar_t *
daemon_auth(const uint8_t *msk, size_t mskl,
	    const uint8_t *octets, size_t octetsl)
{
	rc_vchar_t km, kd, *k, *od, *auth;

	km.v = (void *)msk;   km.l = mskl;
	kd.v = (void *)KEYPAD; kd.l = KEYPADLEN;
	k = eay_hmacsha2_256_one(&km, &kd);
	if (!k)
		return NULL;

	od = rc_vmalloc(octetsl);
	if (!od) { rc_vfree(k); return NULL; }
	memcpy(od->v, octets, octetsl);
	od->l = octetsl;
	auth = eay_hmacsha2_256_one(k, od);
	rc_vfree(k);
	rc_vfree(od);
	return auth;
}

/* independent oracle: raw OpenSSL HMAC nested the same way */
static void
ref_auth(const uint8_t *msk, size_t mskl,
	 const uint8_t *octets, size_t octetsl,
	 uint8_t out[32])
{
	uint8_t k[32];
	unsigned klen = 0, olen = 0;
	HMAC(EVP_sha256(), msk, (int)mskl,
	     (const unsigned char *)KEYPAD, KEYPADLEN, k, &klen);
	if (klen != 32) abort();
	HMAC(EVP_sha256(), k, 32, octets, (int)octetsl, out, &olen);
	if (olen != 32) abort();
}

static void
check_one(const char *name, const uint8_t *msk, size_t mskl,
	  const uint8_t *octets, size_t octetsl)
{
	rc_vchar_t *got = daemon_auth(msk, mskl, octets, octetsl);
	uint8_t want[32];
	ref_auth(msk, mskl, octets, octetsl, want);

	if (!got || got->l != 32 || memcmp(got->v, want, 32) != 0) {
		printf("authdertest: FAIL %s\n", name);
		fails++;
	} else {
		printf("authdertest: PASS %s (HMAC(HMAC(MSK,keypad),octets) = 32B)\n",
		       name);
	}
	if (got)
		rc_vfree(got);
}

int
main(void)
{
	uint8_t msk_a[64], msk_b[16];
	uint8_t oct_empty[0];
	uint8_t oct_a[5] = { 0xde, 0xad, 0xbe, 0xef, 0x00 };
	int i;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;

	for (i = 0; i < 64; i++) msk_a[i] = (uint8_t)(0xa0 + (i & 0x0f));
	for (i = 0; i < 16; i++) msk_b[i] = (uint8_t)(0x50 + (i & 0x0f));

	/* the EAP-MSCHAPv2 MSK is 64 octets (Recv||Send||zeros) */
	check_one("64-byte MSK, 5-byte SignedOctets", msk_a, 64, oct_a, 5);
	check_one("16-byte MSK, 5-byte SignedOctets", msk_b, 16, oct_a, 5);
	check_one("64-byte MSK, empty SignedOctets", msk_a, 64, oct_empty, 0);
	check_one("64-byte MSK, single 0xff", msk_a, 64, (uint8_t[]){ 0xff }, 1);

	printf("authdertest: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
