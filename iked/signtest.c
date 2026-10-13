/*
 * signtest.c — RFC 7427 signer-completeness round-trip KAT (Item C).
 *
 * Verifies the ALGORITHMS this iked can now SIGN on AUTH method 14, for RSA:
 *   RSASSA-PKCS1-v1_5 with SHA-256/384/512
 *   RSASSA-PSS (salt = hash length) with SHA-256/384/512
 * by signing with the production eay_rsassa_*_sign() helpers and verifying
 * the same octets with eay_rfc7427_verify() / eay_rsassa_pkcs1_v1_5_verify().
 * Regenerates a fresh RSA-2048 key per run (no committed key).
 *
 * Links via addtest_ikedsrc like splitcfgtest; run under make check.
 */
#include <config.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <getopt.h>
#include "isakmp.h"
#include "ikev2.h"
#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "crypto_impl.h"
#include "test_util.h"

/* Full-link test stubs (main.o excluded from addtest_ikedsrc). */
TEST_MAIN_STUBS();

static int fails = 0;

#define CHK(cond, what)							\
	do {								\
		if (cond)						\
			printf("signtest: ok - %s\n", what);		\
		else {							\
			printf("signtest: FAIL - %s\n", what);		\
			fails++;					\
		}							\
	} while (0)

/* RFC 7427 A.1.2 / A.2 AlgorithmIdentifiers (mirrors ikev2_auth.c). */
static const uint8_t rfc7427_sha384_ai[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00,
};
static const uint8_t rfc7427_sha512_ai[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00,
};
static const uint8_t rfc7427_pss_sha256_ai[] = {
	0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06,
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
};
static const uint8_t rfc7427_pss_sha384_ai[] = {
	0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06,
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
	0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
	0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x30,
};
static const uint8_t rfc7427_pss_sha512_ai[] = {
	0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30, 0x0d, 0x06,
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
	0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
	0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
	0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x40,
};

/* RFC 7427 A.1.4 ecdsa-with-SHA2 AlgorithmIdentifiers (absent params). */
static const uint8_t rfc7427_ecdsa_sha256_ai[] = {
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x04, 0x03, 0x02,
};
static const uint8_t rfc7427_ecdsa_sha384_ai[] = {
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x04, 0x03, 0x03,
};
static const uint8_t rfc7427_ecdsa_sha512_ai[] = {
	0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x04, 0x03, 0x04,
};

/* Generate a fresh EC P-256 key; return PKCS#8 DER private key + SPKI pub. */
static int
make_ec_key(rc_vchar_t **priv_out, rc_vchar_t **pub_out)
{
	EVP_PKEY *pkey = NULL;
	unsigned char *dp = NULL, *pup = NULL;
	int dl = 0, pl = 0;
	rc_vchar_t *priv = NULL, *pub = NULL;
	int rc = -1;

	pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
	if (!pkey)
		goto out;
	dl = i2d_PrivateKey(pkey, &dp);
	if (dl <= 0)
		goto out;
	priv = rc_vmalloc(dl);
	if (!priv)
		goto out;
	memcpy(priv->v, dp, dl);
	priv->l = dl;
	pl = i2d_PUBKEY(pkey, &pup);
	if (pl <= 0)
		goto out;
	pub = rc_vmalloc(pl);
	if (!pub)
		goto out;
	memcpy(pub->v, pup, pl);
	pub->l = pl;
	rc = 0;
      out:
	OPENSSL_free(dp);
	OPENSSL_free(pup);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (rc != 0) {
		if (priv)
			rc_vfree(priv);
		if (pub)
			rc_vfree(pub);
		return -1;
	}
	*priv_out = priv;
	*pub_out = pub;
	return 0;
}

/* Generate a fresh RSA-2048 key; return PKCS#1 DER private key as a vbuf,
 * and the matching public key DER for verify. */
static int
make_key(rc_vchar_t **priv_out, rc_vchar_t **pub_out)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *kctx = NULL;
	unsigned char *dp = NULL, *pup = NULL;
	int dl = 0, pl = 0;
	rc_vchar_t *priv = NULL, *pub = NULL;
	int rc = -1;

	kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(kctx, &pkey) <= 0)
		goto out;
	/* Private key: PKCS#8 DER (what eay_rsassa_*_sign d2i's with
	 * d2i_PrivateKey(EVP_PKEY_RSA,...)). */
	dl = i2d_PrivateKey(pkey, &dp);
	if (dl <= 0)
		goto out;
	priv = rc_vmalloc(dl);
	if (!priv)
		goto out;
	memcpy(priv->v, dp, dl);
	priv->l = dl;
	/* Public key: SubjectPublicKeyInfo DER (what the verify helpers d2i
	 * with d2i_PUBKEY). */
	pl = i2d_PUBKEY(pkey, &pup);
	if (pl <= 0)
		goto out;
	pub = rc_vmalloc(pl);
	if (!pub)
		goto out;
	memcpy(pub->v, pup, pl);
	pub->l = pl;
	rc = 0;
      out:
	OPENSSL_free(dp);
	OPENSSL_free(pup);
	if (pkey)
		EVP_PKEY_free(pkey);
	if (kctx)
		EVP_PKEY_CTX_free(kctx);
	if (rc != 0) {
		if (priv)
			rc_vfree(priv);
		if (pub)
			rc_vfree(pub);
		return -1;
	}
	*priv_out = priv;
	*pub_out = pub;
	return 0;
}

static void
test_roundtrips(void)
{
	rc_vchar_t *priv = NULL, *pub = NULL;
	rc_vchar_t *octets, *sig;
	const char *msg = "RFC 7427 signer-completeness round-trip, 2026-10-13";
	int good = 0;

	/* octets: an authenticate-style byte string (just the message). */
	octets = rc_vmalloc(strlen(msg) + 1);
	if (!octets)
		return;
	memcpy(octets->v, msg, strlen(msg));
	octets->l = strlen(msg);

	if (make_key(&priv, &pub) != 0)
		goto done;

	/* 1. RSASSA-PSS SHA-256/384/512 (salt = hash len), via eay_rfc7427_verify. */
	sig = eay_rsassa_pss_sign("SHA256", octets, priv, 32);
	CHK(sig != NULL, "PSS-SHA256 sign produced a signature");
	if (sig) {
		good = (eay_rfc7427_verify(octets, rfc7427_pss_sha256_ai,
					  sizeof(rfc7427_pss_sha256_ai),
					  sig, pub) == 0);
		CHK(good, "PSS-SHA256 sign/verify round-trip");
		rc_vfree(sig);
	}
	sig = eay_rsassa_pss_sign("SHA384", octets, priv, 48);
	CHK(sig != NULL, "PSS-SHA384 sign produced a signature");
	if (sig) {
		good = (eay_rfc7427_verify(octets, rfc7427_pss_sha384_ai,
					  sizeof(rfc7427_pss_sha384_ai),
					  sig, pub) == 0);
		CHK(good, "PSS-SHA384 sign/verify round-trip");
		rc_vfree(sig);
	}
	sig = eay_rsassa_pss_sign("SHA512", octets, priv, 64);
	CHK(sig != NULL, "PSS-SHA512 sign produced a signature");
	if (sig) {
		good = (eay_rfc7427_verify(octets, rfc7427_pss_sha512_ai,
					  sizeof(rfc7427_pss_sha512_ai),
					  sig, pub) == 0);
		CHK(good, "PSS-SHA512 sign/verify round-trip");
		rc_vfree(sig);
	}

	/* 2. RSASSA-PKCS1-v1_5 SHA-384/512 (the new SHA-2 sign chain). */
	sig = eay_rsassa_pkcs1_v1_5_sign("SHA384", octets, priv);
	CHK(sig != NULL, "PKCS1-SHA384 sign produced a signature");
	if (sig) {
		good = (eay_rfc7427_verify(octets, rfc7427_sha384_ai,
					  sizeof(rfc7427_sha384_ai),
					  sig, pub) == 0);
		CHK(good, "PKCS1-SHA384 sign/verify round-trip (v14 AI)");
		rc_vfree(sig);
	}
	sig = eay_rsassa_pkcs1_v1_5_sign("SHA512", octets, priv);
	CHK(sig != NULL, "PKCS1-SHA512 sign produced a signature");
	if (sig) {
		good = (eay_rfc7427_verify(octets, rfc7427_sha512_ai,
					  sizeof(rfc7427_sha512_ai),
					  sig, pub) == 0);
		CHK(good, "PKCS1-SHA512 sign/verify round-trip (v14 AI)");
		rc_vfree(sig);
	}
	/* SHA-256 PKCS1 (the historical path) via the classic verify, too. */
	sig = eay_rsassa_pkcs1_v1_5_sign("SHA256", octets, priv);
	CHK(sig != NULL, "PKCS1-SHA256 sign produced a signature");
	if (sig) {
		good = (eay_rsassa_pkcs1_v1_5_verify("SHA256", octets, sig,
						     pub) == 0);
		CHK(good, "PKCS1-SHA256 sign/verify round-trip");
		rc_vfree(sig);
	}

      done:
	if (octets)
		rc_vfree(octets);
	if (priv)
		rc_vfree(priv);
	if (pub)
		rc_vfree(pub);
}

/* RFC 7427 method-14 ECDSA DS: sign with eay_ecdsa_ds_sign (DER
 * Ecdsa-Sig-Value) and verify with eay_rfc7427_verify over ecdsa-with-SHA2.
 * P-256 key; sign+verify each of SHA-256/384/512. */
static void
test_ecdsa_ds(void)
{
	rc_vchar_t *priv = NULL, *pub = NULL;
	rc_vchar_t *octets, *sig;
	const char *msg = "RFC 7427 ECDSA DS (method 14) round-trip, 2026-10-13";
	int good = 0;

	octets = rc_vmalloc(strlen(msg) + 1);
	if (!octets)
		return;
	memcpy(octets->v, msg, strlen(msg));
	octets->l = strlen(msg);

	if (make_ec_key(&priv, &pub) != 0)
		goto done;

	sig = eay_ecdsa_ds_sign("SHA256", octets, priv);
	CHK(sig != NULL, "ECDSA-DS-SHA256 sign produced a signature");
	if (sig) {
		good = (eay_rfc7427_verify(octets, rfc7427_ecdsa_sha256_ai,
					  sizeof(rfc7427_ecdsa_sha256_ai),
					  sig, pub) == 0);
		CHK(good, "ECDSA-DS-SHA256 sign/verify round-trip");
		rc_vfree(sig);
	}
	sig = eay_ecdsa_ds_sign("SHA384", octets, priv);
	CHK(sig != NULL, "ECDSA-DS-SHA384 sign produced a signature");
	if (sig) {
		good = (eay_rfc7427_verify(octets, rfc7427_ecdsa_sha384_ai,
					  sizeof(rfc7427_ecdsa_sha384_ai),
					  sig, pub) == 0);
		CHK(good, "ECDSA-DS-SHA384 sign/verify round-trip");
		rc_vfree(sig);
	}
	sig = eay_ecdsa_ds_sign("SHA512", octets, priv);
	CHK(sig != NULL, "ECDSA-DS-SHA512 sign produced a signature");
	if (sig) {
		good = (eay_rfc7427_verify(octets, rfc7427_ecdsa_sha512_ai,
					  sizeof(rfc7427_ecdsa_sha512_ai),
					  sig, pub) == 0);
		CHK(good, "ECDSA-DS-SHA512 sign/verify round-trip");
		rc_vfree(sig);
	}

      done:
	if (octets)
		rc_vfree(octets);
	if (priv)
		rc_vfree(priv);
	if (pub)
		rc_vfree(pub);
}

int
main(int argc, char *argv[])
{
	printf("signtest: RFC 7427 signer-completeness round-trip KAT\n");
	test_init(argv[0]);
	test_roundtrips();
	test_ecdsa_ds();
	if (fails) {
		printf("signtest: %d check(s) FAILED\n", fails);
		return 1;
	}
	printf("signtest: all checks passed\n");
	return 0;
}
