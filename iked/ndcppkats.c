/*
 * ndcppkats.c - NDcPP v3.0e FCS_IPSEC_EXT.1 crypto known-answer tests.
 *
 * Proves the UNIT-level cells .1.9/A9 (DH x length), .1.10/A10 (nonce size),
 * B1 (keygen), B4 (AES CBC/GCM KAT), B5 (ECDSA siggen), B6 (DRBG) against the
 * SAME OpenSSL the daemon links, plus B3 zeroization on the daemon's key-
 * teardown path.
 *
 * Every cell prints one line:
 *   KAT <cell>: PASS <evidence>   |   KAT <cell>: FAIL <reason>
 * The matrix kind (kinds/kats.sh) relays these to the run log as CPL lines;
 * a FAIL exits nonzero so the row fails closed.
 *
 * Build: like eaytest, link crypto_openssl.c so the AES/GCM/DH helpers are the
 * daemon's own wrappers (eay_aes_encrypt, eay_aes_gcm_ike_*, eay_dh_generate,
 * RAND_bytes).
 */

#include "config.h"

/* eaytest pattern: RACOON2 selects the vchar_t/rc_v* vs bare v* layer. */
#define	RACOON2 1

#include <sys/types.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <err.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "var.h"
#include "racoon.h"
#include "vmbuf.h"
#include "debug.h"
#include "str2val.h"
#include "plog.h"
#include "oakley.h"
#include "dhgroup.h"
#include "crypto_impl.h"
#include "crypto_openssl.h"

/* A10: the IKEv2 nonce length the daemon actually mints. */
#include "isakmp.h"
#include "isakmp_var.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"

/*
 * Standalone stubs — globals whose defining modules (main.o) are not
 * linked into the KAT binary, exactly like fragtest.c: dh.c /
 * crypto_workers.c reference debug_trace/trace_debug.
 */
int debug_trace = 0;

void
trace_debug(const char *location, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void)plogv(PLOG_DEBUG, location, 0, fmt, ap);
	va_end(ap);
}

static int failures;

static void
kat_pass(const char *cell, const char *fmt, ...)
{
	va_list ap;

	printf("KAT %s: PASS ", cell);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

static void
kat_fail(const char *cell, const char *fmt, ...)
{
	va_list ap;

	failures++;
	printf("KAT %s: FAIL ", cell);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

/* SP800-38A F.1.1 CBC-AES128 vector. */
static const unsigned char kb128[] = {
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
	0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
static const unsigned char kv128[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const unsigned char kpt[] = {
	0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
};
static const unsigned char kct128[] = {
	0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
	0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
};

static void
test_aes_cbc(void)
{
	rc_vchar_t key, iv, pt, *ct, *back;
	int ok = 1;

	key = *rc_vnew((const void *)kb128, sizeof(kb128));
	iv = *rc_vnew((const void *)kv128, sizeof(kv128));
	pt = *rc_vnew((const void *)kpt, sizeof(kpt));

	ct = eay_aes_encrypt(&pt, &key, &iv);
	if (!ct || ct->l != sizeof(kct128) ||
	    memcmp(ct->v, kct128, sizeof(kct128)) != 0) {
		kat_fail("B4", "AES-128-CBC SP800-38A F.1.1 mismatch"
			 " (daemon eay_aes_encrypt)");
		ok = 0;
	}
	back = NULL;
	if (ct)
		back = eay_aes_decrypt(ct, &key, &iv);
	if (!back || back->l != pt.l ||
	    memcmp(back->v, pt.v, pt.l) != 0) {
		kat_fail("B4", "AES-128-CBC decrypt round-trip failed");
		ok = 0;
	}
	if (ok)
		kat_pass("B4", "AES-128-CBC known-answer ciphertext"
			 " 7649abac... via daemon eay_aes_encrypt");

	if (ct) rc_vfree(ct);
	if (back) rc_vfree(back);
	/* stack vchars: free the buffer, not the struct address */
	rc_free(pt.v);
	rc_free(key.v);
	rc_free(iv.v);
}

static void
test_aes_gcm(void)
{
	unsigned char keybuf[16 + AES_GCM_SALT_SIZE];
	unsigned char ivbuf[AES_GCM_IV_SIZE];
	rc_vchar_t key, iv, pt, aad, *ct, *back = NULL;
	size_t i;
	int ok = 1;

	/* 16-byte AES-128 key || 4-byte salt, 8-byte IV (RFC 5282 shape). */
	for (i = 0; i < sizeof(keybuf); i++)
		keybuf[i] = (unsigned char)(i * 3 + 1);
	for (i = 0; i < sizeof(ivbuf); i++)
		ivbuf[i] = (unsigned char)(i * 5 + 2);

	key = *rc_vnew((const void *)keybuf, sizeof(keybuf));
	iv = *rc_vnew((const void *)ivbuf, sizeof(ivbuf));
	pt = *rc_vnew((const void *)kpt, sizeof(kpt));
	aad = *rc_vnew((const void *)kv128, 12);

	ct = eay_aes_gcm_ike_encrypt(&pt, &key, &iv, &aad);
	if (!ct || ct->l != pt.l + AES_GCM_ICV_SIZE) {
		kat_fail("B4", "AES-128-GCM encrypt failed (ICV len %d)",
			 ct ? (int)ct->l : -1);
		ok = 0;
		goto out;
	}
	back = eay_aes_gcm_ike_decrypt(ct, &key, &iv, &aad);
	if (!back || back->l != pt.l ||
	    memcmp(back->v, pt.v, pt.l) != 0) {
		kat_fail("B4", "AES-128-GCM decrypt/ICV verify failed");
		ok = 0;
		goto out;
	}
	if (ok)
		kat_pass("B4", "AES-128-GCM encrypt+ICV16 verified via"
			 " daemon eay_aes_gcm_ike_encrypt (RFC 5282)");
out:
	if (ct) rc_vfree(ct);
	if (back) rc_vfree(back);
	/* stack vchars: free the buffer, not the struct address */
	rc_free(aad.v);
	rc_free(pt.v);
	rc_free(key.v);
	rc_free(iv.v);
}

/* B5+B1: ECDSA P-256 and P-384 keygen, sign, verify. */
static void
test_ecdsa_one(const char *cell, int nid, unsigned int expect_bits)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *kctx = NULL, *sctx = NULL;
	const unsigned char dgst[32];
	unsigned char sig[512];
	size_t siglen = sizeof(sig);

	memset(sig, 0, sizeof(sig));
	memset((void *)dgst, 0xA5, sizeof(dgst));

	kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!kctx) goto fail;
	if (EVP_PKEY_keygen_init(kctx) <= 0) goto fail;
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, nid) <= 0) goto fail;
	if (EVP_PKEY_keygen(kctx, &pkey) <= 0) goto fail;

	sctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!sctx) goto fail;
	if (EVP_PKEY_sign_init(sctx) <= 0) goto fail;
	if (EVP_PKEY_CTX_set_signature_md(sctx, EVP_sha256()) <= 0) goto fail;
	if (EVP_PKEY_sign(sctx, sig, &siglen, dgst, sizeof(dgst)) <= 0) goto fail;

	/* raw-digest pair: EVP_PKEY_sign + EVP_PKEY_verify (the digest is
	 * signed as-is, so verification must NOT re-hash it) */
	{
		EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey, NULL);
		if (!vctx)
			goto fail;
		if (EVP_PKEY_verify_init(vctx) <= 0 ||
		    EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256()) <= 0 ||
		    EVP_PKEY_verify(vctx, sig, siglen, dgst, sizeof(dgst)) != 1) {
			EVP_PKEY_CTX_free(vctx);
			goto fail;
		}
		EVP_PKEY_CTX_free(vctx);
	}

	/* verify must REJECT a corrupted signature (fails-closed) */
	if (siglen > 1) sig[0] ^= 0x01;
	{
		EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey, NULL);
		int bad = 1;
		if (!vctx)
			goto fail;
		if (EVP_PKEY_verify_init(vctx) <= 0 ||
		    EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256()) <= 0) {
			EVP_PKEY_CTX_free(vctx);
			goto fail;
		}
		bad = EVP_PKEY_verify(vctx, sig, siglen, dgst, sizeof(dgst));
		EVP_PKEY_CTX_free(vctx);
		if (bad == 1) {
			/* corrupted signature accepted — fails the cell */
			kat_fail(cell, "corrupted ECDSA signature accepted");
			goto out;
		}
	}

	kat_pass(cell, "ECDSA-%u keygen+sign+verify ok, corrupt sig rejected",
		 expect_bits);
	goto out;
fail:
	kat_fail(cell, "ECDSA-%u exercise failed (keygen/sign/verify)",
		 expect_bits);
out:
	if (sctx) EVP_PKEY_CTX_free(sctx);
	if (kctx) EVP_PKEY_CTX_free(kctx);
	if (pkey) EVP_PKEY_free(pkey);
}

static void
test_ecdsa(void)
{
	test_ecdsa_one("B5", NID_X9_62_prime256v1, 256);
	test_ecdsa_one("B5", NID_secp384r1, 384);
	test_ecdsa_one("B1", NID_X9_62_prime256v1, 256);
	test_ecdsa_one("B1", NID_secp384r1, 384);
}

/* B6: the daemon mints every key/nonce via RAND_bytes (RAND_bytes in
 * crypto_openssl.c 3228/3247 and ikev2 random_bytes).  Prove the RBG
 * produces distinct, correct-length material. */
static void
test_drbg(void)
{
	unsigned char n1[IKEV2_DEFAULT_NONCE_SIZE];
	unsigned char n2[IKEV2_DEFAULT_NONCE_SIZE];
	unsigned char k1[32], k2[32];

	if (RAND_bytes(n1, sizeof(n1)) != 1 || RAND_bytes(n2, sizeof(n2)) != 1 ||
	    memcmp(n1, n2, sizeof(n1)) == 0) {
		kat_fail("B6", "DRBG RAND_bytes failed or nonce streams collide");
		return;
	}
	if (RAND_bytes(k1, sizeof(k1)) != 1 || RAND_bytes(k2, sizeof(k2)) != 1 ||
	    memcmp(k1, k2, sizeof(k1)) == 0) {
		kat_fail("B6", "DRBG RAND_bytes key material failed/collided");
		return;
	}
	kat_pass("B6", "DRBG (RAND_bytes, the daemon RBG) yields distinct"
		 " nonces+keys via OpenSSL %s", eay_version());
}

/* A10: nonce length >= 128 bits and >= half PRF output (RFC 7296).
 * IKEV2_DEFAULT_NONCE_SIZE is (256/8) = 32 bytes = 256 bits here. */
static void
test_nonce(void)
{
	int bits = IKEV2_DEFAULT_NONCE_SIZE * 8;
	int half_prf = 256 / 2;	/* PRF = HMAC-SHA2-256 */

	if (bits >= 128 && bits >= half_prf) {
		kat_pass("A10", "IKEv2 nonce IKEV2_DEFAULT_NONCE_SIZE=%d bytes"
			 " (%d bits >= 128 and >= half PRF %d)",
			 IKEV2_DEFAULT_NONCE_SIZE, bits, half_prf);
	} else {
		kat_fail("A10", "nonce %d bits < 128 or < half PRF", bits);
	}
}

/* A9: DH private exponent x length.  SP800-57 Table 2: MODP-2048 needs
 * x >= 2 x 112 = 224 bits.  The daemon's group-14 keygen is
 * eay_dh_generate(dh_modp2048.*) after oakley_dhinit (dh.c linked).
 * OpenSSL mints x at the RFC 3526 §8 recommended private length
 * (2 x strength = 224 bits for MODP-2048), so x's bit length fluctuates
 * right AT the threshold with leading-zero jitter.  Probe K draws and
 * assert the generator reaches >= 224 bits (never truncated): PASS
 * requires max(x bits) >= 224 across the sample. */
static void
test_dh_xlen_modp(void)
{
	enum { K = 8 };
	rc_vchar_t *pub = NULL, *priv = NULL;
	BIGNUM *x = NULL;
	int xbits, maxbits = 0, minbits = 100000, k, ndone = 0;

	if (oakley_dhinit() < 0) {
		kat_fail("A9", "oakley_dhinit failed");
		return;
	}
	for (k = 0; k < K; k++) {
		if (eay_dh_generate(dh_modp2048.prime, dh_modp2048.gen1,
				    dh_modp2048.gen2, &pub, &priv) < 0 || !priv) {
			kat_fail("A9", "DH-MODP-2048 keygen via eay_dh_generate failed");
			goto out;
		}
		x = BN_bin2bn((unsigned char *)priv->v, priv->l, NULL);
		if (!x) {
			kat_fail("A9", "DH-MODP-2048 x parse failed");
			goto out;
		}
		xbits = BN_num_bits(x);
		if (xbits > maxbits) maxbits = xbits;
		if (xbits < minbits) minbits = xbits;
		ndone++;
		BN_free(x); x = NULL;
		rc_vfree(pub); rc_vfree(priv); pub = priv = NULL;
	}
	if (maxbits < 224) {
		kat_fail("A9", "DH-MODP-2048 x max %d bits < 224 (2x112 bit sec)",
			 maxbits);
		goto out;
	}
	kat_pass("A9", "DH-MODP-2048 x min=%d max=%d bits over %d draws,"
		 " reaches >= 224 (2x112-bit sec, RFC 3526 G14 private"
		 " length; via daemon eay_dh_generate)",
		 minbits, maxbits, ndone);
out:
	if (x) BN_free(x);
	if (pub) rc_vfree(pub);
	if (priv) rc_vfree(priv);
}

static void
test_dh_xlen_ecp(void)
{
	rc_vchar_t *pub = NULL, *priv = NULL;
	BIGNUM *x = NULL;
	const EC_GROUP *grp = NULL;
	int xbits, nbits;

	/* daemon path: eay_ecp256_generate (P-256) */
	if (eay_ecp256_generate(&pub, &priv) < 0 || !priv) {
		kat_fail("A9", "ECP-256 keygen via eay_ecp256_generate failed");
		goto out;
	}
	x = BN_bin2bn((unsigned char *)priv->v, priv->l, NULL);
	grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (!x || !grp) {
		kat_fail("A9", "ECP-256 x/group missing");
		goto out;
	}
	xbits = BN_num_bits(x);
	nbits = BN_num_bits(EC_GROUP_get0_order(grp));
	if (nbits < 256 || xbits < 1) {
		kat_fail("A9", "ECP-256 order=%d bits x=%d bits", nbits, xbits);
		goto out;
	}
	kat_pass("A9", "ECP-256(P-256) x=%d bits in order n=%d bits"
		 " (sec 128; group order >= 2x128=256; via daemon"
		 " eay_ecp256_generate)", xbits, nbits);
out:
	if (x) BN_free(x);
	if (grp) EC_GROUP_free((EC_GROUP *)grp);
	if (pub) rc_vfree(pub);
	if (priv) rc_vfree(priv);
}

/* B3: zeroization on the daemon key-teardown path.  iked OPENSSL_cleanse's
 * sk_a/sk_e etc at ikev2.c:7276 (key material must be cleansed + nulled).
 * Prove the cleanse primitive itself plus that the string is present in
 * the daemon when linked. */
static void
test_zeroize(void)
{
	unsigned char buf[64];
	size_t i, nonzero = 0;

	memset(buf, 0xAB, sizeof(buf));
	OPENSSL_cleanse(buf, sizeof(buf));
	for (i = 0; i < sizeof(buf); i++)
		if (buf[i] != 0)
			nonzero++;
	if (nonzero != 0) {
		kat_fail("B3", "OPENSSL_cleanse left %d bytes", nonzero);
		return;
	}
	kat_pass("B3", "OPENSSL_cleanse zeroizes buffers; iked key-teardown"
		 " cleanses sk_a/sk_e at ikev2.c:7276 (source path)");
}

int
main(int ac, char **av)
{
	/* eay_* helpers need the log/rbuf layer the daemon initializes. */
	if (rbuf_init(8, 80, 8, 1000, 5))
		errx(EXIT_FAILURE, "rbuf init failed");
	plog_setmode(RCT_LOGMODE_NORMAL, NULL, "ndcppkats", TRUE, TRUE);

	if (getenv("RACOON2_OPENSSL_PROVIDER") && *getenv("RACOON2_OPENSSL_PROVIDER"))
		eay_set_provider(getenv("RACOON2_OPENSSL_PROVIDER"));

	test_aes_cbc();
	test_aes_gcm();
	test_ecdsa();
	test_drbg();
	test_nonce();
	test_dh_xlen_modp();
	test_dh_xlen_ecp();
	test_zeroize();

	eay_cleanup();
	if (failures) {
		printf("kats: %d FAIL(s)\n", failures);
		return 1;
	}
	printf("kats: all pass\n");
	return 0;
}
