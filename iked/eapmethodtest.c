/*
 * iked/eapmethodtest.c - hermetic test of the EAP responder AUTH method
 * selection (ikev2_eap_responder_method, ike_conf.c).
 *
 * The responder computes which signature method to present in the FIRST
 * IKE_AUTH response of an EAP exchange (responder-cert case, RFC 7296
 * s2.16).  The method number must reflect the configured auth method and,
 * for ECDSA, THE CURVE of the responder private key - P-256 -> 9
 * (IKEV2_AUTH_ECDSA_SHA256_P256), P-384 -> 10, P-521 -> 11 (RFC 4754),
 * mirroring ikev2_auth_method().  An RSA config yields method 14 (DS,
 * RFC 7427) when SIG_HASH_ALGORITHMS was exchanged, else method 1
 * (RSASIG).  A key-load failure (missing/unreadable key, or an
 * unsupported curve) must FAIL - the function returns 0.  The CALLER
 * (ikev2_responder_eap_auth_send, static in ikev2.c) treats "signature
 * method configured but resolution failed" as an abort, NOT as an
 * EAP-only no-CERT+AUTH downgrade; this test asserts the SELECTOR
 * contract (0 on key failure) that feeds that decision - it does NOT
 * drive the static caller itself.
 *
 * Keys are generated AT RUNTIME here with OpenSSL EVP (never committed,
 * never fetched) and written to $TMPDIR, so the test is hermetic and has
 * no private-key fixtures in the tree.
 *
 * Requires: OpenSSL EVP + the iked object set (addtest_ikedsrc) like the
 * other addtest_ikev2 programs.  Returns 0 iff all pass.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "ikev2_eap.h"
#include "getopt.h"
#include "test_util.h"

TEST_MAIN_STUBS()

/* ---- helpers to spin up a temp key+cert file pair (runtime) ---- */

/* generate a self-signed EC key+cert with the given curve name;
 * writes <base>-key.pem and <base>-cert.pem, returns 0 on success. */
static int
gen_ec_pair(const char *base, int curve_nid)
{
	char kpath[512], cpath[512];
	EVP_PKEY *pkey = NULL;
	X509 *x = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	X509_NAME *name = NULL;
	int rc = -1;

	snprintf(kpath, sizeof(kpath), "%s-key.pem", base);
	snprintf(cpath, sizeof(cpath), "%s-cert.pem", base);

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx) { fprintf(stderr, "ctx: %s\n", ERR_error_string(ERR_get_error(), NULL)); goto out; }
	if (EVP_PKEY_keygen_init(pctx) <= 0) { fprintf(stderr, "init: %s\n", ERR_error_string(ERR_get_error(), NULL)); goto out; }
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) <= 0) {
		fprintf(stderr, "curve: %s\n", ERR_error_string(ERR_get_error(), NULL)); goto out; }
	if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { fprintf(stderr, "keygen: %s\n", ERR_error_string(ERR_get_error(), NULL)); goto out; }

	x = X509_new();
	if (!x) { fprintf(stderr, "x509: %s\n", ERR_error_string(ERR_get_error(), NULL)); goto out; }
	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 0);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), 3600L * 24 * 30);
	name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				  (unsigned char *)"eapmethodtest", -1, -1, 0);
	X509_set_issuer_name(x, name);
	X509_set_pubkey(x, pkey);
	if (!X509_sign(x, pkey, EVP_sha256())) { fprintf(stderr, "sign: %s\n", ERR_error_string(ERR_get_error(), NULL)); goto out; }

	{
		FILE *fp = fopen(cpath, "w");
		if (!fp) goto out;
		PEM_write_X509(fp, x);
		fclose(fp);
		fp = fopen(kpath, "w");
		if (!fp) goto out;
		PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
		fclose(fp);
	}
	rc = 0;
out:
	if (pkey) EVP_PKEY_free(pkey);
	if (x) X509_free(x);
	if (pctx) EVP_PKEY_CTX_free(pctx);
	return rc;
}

/* an rc_alglist with a single auth method */
static struct rc_alglist *
mkalg(rc_type t)
{
	struct rc_alglist *a = racoon_calloc(1, sizeof(*a));
	if (a)
		a->algtype = t;
	return a;
}

/* point an SA at a fresh calloc'd remote (with ikev2 sub) */
static struct rcf_remote *
mkrmconf(void)
{
	struct rcf_remote *rm =
		(struct rcf_remote *)racoon_calloc(1, sizeof(struct rcf_remote));
	if (!rm)
		return NULL;
	rm->ikev2 = (struct rcf_kmp *)racoon_calloc(1, sizeof(struct rcf_kmp));
	if (!rm->ikev2) {
		racoon_free(rm);
		return NULL;
	}
	return rm;
}

/* add an X509PEM pubkey entry (cert + privkey paths) to rmconf->my_pubkey */
static int
mk_pubkey(struct rcf_kmp *kmp, const char *cert, const char *priv)
{
	struct rc_pklist *pk =
		(struct rc_pklist *)racoon_calloc(1, sizeof(struct rc_pklist));
	if (!pk)
		return -1;
	pk->ftype = RCT_FTYPE_X509PEM;
	pk->pubkey = rc_vnew((uint8_t *)(uintptr_t)cert, strlen(cert));
	pk->privkey = rc_vnew((uint8_t *)(uintptr_t)priv, strlen(priv));
	pk->next = kmp->my_pubkey;
	kmp->my_pubkey = pk;
	return 0;
}

int
main(void)
{
	struct ikev2_sa *sa;
	struct rcf_remote *rm;
	struct rc_alglist *alg;
	char tdir[512];
	char base[512];
	int got, fails = 0;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;
	ikev2_sa_init();
	sched_init();

	snprintf(tdir, sizeof(tdir), "/tmp/eapmethodtest-%d", (int)getpid());
	{
		char mk[600];
		snprintf(mk, sizeof(mk), "mkdir -p %s", tdir);
		if (system(mk) != 0)
			return 2;
	}

	/* ---- 1..3. ECDSA curve -> method 9/10/11 ---- */
	{
		int curves[3] = { NID_X9_62_prime256v1, NID_secp384r1, NID_secp521r1 };
		int want[3] = { IKEV2_AUTH_ECDSA_SHA256_P256,
				IKEV2_AUTH_ECDSA_SHA384_P384,
				IKEV2_AUTH_ECDSA_SHA512_P521 };
		const char *cname[3] = { "P-256", "P-384", "P-521" };
		int i;
		for (i = 0; i < 3; i++) {
			char kpath[512], cpath[512];
			snprintf(base, sizeof(base), "%s/c%d", tdir, i);
			if (gen_ec_pair(base, curves[i])) {
				/* a curve we cannot generate means the
				 * mapping for that branch is UNTESTED, not
				 * a SKIP: fail the test rather than report a
				 * false green. */
				printf("eapmethodtest: FAIL %d cannot gen %s key "
				       "(mapping untested)\n",
				       i + 1, cname[i]);
				fails++;
				continue;
			}
			snprintf(cpath, sizeof(cpath), "%s-cert.pem", base);
			snprintf(kpath, sizeof(kpath), "%s-key.pem", base);

			sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
			if (!sa) return 2;
			rm = mkrmconf();
			alg = mkalg(RCT_ALG_ECDSA);
			if (!rm || !alg) return 2;
			rm->ikev2->kmp_auth_method = alg;
			if (mk_pubkey(rm->ikev2, cpath, kpath)) return 2;
			sa->rmconf = rm;
			got = ikev2_eap_responder_method(sa);
			if (got == want[i])
				printf("eapmethodtest: PASS %d ECDSA %s -> method %d\n",
				       i + 1, cname[i], got);
			else {
				printf("eapmethodtest: FAIL %d ECDSA %s -> %d (want %d)\n",
				       i + 1, cname[i], got, want[i]);
				fails++;
			}
			sa->rmconf = NULL;
			ikev2_dispose_sa(sa);
			racoon_free(alg);
			rc_vfree(rm->ikev2->my_pubkey->pubkey);
			rc_vfree(rm->ikev2->my_pubkey->privkey);
			racoon_free(rm->ikev2->my_pubkey);
			racoon_free(rm->ikev2);
			racoon_free(rm);
		}
	}

	/* ---- 4. ECDSA key-load failure -> 0 (must NOT look like a method) ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	rm = mkrmconf();
	alg = mkalg(RCT_ALG_ECDSA);
	if (!rm || !alg) return 2;
	rm->ikev2->kmp_auth_method = alg;
	/* point at a Nonexistent key file: ikev2_private_key() returns NULL,
	 * and the ECDSA branch must return 0 (the caller then ABORTS rather
	 * than downgrading to EAP-only no-CERT+AUTH). */
	if (mk_pubkey(rm->ikev2, "/no/such/cert.pem", "/no/such/key.pem"))
		return 2;
	sa->rmconf = rm;
	got = ikev2_eap_responder_method(sa);
	if (got == 0)
		printf("eapmethodtest: PASS 4 ECDSA key-load failure -> 0 (no method)\n");
	else {
		printf("eapmethodtest: FAIL 4 ECDSA key failure -> %d (want 0)\n", got);
		fails++;
	}
	sa->rmconf = NULL;
	ikev2_dispose_sa(sa);
	racoon_free(alg);
	rc_vfree(rm->ikev2->my_pubkey->pubkey);
	rc_vfree(rm->ikev2->my_pubkey->privkey);
	racoon_free(rm->ikev2->my_pubkey);
	racoon_free(rm->ikev2);
	racoon_free(rm);

	/* ---- 5. RSA -> DS (sig_hash_algos_ds set) ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	rm = mkrmconf();
	alg = mkalg(RCT_ALG_RSASIG);
	if (!rm || !alg) return 2;
	rm->ikev2->kmp_auth_method = alg;
	sa->rmconf = rm;
	sa->sig_hash_algos_ds = 1;
	got = ikev2_eap_responder_method(sa);
	if (got == IKEV2_AUTH_DS)
		printf("eapmethodtest: PASS 5 RSA -> DS (method %d)\n", got);
	else {
		printf("eapmethodtest: FAIL 5 RSA+DS -> %d (want %d)\n",
		       got, IKEV2_AUTH_DS);
		fails++;
	}
	sa->rmconf = NULL;
	ikev2_dispose_sa(sa);
	racoon_free(alg);
	racoon_free(rm->ikev2);
	racoon_free(rm);

	/* ---- 6. RSA, no SIG_HASH exchanged -> RSASIG ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	rm = mkrmconf();
	alg = mkalg(RCT_ALG_RSASIG);
	if (!rm || !alg) return 2;
	rm->ikev2->kmp_auth_method = alg;
	sa->rmconf = rm;
	sa->sig_hash_algos_ds = 0;
	got = ikev2_eap_responder_method(sa);
	if (got == IKEV2_AUTH_RSASIG)
		printf("eapmethodtest: PASS 6 RSA (no SIGHASH) -> RSASIG (method %d)\n", got);
	else {
		printf("eapmethodtest: FAIL 6 RSA -> %d (want %d)\n",
		       got, IKEV2_AUTH_RSASIG);
		fails++;
	}
	sa->rmconf = NULL;
	ikev2_dispose_sa(sa);
	racoon_free(alg);
	racoon_free(rm->ikev2);
	racoon_free(rm);

	/* ---- 7. EAP-only (no signature method) -> 0 ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	rm = mkrmconf();
	alg = mkalg(RCT_ALG_EAP);
	if (!rm || !alg) return 2;
	rm->ikev2->kmp_auth_method = alg;
	sa->rmconf = rm;
	got = ikev2_eap_responder_method(sa);
	if (got == 0)
		printf("eapmethodtest: PASS 7 EAP-only -> 0\n");
	else {
		printf("eapmethodtest: FAIL 7 EAP-only -> %d (want 0)\n", got);
		fails++;
	}
	sa->rmconf = NULL;
	ikev2_dispose_sa(sa);
	racoon_free(alg);
	racoon_free(rm->ikev2);
	racoon_free(rm);

	/* ---- 8. NULL sa -> 0 (no crash) ---- */
	got = ikev2_eap_responder_method(NULL);
	if (got != 0) {
		printf("eapmethodtest: FAIL 8 NULL sa -> %d (want 0)\n", got);
		fails++;
	} else {
		printf("eapmethodtest: PASS 8 NULL sa -> 0\n");
	}

	/* ---- 9. NULL rmconf (sa set, config NULL) -> 0 (no crash) ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	sa->rmconf = NULL;	/* explicit: ike_conf.c:5413 guard */
	got = ikev2_eap_responder_method(sa);
	if (got != 0) {
		printf("eapmethodtest: FAIL 9 NULL rmconf -> %d (want 0)\n", got);
		fails++;
	} else {
		printf("eapmethodtest: PASS 9 NULL rmconf -> 0\n");
	}
	sa->rmconf = NULL;
	ikev2_dispose_sa(sa);

	if (fails == 0)
		printf("eapmethodtest: ALL PASS (0 failures)\n");
	else
		printf("eapmethodtest: %d FAILURES\n", fails);
	return fails ? 1 : 0;
}
