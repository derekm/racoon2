/*
 * addkekat.c - RFC 9370 ADDKE ML-KEM-768 vs NIST FIPS 203 KATs.
 *
 * Independent pin of the EVP wrappers against the NIST known-answer
 * vectors (post-quantum-cryptography/KAT, kat_MLKEM_768.rsp):
 *   1. deterministic keygen from seed d||z must reproduce the KAT pk
 *   2. decapsulation of the KAT ct with our keypair must reproduce ss
 *   3. import of the NIST-provided sk + decap of NIST ct_n => ss_n
 *      (implicit-rejection path) must reproduce ss_n
 *
 * Vector file format is the standard NIST .rsp; only the first
 * vectors are shipped here (iked/kat_MLKEM_768.rsp), the full
 * 1000-vector file can be dropped in place for exhaustive runs.
 */

#include "config.h"

#ifdef WITH_ADDKE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "racoon.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"

static int failures;

static void
hex2bin_line(const char *hex, unsigned char *out, size_t max, size_t *len)
{
	size_t n = strlen(hex) / 2;
	size_t i;

	if (n > max)
		n = max;
	for (i = 0; i < n; i++) {
		unsigned v;
		if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
			*len = 0;
			return;
		}
		out[i] = (unsigned char)v;
	}
	*len = n;
}

/* parse "key = hex" (allow stray \r) */
static int
kat_field(const char *line, const char *key, unsigned char *out,
	  size_t max, size_t *len)
{
	size_t kl = strlen(key);
	const char *eq;

	if (strncmp(line, key, kl) != 0)
		return 0;
	eq = line + kl;
	while (*eq == ' ' || *eq == '\t')
		eq++;
	if (*eq != '=')
		return 0;
	eq++;
	while (*eq == ' ' || *eq == '\t')
		eq++;
	hex2bin_line(eq, out, max, len);
	return 1;
}

#define KAT_MAXLINE	16384

struct katvec {
	unsigned char z[32], d[32];
	unsigned char pk[1184], sk[2400];
	unsigned char ct[1088], ss[32];
	unsigned char ct_n[1088], ss_n[32];
};

static int
kat_run(const struct katvec *v, int idx)
{
	unsigned char seed[64];
	EVP_PKEY_CTX *ctx = NULL, *dctx = NULL;
	EVP_PKEY *kp = NULL, *kat_kp = NULL;
	unsigned char outpk[1184], outss[32], outss2[32];
	size_t opkl = sizeof(outpk), os1 = sizeof(outss),
	       os2 = sizeof(outss2);
	OSSL_PARAM params[2];
	int rc = -1;

	/* 1. deterministic keygen: seed = d || z */
	memcpy(seed, v->d, 32);
	memcpy(seed + 32, v->z, 32);
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
	if (ctx == NULL)
		goto done;
	params[0] = OSSL_PARAM_construct_octet_string(
	    OSSL_PKEY_PARAM_ML_KEM_SEED, seed, sizeof(seed));
	params[1] = OSSL_PARAM_construct_end();
	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
	    EVP_PKEY_keygen(ctx, &kp) <= 0)
		goto done;
	if (EVP_PKEY_get_raw_public_key(kp, outpk, &opkl) <= 0 ||
	    opkl != sizeof(outpk) ||
	    memcmp(outpk, v->pk, sizeof(outpk)) != 0) {
		fprintf(stderr, "  vector %d: keygen PK differs\n", idx);
		goto done;
	}

	/* 2. decapsulate the KAT ct with our (deterministic) keypair */
	dctx = EVP_PKEY_CTX_new(kp, NULL);
	if (dctx == NULL ||
	    EVP_PKEY_decapsulate_init(dctx, NULL) <= 0 ||
	    EVP_PKEY_decapsulate(dctx, outss, &os1, v->ct, sizeof(v->ct)) <= 0 ||
	    os1 != sizeof(v->ss) ||
	    memcmp(outss, v->ss, sizeof(v->ss)) != 0) {
		fprintf(stderr, "  vector %d: decap ss differs\n", idx);
		goto done;
	}

	/* 3. import NIST sk, decap KAT ct_n => expected ss_n */
	kat_kp = EVP_PKEY_new_raw_private_key(NID_ML_KEM_768, NULL,
					      v->sk, sizeof(v->sk));
	if (kat_kp == NULL) {
		fprintf(stderr, "  vector %d: cannot import KAT sk\n", idx);
		goto done;
	}
	/* free the step-2 ctx before it is overwritten (longer full-file runs) */
	EVP_PKEY_CTX_free(dctx);
	dctx = EVP_PKEY_CTX_new(kat_kp, NULL);
	if (dctx == NULL ||
	    EVP_PKEY_decapsulate_init(dctx, NULL) <= 0 ||
	    EVP_PKEY_decapsulate(dctx, outss2, &os2,
				 v->ct_n, sizeof(v->ct_n)) <= 0 ||
	    os2 != sizeof(v->ss_n) ||
	    memcmp(outss2, v->ss_n, sizeof(v->ss_n)) != 0) {
		fprintf(stderr, "  vector %d: implicit-reject ss_n differs\n",
			idx);
		goto done;
	}

	rc = 0;
      done:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_CTX_free(dctx);
	EVP_PKEY_free(kp);
	EVP_PKEY_free(kat_kp);
	return rc;
}

int
main(void)
{
	const char *path = "kat_MLKEM_768.rsp";
	FILE *f;
	char line[KAT_MAXLINE];
	struct katvec cur;
	int have = 0;		/* a "count = " line seen: an open vector */
	int nvec = 0, passed = 0;

	f = fopen(path, "r");
	if (f == NULL) {
		/* try the src dir (in-tree run through make check) */
		f = fopen("../../iked/kat_MLKEM_768.rsp", "r");
	}
	if (f == NULL) {
		fprintf(stderr, "addkekat: cannot open %s\n", path);
		return 77;	/* SKIP: file absent */
	}

	memset(&cur, 0, sizeof(cur));
	/* Streaming: run each vector as the next "count = " arrives (or the
	 * first one at EOF).  This handles any file size, not just the shipped
	 * 20-vector sample, and the reported total is exact — the old buffered
	 * loop capped at KAT_MAXVEC (silently running only the first 20 of the
	 * full 1000-vector file) and printed an nvec off-by-one total. */
	while (fgets(line, sizeof(line), f)) {
		size_t ll = strlen(line);
		size_t len;
		if (ll && line[ll-1] == '\n') line[--ll] = '\0';
		if (ll && line[ll-1] == '\r') line[--ll] = '\0';

		if (strncmp(line, "count = ", 8) == 0) {
			if (have) {
				if (kat_run(&cur, nvec) == 0)
					passed++;
				nvec++;
			}
			memset(&cur, 0, sizeof(cur));
			have = 1;
			continue;
		}
		if (!have)
			continue;
		/* longest first: ct_n/ss_n precede ct/ss in the .rsp */
		if (kat_field(line, "z", cur.z, 32, &len)) {
		} else if (kat_field(line, "d", cur.d, 32, &len)) {
		} else if (kat_field(line, "pk", cur.pk,
				     sizeof(cur.pk), &len)) {
		} else if (kat_field(line, "sk", cur.sk,
				     sizeof(cur.sk), &len)) {
		} else if (kat_field(line, "ct_n", cur.ct_n,
				     sizeof(cur.ct_n), &len)) {
		} else if (kat_field(line, "ss_n", cur.ss_n,
				     sizeof(cur.ss_n), &len)) {
		} else if (kat_field(line, "ct", cur.ct,
				     sizeof(cur.ct), &len)) {
		} else if (kat_field(line, "ss", cur.ss,
				     sizeof(cur.ss), &len)) {
		}
	}
	/* final vector */
	if (have) {
		if (kat_run(&cur, nvec) == 0)
			passed++;
		nvec++;
	}
	fclose(f);

	if (nvec == 0) {
		fprintf(stderr, "addkekat: no vectors parsed from %s\n", path);
		return 1;
	}
	if (passed == nvec) {
		printf("addkekat: %d/%d ML-KEM-768 KAT vectors passed\n",
		       passed, nvec);
		return 0;
	}
	fprintf(stderr, "addkekat: %d/%d vectors passed, FAILURES\n",
		passed, nvec);
	return 1;
}

#endif	/* WITH_ADDKE */
