/*
 * deprtest -- unit test for the deprecated-transform classification
 * (ike_deprecated.c).  The expectations below are an INDEPENDENT
 * transcription of the RFC tables (RFC 8247 s2.1-s2.4/s3.1/s3.2,
 * RFC 8221 s5/s6, RFC 9395 s5) and of the NSA/CNSSP-15 set, so a typo in
 * the daemon table cannot pass: each row is (ctx, type, id) -> expected
 * class mask, RFC level and citation.  Negative rows pin what must NOT be
 * flagged (e.g. ENCR_3DES is MAY for IKE, ENCR_NULL is MUST for ESP,
 * PRF_HMAC_SHA1 / AUTH_HMAC_SHA1_96 are MUST-).
 *
 * IKEv1 rows use the IKEv1 codepoints (RFC 2409 App A, RFC 2407 s4.5):
 * Phase 1 under IKEv1 context, RFC class per RFC 9395 s3 / s5; Phase 2
 * auth attribute under ESP/AH per RFC 8221 s6.  The negatives pin the
 * codepoints that collide with deprecated IKEv2 numbers but are NOT
 * deprecated in IKEv1 (enc 7 = AES, hash 4..6 = SHA-2, auth attr 6/7 =
 * HMAC-SHA2-384/512, not MD5_128 / SHA1_160).
 */
#include <stdio.h>
#include <string.h>

#include "ike_deprecated.h"

#define	N	IKE_DEPR_NSA
#define	R	IKE_DEPR_RFC
#define	MN	IKE_DEPR_LVL_MUST_NOT
#define	SN	IKE_DEPR_LVL_SHOULD_NOT
#define	DP	IKE_DEPR_LVL_DEPRECATED
#define	NL	IKE_DEPR_LVL_NONE
#define	IKE	IKE_DEPR_CTX_IKE
#define	ESP	IKE_DEPR_CTX_ESP
#define	AH	IKE_DEPR_CTX_AH
#define	T_E	IKE_DEPR_T_ENCR
#define	T_P	IKE_DEPR_T_PRF
#define	T_I	IKE_DEPR_T_INTEG
#define	T_K	IKE_DEPR_T_KE
#define	V1	IKE_DEPR_CTX_IKEV1
#define	V1E	IKE_DEPR_T_V1_ENC
#define	V1H	IKE_DEPR_T_V1_HASH
#define	V1A	IKE_DEPR_T_V1_AUTH
#define	V1P	IKE_DEPR_T_V1_P2AUTH

struct expect {
	int ctx;
	unsigned int type, id;
	unsigned int classes;
	int level;
	const char *cite;
};

static const struct expect cases[] = {
	/* RFC 8247 s2.1 / RFC 9395 s5 -- IKE encryption */
	{ IKE, T_E, 1,  N|R, DP, "RFC 9395 s5" },	/* DES_IV64 */
	{ IKE, T_E, 2,  N|R, MN, "RFC 8247 s2.1" },	/* DES */
	{ IKE, T_E, 3,  N,   NL, NULL },		/* 3DES: MAY in 8247 */
	{ IKE, T_E, 4,  R,   DP, "RFC 9395 s5" },	/* RC5 */
	{ IKE, T_E, 5,  R,   DP, "RFC 9395 s5" },	/* IDEA */
	{ IKE, T_E, 6,  R,   DP, "RFC 9395 s5" },	/* CAST */
	{ IKE, T_E, 7,  R,   DP, "RFC 9395 s5" },	/* BLOWFISH */
	{ IKE, T_E, 8,  R,   DP, "RFC 9395 s5" },	/* 3IDEA */
	{ IKE, T_E, 9,  N|R, DP, "RFC 9395 s5" },	/* DES_IV32 */
	{ IKE, T_E, 11, R,   MN, "RFC 8247 s2.1" },	/* NULL */
	{ IKE, T_E, 12, 0,   NL, NULL },		/* AES_CBC MUST */
	{ IKE, T_E, 20, 0,   NL, NULL },		/* AES_GCM_16 */
	{ IKE, T_E, 28, 0,   NL, NULL },		/* CHACHA20_POLY1305 */
	/* RFC 8221 s5 -- ESP encryption */
	{ ESP, T_E, 1,  N|R, MN, "RFC 8221 s5" },
	{ ESP, T_E, 2,  N|R, MN, "RFC 8221 s5" },
	{ ESP, T_E, 3,  N|R, SN, "RFC 8221 s5" },	/* 3DES SHOULD NOT */
	{ ESP, T_E, 4,  R,   DP, "RFC 9395 s5" },
	{ ESP, T_E, 7,  R,   MN, "RFC 8221 s5" },
	{ ESP, T_E, 8,  R,   MN, "RFC 8221 s5" },
	{ ESP, T_E, 9,  N|R, MN, "RFC 8221 s5" },
	{ ESP, T_E, 11, 0,   NL, NULL },		/* ENCR_NULL MUST for ESP */
	{ ESP, T_E, 12, 0,   NL, NULL },
	{ AH,  T_E, 2,  0,   NL, NULL },		/* AH has no ENCR */
	/* RFC 8247 s2.2 / RFC 9395 s5 -- PRF */
	{ IKE, T_P, 1,  N|R, MN, "RFC 8247 s2.2" },	/* HMAC_MD5 */
	{ IKE, T_P, 2,  N,   NL, NULL },		/* HMAC_SHA1 MUST- */
	{ IKE, T_P, 3,  R,   DP, "RFC 9395 s5" },	/* TIGER */
	{ IKE, T_P, 5,  0,   NL, NULL },		/* SHA2_256 */
	/* RFC 8247 s2.3 -- IKE integrity */
	{ IKE, T_I, 1,  N|R, MN, "RFC 8247 s2.3" },	/* HMAC_MD5_96 */
	{ IKE, T_I, 2,  N,   NL, NULL },		/* HMAC_SHA1_96 MUST- */
	{ IKE, T_I, 3,  N|R, MN, "RFC 8247 s2.3" },	/* DES_MAC */
	{ IKE, T_I, 4,  N|R, MN, "RFC 8247 s2.3" },	/* KPDK_MD5 */
	{ IKE, T_I, 6,  N|R, DP, "RFC 9395 s5" },	/* HMAC_MD5_128 */
	{ IKE, T_I, 7,  N|R, DP, "RFC 9395 s5" },	/* HMAC_SHA1_160 */
	{ IKE, T_I, 12, 0,   NL, NULL },
	/* RFC 8221 s6 -- ESP/AH integrity */
	{ ESP, T_I, 1,  N|R, MN, "RFC 8221 s6" },
	{ AH,  T_I, 1,  N|R, MN, "RFC 8221 s6" },
	{ ESP, T_I, 2,  N,   NL, NULL },
	{ AH,  T_I, 3,  N|R, MN, "RFC 8221 s6" },
	{ ESP, T_I, 4,  N|R, MN, "RFC 8221 s6" },
	{ AH,  T_I, 7,  N|R, DP, "RFC 9395 s5" },
	{ ESP, T_I, 12, 0,   NL, NULL },
	/* RFC 8247 s2.4 -- KE methods, every context (IKE, child PFS) */
	{ IKE, T_K, 1,  N|R, MN, "RFC 8247 s2.4" },
	{ IKE, T_K, 2,  N|R, SN, "RFC 8247 s2.4" },
	{ IKE, T_K, 5,  N|R, SN, "RFC 8247 s2.4" },
	{ IKE, T_K, 14, 0,   NL, NULL },
	{ IKE, T_K, 19, 0,   NL, NULL },
	{ IKE, T_K, 22, R,   MN, "RFC 8247 s2.4" },
	{ IKE, T_K, 23, R,   SN, "RFC 8247 s2.4" },
	{ IKE, T_K, 24, R,   SN, "RFC 8247 s2.4" },
	{ IKE, T_K, 31, 0,   NL, NULL },		/* curve25519 */
	{ ESP, T_K, 1,  N|R, MN, "RFC 8247 s2.4" },	/* child PFS */
	{ ESP, T_K, 22, R,   MN, "RFC 8247 s2.4" },
	/* RFC 9370 ADDKE1..7 fold onto the type-4 registry */
	{ ESP, 6,   1,  N|R, MN, "RFC 8247 s2.4" },
	{ ESP, 12,  23, R,   SN, "RFC 8247 s2.4" },
	{ IKE, 7,   2,  N|R, SN, "RFC 8247 s2.4" },
	{ ESP, 6,   36, 0,   NL, NULL },		/* ML-KEM-768 */
	{ ESP, 6,   0,  0,   NL, NULL },		/* NONE */
	/* RFC 8247 s3.1 / s3.2 -- authentication */
	{ IKE, IKE_DEPR_T_AUTH_METHOD, 1,  0,   NL, NULL },	/* RSA: MUST */
	{ IKE, IKE_DEPR_T_AUTH_METHOD, 2,  0,   NL, NULL },	/* PSK: MUST */
	{ IKE, IKE_DEPR_T_AUTH_METHOD, 3,  N|R, SN, "RFC 8247 s3.1" },
	{ IKE, IKE_DEPR_T_AUTH_METHOD, 9,  0,   NL, NULL },
	{ IKE, IKE_DEPR_T_AUTH_METHOD, 14, 0,   NL, NULL },
	{ IKE, IKE_DEPR_T_SIG_HASH, 1, N|R, MN, "RFC 8247 s3.2" },
	{ IKE, IKE_DEPR_T_SIG_HASH, 2, 0,   NL, NULL },
	{ IKE, IKE_DEPR_T_SIG_HASH, 5, 0,   NL, NULL },	/* Identity */
	{ IKE, IKE_DEPR_T_SIG_LEGACY, 1, N, NL, NULL },
	/* RFC 8221 s6 -- AUTH_NONE only with AEAD */
	{ ESP, IKE_DEPR_T_COMBO, 1, R, MN, "RFC 8221 s6" },
	{ AH,  IKE_DEPR_T_COMBO, 1, R, MN, "RFC 8221 s6" },
	{ IKE, IKE_DEPR_T_COMBO, 1, 0, NL, NULL },
	/* IKEv1 itself (RFC 9395 s3) -- RFC class only, never NSA */
	{ V1,  IKE_DEPR_T_V1_PROTO, 1, R, DP, "RFC 9395 s3" },
	{ IKE, IKE_DEPR_T_V1_PROTO, 1, 0, NL, NULL },
	/* IKEv1 Phase 1 encryption (RFC 2409 App A class 1) */
	{ V1,  V1E, 1,  N|R, DP, "RFC 9395 s3" },	/* DES */
	{ V1,  V1E, 2,  R,   DP, "RFC 9395 s5" },	/* IDEA */
	{ V1,  V1E, 3,  R,   DP, "RFC 9395 s5" },	/* Blowfish */
	{ V1,  V1E, 4,  R,   DP, "RFC 9395 s5" },	/* RC5 */
	{ V1,  V1E, 5,  N|R, DP, "RFC 9395 s3" },	/* 3DES */
	{ V1,  V1E, 6,  R,   DP, "RFC 9395 s5" },	/* CAST */
	{ V1,  V1E, 7,  0,   NL, NULL },		/* AES (IKEv2 7 = BLOWFISH) */
	{ V1,  V1E, 8,  0,   NL, NULL },		/* Camellia */
	/* IKEv1 hash (class 2) */
	{ V1,  V1H, 1,  N|R, DP, "RFC 9395 s3" },	/* MD5 */
	{ V1,  V1H, 2,  N,   NL, NULL },		/* SHA */
	{ V1,  V1H, 3,  R,   DP, "RFC 9395 s5" },	/* Tiger */
	{ V1,  V1H, 4,  0,   NL, NULL },		/* SHA2-256 */
	{ V1,  V1H, 6,  0,   NL, NULL },		/* SHA2-512 */
	/* IKEv1 auth method (class 3) */
	{ V1,  V1A, 1,  0,   NL, NULL },		/* PSK */
	{ V1,  V1A, 2,  N|R, DP, "RFC 9395 s3" },	/* DSS */
	{ V1,  V1A, 3,  0,   NL, NULL },		/* RSA sig */
	/* IKEv1 group description (class 4; Phase 2 PFS too) */
	{ V1,  T_K, 1,  N|R, DP, "RFC 9395 s3" },
	{ V1,  T_K, 2,  N|R, DP, "RFC 9395 s3" },
	{ V1,  T_K, 5,  N|R, DP, "RFC 9395 s3" },
	{ V1,  T_K, 14, 0,   NL, NULL },
	{ V1,  T_K, 22, R,   DP, "RFC 9395 s3" },
	{ V1,  T_K, 23, R,   DP, "RFC 9395 s3" },
	{ V1,  T_K, 24, R,   DP, "RFC 9395 s3" },
	/* IKEv1 contexts never borrow the IKEv2 rows */
	{ V1,  T_E, 2,  0,   NL, NULL },
	{ V1,  T_P, 1,  0,   NL, NULL },
	{ IKE, V1E, 1,  0,   NL, NULL },
	/* IKEv1 Phase 2 auth attribute (RFC 2407 s4.5), RFC 8221 s6 */
	{ ESP, V1P, 1,  N|R, MN, "RFC 8221 s6" },	/* HMAC-MD5 */
	{ AH,  V1P, 1,  N|R, MN, "RFC 8221 s6" },
	{ ESP, V1P, 2,  N,   NL, NULL },		/* HMAC-SHA */
	{ AH,  V1P, 3,  N|R, MN, "RFC 8221 s6" },	/* DES-MAC */
	{ ESP, V1P, 4,  N|R, MN, "RFC 8221 s6" },	/* KPDK */
	{ ESP, V1P, 5,  0,   NL, NULL },		/* HMAC-SHA2-256 */
	{ ESP, V1P, 6,  0,   NL, NULL },		/* 384 (IKEv2 6 = MD5_128) */
	{ AH,  V1P, 7,  0,   NL, NULL },		/* 512 (IKEv2 7 = SHA1_160) */
	{ V1,  V1P, 1,  0,   NL, NULL },		/* not a Phase 1 type */
	/* bad context never classifies */
	{ 0,   T_E, 2,  0,   NL, NULL },
	{ 5,   T_E, 2,  0,   NL, NULL },
};

int
main(void)
{
	size_t i;
	int fail = 0, n = 0;
	struct ike_depr_info info;
	const struct ike_depr_entry *e;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		const struct expect *c = &cases[i];
		unsigned int got;

		got = ike_depr_classify(c->ctx, c->type, c->id, &info);
		++n;
		if (got != c->classes || info.classes != c->classes ||
		    info.rfc_level != c->level ||
		    (c->cite == NULL) != (info.rfc_cite == NULL) ||
		    (c->cite && strcmp(c->cite, info.rfc_cite) != 0) ||
		    (c->classes && !info.name)) {
			printf("deprtest: FAIL ctx=%s type=%s id=%u: "
			       "classes 0x%x (want 0x%x) level %s (want %s) "
			       "cite %s (want %s)\n",
			       ike_depr_ctx_str(c->ctx),
			       ike_depr_type_str(c->type), c->id, got,
			       c->classes, ike_depr_level_str(info.rfc_level),
			       ike_depr_level_str(c->level),
			       info.rfc_cite ? info.rfc_cite : "-",
			       c->cite ? c->cite : "-");
			++fail;
		}
	}

	/* every daemon-table row must be covered by an expectation (a row
	 * added without a test fails here) and be internally consistent:
	 * RFC rows carry a level + citation, non-RFC rows carry neither. */
	for (i = 0; (e = ike_depr_entry((int)i)) != NULL; ++i) {
		size_t k;
		int covered = 0;

		if ((e->classes & IKE_DEPR_RFC) &&
		    (e->rfc_level == IKE_DEPR_LVL_NONE || !e->rfc_cite)) {
			printf("deprtest: FAIL table row %s: RFC class without "
			       "level/citation\n", e->name);
			++fail;
		}
		if (!(e->classes & IKE_DEPR_RFC) &&
		    (e->rfc_level != IKE_DEPR_LVL_NONE || e->rfc_cite)) {
			printf("deprtest: FAIL table row %s: level/citation "
			       "without RFC class\n", e->name);
			++fail;
		}
		for (k = 0; k < sizeof(cases) / sizeof(cases[0]); ++k) {
			const struct expect *c = &cases[k];
			unsigned int ct = c->type;

			if (ct >= 6 && ct <= 12)
				ct = IKE_DEPR_T_KE;
			if (ct == e->type && c->id == e->id &&
			    c->ctx >= 1 && (e->ctxmask & (1u << c->ctx)))
				covered = 1;
		}
		if (!covered) {
			printf("deprtest: FAIL table row %s (type %s id %u) has "
			       "no expectation\n", e->name,
			       ike_depr_type_str(e->type), e->id);
			++fail;
		}
	}

	printf("deprtest: %d cases, %d table rows, %d failures\n", n, (int)i,
	       fail);
	return fail ? 1 : 0;
}
