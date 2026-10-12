/*
 * iked/ike_deprecated.c -- deprecated-transform classification table.
 * See ike_deprecated.h and doc/nsa-ipsec-hardening.md s8.
 *
 * Every RFC-class row was checked against the RFC text:
 *   RFC 8247 (IKEv2 algorithm requirements):
 *     s2.1 ENCR: ENCR_DES MUST NOT, ENCR_NULL MUST NOT (also RFC 7296 s5),
 *          ENCR_3DES MAY (so 3DES is NOT RFC-deprecated for IKE).
 *     s2.2 PRF: PRF_HMAC_MD5 MUST NOT (PRF_HMAC_SHA1 is MUST-).
 *     s2.3 INTEG: AUTH_HMAC_MD5_96, AUTH_DES_MAC, AUTH_KPDK_MD5 MUST NOT
 *          (AUTH_HMAC_SHA1_96 is MUST-).
 *     s2.4 KE: groups 1, 22 MUST NOT; 2, 5, 23, 24 SHOULD NOT.
 *     s3.1 Auth method: 3 (DSS) SHOULD NOT.
 *     s3.2 Digital Signature (method 14) hash: SHA1 MUST NOT.
 *   RFC 8221 (ESP/AH algorithm requirements):
 *     s5 ENCR: DES_IV64, DES, BLOWFISH, 3IDEA, DES_IV32 MUST NOT;
 *          3DES SHOULD NOT (ENCR_NULL is MUST for ESP).
 *     s6 INTEG: AUTH_HMAC_MD5_96, AUTH_DES_MAC, AUTH_KPDK_MD5 MUST NOT;
 *          AUTH_NONE MUST NOT unless the ENCR is AEAD (AUTH_HMAC_SHA1_96
 *          is MUST-).
 *   RFC 9395 s5 (IANA status DEPRECATED): ENCR_DES_IV64, RC5, IDEA,
 *     CAST, BLOWFISH, 3IDEA, DES_IV32; PRF_HMAC_TIGER; AUTH_HMAC_MD5_128,
 *     AUTH_HMAC_SHA1_160.
 *
 * NSA-class rows reproduce the historic nsa_deprecated_alg() set (DES,
 * 3DES, HMAC-MD5/MD5, HMAC-SHA1/SHA-1, MODP 768/1024/1536) on the wire
 * codepoints that carry those primitives, plus the SHA-1 signatures
 * (DSS, method-1 SHA-1 DigestInfo, method-14 SHA-1).
 */
#include <stddef.h>

#include "ike_deprecated.h"

#define	C(x)	(1u << (x))
#define	IKE	C(IKE_DEPR_CTX_IKE)
#define	ESP	C(IKE_DEPR_CTX_ESP)
#define	AH	C(IKE_DEPR_CTX_AH)
#define	CHILD	(ESP | AH)
#define	ALL	(IKE | ESP | AH)

#define	N	IKE_DEPR_NSA
#define	R	IKE_DEPR_RFC
#define	MN	IKE_DEPR_LVL_MUST_NOT
#define	SN	IKE_DEPR_LVL_SHOULD_NOT
#define	DP	IKE_DEPR_LVL_DEPRECATED
#define	NL	IKE_DEPR_LVL_NONE

static const struct ike_depr_entry depr_table[] = {
	/* Transform Type 1 - Encryption */
	{ IKE,	IKE_DEPR_T_ENCR, 1,  N|R, DP, "RFC 9395 s5",  "ENCR_DES_IV64" },
	{ ESP,	IKE_DEPR_T_ENCR, 1,  N|R, MN, "RFC 8221 s5",  "ENCR_DES_IV64" },
	{ IKE,	IKE_DEPR_T_ENCR, 2,  N|R, MN, "RFC 8247 s2.1", "ENCR_DES" },
	{ ESP,	IKE_DEPR_T_ENCR, 2,  N|R, MN, "RFC 8221 s5",  "ENCR_DES" },
	{ IKE,	IKE_DEPR_T_ENCR, 3,  N,   NL, NULL,           "ENCR_3DES" },
	{ ESP,	IKE_DEPR_T_ENCR, 3,  N|R, SN, "RFC 8221 s5",  "ENCR_3DES" },
	{ IKE|ESP, IKE_DEPR_T_ENCR, 4, R, DP, "RFC 9395 s5",  "ENCR_RC5" },
	{ IKE|ESP, IKE_DEPR_T_ENCR, 5, R, DP, "RFC 9395 s5",  "ENCR_IDEA" },
	{ IKE|ESP, IKE_DEPR_T_ENCR, 6, R, DP, "RFC 9395 s5",  "ENCR_CAST" },
	{ IKE,	IKE_DEPR_T_ENCR, 7,  R,   DP, "RFC 9395 s5",  "ENCR_BLOWFISH" },
	{ ESP,	IKE_DEPR_T_ENCR, 7,  R,   MN, "RFC 8221 s5",  "ENCR_BLOWFISH" },
	{ IKE,	IKE_DEPR_T_ENCR, 8,  R,   DP, "RFC 9395 s5",  "ENCR_3IDEA" },
	{ ESP,	IKE_DEPR_T_ENCR, 8,  R,   MN, "RFC 8221 s5",  "ENCR_3IDEA" },
	{ IKE,	IKE_DEPR_T_ENCR, 9,  N|R, DP, "RFC 9395 s5",  "ENCR_DES_IV32" },
	{ ESP,	IKE_DEPR_T_ENCR, 9,  N|R, MN, "RFC 8221 s5",  "ENCR_DES_IV32" },
	{ IKE,	IKE_DEPR_T_ENCR, 11, R,   MN, "RFC 8247 s2.1", "ENCR_NULL" },

	/* Transform Type 2 - PRF (IKE only) */
	{ IKE,	IKE_DEPR_T_PRF, 1,   N|R, MN, "RFC 8247 s2.2", "PRF_HMAC_MD5" },
	{ IKE,	IKE_DEPR_T_PRF, 2,   N,   NL, NULL,           "PRF_HMAC_SHA1" },
	{ IKE,	IKE_DEPR_T_PRF, 3,   R,   DP, "RFC 9395 s5",  "PRF_HMAC_TIGER" },

	/* Transform Type 3 - Integrity */
	{ IKE,	IKE_DEPR_T_INTEG, 1, N|R, MN, "RFC 8247 s2.3", "AUTH_HMAC_MD5_96" },
	{ CHILD, IKE_DEPR_T_INTEG, 1, N|R, MN, "RFC 8221 s6", "AUTH_HMAC_MD5_96" },
	{ ALL,	IKE_DEPR_T_INTEG, 2, N,   NL, NULL,           "AUTH_HMAC_SHA1_96" },
	{ IKE,	IKE_DEPR_T_INTEG, 3, N|R, MN, "RFC 8247 s2.3", "AUTH_DES_MAC" },
	{ CHILD, IKE_DEPR_T_INTEG, 3, N|R, MN, "RFC 8221 s6", "AUTH_DES_MAC" },
	{ IKE,	IKE_DEPR_T_INTEG, 4, N|R, MN, "RFC 8247 s2.3", "AUTH_KPDK_MD5" },
	{ CHILD, IKE_DEPR_T_INTEG, 4, N|R, MN, "RFC 8221 s6", "AUTH_KPDK_MD5" },
	{ ALL,	IKE_DEPR_T_INTEG, 6, N|R, DP, "RFC 9395 s5",  "AUTH_HMAC_MD5_128" },
	{ ALL,	IKE_DEPR_T_INTEG, 7, N|R, DP, "RFC 9395 s5",  "AUTH_HMAC_SHA1_160" },

	/* Transform Type 4 - Key Exchange Method (also child PFS and the
	 * RFC 9370 ADDKE1..7 types, which share this registry) */
	{ ALL,	IKE_DEPR_T_KE, 1,    N|R, MN, "RFC 8247 s2.4", "MODP768 (group 1)" },
	{ ALL,	IKE_DEPR_T_KE, 2,    N|R, SN, "RFC 8247 s2.4", "MODP1024 (group 2)" },
	{ ALL,	IKE_DEPR_T_KE, 5,    N|R, SN, "RFC 8247 s2.4", "MODP1536 (group 5)" },
	{ ALL,	IKE_DEPR_T_KE, 22,   R,   MN, "RFC 8247 s2.4", "MODP1024_160POS (group 22)" },
	{ ALL,	IKE_DEPR_T_KE, 23,   R,   SN, "RFC 8247 s2.4", "MODP2048_224POS (group 23)" },
	{ ALL,	IKE_DEPR_T_KE, 24,   R,   SN, "RFC 8247 s2.4", "MODP2048_256POS (group 24)" },

	/* Authentication */
	{ IKE,	IKE_DEPR_T_AUTH_METHOD, 3, N|R, SN, "RFC 8247 s3.1",
	  "AUTH method 3 (DSS, SHA-1)" },
	{ IKE,	IKE_DEPR_T_SIG_HASH, 1, N|R, MN, "RFC 8247 s3.2",
	  "RFC 7427 hash SHA1" },
	{ IKE,	IKE_DEPR_T_SIG_LEGACY, 1, N, NL, NULL,
	  "AUTH method 1 (RSA) with SHA-1 DigestInfo" },

	/* ESP/AH combination rule */
	{ CHILD, IKE_DEPR_T_COMBO, 1, R, MN, "RFC 8221 s6",
	  "AUTH_NONE with non-AEAD ENCR" },
};

#define	NENTRIES	(sizeof(depr_table) / sizeof(depr_table[0]))

const struct ike_depr_entry *
ike_depr_entry(int i)
{
	if (i < 0 || (size_t)i >= NENTRIES)
		return NULL;
	return &depr_table[i];
}

unsigned int
ike_depr_classify(int ctx, unsigned int type, unsigned int id,
		  struct ike_depr_info *out)
{
	unsigned int classes = 0;
	size_t i;

	if (out) {
		out->classes = 0;
		out->rfc_level = IKE_DEPR_LVL_NONE;
		out->rfc_cite = NULL;
		out->name = NULL;
	}
	if (ctx < IKE_DEPR_CTX_IKE || ctx > IKE_DEPR_CTX_AH)
		return 0;
	/* RFC 9370: ADDKE1..ADDKE7 (types 6..12) use the type-4 registry */
	if (type >= 6 && type <= 12)
		type = IKE_DEPR_T_KE;
	for (i = 0; i < NENTRIES; ++i) {
		const struct ike_depr_entry *e = &depr_table[i];

		if (e->type != type || e->id != id ||
		    !(e->ctxmask & C(ctx)))
			continue;
		classes |= e->classes;
		if (out) {
			out->name = e->name;
			if (e->classes & IKE_DEPR_RFC) {
				out->rfc_level = e->rfc_level;
				out->rfc_cite = e->rfc_cite;
			}
		}
	}
	if (out)
		out->classes = classes;
	return classes;
}

const char *
ike_depr_level_str(int level)
{
	switch (level) {
	case IKE_DEPR_LVL_MUST_NOT:
		return "MUST NOT";
	case IKE_DEPR_LVL_SHOULD_NOT:
		return "SHOULD NOT";
	case IKE_DEPR_LVL_DEPRECATED:
		return "DEPRECATED";
	}
	return "-";
}

const char *
ike_depr_ctx_str(int ctx)
{
	switch (ctx) {
	case IKE_DEPR_CTX_IKE:
		return "IKE";
	case IKE_DEPR_CTX_ESP:
		return "ESP";
	case IKE_DEPR_CTX_AH:
		return "AH";
	}
	return "?";
}

const char *
ike_depr_type_str(unsigned int type)
{
	if (type >= 6 && type <= 12)
		return "ADDKE";
	switch (type) {
	case IKE_DEPR_T_ENCR:
		return "ENCR";
	case IKE_DEPR_T_PRF:
		return "PRF";
	case IKE_DEPR_T_INTEG:
		return "INTEG";
	case IKE_DEPR_T_KE:
		return "KE";
	case IKE_DEPR_T_AUTH_METHOD:
		return "AUTH";
	case IKE_DEPR_T_SIG_HASH:
		return "SIGHASH";
	case IKE_DEPR_T_SIG_LEGACY:
		return "SIG";
	case IKE_DEPR_T_COMBO:
		return "COMBO";
	}
	return "?";
}
