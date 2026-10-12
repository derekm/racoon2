/*
 * iked/ike_deprecated.h -- deprecated-transform classification.
 *
 * Two independent classes, each with its own config switch
 * (allow_nsa_deprecated / allow_rfc_deprecated, remote ikev2 clause,
 * global via the default clause; see doc/nsa-ipsec-hardening.md s8):
 *
 *   IKE_DEPR_NSA  NSA "Securing / Configuring IPsec VPNs" (CNSSP-15):
 *                 DES/3DES, MD5, SHA-1, MODP 768/1024/1536.
 *   IKE_DEPR_RFC  IETF requirement levels: RFC 8247 (IKEv2), RFC 8221
 *                 (ESP/AH), RFC 9395 s5 (IANA DEPRECATED).  Each entry
 *                 keeps its level (MUST NOT / SHOULD NOT / DEPRECATED)
 *                 and the section it comes from.
 *
 * An algorithm may be in both classes.  The lookup is keyed by the IANA
 * IKEv2 registries (transform type + transform id), so the same table
 * serves config check (RCT code -> transform id) and negotiation (the
 * peer's wire transform).  Pure table: no iked state, links standalone
 * (deprtest).
 */
#ifndef IKE_DEPRECATED_H
#define IKE_DEPRECATED_H

#define	IKE_DEPR_NSA		0x01
#define	IKE_DEPR_RFC		0x02

/* RFC requirement level of an RFC-class entry */
#define	IKE_DEPR_LVL_NONE	0
#define	IKE_DEPR_LVL_SHOULD_NOT	1
#define	IKE_DEPR_LVL_MUST_NOT	2
#define	IKE_DEPR_LVL_DEPRECATED	3	/* RFC 9395 s5 / IANA "DEPRECATED" */

/* protocol context: the RFC level of one codepoint differs between IKE
 * (RFC 8247) and ESP/AH (RFC 8221), e.g. ENCR_3DES is MAY for IKE but
 * SHOULD NOT for ESP, ENCR_NULL is MUST NOT for IKE but MUST for ESP. */
#define	IKE_DEPR_CTX_IKE	1
#define	IKE_DEPR_CTX_ESP	2
#define	IKE_DEPR_CTX_AH		3

/* key types: IANA transform types 1..4 (ADDKE1..7 = 6..12 share the
 * type-4 Key Exchange Method registry and are folded onto 4), plus
 * pseudo types for the authentication side. */
#define	IKE_DEPR_T_ENCR		1
#define	IKE_DEPR_T_PRF		2
#define	IKE_DEPR_T_INTEG	3
#define	IKE_DEPR_T_KE		4
#define	IKE_DEPR_T_AUTH_METHOD	0x100	/* IKEv2 Auth Method registry */
#define	IKE_DEPR_T_SIG_HASH	0x101	/* RFC 7427 hash (method 14) */
#define	IKE_DEPR_T_SIG_LEGACY	0x102	/* id 1: AUTH method 1 SHA-1 DigestInfo */
#define	IKE_DEPR_T_COMBO	0x103	/* id 1: ESP/AH AUTH_NONE + non-AEAD ENCR */

struct ike_depr_info {
	unsigned int classes;	/* IKE_DEPR_NSA | IKE_DEPR_RFC */
	int rfc_level;		/* IKE_DEPR_LVL_* (RFC class only) */
	const char *rfc_cite;	/* "RFC 8247 s2.4" (RFC class only) */
	const char *name;	/* IANA name, e.g. "ENCR_3DES" */
};

/* Classify (ctx, type, id).  Fills *out (may be NULL) and returns the
 * class mask; 0 = not deprecated in either class. */
unsigned int ike_depr_classify(int ctx, unsigned int type, unsigned int id,
			       struct ike_depr_info *out);
const char *ike_depr_level_str(int level);
const char *ike_depr_ctx_str(int ctx);
const char *ike_depr_type_str(unsigned int type);

/* iteration for the unit test / docs: returns entry i or NULL */
struct ike_depr_entry {
	unsigned int ctxmask;	/* 1 << IKE_DEPR_CTX_* */
	unsigned int type;
	unsigned int id;
	unsigned int classes;
	int rfc_level;
	const char *rfc_cite;
	const char *name;
};
const struct ike_depr_entry *ike_depr_entry(int i);

#endif /* IKE_DEPRECATED_H */
