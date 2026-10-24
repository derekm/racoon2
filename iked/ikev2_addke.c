/*
 * Copyright (c) 2026
 *	Yasuyuki Goda and the racoon2 project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * RFC 9370 Additional Key Exchange (ADDKE) support.
 *
 * STAGE 2 complete: ML-KEM-512/768/1024 crypto (EVP_PKEY), config-driven
 * negotiation (esp_addke_alg / ah_addke_alg), the responder-side
 * IKE_FOLLOWUP_KE state machine, initiator-side followup, the
 * IKE-SA-rekey SKEYSEED feed, multi-round sequential ADDKE, rekey
 * collision TEMPORARY_FAILURE, and the addke_required downgrade gate.
 *
 * Whether a child actually negotiates ADDKE is a config decision (the
 * sa block's addke_alg list); ikev2_addke_selectable() is now only a
 * capability probe for builds with the ML-KEM backend.
 *
 * Build gate: WITH_ADDKE is set by configure when <openssl/ml_kem.h>
 * exists (OpenSSL >= 3.5).  Without it the whole file compiles to
 * nothing and iked rejects type-6 proposals as before.
 */

#include "config.h"

#ifdef WITH_ADDKE

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>		/* errno — NetBSD 11 / gcc requires the public header */
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/evp.h>
#include <openssl/ml_kem.h>
#include <openssl/crypto.h>	/* OPENSSL_cleanse */

#include "racoon.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "dhgroup.h"
#include "oakley.h"
#include "ike_conf.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "crypto_impl.h"	/* random_bytes() — mint fresh per-round links */
#include "debug.h"		/* TRACE() */
#include "plog.h"

/*
 * ML-KEM-768 sizes (OSSL_ML_KEM_768_* in <openssl/ml_kem.h>):
 *   public key   1184 bytes
 *   ciphertext   1088 bytes
 *   shared secret  32 bytes
 */

/*
 * Capability probe: does this build have the crypto backend for RFC
 * 9370 ADDKE?  True when compiled WITH_ADDKE (configure --enable-addke
 * auto: <openssl/ml_kem.h> present, i.e. OpenSSL >= 3.5).
 *
 * Whether a child SA actually NEGOTIATES ADDKE is a config decision:
 * the sa block's addke_alg list (esp_addke_alg { mlkem768; }).
 * ikev2_ipsec_sa_to_proplist emits the type-6 transform only when the
 * policy lists one; the generic matcher then selects/echoes it with no
 * further gating here.
 */
int
ikev2_addke_selectable(void)
{
#ifdef WITH_ADDKE
	return 1;
#else
	return 0;
#endif
}

/*
 * ML-KEM parameter sets (FIPS 203), indexed by IKEv2 transform id
 * (IANA Transform Type 4 / KE method registry: 35=512, 36=768,
 * 37=1024; draft-ietf-ipsecme-ikev2-mlkem-09).
 */
struct ikev2_addke_mlkem_param {
	unsigned int transform_id;
	const char *evp_name;		/* EVP_PKEY_CTX_new_from_name */
	int nid;			/* EVP_PKEY_new_raw_public_key */
	size_t pub_len;
	size_t ct_len;
};

static const struct ikev2_addke_mlkem_param ikev2_addke_mlkem_params[] = {
	{ IKEV2TRANSF_ADDKE_MLKEM512, "ML-KEM-512", NID_ML_KEM_512,
	  OSSL_ML_KEM_512_PUBLIC_KEY_BYTES, OSSL_ML_KEM_512_CIPHERTEXT_BYTES },
	{ IKEV2TRANSF_ADDKE_MLKEM768, "ML-KEM-768", NID_ML_KEM_768,
	  OSSL_ML_KEM_768_PUBLIC_KEY_BYTES, OSSL_ML_KEM_768_CIPHERTEXT_BYTES },
	{ IKEV2TRANSF_ADDKE_MLKEM1024, "ML-KEM-1024", NID_ML_KEM_1024,
	  OSSL_ML_KEM_1024_PUBLIC_KEY_BYTES, OSSL_ML_KEM_1024_CIPHERTEXT_BYTES },
	{ 0, NULL, 0, 0, 0 }
};

static const struct ikev2_addke_mlkem_param *
ikev2_addke_mlkem_param(unsigned int transform_id)
{
	const struct ikev2_addke_mlkem_param *p;

	for (p = ikev2_addke_mlkem_params; p->transform_id != 0; ++p)
		if (p->transform_id == transform_id)
			return p;
	return NULL;
}

/*
 * RFC 9370 ADDKE rounds may carry any KE method (transform id shares the
 * Transform Type 4 / KE-method registry): ML-KEM ids 35/36/37 are a KEM,
 * any classical DH group id (19=ECP256, 14=MODP2048, 31=CURVE25519, ...)
 * is a classical key exchange where BOTH sides send their public value in
 * the KE payload and each computes g^xy from its own generated keypair and
 * the peer's public value (standard IKEv2 DH).  The round engine below
 * dispatches on whether the method is ML-KEM or classical.
 */
int
ikev2_addke_method_is_mlkem(unsigned int transform_id)
{
	return ikev2_addke_mlkem_param(transform_id) != NULL;
}
/* dhgroup for a classical ADDKE method id, or NULL if not a DH group. */
const struct dhgroup *
ikev2_addke_method_dhgroup(unsigned int transform_id)
{
	struct algdef *def;

	if (ikev2_addke_method_is_mlkem(transform_id))
		return NULL;
	def = ikev2_dhinfo(transform_id);
	if (def == NULL || def->definition == NULL)
		return NULL;
	return (const struct dhgroup *)def->definition;
}

/*
 * Generate this ADDKE round's keypair and store the private round state.
 * The public value is returned in *pub (the KEi payload).  ML-KEM keeps an
 * EVP_PKEY in child_sa->addke_priv; a classical DH group keeps the group
 * plus our public/private values (addke_dh / addke_dh_pub / addke_dh_priv)
 * so the followup completion can compute g^xy against the peer's value.
 * Also records the method for the round.  Returns 0 / -1 and leaves *pub
 * NULL on failure.
 */
int
ikev2_addke_round_keygen(struct ikev2_child_sa *child_sa,
			 unsigned int method, rc_vchar_t **pub)
{
	*pub = NULL;
	if (ikev2_addke_method_is_mlkem(method)) {
		EVP_PKEY *kp = NULL;

		if (ikev2_addke_mlkem_keygen(method, pub, &kp) < 0 ||
		    !*pub || !kp) {
			rc_vfree(*pub);
			*pub = NULL;
			EVP_PKEY_free(kp);
			return -1;
		}
		child_sa->addke_priv = kp;
	} else {
		const struct dhgroup *dh =
		    ikev2_addke_method_dhgroup(method);
		rc_vchar_t *priv = NULL;

		if (dh == NULL)
			return -1;
		if (oakley_dh_generate((struct dhgroup *)dh, pub,
				       &priv) < 0 || !*pub || !priv) {
			rc_vfree(*pub);
			rc_vfreez(priv);
			*pub = NULL;
			return -1;
		}
		child_sa->addke_dh = dh;
		child_sa->addke_dh_priv = priv;
		/* keep a copy of our public value for the g^xy compute */
		child_sa->addke_dh_pub = rc_vnew((*pub)->v, (*pub)->l);
		if (child_sa->addke_dh_pub == NULL) {
			rc_vfree(*pub);
			rc_vfreez(priv);
			child_sa->addke_dh_priv = NULL;
			*pub = NULL;
			return -1;
		}
	}
	child_sa->addke_method = method;
	return 0;
}

/*
 * Release this ADDKE round's private state -- the ML-KEM EVP_PKEY or the
 * classical-DH group/public/private values -- and NULL every field, so a
 * later caller (the next round's keygen, an error path, or child-SA
 * teardown) never sees a dangling pointer.  Safe to call repeatedly.
 * rc_vfreez() takes its argument by value and cannot clear the caller's
 * pointer, which is why each field is reset here explicitly.
 */
void
ikev2_addke_round_state_clear(struct ikev2_child_sa *child_sa)
{
	if (child_sa == NULL)
		return;
	if (child_sa->addke_priv) {
		EVP_PKEY_free((EVP_PKEY *)child_sa->addke_priv);
		child_sa->addke_priv = NULL;
	}
	if (child_sa->addke_dh_pub) {
		rc_vfreez(child_sa->addke_dh_pub);
		child_sa->addke_dh_pub = NULL;
	}
	if (child_sa->addke_dh_priv) {
		rc_vfreez(child_sa->addke_dh_priv);
		child_sa->addke_dh_priv = NULL;
	}
	child_sa->addke_dh = NULL;
}

/*
 * Generate an ML-KEM keypair for the given transform id.  Public key
 * is written to *pub (caller frees); key returned via **pkey
 * (EVP_PKEY_free).  Returns 0 on success, -1 on failure.
 */
int
ikev2_addke_mlkem_keygen(unsigned int transform_id, rc_vchar_t **pub,
			 EVP_PKEY **pkey)
{
	const struct ikev2_addke_mlkem_param *param;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *kp = NULL;
	unsigned char *buf;
	size_t publen;
	int r = -1;

	*pub = NULL;
	*pkey = NULL;

	param = ikev2_addke_mlkem_param(transform_id);
	if (param == NULL)
		return -1;
	buf = racoon_malloc(param->pub_len);
	if (buf == NULL)
		return -1;
	publen = param->pub_len;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, param->evp_name, NULL);
	if (ctx == NULL)
		goto done;
	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto done;
	if (EVP_PKEY_keygen(ctx, &kp) <= 0)
		goto done;
	if (EVP_PKEY_get_raw_public_key(kp, buf, &publen) <= 0)
		goto done;

	*pub = rc_vnew(buf, publen);
	*pkey = kp;
	r = 0;
      done:
	EVP_PKEY_CTX_free(ctx);
	racoon_free(buf);
	if (r < 0)
		EVP_PKEY_free(kp);
	return r;
}

/*
 * Encapsulate: produce a ciphertext for the peer's public key and the
 * 32-byte shared secret.  Returns 0 / -1.
 */
int
ikev2_addke_mlkem_encap(unsigned int transform_id, rc_vchar_t *peer_pub,
			rc_vchar_t **ct, rc_vchar_t **shared)
{
	const struct ikev2_addke_mlkem_param *param;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *peer = NULL;
	unsigned char *ctbuf;
	unsigned char ssbuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
	size_t ctlen, sslen = sizeof(ssbuf);
	int r = -1;

	*ct = NULL;
	*shared = NULL;

	param = ikev2_addke_mlkem_param(transform_id);
	if (param == NULL || peer_pub == NULL ||
	    peer_pub->l != param->pub_len)
		return -1;
	ctbuf = racoon_malloc(param->ct_len);
	if (ctbuf == NULL)
		return -1;
	ctlen = param->ct_len;

	peer = EVP_PKEY_new_raw_public_key(param->nid, NULL,
					   peer_pub->v,
					   peer_pub->l);
	if (peer == NULL)
		goto done;
	ctx = EVP_PKEY_CTX_new(peer, NULL);
	if (ctx == NULL)
		goto done;
	if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0)
		goto done;
	if (EVP_PKEY_encapsulate(ctx, ctbuf, &ctlen, ssbuf, &sslen) <= 0)
		goto done;
	if (sslen != OSSL_ML_KEM_SHARED_SECRET_BYTES)
		goto done;

	*ct = rc_vnew(ctbuf, ctlen);
	*shared = rc_vnew(ssbuf, sslen);
	r = 0;
      done:
	OPENSSL_cleanse(ssbuf, sizeof(ssbuf));	/* drop the ML-KEM shared secret */
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peer);
	racoon_free(ctbuf);
	if (r < 0) {
		rc_vfree(*ct);
		*ct = NULL;
		rc_vfree(*shared);
		*shared = NULL;
	}
	return r;
}

/*
 * Decapsulate: recover the shared secret from a ciphertext with our
 * keypair.  Returns 0 / -1.
 */
int
ikev2_addke_mlkem_decap(EVP_PKEY *pkey, rc_vchar_t *ct, rc_vchar_t **shared)
{
	EVP_PKEY_CTX *ctx = NULL;
	unsigned char ssbuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
	size_t sslen = sizeof(ssbuf);
	int r = -1;

	*shared = NULL;
	if (pkey == NULL || ct == NULL)
		return -1;

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (ctx == NULL)
		return -1;
	if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
		goto done;
	if (EVP_PKEY_decapsulate(ctx, ssbuf, &sslen, ct->v, ct->l) <= 0)
		goto done;
	if (sslen != OSSL_ML_KEM_SHARED_SECRET_BYTES)
		goto done;

	*shared = rc_vnew(ssbuf, sslen);
	r = 0;
      done:
	OPENSSL_cleanse(ssbuf, sizeof(ssbuf));	/* drop the ML-KEM shared secret */
	EVP_PKEY_CTX_free(ctx);
	if (r < 0) {
		rc_vfree(*shared);
		*shared = NULL;
	}
	return r;
}

/*
 * Self-test: for each ML-KEM parameter set, keygen -> encap -> decap
 * and check both sides derive the same 32-byte shared secret.
 * Returns 0 on success.  Exposed for the "addketest" check target
 * (WITH_ADDKE builds only).
 */
int
ikev2_addke_selftest(void)
{
	const struct ikev2_addke_mlkem_param *param;
	int r = -1;

	for (param = ikev2_addke_mlkem_params; param->transform_id != 0;
	     ++param) {
		rc_vchar_t *pub = NULL, *ct = NULL, *ss1 = NULL, *ss2 = NULL;
		EVP_PKEY *kp = NULL;

		/* per-iteration verdict; a pass in an earlier set must
		 * not mask a failure in this one */
		r = -1;

		if (ikev2_addke_mlkem_keygen(param->transform_id, &pub, &kp)
		    < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "addke selftest: keygen(%s) failed\n",
			     param->evp_name);
			goto next;
		}
		if (ikev2_addke_mlkem_encap(param->transform_id, pub, &ct,
					    &ss1) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "addke selftest: encapsulate(%s) failed\n",
			     param->evp_name);
			goto next;
		}
		if (ikev2_addke_mlkem_decap(kp, ct, &ss2) < 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "addke selftest: decapsulate(%s) failed\n",
			     param->evp_name);
			goto next;
		}
		if (ss1->l != OSSL_ML_KEM_SHARED_SECRET_BYTES ||
		    ss2->l != OSSL_ML_KEM_SHARED_SECRET_BYTES ||
		    memcmp(ss1->v, ss2->v, OSSL_ML_KEM_SHARED_SECRET_BYTES)
		    != 0) {
			plog(PLOG_INTERR, PLOGLOC, NULL,
			     "addke selftest: shared secrets differ (%s)\n",
			     param->evp_name);
			goto next;
		}
		r = 0;	/* this parameter set passed */
	      next:
		rc_vfree(pub);
		rc_vfree(ct);
		rc_vfreez(ss1);
		rc_vfreez(ss2);
		EVP_PKEY_free(kp);
		if (r < 0)
			break;
	}
	return r;
}

/*
 * RFC 9370 s2.2.4 + draft-ietf-ipsecme-ikev2-mlkem-09:
 *
 * After a CREATE_CHILD_SA that selected an ADDKE transform, the
 * initiator sends IKE_FOLLOWUP_KE (exch 44) requests, one per round:
 *
 *   HDR(IKE_FOLLOWUP_KE), SK { KEi(n), N(ADDITIONAL_KEY_EXCHANGE)(link) }
 *
 * where KEi(n) is a KE payload whose Key Exchange Method field equals
 * the n-th negotiated ADDKE transform ID (36 = ML-KEM-768) carrying the
 * initiator's raw ML-KEM-768 public key (1184 bytes, FIPS 203), and
 * the ADDITIONAL_KEY_EXCHANGE notification (16441) echoes the link the
 * responder issued for this round.  The responder encapsulates against
 * that public key and replies:
 *
 *   HDR(IKE_FOLLOWUP_KE), SK { KEr(n) }            (final round)
 *   HDR(IKE_FOLLOWUP_KE), SK { KEr(n),
 *                              N(ADDITIONAL_KEY_EXCHANGE)(link_{n+1}) }
 *                                                    (non-final round)
 *
 * with KEr(n) carrying the 1088-byte ciphertext (same method field).
 * Per RFC 9370 s2.2.4 the responder mints a FRESH link for EVERY round
 * it expects another followup after (i.e. every non-final response,
 * including the CREATE_CHILD_SA response for round 1 at ikev2_child.c
 * and each IKE_FOLLOWUP_KE response for rounds 2..n-1); the final-round
 * response is KE-only.  The initiator must echo the link received in
 * the LAST response on its next request — not reuse the round-1 link.
 * Both sides accumulate the shared secret from each round into
 * SK(1)||..||SK(n), which appends to the child KEYMAT input after Nr
 * (rfc9370 s2.2.4).
 */

/*
 * Find the pending child_sa whose addke_link matches the
 * ADDITIONAL_KEY_EXCHANGE notification data (the listener state for
 * this followup).  Per rfc9370 s2.2.4 the link data is opaque to the
 * initiator and meaningful only to the responder.
 */
static struct ikev2_child_sa *
followup_ke_find_child(struct ikev2_sa *ike_sa, rc_vchar_t *link,
		       uint16_t ke_method)
{
	struct ikev2_child_sa *sa;
	struct ikev2_child_sa *pending = NULL;
	struct ikev2_child_sa *method_hit = NULL;
	int n_pending = 0;
	int n_method = 0;

	if (link == NULL)
		return NULL;
	for (sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(sa);
	     sa = IKEV2_CHILD_LIST_NEXT(sa)) {
		if (!sa->addke_pending)
			continue;
		n_pending++;
		pending = sa;
		if (sa->addke_method == ke_method) {
			n_method++;
			method_hit = sa;
		}
		if (sa->addke_link && sa->addke_link->l == link->l &&
		    memcmp(sa->addke_link->v, link->v, link->l) == 0)
			return sa;	/* pre-bound link: exact match */
	}
	/*
	 * RFC 9370 s2.2.4: the ADDKE link is chosen by the CREATE_CHILD
	 * initiator and signalled to the peer; the peer (this responder, for
	 * a peer-driven child rekey) must correlate the IKE_FOLLOWUP_KE to
	 * the SA.  A child the responder did not itself create carries a
	 * responder-side link that was never signalled, so the followup
	 * arrives with the peer's link and no exact match is possible.
	 * Correlate by the identifiers that do bind the SA: the sole pending
	 * child, else the sole pending child of this KE method.  Refuse
	 * (STATE_NOT_FOUND) only when genuinely ambiguous — several pending
	 * children of the same method — never guess.
	 */
	if (n_pending == 1)
		/* pending already names the sole child */;
	else if (n_method == 1)
		pending = method_hit;	/* unique method disambiguates */
	else
		pending = NULL;		/* ambiguous across the SA */
	if (!pending)
		return NULL;
	if (pending->addke_link &&
	    (pending->addke_link->l != link->l ||
	     memcmp(pending->addke_link->v, link->v, link->l) != 0)) {
		/* responder-side random link was never signalled: drop it and
		 * adopt the peer's link so the completion is correlated */
		rc_vfreez(pending->addke_link);
		pending->addke_link = NULL;
	}
	if (!pending->addke_link) {
		pending->addke_link = rc_vnew(link->v, link->l);
		if (!pending->addke_link)
			return NULL;
	}
	return pending;
}

/*
 * Initiator side: send the IKE_FOLLOWUP_KE request carrying our
 * ML-KEM public key and the link that ties it to the CREATE_CHILD_SA:
 *
 *   HDR(IKE_FOLLOWUP_KE), SK { KEi(1), N(ADDITIONAL_KEY_EXCHANGE)(link) }
 *
 * The KE payload method equals the negotiated ADDKE id.  Requires a
 * fresh message id (the exchange is independent of the CREATE_CHILD_SA).
 */
int
ikev2_initiator_followup_send(struct ikev2_child_sa *child_sa,
			      rc_vchar_t *pubkey)
{
	struct ikev2_sa *ike_sa = child_sa->parent;
	struct ikev2_payloads payl;
	struct ikev2payl_ke_h keh;
	rc_vchar_t *kei = 0;
	rc_vchar_t *pkt = 0;
	uint32_t message_id;

	if (!child_sa->addke_link || !pubkey)
		return -1;

	ikev2_payloads_init(&payl);
	memset(&keh, 0, sizeof(keh));
	keh.dh_group_id = htons((uint16_t)child_sa->addke_method);
	kei = rc_vprepend(pubkey, &keh, sizeof(keh));
	if (!kei) {
		ikev2_payloads_destroy(&payl);
		return -1;
	}
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, kei, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
						 0, 0,
						 IKEV2_ADDITIONAL_KEY_EXCHANGE,
						 child_sa->addke_link->v,
						 child_sa->addke_link->l),
			    TRUE);

	message_id = ikev2_request_id(ike_sa);
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_FOLLOWUP_KE,
				     (ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0),
				     message_id, ike_sa, &payl);
	rc_vfree(kei);
	ikev2_payloads_destroy(&payl);
	if (!pkt)
		return -1;

	if (ikev2_transmit(ike_sa, pkt) != 0)
		return -1;
	/* ikev2_transmit() takes ownership of and frees pkt (same convention as
	 * ikev2.c:1226 — callers never rc_vfree it again).  The old `rc_vfree(pkt)`
	 * here double-freed the transmit-owned buffer: the iked<->iked isolated
	 * matrix hit `free(): invalid pointer` on the initiator's IKE_FOLLOWUP_KE
	 * exactly at this line. */
	child_sa->addke_followup_msgid = message_id;
	return 0;
}

/*
 * After the IKE_FOLLOWUP_KE response is processed and the send window is
 * committed, start the next queued request.  Completing the ADDKE install
 * queues the DELETE of the rekeyed child (or of the old IKE SA) while this
 * response still holds the window, so ikev2_request_initiator_start() could
 * not send it.  The generic response path (ikev2.c, informational and
 * CREATE_CHILD responses) wakes the next pending child at this point; the
 * followup path returned without doing so, and the DELETE then waited for
 * the next unrelated exchange (DPD or the next rekey) while the old SAs
 * stayed installed on both peers (RFC 7296 s2.8: the rekey initiator
 * deletes the old SA once the new one is in place).
 */
static void
ikev2_followup_wakeup_next(struct ikev2_sa *ike_sa)
{
	struct ikev2_child_sa *next_child_sa;

	next_child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (next_child_sa)
		ikev2_wakeup_child_sa(next_child_sa);
}

/*
 * Initiator side: complete one ADDKE round once the followup response
 * carried the peer's KEr ciphertext.  Decapsulate to this round's shared
 * secret, append it to the accumulated SK(1..n).  If more ADDKE rounds
 * remain (multi-round, RFC 9370 s2.2.1), generate the next round's keypair
 * and send its IKE_FOLLOWUP_KE, keeping the child pending.  After the last
 * round, install the child with the ADDKE keymat (same path as the
 * responder's deferred install).
 */
int
ikev2_initiator_followup_complete(struct ikev2_child_sa *child_sa,
				  rc_vchar_t *ciphertext)
{
	EVP_PKEY *kp;
	rc_vchar_t *ss = NULL;
	unsigned int method = child_sa->addke_method;
	const struct dhgroup *dh = NULL;

	if (!ciphertext)
		return -1;

	if (ikev2_addke_method_is_mlkem(method)) {
		/* KEM round: decap the ciphertext with our round keypair */
		kp = (EVP_PKEY *)child_sa->addke_priv;
		child_sa->addke_priv = NULL;
		if (!kp)
			return -1;
		if (ikev2_addke_mlkem_decap(kp, ciphertext, &ss) < 0 ||
		    ss == NULL ||
		    ss->l != OSSL_ML_KEM_SHARED_SECRET_BYTES) {
			rc_vfreez(ss);
			EVP_PKEY_free(kp);
			return -1;
		}
		EVP_PKEY_free(kp);
	} else {
		/* classical DH round: the peer-returned value is its public
		 * value; compute g^xy from our stored keypair (RFC 9370
		 * allows classical key exchanges in the rounds) */
		dh = child_sa->addke_dh;
		if (dh == NULL || child_sa->addke_dh_pub == NULL ||
		    child_sa->addke_dh_priv == NULL) {
			return -1;
		}
		if (oakley_dh_compute((struct dhgroup *)dh,
		    child_sa->addke_dh_pub, child_sa->addke_dh_priv,
		    ciphertext, &ss) < 0 || ss == NULL) {
			rc_vfreez(ss);
			return -1;
		}
		/* this round's keypair is consumed; clear (and NULL) the
		 * round state so child teardown cannot free it again */
		ikev2_addke_round_state_clear(child_sa);
	}

	/* append this round's shared secret to SK(1)..SK(n), in order */
	{
		rc_vchar_t *acc;

		acc = rc_vmalloc((child_sa->addke_sk ?
				  child_sa->addke_sk->l : 0) + ss->l);
		if (!acc) {
			rc_vfreez(ss);
			return -1;
		}
		if (child_sa->addke_sk) {
			memcpy(acc->v, child_sa->addke_sk->v,
			       child_sa->addke_sk->l);
			rc_vfreez(child_sa->addke_sk);
			child_sa->addke_sk = 0;
		}
		memcpy(acc->v + acc->l - ss->l, ss->v, ss->l);
		child_sa->addke_sk = acc;
		rc_vfreez(ss);
		ss = 0;
	}

	/* advance the round cursor; install only after the last round */
	++child_sa->addke_round;
	if (child_sa->addke_round < child_sa->addke_nrounds) {
		/* more rounds: keygen next method, send next followup, stay pending */
		rc_vchar_t *pub = NULL;
		unsigned int method =
		    child_sa->addke_methods[child_sa->addke_round];

		if (ikev2_addke_round_keygen(child_sa, method, &pub) < 0 ||
		    !pub) {
			rc_vfree(pub);
			return -1;
		}
		if (ikev2_initiator_followup_send(child_sa, pub) != 0) {
			isakmp_log(child_sa->parent, 0, 0, 0,
			    PLOG_INTERR, PLOGLOC,
			    "failed sending IKE_FOLLOWUP_KE (round %d)\n",
			    child_sa->addke_round);
			rc_vfree(pub);
			ikev2_addke_round_state_clear(child_sa);
			return -1;
		}
		rc_vfree(pub);
		/* re-arm the followup-wait timeout for the next round */
		ikev2_child_addke_arm_timeout(child_sa);
		isakmp_log(child_sa->parent, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
		    "initiator ADDKE round %d/%d done; next followup sent\n",
		    child_sa->addke_round, child_sa->addke_nrounds);
		return 0;
	}

	if (ikev2_child_addke_install(child_sa) < 0) {
		rc_vfreez(child_sa->addke_sk);
		child_sa->addke_sk = NULL;
		return -1;
	}
	/*
	 * RFC 9370 s2.2.4 (initiator side of a child rekey): the
	 * CREATE_CHILD_SA response path defers the rekey-finalize for an
	 * addke_pending child (see ikev2_createchild_initiator_recv), so
	 * now that the ADDKE child is installed with the KEM keymat,
	 * finish it via the shared RFC 7296 §2.8 finalize: deletes the old
	 * child, or on a rekey collision applies the RFC 7296 nonce rule
	 * instead of unconditionally deleting the preceded SA.
	 */
	if (child_sa->preceding_satype != 0)
		ikev2_initiator_rekey_finalize(child_sa->parent, child_sa);
	return 0;
}

void
ikev2_followup_ke_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		       struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *link_notify = 0;
	struct ikev2_child_sa *child_sa = 0;
	rc_vchar_t *peer_ke = 0;
	rc_vchar_t *link = 0;
	rc_vchar_t *ct = 0, *ss = 0;
	uint16_t ke_method;
	int is_response;
	int rekey_link_match = 0;	/* followup links to the pending IKE-SA rekey */
	int type;
	uint32_t saved_mid;

	ikehdr = (struct ikev2_header *)msg->v;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;

	/*
	 * Snapshot the inbound window before the ack below. If the response we
	 * build for this followup fails to transmit, we restore the window so a
	 * retransmit of THIS message id passes the ordering check and re-enters
	 * (the SK deferral makes re-entry safe); without it the window is
	 * consumed and the retransmit is dropped, killing the round.
	 */
	saved_mid = ike_sa->recv_message_id;

	/*
	 * Ack the request's message id in our window (same as
	 * ikev2_createchild_responder_recv): the followup is an
	 * independent exchange and its id must advance the window, or
	 * the peer's next request arrives "unordered" and is dropped.
	 *
	 * The ack must be conditional: ikev2_input validates/advances
	 * recv_message_id only on NON-fragmented messages.  Our
	 * followup routinely carries an 1184-byte ML-KEM public key, so
	 * it arrives IKE-fragmented (RFC 7383) and the ordering check
	 * never ran -- blindly asserting equality here aborts the daemon
	 * (observed live: __assert_fail in ikev2_update_message_id on
	 * the ADDKE rekey followup).  Only advance when the window
	 * actually matches; otherwise log and continue (the fragment
	 * path already established authenticity).
	 */
	if (!is_response) {
		uint32_t fid = get_uint32(&ikehdr->message_id);

		if (ike_sa->recv_message_id == fid)
			ikev2_update_message_id(ike_sa, fid, FALSE);
		else
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_DEBUG, PLOGLOC,
				   "IKE_FOLLOWUP_KE msgid %u (window at %u); "
				   "not advancing (fragmented path)\n",
				   fid, ike_sa->recv_message_id);
	}

	/* We are always the responder for ADDKE at this stage. */
	if (is_response) {
		struct ikev2_payload_header *rp;
		struct ikev2payl_ke *rke = 0;
		struct ikev2_payload_header *rlink = 0;
		struct ikev2_child_sa *rchild = 0;
		rc_vchar_t *rct = 0;
		int rtype;
		uint32_t rmsgid;

		/*
		 * Initiator side: our IKE_FOLLOWUP_KE request got a
		 * response.  Find the pending child (or the initiator
		 * IKE_SA-rekey ADDKE) by the message id we used for the
		 * request, parse the KEr(1) ciphertext, decapsulate to
		 * SK(1), and complete the deferred keymat install.
		 */
		/* parse: SK { KEr(n), [N(ADDITIONAL_KEY_EXCHANGE)(link)] } */
		rp = (struct ikev2_payload_header *)(ikehdr + 1);
		for (rtype = ikehdr->next_payload;
		     rtype != IKEV2_NO_NEXT_PAYLOAD;
		     POINT_NEXT_PAYLOAD(rp, rtype)) {
			if (rtype == IKEV2_PAYLOAD_KE) {
				if (rke) {
					isakmp_log(ike_sa, local, remote, msg,
						   PLOG_PROTOERR, PLOGLOC,
						   "duplicate KE payload\n");
					return;
				}
				rke = (struct ikev2payl_ke *)rp;
			} else if (rtype == IKEV2_PAYLOAD_NOTIFY) {
				struct ikev2payl_notify *nt =
				    (struct ikev2payl_notify *)rp;
				if (get_notify_type(nt) ==
				    IKEV2_ADDITIONAL_KEY_EXCHANGE) {
					if (rlink) {
						isakmp_log(ike_sa, local,
						    remote, msg,
						    PLOG_PROTOERR, PLOGLOC,
						    "duplicate "
						    "ADDITIONAL_KEY_EXCHANGE\n");
						return;
					}
					rlink = rp;
				}
			}
		}
		if (!rke) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "IKE_FOLLOWUP_KE response missing KE\n");
			return;
		}
		rmsgid = get_uint32(&ikehdr->message_id);
		for (rchild = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
		     !IKEV2_CHILD_LIST_END(rchild);
		     rchild = IKEV2_CHILD_LIST_NEXT(rchild)) {
			if (rchild->addke_pending &&
			    rchild->addke_followup_msgid == rmsgid)
				break;
		}
		if (IKEV2_CHILD_LIST_END(rchild))
			rchild = NULL;
		if (!rchild) {
#ifdef WITH_ADDKE
			/* not a pending child: an initiator IKE_SA-rekey
			 * ADDKE whose followup request we sent. */
			if (ike_sa->addke_rekey_pending &&
			    ike_sa->addke_rekey_init &&
			    ikev2_rekey_ikesa_init_followup_msgid(ike_sa) ==
				rmsgid) {
				if (get_payload_data_length(&rke->header) <
				    sizeof(rke->ke_h)) {
					isakmp_log(ike_sa, local, remote,
					    msg, PLOG_PROTOERR, PLOGLOC,
					    "IKE_FOLLOWUP_KE short KE payload\n");
					return;	/* malformed short KE */
				}
				rct = rc_vnew((const u_char *)(rke + 1),
					      get_payload_data_length(&rke->header) -
					      sizeof(rke->ke_h));
				if (!rct)
					return;
				{
					const uint8_t *lb = NULL;
					size_t ll = 0;

					if (rlink) {
						struct ikev2payl_notify *nt =
						    (struct ikev2payl_notify *)rlink;
						size_t dl;

						if (get_payload_length(rlink) >=
						    (int)(sizeof(*nt) +
							  nt->nh.spi_size)) {
							dl = get_payload_length(rlink) -
							    sizeof(*nt) -
							    nt->nh.spi_size;
							if (dl > 0 && dl <= 64) {
								lb = get_notify_data(nt);
								ll = dl;
							}
						}
					}
					if (ikev2_rekey_ikesa_init_addke_complete(
						ike_sa, rct, lb, ll) < 0) {
						isakmp_log(ike_sa, local,
						    remote, msg, PLOG_INTERR,
						    PLOGLOC,
						    "failed completing "
						    "initiator IKE_SA-rekey "
						    "ADDKE\n");
						/* Fail closed:
						 * complete() may have
						 * consumed the deferred
						 * ML-KEM key and appended
						 * SK(n) before rejecting a
						 * missing / oversized next
						 * link. Do NOT advance the
						 * message id (that ACKs the
						 * peer so it stops
						 * retransmitting a request we
						 * did not complete) and
						 * abandon the parked rekey
						 * so it cannot later finish
						 * from slid-around state. */
						ikev2_rekey_abandon_parked(
						    ike_sa);
						rc_vfree(rct);
						return;
					}
				}
				ikev2_update_message_id(ike_sa, rmsgid, TRUE);
				ikev2_followup_wakeup_next(ike_sa);
				rc_vfree(rct);
				return;
			}
#endif
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "IKE_FOLLOWUP_KE response for unknown "
				   "pending child (msgid %u)\n", rmsgid);
			return;
		}

		/*
		 * RFC 9370 s2.2.4: the responder mints a FRESH
		 * ADDITIONAL_KEY_EXCHANGE (16441) link on every non-final
		 * followup response so the initiator can tie its next
		 * request to the next round.  Adopt it (replacing the
		 * round-1 / previous-round link) while this child still
		 * has another round pending, so the next
		 * ikev2_initiator_followup_send() echoes the responder's
		 * new link instead of the stale one — a strict peer (iOS)
		 * rejects a followup carrying an unknown link.
		 */
		if (rchild->addke_round + 1 < rchild->addke_nrounds) {
			/*
			 * RFC 9370 s2.2.4: a non-final followup response
			 * MUST carry a FRESH ADDITIONAL_KEY_EXCHANGE link
			 * for the next round. A missing or unusable
			 * (not 1..64 B) link: we do NOT echo the stale
			 * previous-round link into the next request (a
			 * strict peer, iOS, rejects that; the IKE-SA rekey
			 * initiator similarly rejects it). We stop the round
			 * here — the message id is not advanced, so the child
			 * ADDKE series cannot proceed and is abandoned by the
			 * per-child followup timeout, not continued with a
			 * stale link.
			 */
			struct ikev2payl_notify *nt;
			size_t dl;

			if (!rlink) {
				isakmp_log(ike_sa, local, remote, msg,
				    PLOG_PROTOERR, PLOGLOC,
				    "IKE_FOLLOWUP_KE response missing "
				    "ADDITIONAL_KEY_EXCHANGE link "
				    "(round %d/%d)\n",
				    rchild->addke_round + 1,
				    rchild->addke_nrounds);
				return;
			}
			nt = (struct ikev2payl_notify *)rlink;
			if (get_payload_length(rlink) <
			    (int)(sizeof(struct ikev2payl_notify) +
				  nt->nh.spi_size)) {
				isakmp_log(ike_sa, local, remote, msg,
				    PLOG_PROTOERR, PLOGLOC,
				    "IKE_FOLLOWUP_KE response "
				    "truncated ADDITIONAL_KEY_EXCHANGE\n");
				return;
			}
			dl = get_payload_length(rlink) -
			     (int)(sizeof(struct ikev2payl_notify) +
				   nt->nh.spi_size);
			if (dl == 0 || dl > 64) {
				isakmp_log(ike_sa, local, remote, msg,
				    PLOG_PROTOERR, PLOGLOC,
				    "IKE_FOLLOWUP_KE response "
				    "ADDITIONAL_KEY_EXCHANGE link not "
				    "usable (%zu B)\n", dl);
				return;
			}
			rc_vfreez(rchild->addke_link);
			rchild->addke_link = rc_vnew(get_notify_data(nt), dl);
			if (rchild->addke_link == NULL)
				return;	/* ENOMEM */
			TRACE((PLOGLOC,
			       "initiator adopted fresh ADDKE link "
			       "(%zu B) for round %d/%d\n",
			       dl, rchild->addke_round + 1,
			       rchild->addke_nrounds));
		}

		if (get_payload_data_length(&rke->header) < sizeof(rke->ke_h)) {
			isakmp_log(ike_sa, local, remote, msg, PLOG_PROTOERR,
				   PLOGLOC,
				   "IKE_FOLLOWUP_KE short KE payload\n");
			return;	/* malformed short KE */
		}
		rct = rc_vnew((const u_char *)(rke + 1),
			      get_payload_data_length(&rke->header) -
			      sizeof(rke->ke_h));
		if (!rct)
			return;
		if (ikev2_initiator_followup_complete(rchild, rct) < 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "failed completing initiator ADDKE\n");
			rc_vfree(rct);
			return;
		}
		/* response to our followup request: commit the send window so
		 * request_pending drops and the next exchange is not blocked
		 * (review 2026-09-24: was never committed, retransmit never
		 * stopped -- the matrix initiator stalled here). */
		ikev2_update_message_id(ike_sa, rmsgid, TRUE);
		ikev2_followup_wakeup_next(ike_sa);
		rc_vfree(rct);
		return;
	}

	/* parse: SK { KEi(1), N(ADDITIONAL_KEY_EXCHANGE)(link) } */
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_KE:
			if (ke) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "duplicate KE payload\n");
				goto invalid;
			}
			ke = (struct ikev2payl_ke *)p;
			break;
		case IKEV2_PAYLOAD_NOTIFY: {
			struct ikev2payl_notify *nt =
			    (struct ikev2payl_notify *)p;
			if (get_notify_type(nt) ==
			    IKEV2_ADDITIONAL_KEY_EXCHANGE) {
				if (link_notify) {
					isakmp_log(ike_sa, local, remote,
						   msg, PLOG_PROTOERR,
						   PLOGLOC,
						   "duplicate "
						   "ADDITIONAL_KEY_EXCHANGE\n");
					goto invalid;
				}
				link_notify = p;
			}
			break;
		}
		default:
			break;
		}
	}

	if (!ke || !link_notify) {
		/*
		 * Dump the payload chain we actually received so a
		 * followup mismatch is diagnosable at the wire level
		 * (observed live: iOS rekey selected ADDKE, our
		 * response carried the type-6 echo, but the followup
		 * rejected here — need the real payload types/hex).
		 */
		char chain[128];
		size_t coff = 0;
		struct ikev2_payload_header *cp;

		chain[0] = '\0';
		cp = (struct ikev2_payload_header *)(ikehdr + 1);
		for (type = ikehdr->next_payload;
		     type != IKEV2_NO_NEXT_PAYLOAD && coff < sizeof(chain) - 8;
		     POINT_NEXT_PAYLOAD(cp, type)) {
			coff += snprintf(&chain[coff], sizeof(chain) - coff,
					 " %d(%u)", type,
					 get_payload_length(cp));
		}
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "IKE_FOLLOWUP_KE missing KE or "
			   "ADDITIONAL_KEY_EXCHANGE payload; chain:%s\n",
			   chain);
		goto invalid;
	}

	/* the link data is the notification's SPI-less data
	 * (payload minus generic header minus notify header minus SPI,
	 * same accounting as the notify walkers in ikev2_notify.c) */
	{
		struct ikev2payl_notify *ln =
		    (struct ikev2payl_notify *)link_notify;
		size_t ln_len;

		if (get_payload_length(link_notify) <
		    sizeof(struct ikev2payl_notify) + ln->nh.spi_size) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "IKE_FOLLOWUP_KE truncated "
				   "ADDITIONAL_KEY_EXCHANGE notify\n");
			goto invalid;
		}
		ln_len = get_payload_length(link_notify) -
			 sizeof(struct ikev2payl_notify) -
			 ln->nh.spi_size;

		link = rc_vnew(get_notify_data(ln), ln_len);
	}
	if (!link)
		goto nomem;

	/* KE payload must reference a supported ADDKE method: an ML-KEM id
	 * (35/36/37) or a classical DH group id from the KE-method registry.
	 * RFC 9370 allows classical key exchanges in the multiple rounds. */
	ke_method = get_uint16(&ke->ke_h.dh_group_id);
	if (!ikev2_addke_method_is_mlkem(ke_method) &&
	    ikev2_addke_method_dhgroup(ke_method) == NULL) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "IKE_FOLLOWUP_KE method %u unsupported\n",
			   ke_method);
		goto invalid;
	}

	/* the KE payload carries the initiator's public value: the ML-KEM
	 * public key for a KEM round, or the DH public value otherwise */
	if (get_payload_data_length(&ke->header) < sizeof(ke->ke_h))
		goto invalid;	/* underflow guard before the size_t subtract */
	peer_ke = rc_vnew((const u_char *)(ke + 1),
			  get_payload_data_length(&ke->header) -
			  sizeof(ke->ke_h));
	if (!peer_ke)
		goto nomem;

	/* bind the round to the negotiated method and length-check the peer
	 * public value (ML-KEM pub_len, or the DH group's public length) */
	if (ikev2_addke_method_is_mlkem(ke_method)) {
		const struct ikev2_addke_mlkem_param *param =
		    ikev2_addke_mlkem_param(ke_method);

		if (peer_ke->l != param->pub_len) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "IKE_FOLLOWUP_KE KEi length %zu != %zu "
				   "(method %u)\n",
				   peer_ke->l, param->pub_len, ke_method);
			goto invalid;
		}
	} else {
		const struct dhgroup *dh =
		    ikev2_addke_method_dhgroup(ke_method);

		if (peer_ke->l != dh_value_len((struct dhgroup *)dh)) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "IKE_FOLLOWUP_KE KEi length %zu != %zu "
				   "(group %u)\n",
				   peer_ke->l,
				   dh_value_len((struct dhgroup *)dh),
				   ke_method);
			goto invalid;
		}
	}

	/* find the pending state this followup links to: either a child
	 * (child-SA ADDKE rekey) or a deferred IKE-SA rekey */
	if (ike_sa->addke_rekey_pending &&
	    ike_sa->addke_rekey_link && link &&
	    ike_sa->addke_rekey_link->l == link->l &&
	    memcmp(ike_sa->addke_rekey_link->v, link->v, link->l) == 0) {
		/*
		 * IKE-SA rekey path: child_sa stays NULL; the deferred
		 * completion uses ike_sa state.  Fall through to the
		 * encapsulate step below.
		 */
		child_sa = NULL;
		rekey_link_match = 1;
	} else {
		child_sa = followup_ke_find_child(ike_sa, link, ke_method);
	}
	/*
	 * A pending IKE-SA rekey is no licence to accept any link: the
	 * N(16441) blob is what ties this followup to that rekey (RFC 9370
	 * s2.2.2), so a link that matches neither the rekey nor a child has
	 * no key exchange state and gets STATE_NOT_FOUND.  Completing the
	 * rekey on an unmatched link hid an initiator that never echoed the
	 * responder's link.
	 */
	if (!child_sa && !rekey_link_match) {
		/* rfc9370 s2.2.4: no key exchange state -> STATE_NOT_FOUND */
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOWARN, PLOGLOC,
			   "IKE_FOLLOWUP_KE: no pending ADDKE state for link\n");
		errno = 0;
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0,
					  IKEV2_STATE_NOT_FOUND, 0, 0);
		goto done;
	}

	/* responder side of the round: ML-KEM encapsulates (KEr = ciphertext);
	 * a classical DH round generates OUR keypair, sends OUR public value
	 * as KEr, and computes g^xy from both public values. */
	if (ikev2_addke_method_is_mlkem(ke_method)) {
		if (ikev2_addke_mlkem_encap(ke_method, peer_ke, &ct, &ss) < 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "ML-KEM encapsulate failed (method %u)\n",
				   ke_method);
			goto invalid;
		}
	} else {
		const struct dhgroup *dh =
		    ikev2_addke_method_dhgroup(ke_method);
		rc_vchar_t *our_pub = NULL, *our_priv = NULL, *gxy = NULL;

		if (oakley_dh_generate((struct dhgroup *)dh, &our_pub,
				       &our_priv) < 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "ADDKE DH generate failed (group %u)\n",
				   ke_method);
			goto invalid;
		}
		/* g^xy from our generated keypair and the peer's public value */
		if (oakley_dh_compute((struct dhgroup *)dh, our_pub,
				      our_priv, peer_ke, &gxy) < 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "ADDKE DH compute failed (group %u)\n",
				   ke_method);
			rc_vfree(our_pub);
			rc_vfreez(our_priv);
			goto invalid;
		}
		rc_vfreez(our_priv);
		/* KEr carries our public value; ss = g^xy */
		ct = our_pub;
		ss = gxy;
	}
	if (ikev2_addke_method_is_mlkem(ke_method)) {
		const struct ikev2_addke_mlkem_param *param =
		    ikev2_addke_mlkem_param(ke_method);

		if (ct->l != param->ct_len ||
		    ss->l != OSSL_ML_KEM_SHARED_SECRET_BYTES) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "ML-KEM sizes ct=%zu ss=%zu (method %u)\n",
				   ct->l, ss->l, ke_method);
			goto invalid;
		}
	} else {
		/* KEr carries the public value (x||y for ECP = dh_value_len);
		 * the derived shared secret is the bare group field length
		 * (s* = g^xy, and for ECP just the x-coordinate = prime->l).
		 * These differ for the ECP/Brainpool groups. */
		size_t klen = dh_value_len((struct dhgroup *)
		    ikev2_addke_method_dhgroup(ke_method));
		size_t slen = ((struct dhgroup *)
		    ikev2_addke_method_dhgroup(ke_method))->prime->l;

		if (ct->l != klen || ss->l != slen) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "classical DH sizes KEr=%zu ss=%zu "
				   "(group %u)\n",
				   ct->l, ss->l, ke_method);
			goto invalid;
		}
	}

	/* SK(1) now known: complete the deferred exchange. */
	if (rekey_link_match) {
		int rr;

		/*
		 * Multi-round IKE-SA rekey: a non-final followup mints a
		 * fresh 16441 and stays parked.  Only the final round
		 * derives SKEYSEED and establishes the new SA.
		 */
		rr = ikev2_rekey_responder_addke_round(ike_sa, ss, ct,
			get_uint32(&ikehdr->message_id), ke_method);
		if (rr < 0) {
			if (rr == -2) {
				/* pre-send local send failure (nothing reached
				 * the wire; SK/link/round uncommitted): restore
				 * the inbound window so a retransmit of this
				 * followup re-enters, and do
				 * NOT emit STATE_NOT_FOUND (not a protocol
				 * error). The SK was not appended (deferred), so
				 * re-entry cannot double it. */
				isakmp_log(ike_sa, local, remote, msg,
				    PLOG_INTERR, PLOGLOC,
				    "IKE-SA rekey round response send failed\n");
				ike_sa->recv_message_id = saved_mid;
				rc_vfreez(ss);
				ss = 0;
				goto done;
			}
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "failed ADDKE IKE-SA rekey round\n");
			rc_vfreez(ss);
			ss = 0;
			goto invalid;
		}
		if (rr > 0) {
			rc_vfreez(ss);
			ss = 0;
			goto done;
		}
		{
			int cr = ikev2_rekey_responder_addke_complete(ike_sa,
					ike_sa->addke_rekey_sk, ct,
					get_uint32(&ikehdr->message_id),
					ke_method);
			if (cr < 0) {
				if (cr == -2) {
					/* final KEr already sent: the peer holds
					 * the success signal. Abandon WITHOUT
					 * STATE_NOT_FOUND (it would replace the
					 * armed cache and desync the rekey). */
					isakmp_log(ike_sa, local, remote, msg,
						   PLOG_INTERR, PLOGLOC,
						   "ADDKE IKE-SA rekey local "
						   "establish failed after KEr sent\n");
					rc_vfreez(ss);
					ss = 0;
					goto done;
				}
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_INTERR, PLOGLOC,
					   "failed to complete ADDKE IKE-SA rekey\n");
				rc_vfreez(ss);
				ss = 0;
				goto invalid;
			}
		}
		rc_vfreez(ss);
		ss = 0;
		goto done;
	}

	/*
	 * Multi-round check (rfc9370 s2.2.4): the KE method field of
	 * this followup MUST match the n-th negotiated ADDKE method.
	 * Round cursor starts at 0; advance after each completed round.
	 */
	if (child_sa->addke_nrounds > 0 &&
	    child_sa->addke_round < child_sa->addke_nrounds &&
	    ke_method !=
		child_sa->addke_methods[child_sa->addke_round]) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "IKE_FOLLOWUP_KE method %u != round %d method %u\n",
			   ke_method, child_sa->addke_round,
			   child_sa->addke_methods[child_sa->addke_round]);
		goto invalid;
	}

	/* The shared secret ss for this round is appended to addke_sk ONLY after
	 * the response is successfully transmitted (below). Appending before
	 * the send means a retransmit that re-enters this handler appends
	 * again -> addke_sk = ss1|ss2 while the initiator decaps only the
	 * second KEr -> key mismatch (ML-KEM encap is not replay-stable). */
	{
		struct ikev2_payloads payl;
		struct ikev2payl_ke_h keh;
		rc_vchar_t *ker = 0;
		rc_vchar_t *pkt;
		int more_rounds =
		    (child_sa->addke_round + 1 < child_sa->addke_nrounds);
		rc_vchar_t *new_link = NULL;
		rc_vchar_t *newsk = NULL;

		ikev2_payloads_init(&payl);
		memset(&keh, 0, sizeof(keh));
		keh.dh_group_id = htons((uint16_t)ke_method);
		ker = rc_vprepend(ct, &keh, sizeof(keh));
		if (!ker) {
			ikev2_payloads_destroy(&payl);
			goto nomem;
		}
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ker, FALSE);
		/*
		 * RFC 9370 s2.2.4: whenever another followup is expected
		 * (this is NOT the final round), the responder MUST mint a
		 * FRESH ADDITIONAL_KEY_EXCHANGE (16441) link for the NEXT
		 * round and return it in this response; the initiator
		 * echoes it on the next request.  The final round's
		 * response is KE-only.  Store the new link into
		 * child_sa->addke_link so the next IKE_FOLLOWUP_KE request
		 * exact-matches (followup_ke_find_child) against the link
		 * we just issued.  Without this neither iked (re-sending
		 * the stale round-1 link) nor a strict peer (iOS) can
		 * complete round 2+.
		 */
		if (more_rounds) {
			new_link = random_bytes(16);
			if (!new_link) {
				ikev2_payloads_destroy(&payl);
				rc_vfree(ker);
				goto nomem;
			}
			ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
					    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
								 0, 0,
								 IKEV2_ADDITIONAL_KEY_EXCHANGE,
								 new_link->v,
								 new_link->l),
					    TRUE);
			/* The fresh link is committed to
			 * child_sa->addke_link ONLY after the response is
			 * actually transmitted (below), so a failed send
			 * leaves the old link + round in place and
			 * followup_ke_find_child still matches the
			 * initiator's retransmit. This mirrors the rekey
			 * responder (ikev2_rekey_responder_addke_round). */
		}
		/*
		 * Pre-allocate this round's accumulated SK(1..n) BEFORE the
		 * response is sent: nothing that can fail (malloc) may remain
		 * after a successful transmit. The link and the SK are then
		 * committed below as ONE atomic pointer-swing, so the committed
		 * child state always matches what the peer decaps on the next
		 * round. (After a send succeeds, a retransmit is answered from
		 * the response cache and the advanced window — not by append
		 * placement; pre-allocating removes the one failing `goto nomem`
		 * a post-send append could otherwise interpose between the link
		 * swap and the SK store.)
		 */
		newsk = rc_vmalloc((child_sa->addke_sk ?
				    child_sa->addke_sk->l : 0) + ss->l);
		if (!newsk) {
			if (new_link)
				rc_vfree(new_link);
			ikev2_payloads_destroy(&payl);
			goto nomem;
		}
		if (child_sa->addke_sk)
			memcpy(newsk->v, child_sa->addke_sk->v,
			       child_sa->addke_sk->l);
		memcpy(newsk->v + newsk->l - ss->l, ss->v, ss->l);
		pkt = ikev2_packet_construct(IKEV2EXCH_IKE_FOLLOWUP_KE,
					     (ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0) |
					     IKEV2FLAG_RESPONSE,
					     get_uint32(&ikehdr->message_id),
					     ike_sa, &payl);
		rc_vfree(ker);
		if (!pkt) {
			if (new_link)
				rc_vfree(new_link);
			rc_vfree(newsk);
			ikev2_payloads_destroy(&payl);
			goto nomem;
		}
		if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "failed sending IKE_FOLLOWUP_KE response\n");
			rc_vfree(pkt);	/* failure path: caller owns the packet */
			if (new_link)
				rc_vfree(new_link);
			rc_vfree(newsk);
			ikev2_payloads_destroy(&payl);
			/* restore the inbound window so a retransmit of THIS id
			 * passes the ordering check and re-enters; the SK/link/
			 * round are all uncommitted, so re-entry cannot double
			 * them. */
			ike_sa->recv_message_id = saved_mid;
			goto done;	/* not sent: keep old link + round */
		}
		ikev2_payloads_destroy(&payl);
		/* atomic commit after a successful transmit (no alloc here):
		 * link (if any) + accumulated SK pointer-swing together. */
		if (more_rounds) {
			rc_vfreez(child_sa->addke_link);
			child_sa->addke_link = new_link;
			new_link = NULL;	/* now owned by the child */
			TRACE((PLOGLOC,
			       "ADDKE: minted fresh followup link (%zu B) "
			       "for round %d/%d\n",
			       child_sa->addke_link->l,
			       child_sa->addke_round + 1,
			       child_sa->addke_nrounds));
		}
		rc_vfreez(child_sa->addke_sk);
		child_sa->addke_sk = newsk;
		newsk = NULL;	/* now owned by the child */
		rc_vfreez(ss);
		ss = 0;
	}
	++child_sa->addke_round;
	if (child_sa->addke_round < child_sa->addke_nrounds) {
		/* more rounds: re-arm the followup-wait timeout, stay pending */
		if (child_sa->timer)
			SCHED_KILL(child_sa->timer);
		ikev2_child_addke_arm_timeout(child_sa);
		isakmp_log(ike_sa, local, remote, msg, PLOG_DEBUG, PLOGLOC,
			   "ADDKE round %d/%d done; waiting for next followup\n",
			   child_sa->addke_round, child_sa->addke_nrounds);
		goto done;
	}

	/* final round: install the child with the accumulated SK(1..n) */
	child_sa->addke_round = 0;
	child_sa->addke_nrounds = 0;
	if (ikev2_child_addke_install(child_sa) < 0) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_INTERR, PLOGLOC,
			   "failed to install ADDKE child\n");
		rc_vfreez(child_sa->addke_sk);
		child_sa->addke_sk = 0;
		/* The final KEr for this followup was already transmitted and
		 * cached above; the peer holds the success signal. Do NOT goto
		 * invalid: STATE_NOT_FOUND here would REPLACE the armed cache
		 * and tell the initiator to abandon a child it already believes
		 * is up. Log and abandon locally only. */
		goto done;
	}
	goto done;

      invalid:
	/* The CREATE_CHILD_SA already succeeded; a broken followup
	 * must not tear the IKE_SA down.  Per rfc9370 s2.2.4 ask the
	 * initiator to cancel the series (non-fatal). */
	if (!is_response)
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0,
					  IKEV2_STATE_NOT_FOUND, 0, 0);
	goto done;

      nomem:
	++isakmpstat.fail_process_packet;
      done:
	if (peer_ke)
		rc_vfree(peer_ke);
	if (link)
		rc_vfree(link);
	if (ct)
		rc_vfree(ct);
	if (ss)
		rc_vfreez(ss);
}

#endif	/* WITH_ADDKE */
