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
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/evp.h>
#include <openssl/ml_kem.h>

#include "racoon.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
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
		rc_vfree(ss1);
		rc_vfree(ss2);
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
 * initiator sends IKE_FOLLOWUP_KE (exch 44) requests:
 *
 *   HDR(IKE_FOLLOWUP_KE), SK { KEi(1), N(ADDITIONAL_KEY_EXCHANGE)(link) }
 *
 * where KEi(1) is a KE payload whose Key Exchange Method field equals
 * the negotiated ADDKE transform ID (36 = ML-KEM-768) carrying the
 * initiator's raw ML-KEM-768 public key (1184 bytes, FIPS 203), and
 * the ADDITIONAL_KEY_EXCHANGE notification (16441) echoes the link
 * data from our CREATE_CHILD_SA response.  The responder encapsulates
 * against that public key and replies:
 *
 *   HDR(IKE_FOLLOWUP_KE), SK { KEr(1) }
 *
 * with KEr(1) carrying the 1088-byte ciphertext (same method field).
 * Both sides now share the 32-byte ML-KEM-768 shared secret, which
 * appends to the child KEYMAT input after Nr (rfc9370 s2.2.4).
 */

/*
 * Find the pending child_sa whose addke_link matches the
 * ADDITIONAL_KEY_EXCHANGE notification data (the listener state for
 * this followup).  Per rfc9370 s2.2.4 the link data is opaque to the
 * initiator and meaningful only to the responder.
 */
static struct ikev2_child_sa *
followup_ke_find_child(struct ikev2_sa *ike_sa, rc_vchar_t *link)
{
	struct ikev2_child_sa *sa;

	if (link == NULL)
		return NULL;
	for (sa = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(sa);
	     sa = IKEV2_CHILD_LIST_NEXT(sa)) {
		if (sa->addke_pending && sa->addke_link &&
		    sa->addke_link->l == link->l &&
		    memcmp(sa->addke_link->v, link->v, link->l) == 0)
			return sa;
	}
	return NULL;
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
				     IKEV2FLAG_INITIATOR,
				     message_id, ike_sa, &payl);
	rc_vfree(kei);
	ikev2_payloads_destroy(&payl);
	if (!pkt)
		return -1;

	if (ikev2_transmit(ike_sa, pkt) != 0) {
		rc_vfree(pkt);
		return -1;
	}
	rc_vfree(pkt);
	child_sa->addke_followup_msgid = message_id;
	return 0;
}

/*
 * Initiator side: complete the ADDKE child once the followup response
 * carried the peer's KEr(1) ciphertext.  Decapsulate to SK(1), then
 * install the child with the ADDKE keymat (same path as the
 * responder's deferred install).
 */
int
ikev2_initiator_followup_complete(struct ikev2_child_sa *child_sa,
				  rc_vchar_t *ciphertext)
{
	EVP_PKEY *kp;
	rc_vchar_t *ss = NULL;

	kp = (EVP_PKEY *)child_sa->addke_priv;
	child_sa->addke_priv = NULL;
	if (!kp || !ciphertext)
		return -1;

	if (ikev2_addke_mlkem_decap(kp, ciphertext, &ss) < 0 ||
	    ss == NULL ||
	    ss->l != OSSL_ML_KEM_SHARED_SECRET_BYTES) {
		rc_vfree(ss);
		EVP_PKEY_free(kp);
		return -1;
	}
	EVP_PKEY_free(kp);

	child_sa->addke_sk = ss;
	if (ikev2_child_addke_install(child_sa) < 0) {
		child_sa->addke_sk = NULL;
		rc_vfree(ss);
		return -1;
	}
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
	int type;

	ikehdr = (struct ikev2_header *)msg->v;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;

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
	{
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
		struct ikev2_child_sa *rchild = 0;
		rc_vchar_t *rct = 0;
		int rtype;
		uint32_t rmsgid;

		/*
		 * Initiator side: our IKE_FOLLOWUP_KE request got a
		 * response.  Find the pending child by the message id
		 * we used for the request, parse the KEr(1) ciphertext,
		 * decapsulate to SK(1), and complete the deferred
		 * keymat install.
		 */
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
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "IKE_FOLLOWUP_KE response for unknown "
				   "pending child (msgid %u)\n", rmsgid);
			return;
		}

		/* parse: SK { KEr(1) } */
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
			}
		}
		if (!rke) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "IKE_FOLLOWUP_KE response missing KE\n");
			return;
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

	/* KE payload must reference a supported ADDKE method */
	ke_method = get_uint16(&ke->ke_h.dh_group_id);
	if (ikev2_addke_mlkem_param(ke_method) == NULL) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "IKE_FOLLOWUP_KE method %u unsupported\n",
			   ke_method);
		goto invalid;
	}

	/* the KE payload carries the initiator's ML-KEM public key */
	peer_ke = rc_vnew((const u_char *)(ke + 1),
			  get_payload_data_length(&ke->header) -
			  sizeof(ke->ke_h));
	if (!peer_ke)
		goto nomem;
	{
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
	} else {
		child_sa = followup_ke_find_child(ike_sa, link);
	}
	if (!child_sa && !ike_sa->addke_rekey_pending) {
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

	/* responder encapsulates against the initiator's public key */
	if (ikev2_addke_mlkem_encap(ke_method, peer_ke, &ct, &ss) < 0) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_INTERR, PLOGLOC,
			   "ML-KEM encapsulate failed (method %u)\n",
			   ke_method);
		goto invalid;
	}
	{
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
	}

	/* SK(1) now known: complete the deferred exchange. */
	if (ike_sa->addke_rekey_pending) {
		/* ADDKE IKE-SA rekey: finish SKEYSEED + keys with SK(1),
		 * reply KEr(1) inside the completion. */
		if (ikev2_rekey_responder_addke_complete(ike_sa, ss) < 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "failed to complete ADDKE IKE-SA rekey\n");
			rc_vfree(ss);
			ss = 0;
			goto invalid;
		}
		rc_vfree(ss);
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

	/* append this round's shared secret to SK(1)..SK(n), in order */
	{
		rc_vchar_t *acc;

		acc = rc_vmalloc((child_sa->addke_sk ?
				  child_sa->addke_sk->l : 0) + ss->l);
		if (!acc) {
			rc_vfree(ss);
			ss = 0;
			goto nomem;
		}
		if (child_sa->addke_sk) {
			memcpy(acc->v, child_sa->addke_sk->v,
			       child_sa->addke_sk->l);
			rc_vfree(child_sa->addke_sk);
			child_sa->addke_sk = 0;
		}
		memcpy(acc->v + acc->l - ss->l, ss->v, ss->l);
		child_sa->addke_sk = acc;
		rc_vfree(ss);
		ss = 0;
	}

	/*
	 * Reply the ciphertext BEFORE finishing: the peer needs KEr(n)
	 * for this round before it sends the next followup, and if
	 * more rounds remain the child must stay pending.
	 */
	{
		struct ikev2_payloads payl;
		struct ikev2payl_ke_h keh;
		rc_vchar_t *ker = 0;
		rc_vchar_t *pkt;

		ikev2_payloads_init(&payl);
		memset(&keh, 0, sizeof(keh));
		keh.dh_group_id = htons((uint16_t)ke_method);
		ker = rc_vprepend(ct, &keh, sizeof(keh));
		if (!ker) {
			ikev2_payloads_destroy(&payl);
			goto nomem;
		}
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ker, FALSE);
		pkt = ikev2_packet_construct(IKEV2EXCH_IKE_FOLLOWUP_KE,
					     IKEV2FLAG_RESPONSE,
					     get_uint32(&ikehdr->message_id),
					     ike_sa, &payl);
		rc_vfree(ker);
		if (!pkt) {
			ikev2_payloads_destroy(&payl);
			goto nomem;
		}
		if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0)
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "failed sending IKE_FOLLOWUP_KE response\n");
		ikev2_payloads_destroy(&payl);
	}

	/* advance the round cursor; install only after the last round */
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
		child_sa->addke_sk = 0;
		goto invalid;
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
		rc_vfree(ss);
}

#endif	/* WITH_ADDKE */
