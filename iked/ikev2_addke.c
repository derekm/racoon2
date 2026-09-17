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
 * STAGE 1: real ML-KEM-768 crypto (EVP_PKEY_ML_KEM768), negotiation
 * plumbing, and the matcher gate.  The responder-side followup state
 * machine and GSKM_seed keymat feed are STAGE 2 (IKE_FOLLOWUP_KE).
 *
 * Selection policy (rfc9370 s2.2.4): selecting an ADDKE proposal in the
 * CREATE_CHILD_SA response commits us to the IKE_FOLLOWUP_KE series.
 * ikev2_addke_selectable() gates ACCEPTING ADDKE proposals in
 * ikev2_compare_transforms: it stays false until the followup exchange
 * machinery exists, so a WITH_ADDKE build keeps matching the peer's
 * non-ADDKE proposals (the behaviour live-verified on iOS) instead of
 * selecting ADDKE and then failing the followup series.
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
 * Gate: may ikev2_compare_transforms select an ADDKE-bearing proposal?
 * True now that the IKE_FOLLOWUP_KE responder state machine (stage 2)
 * exists: selecting ADDKE in the CREATE_CHILD_SA response commits us
 * to the followup exchanges, and the responder arms addke_pending on
 * the child + includes the ADDITIONAL_KEY_EXCHANGE notification in the
 * response (rfc9370 s2.2.4).
 */
int
ikev2_addke_selectable(void)
{
	return 1;
}

/*
 * Generate an ML-KEM-768 keypair.  Public key is written to *pub
 * (caller frees); key returned via **pkey (EVP_PKEY_free).
 * Returns 0 on success, -1 on failure.
 */
int
ikev2_addke_mlkem_keygen(rc_vchar_t **pub, EVP_PKEY **pkey)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *kp = NULL;
	unsigned char buf[OSSL_ML_KEM_768_PUBLIC_KEY_BYTES];
	size_t publen = sizeof(buf);
	int r = -1;

	*pub = NULL;
	*pkey = NULL;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
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
	if (r < 0)
		EVP_PKEY_free(kp);
	return r;
}

/*
 * Encapsulate: produce a ciphertext for the peer's public key and the
 * 32-byte shared secret.  Returns 0 / -1.
 */
int
ikev2_addke_mlkem_encap(rc_vchar_t *peer_pub, rc_vchar_t **ct,
			rc_vchar_t **shared)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *peer = NULL;
	unsigned char ctbuf[OSSL_ML_KEM_768_CIPHERTEXT_BYTES];
	unsigned char ssbuf[OSSL_ML_KEM_SHARED_SECRET_BYTES];
	size_t ctlen = sizeof(ctbuf), sslen = sizeof(ssbuf);
	int r = -1;

	*ct = NULL;
	*shared = NULL;

	if (peer_pub == NULL || peer_pub->l != OSSL_ML_KEM_768_PUBLIC_KEY_BYTES)
		return -1;

	peer = EVP_PKEY_new_raw_public_key(NID_ML_KEM_768, NULL,
					   peer_pub->v,
					   peer_pub->l);
	if (peer == NULL)
		return -1;
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
 * Self-test: keygen -> encap -> decap and check both sides derive the
 * same 32-byte shared secret.  Returns 0 on success.
 * Exposed for the "addketest" check target (WITH_ADDKE builds only).
 */
int
ikev2_addke_selftest(void)
{
	rc_vchar_t *pub = NULL, *ct = NULL, *ss1 = NULL, *ss2 = NULL;
	EVP_PKEY *kp = NULL;
	int r = -1;

	if (ikev2_addke_mlkem_keygen(&pub, &kp) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "addke selftest: keygen failed\n");
		goto done;
	}
	if (ikev2_addke_mlkem_encap(pub, &ct, &ss1) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "addke selftest: encapsulate failed\n");
		goto done;
	}
	if (ikev2_addke_mlkem_decap(kp, ct, &ss2) < 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "addke selftest: decapsulate failed\n");
		goto done;
	}
	if (ss1->l != OSSL_ML_KEM_SHARED_SECRET_BYTES ||
	    ss2->l != OSSL_ML_KEM_SHARED_SECRET_BYTES ||
	    memcmp(ss1->v, ss2->v, OSSL_ML_KEM_SHARED_SECRET_BYTES) != 0) {
		plog(PLOG_INTERR, PLOGLOC, NULL,
		     "addke selftest: shared secrets differ\n");
		goto done;
	}
	r = 0;
      done:
	rc_vfree(pub);
	rc_vfree(ct);
	rc_vfree(ss1);
	rc_vfree(ss2);
	EVP_PKEY_free(kp);
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

	/* We are always the responder for ADDKE at this stage. */
	if (is_response) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOWARN, PLOGLOC,
			   "unexpected IKE_FOLLOWUP_KE response\n");
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
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "IKE_FOLLOWUP_KE missing KE or "
			   "ADDITIONAL_KEY_EXCHANGE payload\n");
		goto invalid;
	}

	/* the link data is the notification's SPI-less data */
	link = rc_vnew(get_notify_data((struct ikev2payl_notify *)link_notify),
		       get_payload_data_length(link_notify) -
		       ((struct ikev2payl_notify *)link_notify)->nh.spi_size);
	if (!link)
		goto nomem;

	/* KE payload must reference the negotiated ADDKE method */
	ke_method = get_uint16(&ke->ke_h.dh_group_id);
	if (ke_method != IKEV2TRANSF_ADDKE_MLKEM768) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "IKE_FOLLOWUP_KE method %u != ML-KEM-768 (%u)\n",
			   ke_method, IKEV2TRANSF_ADDKE_MLKEM768);
		goto invalid;
	}

	/* the KE payload carries the initiator's ML-KEM-768 public key */
	peer_ke = rc_vnew((const u_char *)(ke + 1),
			  get_payload_data_length(&ke->header) -
			  sizeof(ke->ke_h));
	if (!peer_ke)
		goto nomem;
	if (peer_ke->l != OSSL_ML_KEM_768_PUBLIC_KEY_BYTES) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "IKE_FOLLOWUP_KE KEi length %zu != %d\n",
			   peer_ke->l, OSSL_ML_KEM_768_PUBLIC_KEY_BYTES);
		goto invalid;
	}

	/* find the pending child this followup links to */
	child_sa = followup_ke_find_child(ike_sa, link);
	if (!child_sa) {
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
	if (ikev2_addke_mlkem_encap(peer_ke, &ct, &ss) < 0) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_INTERR, PLOGLOC,
			   "ML-KEM-768 encapsulate failed\n");
		goto invalid;
	}
	if (ct->l != OSSL_ML_KEM_768_CIPHERTEXT_BYTES ||
	    ss->l != OSSL_ML_KEM_SHARED_SECRET_BYTES) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_INTERR, PLOGLOC,
			   "ML-KEM-768 sizes ct=%zu ss=%zu\n",
			   ct->l, ss->l);
		goto invalid;
	}

	/* SK(1) now known; install the child with the ADDKE keymat */
	child_sa->addke_sk = ss;
	ss = 0;
	if (ikev2_child_addke_install(child_sa) < 0) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_INTERR, PLOGLOC,
			   "failed to install ADDKE child\n");
		child_sa->addke_sk = 0;
		goto invalid;
	}

	/* reply with the ciphertext: HDR(IKE_FOLLOWUP_KE), SK { KEr } */
	{
		struct ikev2_payloads payl;
		struct ikev2payl_ke_h keh;
		rc_vchar_t *ker = 0;
		rc_vchar_t *pkt;

		ikev2_payloads_init(&payl);
		memset(&keh, 0, sizeof(keh));
		keh.dh_group_id =
		    htons((uint16_t)IKEV2TRANSF_ADDKE_MLKEM768);
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
