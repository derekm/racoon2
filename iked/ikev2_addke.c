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
 * False until the IKE_FOLLOWUP_KE responder state machine exists.
 */
int
ikev2_addke_selectable(void)
{
	/* STAGE 2 (IKE_FOLLOWUP_KE + GSKM_seed) not yet implemented. */
	return 0;
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
 * RFC 9370 s2.2.4: ADDITIONAL_KEY_EXCHANGE notification (16441)
 * carries the message ID of the CREATE_CHILD_SA request that the
 * ADDKE exchange is linked to.  The heartbeat of STAGE 2.
 */
static int
followup_ke_link_msgid(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		       uint32_t *link_msgid)
{
	(void)ike_sa;
	(void)msg;
	(void)link_msgid;
	return -1;	/* STAGE 2: not implemented */
}

void
ikev2_followup_ke_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		       struct sockaddr *remote, struct sockaddr *local)
{
	uint32_t link_msgid;
	struct ikev2_header *ikehdr;
	/* STAGE 2: allocate followup state per CREATE_CHILD_SA. */
	int is_response;

	ikehdr = (struct ikev2_header *)msg->v;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;

	/* We never select ADDKE proposals (ikev2_addke_selectable()=0),
	 * so an incoming IKE_FOLLOWUP_KE is a protocol anomaly. */
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC,
		   "IKE_FOLLOWUP_KE received without negotiated ADDKE "
		   "(addke selectable gate is off)\n");
	++isakmpstat.unexpected_exchange_type;
	if (!is_response) {
		errno = 0;
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0,
					  IKEV2_INVALID_SYNTAX, 0, 0);
	}
	(void)link_msgid;
	(void)followup_ke_link_msgid;
}

#endif	/* WITH_ADDKE */
