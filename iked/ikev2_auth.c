/* $Id: ikev2_auth.c,v 1.25 2008/02/06 08:09:00 mk Exp $ */

/*
 * Copyright (C) 2004-2005 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <config.h>

#include <assert.h>
#include <string.h>
#include <openssl/crypto.h>	/* CRYPTO_memcmp */
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
#  include <sys/time.h>
#  include <time.h>
#else
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  else
#    include <time.h>
#  endif
#endif
#include <sys/errno.h>

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "crypto_impl.h"

#include "debug.h"

/* RFC 7427 A.1.2 sha256WithRSAEncryption AlgorithmIdentifier, DER-encoded
 * (15 bytes: SEQUENCE{ OID 1.2.840.113549.1.1.11, NULL }).  File-scope so the
 * AUTH sign/verify switch cases do not open with a declaration after a label
 * (C89: label must be followed by a statement; clang errors, gcc tolerated). */
static const uint8_t rfc7427_sha256_ai[] = {
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
};

static rc_vchar_t *ikev2_auth_input(struct ikev2_sa *, int);

/*
 * IKEv2 AUTH
 */

/*
 * generate octet string for auth calculation input
 */
static rc_vchar_t *
ikev2_auth_input(struct ikev2_sa *sa, int i_to_r)
{
	rc_vchar_t *message;
	rc_vchar_t *octets = 0;
	rc_vchar_t *nonce;
	rc_vchar_t *sk;
	rc_vchar_t *id;
	struct keyed_hash *prf = sa->prf;
	uint8_t *p;
	rc_vchar_t *prf_output = 0;

	TRACE((PLOGLOC, "ikev2_auth_input(%p, %d)\n", sa, i_to_r));

	/* (draft-17)
	 * For the responder, the octets to
	 * be signed start with the first octet of the first SPI in the header
	 * of the second message and end with the last octet of the last payload
	 * in the second message.  Appended to this (for purposes of computing
	 * the signature) are the initiator's nonce Ni (just the value, not the
	 * payload containing it), and the value prf(SK_pr,IDr') where IDr' is
	 * the responder's ID payload excluding the fixed header.
	 */
	/* sign(packet | Ni | prf(SK_pr, IDr')) */

	/*
	 * the initiator signs the first message, starting with the
	 * first octet of the first SPI in the header and ending with the last
	 * octet of the last payload.  Appended to this (for purposes of
	 * computing the signature) are the responder's nonce Nr, and the value
	 * prf(SK_pi,IDi'). In the above calculation, IDi' and IDr' are the
	 * entire ID payloads excluding the fixed header.
	 */
	/* sign(packet | Nr | prf(SK_pi, IDi')) */

	/*
	 * Optionally, messages 3 and 4 MAY include a certificate, or
	 * certificate chain providing evidence that the key used to compute a
	 * digital signature belongs to the name in the ID payload. The
	 * signature or MAC will be computed using algorithms dictated by the
	 * type of key used by the signer, and specified by the Auth Method
	 * field in the Authentication payload.
	 */

	/*
	 * In the case of a pre-shared key, the AUTH
	 * value is computed as:
	 *
	 * AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>)
	 */

#ifdef notyet
	/*
	 * For EAP methods that create a shared key as a side effect of
	 * authentication, that shared key MUST be used by both the initiator
	 * and responder to generate AUTH payloads in messages 5 and 6 using the
	 * syntax for shared secrets specified in section 2.15. The shared key
	 * from EAP is the field from the EAP specification named MSK. The
	 * shared key generated during an IKE exchange MUST NOT be used for any
	 * other purpose.
	 *
	 * EAP methods that do not establish a shared key SHOULD NOT be used, as
	 * they are subject to a number of man-in-the-middle attacks [EAPMITM]
	 * if these EAP methods are used in other protocols that do not use a
	 * server-authenticated tunnel.  Please see the Security Considerations
	 * section for more details. If EAP methods that do not generate a
	 * shared key are used, the AUTH payloads in messages 7 and 8 MUST be
	 * generated using SK_pi and SK_pr respectively.
	 */
#endif

	/* (draft-eronen-ipsec-ikev2-clarifications-05.txt)
	 * 3.1  Data included in AUTH payload calculation
	 *
	 * Section 2.15 describes how the AUTH payloads are calculated; this
	 * calculation involves values prf(SK_pi,IDi') and prf(SK_pr,IDr').  The
	 * text describes the method in words, but does not give clear
	 * definitions of what is signed or MACed.
	 *
	 * The initiator's signed octets can be described as:
	 *
	 * InitiatorSignedOctets = RealMessage1 | NonceRData | MACedIDForI
	 * GenIKEHDR = [ four octets 0 if using port 4500 ] | RealIKEHDR
	 * RealIKEHDR =  SPIi | SPIr |  . . . | Length
	 * RealMessage1 = RealIKEHDR | RestOfMessage1
	 * NonceRPayload = PayloadHeader | NonceRData
	 * InitiatorIDPayload = PayloadHeader | RestOfIDPayload
	 * RestOfInitIDPayload = IDType | RESERVED | InitIDData
	 * MACedIDForI = prf(SK_pi, RestOfInitIDPayload)
	 *
	 * The responder's signed octets can be described as:
	 *
	 * ResponderSignedOctets = RealMessage2 | NonceIData | MACedIDForR
	 * GenIKEHDR = [ four octets 0 if using port 4500 ] | RealIKEHDR
	 * RealIKEHDR =  SPIi | SPIr |  . . . | Length
	 * RealMessage2 = RealIKEHDR | RestOfMessage2
	 * NonceIPayload = PayloadHeader | NonceIData
	 * ResponderIDPayload = PayloadHeader | RestOfIDPayload
	 * RestOfRespIDPayload = IDType | RESERVED | InitIDData
	 * MACedIDForR = prf(SK_pr, RestOfRespIDPayload)
	 */

	if (sa->is_initiator ? i_to_r : (!i_to_r)) {
		assert(sa->my_first_message);
		message = sa->my_first_message;
	} else {
		assert(sa->peer_first_message);
		message = sa->peer_first_message;
	}
	if (i_to_r) {
		nonce = sa->n_r;
		sk = sa->sk_p_i;
		id = sa->id_i;
	} else {
		nonce = sa->n_i;
		sk = sa->sk_p_r;
		id = sa->id_r;
	}

	/* NOTE: `sk` here is sk_p_r / sk_p_i — an IKE SKEYSEED-derived secret.
	 * It and the signed octets (which carry the IntAuth appendix when
	 * WITH_INTERMEDIATE) must NEVER be plogdumped. */

	/* prf(SK, ID) */
	prf_output = keyed_hash(prf, sk, id);
	if (!prf_output)
		goto end;

	IF_TRACE({
		TRACE((PLOGLOC, "prf(SK, ID) length=%lu\n",
		    (unsigned long)prf_output->l));
	});

	/* octets = message | N | prf(SK, ID) */
	octets = rc_vmalloc(message->l + nonce->l + prf_output->l);
	if (!octets)
		goto end;

	p = (uint8_t *)octets->v;
	VCONCAT(octets, p, message);
	VCONCAT(octets, p, nonce);
	VCONCAT(octets, p, prf_output);

#ifdef WITH_INTERMEDIATE
	/* RFC 9242 s3.3.2: append IntAuth = IntAuth_iN | IntAuth_rN |
	 * IKE_AUTH_MID to the signed/MACed blob when intermediate rounds ran. */
	if (sa->intermediate_negotiated && sa->intermediate_rounds > 0) {
		rc_vchar_t *ia, *grown;
		uint8_t midb[4];
		uint8_t *q;

		if (!sa->intauth_i || !sa->intauth_r)
			goto fail_intauth;

		/* RFC 9242 s3.3.2: IKE_AUTH_MID = the Message ID the IKE_AUTH
		 * exchange actually runs under ("exactly as it appears on the
		 * wire").  intermediate_rounds + 1 is that value for the current
		 * single-round IKE_INTERMEDIATE (each round consumes exactly one
		 * request msgid; IKE_SA_INIT=0, round-1 request=1, AUTH=2) --
		 * it is NOT an arbitrary counter and must keep tracking the real
		 * AUTH msgid if multi-round / card AUTH msgid allocation ever
		 * changes (see ikev2_check_message_ordering / send_message_id). */
		put_uint32((uint8_t *)midb, (uint32_t)(sa->intermediate_rounds + 1));
		ia = rc_vmalloc(sa->intauth_i->l + sa->intauth_r->l + 4);
		if (!ia)
			goto fail_intauth;
		q = (uint8_t *)ia->v;
		memcpy(q, sa->intauth_i->v, sa->intauth_i->l);
		q += sa->intauth_i->l;
		memcpy(q, sa->intauth_r->v, sa->intauth_r->l);
		q += sa->intauth_r->l;
		memcpy(q, midb, 4);
		IF_TRACE({
			/* non-secret: lengths only.  sa->intauth_i/r are sk_p-keyed
			 * PRF outputs (secret MACs) and must NEVER be logged. */
			TRACE((PLOGLOC, "IntAuth [i->r=%d] i_len=%zu r_len=%zu\n",
			       i_to_r, sa->intauth_i->l, sa->intauth_r->l));
		});
		/* rc_vconcat reallocs dest IN PLACE and returns it (may
		 * be a new pointer); octets aliases grown -- do NOT free
		 * octets separately or we double-free. */
		grown = rc_vconcat(octets, ia->v, ia->l);
		rc_vfree(ia);
		if (!grown)
			goto fail_intauth;
		octets = grown;
	}
#endif

	/* NOTE: `octets` = message | N | prf(SK, ID) [ | IntAuth_iN | IntAuth_rN
	 * | IKE_AUTH_MID ] — contains the SK-keyed MAC and the IntAuth appendix.
	 * Secret; never plogdump. */

      end:
	if (prf_output)
		rc_vfree(prf_output);
	return octets;

      fail_intauth:
	/* Fail CLOSED: intermediate rounds ran (RFC 9242) but the chained
	 * IntAuth is missing or couldn't be built -- never emit a classical
	 * (no-IntAuth) AUTH blob that a compliant peer would reject confusingly,
	 * and never sign without the mandatory RFC 9242 appendix. */
	if (prf_output)
		rc_vfree(prf_output);
	if (octets) {
		rc_vfree(octets);
		octets = 0;
	}
	return NULL;
}


/*
 * map an ECDSA IKEv2 AUTH method number to the OpenSSL digest name
 * (RFC4754: 9 -> SHA256, 10 -> SHA384, 11 -> SHA512)
 */
static const char *
ikev2_auth_ecdsa_hash(int method)
{
	switch (method) {
	case IKEV2_AUTH_ECDSA_SHA256_P256:
		return "SHA256";
	case IKEV2_AUTH_ECDSA_SHA384_P384:
		return "SHA384";
	case IKEV2_AUTH_ECDSA_SHA512_P521:
		return "SHA512";
	}
	return NULL;
}

/*
 * returns the content of Auth payload
 * (including struct ikev2payl_auth_h but does not include payload header)
 */
rc_vchar_t *
ikev2_auth_calculate(struct ikev2_sa *sa, int i_to_r)
{
	int method;
	rc_vchar_t *id;
	rc_vchar_t *octets = 0;
	rc_vchar_t *authdata = 0;
	struct ikev2payl_auth_h auth_hdr;
	rc_vchar_t *auth_payload = 0;
	rc_vchar_t *privkey = 0;
	rc_vchar_t *k = 0;
	rc_vchar_t *sharedkey = 0;

	method = ikev2_auth_method(sa);
	if (method == 0)
		goto fail;

	if (i_to_r) {
		id = sa->id_i;
	} else {
		id = sa->id_r;
	}

	octets = ikev2_auth_input(sa, i_to_r);
	if (!octets)
		goto fail_nomem;
	switch (method) {
#ifdef HAVE_SIGNING_C
	case IKEV2_AUTH_RSASIG:
		/* (draft-17)
		 * RSA Digital Signature (1) - Computed as specified in section
		 * 2.15 using an RSA private key over a PKCS#1 padded hash.
		 */
		privkey = ikev2_private_key(sa, id);
		if (!privkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get private key\n");
			goto fail;
		}
		/* (RFC8247)
		 * Section 3.2 requires SHA-256 for IKEv2 AUTH PKCS#1-v1.5 RSA
		 * signatures; SHA-1 MUST NOT be used for this purpose.
		 */
		authdata = eay_rsassa_pkcs1_v1_5_sign("SHA256", octets, privkey);
		if (!authdata) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed calculating RSA signature\n");
			goto fail;
		}
		break;
	case IKEV2_AUTH_DS:
		/* (RFC7427)
		 * Digital Signature (14) - RSA signature over SHA-256, with the
		 * auth data prefixed by [1-octet length][AlgorithmIdentifier].
		 */
		privkey = ikev2_private_key(sa, id);
		if (!privkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get private key\n");
			goto fail;
		}
		{
			rc_vchar_t *ori;
		const size_t _ai_len = sizeof(rfc7427_sha256_ai);
			ori = eay_rsassa_pkcs1_v1_5_sign("SHA256", octets, privkey);
			if (!ori) {
				isakmp_log(sa, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed calculating RSA signature\n");
				goto fail;
			}
			authdata = rc_vmalloc(1 + _ai_len + ori->l);
			if (!authdata) {
				rc_vfree(ori);
				goto fail_nomem;
			}
			authdata->u[0] = (uint8_t)_ai_len;
			memcpy(authdata->u + 1, rfc7427_sha256_ai, _ai_len);
			memcpy(authdata->u + 1 + _ai_len, ori->v, ori->l);
			rc_vfree(ori);
		}
		break;
	case IKEV2_AUTH_DSS:
		/* (draft-17)
		 * DSS Digital Signature (3) - Computed as specified in section
		 * 2.15 using a DSS private key over a SHA-1 hash.
		 */
		privkey = ikev2_private_key(sa, id);
		if (!privkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get private key\n");
			goto fail;
		}
		authdata = eay_dss_sign(octets, privkey);
		if (!authdata) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed calculating DSS signature\n");
			goto fail;
		}
		break;
	case IKEV2_AUTH_ECDSA_SHA256_P256:
	case IKEV2_AUTH_ECDSA_SHA384_P384:
	case IKEV2_AUTH_ECDSA_SHA512_P521:
		/* (RFC4754)
		 * ECDSA Digital Signature (9/10/11) - Computed as specified in
		 * section 3.3.2 using an ECDSA private key over a SHA-* hash.
		 * The signature data is the raw r||s octet string.
		 */
		privkey = ikev2_private_key(sa, id);
		if (!privkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get private key\n");
			goto fail;
		}
		authdata = eay_ecdsa_sign(ikev2_auth_ecdsa_hash(method),
					  octets, privkey);
		if (!authdata) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed calculating ECDSA signature\n");
			goto fail;
		}
		break;
#endif
	case IKEV2_AUTH_SHARED_KEY:
		/* (draft-17)
		 * Shared Key Message Integrity Code (2) - Computed as specified in
		 * section 2.15 using the shared key associated with the identity
		 * in the ID payload and the negotiated prf function
		 */
		/* (draft-17)
		 * If the negotiated prf takes a fixed size key, the shared
		 * secret MUST be of that fixed size.
		 */
		{
			static rc_vchar_t keypad =
				VCHAR_INIT(IKEV2_SHAREDSECRET_KEYPAD,
					   IKEV2_SHAREDSECRET_KEYPADLEN);

#ifdef notyet
			/* EAP case: shared key is dynamically obtained from server */
#endif
			sharedkey = ikev2_pre_shared_key(sa);
			if (!sharedkey)
				goto fail_no_shared_key;
			if (!sa->prf->method->is_variable_keylen &&
			    sharedkey->l != (size_t)sa->prf->method->preferred_key_len)
				goto fail_bad_preshared_key;

			IF_TRACE({
				TRACE((PLOGLOC, "sharedkey (%lu bytes, NOT dumped)\n",
				       (unsigned long)sharedkey->l));
			});
			k = keyed_hash(sa->prf, sharedkey,
				       (rc_vchar_t *)&keypad);
			rc_vfreez(sharedkey);
			if (!k)
				goto fail_nomem;
			IF_TRACE({
				TRACE((PLOGLOC, "k length=%lu\n",
				    (unsigned long)k->l));
			});
			authdata = keyed_hash(sa->prf, k, octets);
			if (!authdata)
				goto fail_nomem;
		}
		break;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "unsupported auth method (%d)\n", method);
		goto end;
		break;
	}
	IF_TRACE({
		TRACE((PLOGLOC, "auth data\n"));
		plogdump(PLOG_DEBUG, PLOGLOC, 0, authdata->v, authdata->l);
	});
	auth_hdr.auth_method = method;
	memset(&auth_hdr.reserved, 0, sizeof(auth_hdr.reserved));
	auth_payload = rc_vprepend(authdata, &auth_hdr, sizeof(auth_hdr));
	if (!auth_payload)
		goto fail_nomem;

      end:
      fail:
	if (privkey)
		rc_vfreez(privkey);
	if (authdata)
		rc_vfree(authdata);
	if (octets)
		rc_vfree(octets);
	if (k)
		rc_vfreez(k);
	return auth_payload;

      fail_nomem:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	goto fail;

      fail_no_shared_key:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "no shared key with peer\n");
	goto fail;

      fail_bad_preshared_key:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "pre-shared key length (%lu) does not match prf's fixed key length (%d)\n",
		   (unsigned long)sharedkey->l, sa->prf->method->preferred_key_len);
	goto fail;
}

/*
 * returns:
 *  VERIFIED_SUCCESS (1) if verified successfully
 *  VERIFIED_FAILURE (-1) if doesn't match or on error
 *  VERIFIED_WAITING (0) if to be decided later
 */
int
ikev2_auth_verify(struct ikev2_sa *sa, int i_to_r,
		  struct ikev2payl_auth *auth_payload)
{
	int result = VERIFIED_FAILURE;
	unsigned int method;
	rc_vchar_t *id;
	rc_vchar_t *octets = 0;
	rc_vchar_t *authdata = 0;
	rc_vchar_t *pubkey = 0;
	rc_vchar_t *k = 0;
	rc_vchar_t *sharedkey = 0;
	rc_vchar_t *prf_output = 0;

	TRACE((PLOGLOC, "ikev2_auth_verify(%p, %d, %p)\n", sa, i_to_r,
	       auth_payload));

	method = auth_payload->ah.auth_method;

	if (i_to_r) {
		id = sa->id_i;
	} else {
		id = sa->id_r;
	}

	authdata = rc_vnew((uint8_t *)(auth_payload + 1),
			get_payload_length(auth_payload) -
			sizeof(*auth_payload));
	if (!authdata)
		goto end;

	octets = ikev2_auth_input(sa, i_to_r);
	if (!octets)
		goto end;

	TRACE((PLOGLOC, "auth method %d\n", method));
	switch (method) {
#ifdef HAVE_SIGNING_C
	case IKEV2_AUTH_RSASIG:
		/* (RFC 7296 s3.8 / F6) RSA Digital Signature (1): hash is not
		 * negotiated.  Recover DigestInfo; accept SHA-1 (interop with
		 * strongSwan auth=rsa / Windows / iOS) or SHA-256 (iked<->iked).
		 */
		pubkey = ikev2_public_key(sa, id, &sa->due_time);
		if (!pubkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get public key\n");
			goto fail;
		}
		if (eay_rsassa_pkcs1_v1_5_verify_auth(octets, authdata,
						      pubkey) == 0)
			result = VERIFIED_SUCCESS;
		else
			result = VERIFIED_FAILURE;
		break;
	case IKEV2_AUTH_DS:
		/* (RFC7427 s3)
		 * Digital Signature (14) - auth data = [1-octet len][AI][signature].
		 * The AlgorithmIdentifier names the scheme and hash; any SHA-2
		 * RSASSA-PKCS1-v1_5, RSASSA-PSS or ECDSA identifier is accepted
		 * (eay_rfc7427_verify), SHA-1 is not (RFC 8247 s3.2). */
		pubkey = ikev2_public_key(sa, id, &sa->due_time);
		if (!pubkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get public key\n");
			goto fail;
		}
		if (authdata->l < 1 || authdata->u[0] == 0 ||
		    authdata->l < 1 + (size_t)authdata->u[0] + 1) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "malformed RFC 7427 authentication data\n");
			result = VERIFIED_FAILURE;
			break;
		}
		{
			size_t _ai_len = authdata->u[0];
			rc_vchar_t sig_view;

			memset(&sig_view, 0, sizeof(sig_view));
			sig_view.l = authdata->l - 1 - _ai_len;
			sig_view.u = authdata->u + 1 + _ai_len;
			if (eay_rfc7427_verify(octets, authdata->u + 1, _ai_len,
					       &sig_view, pubkey) == 0)
				result = VERIFIED_SUCCESS;
			else
				result = VERIFIED_FAILURE;
		}
		break;
	case IKEV2_AUTH_DSS:
		/* (draft-17)
		 * DSS Digital Signature (3) - Computed as specified in section
		 * 2.15 using a DSS private key over a SHA-1 hash.
		 */
		pubkey = ikev2_public_key(sa, id, &sa->due_time);
		if (!pubkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get public key\n");
			goto fail;
		}
		if (eay_dss_verify(octets, authdata, pubkey) == 0)
			result = VERIFIED_SUCCESS;
		else
			result = VERIFIED_FAILURE;
		break;
	case IKEV2_AUTH_ECDSA_SHA256_P256:
	case IKEV2_AUTH_ECDSA_SHA384_P384:
	case IKEV2_AUTH_ECDSA_SHA512_P521:
		pubkey = ikev2_public_key(sa, id, &sa->due_time);
		if (!pubkey) {
			isakmp_log(sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed to get public key\n");
			goto fail;
		}
		if (eay_ecdsa_verify(ikev2_auth_ecdsa_hash(method),
				     octets, authdata, pubkey) == 0)
			result = VERIFIED_SUCCESS;
		else
			result = VERIFIED_FAILURE;
		break;
#endif
	case IKEV2_AUTH_SHARED_KEY:
		/* (draft-17)
		 * Shared Key Message Integrity Code (2) - Computed as specified in
		 * section 2.15 using the shared key associated with the identity
		 * in the ID payload and the negotiated prf function
		 */
		/* (draft-17)
		 * If the negotiated prf takes a fixed size key, the shared
		 * secret MUST be of that fixed size.
		 */
		{
			static rc_vchar_t keypad =
				VCHAR_INIT(IKEV2_SHAREDSECRET_KEYPAD,
					   IKEV2_SHAREDSECRET_KEYPADLEN);

			sharedkey = ikev2_pre_shared_key(sa);
			if (!sharedkey)
				goto fail_no_shared_key;
			if (!sa->prf->method->is_variable_keylen &&
			    sharedkey->l != (size_t)sa->prf->method->preferred_key_len)
				goto fail_bad_preshared_key;
			IF_TRACE({
				TRACE((PLOGLOC, "sharedkey (%lu bytes, NOT dumped)\n",
				       (unsigned long)sharedkey->l));
			});
			k = keyed_hash(sa->prf, sharedkey, &keypad);
			rc_vfreez(sharedkey);
			if (!k)
				goto fail_nomem;
			IF_TRACE({
				TRACE((PLOGLOC, "k length=%lu\n",
				    (unsigned long)k->l));
			});
			prf_output = keyed_hash(sa->prf, k, octets);
			if (!prf_output)
				goto fail_nomem;
			IF_TRACE({
				TRACE((PLOGLOC, "prf(k, octets)\n"));
				plogdump(PLOG_DEBUG, PLOGLOC, 0, prf_output->v,
					 prf_output->l);
			});
			if (prf_output->l == authdata->l &&
			    CRYPTO_memcmp(prf_output->v, authdata->v,
				      prf_output->l) == 0)
				result = VERIFIED_SUCCESS;
			else
				result = VERIFIED_FAILURE;
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "psk verify result=%d prf_out_len=%lu authdata_len=%lu\n",
			     result, (unsigned long)prf_output->l,
			     (unsigned long)authdata->l);
		}
		break;
	default:
		plog(PLOG_PROTOERR, PLOGLOC, 0,
		     "unsupported auth method (%d)\n", method);
		goto end;
		break;
	}
      end:
      fail:
	TRACE((PLOGLOC, "result: %d\n", result));
	if (pubkey)
		rc_vfree(pubkey);
	if (authdata)
		rc_vfree(authdata);
	if (octets)
		rc_vfree(octets);
	if (k)
		rc_vfreez(k);
	if (prf_output)
		rc_vfree(prf_output);
	return result;

      fail_nomem:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	goto fail;

      fail_no_shared_key:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "no shared key with peer\n");
	goto fail;

      fail_bad_preshared_key:
	isakmp_log(sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "pre-shared key length (%lu) does not match prf's fixed key length (%d)\n",
		   (unsigned long)sharedkey->l, sa->prf->method->preferred_key_len);
	goto fail;
}

/*
 * convert internal code to the method ID of IKEv2 Authentication payload
 */
int
ikev2_auth_method(struct ikev2_sa *sa)
{
	struct rc_alglist *alg;

	alg = ikev2_kmp_auth_method(sa->rmconf);
	if (!alg) {
		isakmp_log(sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "configuration does not specify kmp_auth_method\n");
		return 0;
	}
	switch (alg->algtype) {
	case RCT_ALG_PSK:
		return IKEV2_AUTH_SHARED_KEY;
	case RCT_ALG_DSS:
		return IKEV2_AUTH_DSS;
	case RCT_ALG_RSASIG:
		/* RFC 7427: when N(SIG_HASH_ALGORITHMS) was exchanged with the peer,
		 * use AUTH method 14 (DS) so the signature can carry a SHA-2 hash.
		 * Classic method 1 is SHA-1-only and OpenSSL >=3.5 refuses SHA-1
		 * signing.  Only negotiated when the PEER offered 16431 (charon);
		 * iked<->iked rows keep method 1. */
		if (sa->sig_hash_algos_ds)
			return IKEV2_AUTH_DS;
		return IKEV2_AUTH_RSASIG;
	case RCT_ALG_ECDSA:
#ifdef HAVE_SIGNING_C
		/* (RFC4754)
		 * The method number reflects the curve of the private key:
		 * P-256 -> 9, P-384 -> 10, P-521 -> 11.
		 */
		{
			rc_vchar_t *privkey;
			int bits;

			privkey = ikev2_private_key(sa, sa->id_i);
			if (!privkey) {
				isakmp_log(sa, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "failed to get private key\n");
				return 0;
			}
			bits = eay_ecdsa_curve_bits(privkey);
			rc_vfreez(privkey);
			switch (bits) {
			case 256:
				return IKEV2_AUTH_ECDSA_SHA256_P256;
			case 384:
				return IKEV2_AUTH_ECDSA_SHA384_P384;
			case 521:
				return IKEV2_AUTH_ECDSA_SHA512_P521;
			default:
				isakmp_log(sa, 0, 0, 0,
					   PLOG_INTERR, PLOGLOC,
					   "unsupported ECDSA curve (%d bits)\n", bits);
				return 0;
			}
		}
#else
		return 0;
#endif
	default:
		isakmp_log(sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unsupported auth method (%s)\n",
			   rct2str(alg->algtype));
		return 0;
	}
}

/*
 * perform the verification
 */
void
ikev2_verify(struct verified_info *info)
{
	struct ikev2_sa *ike_sa;
	struct ikev2payl_auth *auth;

	if (info->result != VERIFIED_WAITING)
		goto done;

	ike_sa = (struct ikev2_sa *)info->callback_param;
	auth = (struct ikev2payl_auth *)info->verify_param;

	info->result = ikev2_auth_verify(ike_sa, !info->is_initiator, auth);
	if (info->result == VERIFIED_FAILURE) {
		isakmp_log(ike_sa, info->local, info->remote, info->packet,
			   PLOG_PROTOERR, PLOGLOC, "authentication failure\n");
		++isakmpstat.authentication_failed;
	} else if (info->result == VERIFIED_WAITING)
		return;

    done:
	info->verified_callback(info);
}
