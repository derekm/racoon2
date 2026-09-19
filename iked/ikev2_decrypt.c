/* $Id$
 *
 * IKEv2 encrypted-payload decrypt (send/receive direction).
 *
 * Extracted from ikev2_payload.c so the standalone RFC 7383
 * fragtest can link the real ikev2_decrypt_local() that
 * ikev2_frag_send() needs (the CI unit suite otherwise fails
 * with 'undefined reference to ikev2_decrypt_local').
 *
 * Copyright (C) 2004-2005 WIDE Project.
 * All rights reserved.  Redistribution subject to the license
 * in ikev2_payload.c.
 */

#include <config.h>

#include <assert.h>
#include <string.h>
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
#include <sys/socket.h>
#include <sys/errno.h>

#include <netinet/in.h>

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "crypto_impl.h"
#include "encryptor.h"

#include "debug.h"


/*
 * decrypt Encrypted Payload.
 *
 * Encrypted Payload is truncated to its header only, and the
 * decrypted data are repositioned as the payloads following the
 * Encrypted Payload.
 * XXX directly modifies the vmbuf internal
 *
 * packet buffer length is adjusted to the tail of decrypted data.
 * returns 0 if successful, non-zero if fails
 */
static int
ikev2_decrypt_internal(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
		       int use_send_key)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;
	int block_len;
	int iv_len;
	uint8_t *iv;
	uint8_t *ciphertext;
	size_t icv_len;
	rc_vchar_t *ivbuf = 0;
	rc_vchar_t *orig = 0;
	rc_vchar_t *decrypted = 0;
	uint8_t *d;
	unsigned int pad_length;
	size_t decrypted_payloads_len;
	size_t ciphertext_len;
	size_t msglen;
	int retval = -1;

	TRACE((PLOGLOC, "ikev2_decrypt(%p, %p)\n", ike_sa, packet));
	if (!ike_sa->encryptor || !ike_sa->authenticator) {
		TRACE((PLOGLOC,
		       "encrypted message arrived to premature ike_sa\n"));
		return -1;
	}

	block_len = encryptor_block_length(ike_sa->encryptor);
	iv_len = encryptor_iv_length(ike_sa->encryptor);
	if (encryptor_icv_length(ike_sa->encryptor) > 0)
		icv_len = encryptor_icv_length(ike_sa->encryptor);
	else
		icv_len = auth_output_length(ike_sa->authenticator);

	ikehdr = (struct ikev2_header *)packet->v;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	while (type != IKEV2_NO_NEXT_PAYLOAD && type != IKEV2_PAYLOAD_ENCRYPTED) {
		POINT_NEXT_PAYLOAD(p, type);
	}
	if (type != IKEV2_PAYLOAD_ENCRYPTED) {
		TRACE((PLOGLOC, "packet does not have ENCRYPTED payload\n"));
		return -1;
	}

	if (get_payload_data_length(p) < iv_len + 1 + icv_len) {
		TRACE((PLOGLOC, "short payload\n"));
		return -1;
	}

	iv = (uint8_t *)(p + 1);
	ciphertext = iv + iv_len;
	if (encryptor_icv_length(ike_sa->encryptor) > 0)
		ciphertext_len = get_payload_data_length(p) - iv_len;
	else
		ciphertext_len = get_payload_data_length(p) - iv_len - icv_len;

	/* decrypt */
	ivbuf = rc_vnew(iv, iv_len);
	if (!ivbuf)
		goto fail;
	orig = rc_vnew(ciphertext, ciphertext_len);
	if (!orig)
		goto fail_nomem;
	if (encryptor_icv_length(ike_sa->encryptor) > 0) {
		rc_vchar_t *aad;

		aad = rc_vnew(packet->v, (uint8_t *)(p + 1) - (uint8_t *)packet->v);
		if (!aad)
			goto fail_nomem;
		decrypted = encryptor_decrypt_aead(ike_sa->encryptor, orig,
		    use_send_key ? (ike_sa->is_initiator ? ike_sa->sk_e_i
					  : ike_sa->sk_e_r)
			 : (ike_sa->is_initiator ? ike_sa->sk_e_r
					  : ike_sa->sk_e_i),
		    ivbuf, aad);
		rc_vfree(aad);
	} else {
		decrypted = encryptor_decrypt(ike_sa->encryptor, orig,
		    use_send_key ? (ike_sa->is_initiator ? ike_sa->sk_e_i
					  : ike_sa->sk_e_r)
			 : (ike_sa->is_initiator ? ike_sa->sk_e_r
					  : ike_sa->sk_e_i),
		    ivbuf);
	}
	if (!decrypted)
		goto fail;

	d = (uint8_t *)decrypted->v;
	pad_length = d[decrypted->l - 1];
	if (pad_length + 1 > decrypted->l)	/* +1 for Pad Length field */
		goto fail;	/* malformed */
	decrypted_payloads_len = decrypted->l - pad_length - 1;

	/* truncate ENCRYPTED payload to header only */
	put_uint16(&p->payload_length, sizeof(struct ikev2_payload_header));

	/* copy decrypted payloads into original packet buffer */
	memcpy(iv, decrypted->v, decrypted_payloads_len);	/* overwrites original data */

	/* adjust the buffer length */
	msglen = iv - (uint8_t *)packet->v + decrypted_payloads_len;
	packet->l = msglen;	/* XXX modifies vmbuf internal */
	put_uint32(&ikehdr->length, msglen);
	retval = 0;

      end:
	if (orig)
		rc_vfree(orig);
	if (decrypted)
		rc_vfree(decrypted);
	if (ivbuf)
		rc_vfree(ivbuf);
	return retval;

      fail_nomem:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
      fail:
	retval = -1;
	goto end;
}

/* Decrypt a message received from the peer (uses the RECEIVE-direction key). */
int
ikev2_decrypt(struct ikev2_sa *ike_sa, rc_vchar_t *packet)
{
	return ikev2_decrypt_internal(ike_sa, packet, 0);
}

/*
 * Decrypt a message we built and encrypted ourselves in this process (uses the
 * SEND-direction key).  ikev2_frag_send() needs this to re-extract the inner
 * payloads of its own just-encrypted packet before chunking them into SKF
 * fragments — a RECEIVE-direction decrypt there decodes with the wrong key and
 * yields garbage inner payloads (the iked<->iked matrix observed this).
 */
int
ikev2_decrypt_local(struct ikev2_sa *ike_sa, rc_vchar_t *packet)
{
	return ikev2_decrypt_internal(ike_sa, packet, 1);
}
