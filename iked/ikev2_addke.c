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
 * SKELETON: compile-time scaffolding for the PQC milestone.  The
 * negotiation plumbing is in place (transform type 6 constants in
 * ikev2.h, proposal rejection in ikev2_compare_transforms, exchange
 * type 44 dispatch in ikev2_established_recv); the crypto and the
 * follow-up exchange state machine land here incrementally.
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

#include "racoon.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "plog.h"

/* RFC 9370 s2.2.4: ADDITIONAL_KEY_EXCHANGE notification (16441)
 * carries the message ID of the CREATE_CHILD_SA request that the
 * ADDKE exchange is linked to.  Extract (and, for the response,
 * echo) that linkage. */
static int
followup_ke_link_msgid(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		       uint32_t *link_msgid)
{
	/* TODO(PQC): walk notification payloads for
	 * IKEV2_ADDITIONAL_KEY_EXCHANGE and store the CREATE_CHILD_SA
	 * message id it references (rfc9370 s2.2.4). */
	(void)ike_sa;
	(void)msg;
	(void)link_msgid;
	return -1;	/* unimplemented: reject for now */
}

void
ikev2_followup_ke_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		       struct sockaddr *remote, struct sockaddr *local)
{
	uint32_t link_msgid;
	struct ikev2_header *ikehdr;
	int is_response;

	ikehdr = (struct ikev2_header *)msg->v;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;

	/* RFC 9370 s2.2.4: the initiator includes the
	 * ADDITIONAL_KEY_EXCHANGE notification linking this exchange
	 * to the CREATE_CHILD_SA; the responder echoes it.  No
	 * linkage, no valid exchange. */
	if (is_response || followup_ke_link_msgid(ike_sa, msg, &link_msgid) < 0) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "IKE_FOLLOWUP_KE: missing/unimplemented "
			   "ADDITIONAL_KEY_EXCHANGE linkage\n");
		if (!is_response) {
			errno = 0;
			(void)ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0,
						  IKEV2_INVALID_SYNTAX, 0, 0);
		}
		return;
	}

	/* TODO(PQC): perform the ML-KEM-768 key exchange
	 * (EVP_PKEY_ML_KEM768 / EVP_KEM, <openssl/ml_kem.h>) and
	 * derive GSKM_seed per rfc9370 s3.2.3 to feed
	 * ikev2_createchild_derive_keymat.  Until then the exchange
	 * is refused; the notifier keeps the peer from hanging. */
	errno = 0;
	(void)ikev2_respond_error(ike_sa, msg, remote, local,
				  0, 0, 0, IKEV2_NO_PROPOSAL_CHOSEN, 0, 0);
}

#endif	/* WITH_ADDKE */
