/*
 * Copyright (C) 2004-2005 WIDE Project.
 * Copyright (C) 2026 the racoon2 project.
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

/*
 * RFC 9242 IKE_INTERMEDIATE helpers that must outlive ikev2.c.
 *
 * ikev2.c still owns the exchange (exch 43, IntAuth chain, ADDKE round).
 * This TU exists so SA dispose can release IntAuth / ML-KEM state without
 * pulling the 7.8k-line ikev2.c through the GitHub contents push path.
 */

#include "config.h"

#ifdef WITH_INTERMEDIATE

#include <openssl/evp.h>

#include "racoon.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"

void
ikev2_intermediate_clear(struct ikev2_sa *sa)
{
	if (!sa)
		return;
	ikev2_intermediate_clear_replay(sa);
	rc_vfreez(sa->intauth_i);
	sa->intauth_i = 0;
	rc_vfreez(sa->intauth_r);
	sa->intauth_r = 0;
	rc_vfreez(sa->intermediate_req);
	sa->intermediate_req = 0;
	rc_vfreez(sa->intermediate_resp);
	sa->intermediate_resp = 0;
	/* H1: retained gen-0 receive keys (must not leak; set on responder SA
	 * that did an RFC 9242 key update). */
	rc_vfreez(sa->prev_sk_a_r);
	sa->prev_sk_a_r = 0;
	rc_vfreez(sa->prev_sk_e_r);
	sa->prev_sk_e_r = 0;
	if (sa->intermediate_priv) {
		EVP_PKEY_free((EVP_PKEY *)sa->intermediate_priv);
		sa->intermediate_priv = 0;
	}
}

/* Drop only the gen-0 response replay cache.  Called once IKE_AUTH is
 * accepted (the RFC 9242 window is over); unlike ikev2_intermediate_clear
 * it does NOT drop the retained prev-gen receive keys, which the classical
 * (non-AEAD) gen-rolled retransmit path ikev2_check_icv_prev_gen() still
 * needs until dispose. */
void
ikev2_intermediate_clear_replay(struct ikev2_sa *sa)
{
	if (!sa)
		return;
	rc_vfreez(sa->intermediate_replay);
	sa->intermediate_replay = 0;
	if (sa->intermediate_replay_frags) {
		int i;

		for (i = 0; i < sa->intermediate_replay_nfrags; i++)
			if (sa->intermediate_replay_frags[i])
				rc_vfree(sa->intermediate_replay_frags[i]);
		racoon_free(sa->intermediate_replay_frags);
		sa->intermediate_replay_frags = 0;
		sa->intermediate_replay_nfrags = 0;
	}
	sa->intermediate_replay_msgid = 0;
}

#endif /* WITH_INTERMEDIATE */
