/* $Id: ikev2_rekey.c,v 1.66 2008/02/06 08:09:00 mk Exp $ */

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
#include <netinet/in.h>		/* for htons() */

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_notify.h"
#include "ike_conf.h"
#include "dhgroup.h"
#include "oakley.h"		/* for prototypes */
#include "crypto_impl.h"

#include "debug.h"

extern struct isakmp_domain ikev2_createchild_doi;

/*
 * Initiate Rekey CHILD_SA
 */
void
ikev2_rekey_childsa(struct ikev2_child_sa *old_child_sa, rc_type satype,
		    uint32_t spi)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *new_child_sa;

	/* (draft-17)
	 *
	 * Initiator                                 Responder
	 * -----------                               -----------
	 * HDR, SK {[N], SA, Ni, [KEi],
	 * [TSi, TSr]}             -->
	 *
	 * The initiator sends SA offer(s) in the SA payload, a nonce in the Ni
	 * payload, optionally a Diffie-Hellman value in the KEi payload, and
	 * the proposed traffic selectors in the TSi and TSr payloads. If this
	 * CREATE_CHILD_SA exchange is rekeying an existing SA other than the
	 * IKE_SA, the leading N payload of type REKEY_SA MUST identify the SA
	 * being rekeyed. If this CREATE_CHILD_SA exchange is not rekeying an
	 * existing SA, the N payload MUST be omitted.  If the SA offers include
	 * different Diffie-Hellman groups, KEi MUST be an element of the group
	 * the initiator expects the responder to accept. If it guesses wrong,
	 * the CREATE_CHILD_SA exchange will fail and it will have to retry with
	 * a different KEi.
	 */

	/* (draft-eronen-ipsec-ikev2-clarifications-05.txt)
	 * o  It is not clear which SA to send in a rekeying a child SA.  The
	 * relevant sentence says "If this CREATE_CHILD_SA exchange is
	 * rekeying an existing SA other than the IKE_SA, the leading N
	 * payload of type REKEY_SA MUST identify the SA being rekeyed."
	 * That can be clarified by adding "sender's inbound" before "SA
	 * being rekeyed".
	 */

	TRACE((PLOGLOC, "rekeying %p\n", old_child_sa));

	ike_sa = old_child_sa->parent;
	TRACE((PLOGLOC, "ike_sa: %p\n", ike_sa));

	if (ike_sa->state != IKEV2_STATE_ESTABLISHED) {
		INFO((PLOGLOC,
		      "can't start rekey (ike_sa state %d != ESTABLISHED)\n",
		      ike_sa->state));
		return;
	}

	/*
	 * CP-server used to skip initiator rekey and wait for the
	 * client.  Apple never CREATE_CHILD before the 3600s hard
	 * lifetime, so the CHILD dies idle.  Rekey from this side.
	 */
	new_child_sa = ikev2_create_child_initiator(ike_sa);
	TRACE((PLOGLOC, "new_child_sa: %p\n", new_child_sa));
	if (!new_child_sa) {
		TRACE((PLOGLOC, "failed creating child_sa\n"));
		goto fail_nomem;
	}

	new_child_sa->preceding_satype = satype;
	new_child_sa->preceding_spi = spi;

	{
		struct rcf_selector *sl = old_child_sa->selector;

		if (!sl)
			goto fail;
		/* Responder children store inbound; initiator CREATE_CHILD
		 * needs the outbound twin. */
		if (sl->direction == RCT_DIR_OUTBOUND) {
			if (rcf_get_selector(rc_vmem2str(sl->sl_index),
			    &new_child_sa->selector) != 0) {
				TRACE((PLOGLOC, "failed rcf_get_selector()\n"));
				goto fail;
			}
		} else if (rcf_get_rvrs_selector(sl,
		    &new_child_sa->selector) != 0) {
			TRACE((PLOGLOC, "failed rcf_get_rvrs_selector()\n"));
			goto fail;
		}
		if (sl->next) {
			if (sl->next->direction == RCT_DIR_OUTBOUND) {
				if (rcf_get_selector(
				    rc_vmem2str(sl->next->sl_index),
				    &new_child_sa->selector->next) != 0) {
					TRACE((PLOGLOC,
					    "failed rcf_get_selector()\n"));
					goto fail;
				}
			} else if (rcf_get_rvrs_selector(sl->next,
			    &new_child_sa->selector->next) != 0) {
				TRACE((PLOGLOC,
				    "failed rcf_get_rvrs_selector()\n"));
				goto fail;
			}
		}
	}

	/*
	 * Offer ONLY the proposal matching the child SA being rekeyed.
	 *
	 * ikev2_ipsec_conf_to_proplist(conf, TRUE) builds a proposal
	 * for every configured ipsec block (here: GCM, GCM-12, GCM-8
	 * and CBC/SHA2 = 4 proposals) with need_pfs forcing a DH
	 * transform and an ESN pair in each.  GETSPI (via
	 * ikev2_child_getspi_response) stamps the kernel-allocated
	 * SPI into the FIRST matching proposal only; the remaining
	 * proposals keep the config SPI -- 0.  RFC 7296 2.8/2.7
	 * requires a nonzero SPI in an ESP proposal, and a strict
	 * peer (iOS) answers such a message INVALID_SYNTAX then
	 * deletes the IKE_SA.
	 *
	 * RFC 7296 2.8 also says the rekey offer should match the SA
	 * being rekeyed.  The child we are rekeying already carries
	 * the negotiated proposal (my_proposal[1], matched at AUTH,
	 * currently in use), so duplicate that single proposal for
	 * the new child instead of regenerating the whole config
	 * matrix; GETSPI will stamp the fresh SPI into it.
	 */
	new_child_sa->my_proposal = proplist_new();
	if (!new_child_sa->my_proposal)
		goto fail_nomem;
	if (old_child_sa->my_proposal &&
	    old_child_sa->my_proposal[1]) {
		/* clone the negotiated proposal: header node plus the
		 * transform chain (tnext/next) */
		new_child_sa->my_proposal[1] =
		    proppair_clone(old_child_sa->my_proposal[1]);
		if (!new_child_sa->my_proposal[1]) {
			proplist_discard(new_child_sa->my_proposal);
			new_child_sa->my_proposal = 0;
			TRACE((PLOGLOC,
			       "failed duplicating negotiated proposal "
			       "for rekey\n"));
			goto fail;
		}
	} else {
		/* no negotiated proposal recorded: fall back to the
		 * config-derived list (pre-existing behavior) */
		new_child_sa->my_proposal =
		    ikev2_ipsec_conf_to_proplist(new_child_sa, TRUE);
	}
	if (!new_child_sa->my_proposal) {
		TRACE((PLOGLOC,
		       "failed creating proposal list of initiator SA\n"));
		goto fail;
	}

	new_child_sa->srclist = old_child_sa->srclist;
	old_child_sa->srclist = 0;
	new_child_sa->dstlist = old_child_sa->dstlist;
	old_child_sa->dstlist = 0;

	isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
	    "initiating CREATE_CHILD_SA rekey child=%p spi=0x%08x\n",
	    old_child_sa, spi);

	sadb_request_initialize(&new_child_sa->sadb_request,
				debug_pfkey ? &sadb_debug_method
				    : &sadb_rekey_request_method,
				&ikev2_sadb_callback,
				sadb_new_seq(),
				new_child_sa);
	TRACE((PLOGLOC, "issuing getspi\n"));
	ikev2_child_getspi(new_child_sa);
	return;

      fail_nomem:
	old_child_sa->rekey_inprogress = FALSE;
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	return;
      fail:
	old_child_sa->rekey_inprogress = FALSE;
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed starting rekeying\n");
	return;
}

/*
 * REKEY IKE_SA
 */
/*
 * payload interpretation data for ike_sa rekeying
 */
struct isakmp_domain ikev2_rekey_doi = {
	/* informations for parse_sa */
	ikev2_check_spi_size,	/* check_spi_size */
	sizeof(isakmp_cookie_t),	/* ike_spi_size */
	FALSE,			/* check_reserved_fields */
	FALSE,			/* transform_number */
	ikev2_get_transforms,	/* get_transforms */
	ikev2_compare_transforms,
	ikev2_match_transforms
};

static void rekey_ikesa_callback(enum request_callback, struct ikev2_child_sa *,
				 void *);
static int rekey_skeyseed(struct ikev2_sa *, struct ikev2_sa *, rc_vchar_t *);
static void ikev2_rekey_ikesa_init_send(struct ikev2_child_sa *);
static void ikev2_rekey_ikesa_init_recv(struct ikev2_child_sa *, rc_vchar_t *);

static void ikev2_child_adopt(struct ikev2_sa *old_sa, struct ikev2_sa *new_sa);

void
ikev2_rekey_ikesa_initiate(struct ikev2_sa *ike_sa)
{
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
		   "initiating IKE_SA rekey\n");
	ikev2_sa_stop_grace_timer(ike_sa);
	(void) ikev2_request_initiator_start(ike_sa, rekey_ikesa_callback, 0);
}

static void
rekey_ikesa_callback(enum request_callback action,
		     struct ikev2_child_sa *child_sa,
		     void *data)
{
	struct ikev2_sa *ike_sa;

	TRACE((PLOGLOC, "rekey_ikesa_callback(%d, %p, %p)\n", action, child_sa,
	       data));

	ike_sa = child_sa->parent;
	switch (action) {
	case REQUEST_CALLBACK_CONTINUE:
		if (ike_sa->rekey_inprogress) {
			TRACE((PLOGLOC, "peer initiated rekey already\n"));
			ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_EXPIRED);
		} else {
			ike_sa->rekey_inprogress = TRUE;
			ikev2_rekey_ikesa_init_send(child_sa);
		}
		break;
	case REQUEST_CALLBACK_TRANSMIT_ERROR:
		/* none here */
		break;
	case REQUEST_CALLBACK_RESPONSE:
		ikev2_rekey_ikesa_init_recv(child_sa, (rc_vchar_t *)data);
		break;
	default:
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unknown action code %d\n", (int)action);
		break;
	}
}


/* async KEi for ikev2_rekey_ikesa_init_send (REKEY IKE_SA) */
struct ikev2_rekey_init_ctx {
	struct ikev2_sa *old_sa;
	struct ikev2_sa *new_sa;
	struct ikev2_child_sa *child_sa;
	int serial;	/* old_sa->serial_number, for liveness check */
	struct algdef *dhgrpdef;
	struct ikev2_payloads payl;
	int payl_inited;
	rc_vchar_t *sa;
	struct prop_pair **proplist;
};
static void ikev2_rekey_init_send_tail(struct ikev2_rekey_init_ctx *);

static void
ikev2_rekey_init_ctx_free(struct ikev2_rekey_init_ctx *ctx)
{
	if (ctx->sa)
		rc_vfree(ctx->sa);
	if (ctx->proplist)
		proplist_discard(ctx->proplist);
	if (ctx->payl_inited)
		ikev2_payloads_destroy(&ctx->payl);
	rc_free(ctx);
}

/*
 * Abort an initiator-side IKE_SA rekey that failed before establishment:
 * unlink the stub new_sa (never inserted into the SA list, so periodic
 * disposal cannot reach it) and release the rekey lock, so the SA can be
 * rekeyed again.  Do NOT use when old_sa itself is being torn down
 * (DYING/DEAD): there the new_sa link must survive so ikev2_dispose_sa
 * recurses into it.
 */
static void
ikev2_rekey_init_abort(struct ikev2_sa *old_sa, struct ikev2_sa *new_sa)
{
	if (old_sa->new_sa == new_sa)
		old_sa->new_sa = NULL;
	old_sa->rekey_inprogress = FALSE;
	if (new_sa)
		ikev2_dispose_sa(new_sa);
}

static void
ikev2_rekey_ikesa_init_dh_done(int rc, void *arg)
{
	struct ikev2_rekey_init_ctx *ctx = arg;
	struct ikev2_sa *old_sa;
	struct ikev2_child_sa *child_sa;

	/*
	 * The worker wrote into new_sa->dhpub/dhpriv while the SA was
	 * pinned by crypto_pending (periodic task skips pending SAs).
	 * Confirm old_sa is still the live list member we submitted
	 * for, release its pin either way, then confirm the new_sa
	 * link survived.
	 */
	old_sa = ikev2_find_sa_by_serial(ctx->serial);
	if (old_sa == NULL || old_sa != ctx->old_sa) {
		/* SA disposed while DH ran; nothing to resume */
		ikev2_rekey_init_ctx_free(ctx);
		return;
	}
	old_sa->crypto_pending = 0;
	if (old_sa->new_sa != ctx->new_sa) {
		/* rekey was abandoned while DH ran */
		ikev2_rekey_init_ctx_free(ctx);
		return;
	}
	child_sa = ctx->child_sa;

	if (old_sa->state == IKEV2_STATE_DYING ||
	    old_sa->state == IKEV2_STATE_DEAD ||
	    child_sa->state == IKEV2_CHILD_STATE_EXPIRED) {
		ikev2_rekey_init_ctx_free(ctx);
		return;
	}
	if (rc != 0) {
		TRACE((PLOGLOC, "failed generating DH values\n"));
		isakmp_log(old_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC, "failed to send REKEY IKE_SA\n");
		++isakmpstat.fail_send_packet;
		ikev2_rekey_init_abort(old_sa, ctx->new_sa);
		ikev2_rekey_init_ctx_free(ctx);
		return;
	}
	ikev2_rekey_init_send_tail(ctx);
}
static void
ikev2_rekey_ikesa_init_send(struct ikev2_child_sa *child_sa)
{
	/*
	 * REKEY IKE_SA (initiator):
	 *
	 * -->    HDR, SK {SA, Ni, KEi}
	 * <--    HDR, SK {SA, Nr, KEr}
	 *
	 * The responder replies (using the same Message ID to respond)
	 * with the accepted offer in an SA payload, and a Diffie-Hellman
	 * value in the KEr payload if the selected cryptographic suite
	 * includes that group.
	 *
	 * The new IKE_SA has its message counters set to 0, regardless of
	 * what they were in the earlier IKE_SA. The window size starts at
	 * 1 for any new IKE_SA.
	 *
	 * KEi and KEr are required for rekeying an IKE_SA.
	 */

	/* this routine is similar to ikev2_initiator_start() */

	struct ikev2_payloads payl;
	struct rcf_remote *conf;
	struct ikev2_sa *old_sa;
	struct ikev2_sa *new_sa = 0;
	struct prop_pair **proplist = 0;
	rc_vchar_t *sa = 0;
	struct ikev2_rekey_init_ctx *ctx;

	child_sa->message_id = ikev2_request_id(child_sa->parent);
	TRACE((PLOGLOC, "child_sa %p message_id %d\n", child_sa, child_sa->message_id));

	ikev2_payloads_init(&payl);

	/* create new ike_sa */
	old_sa = child_sa->parent;
	conf = rcf_deepcopy_remote(old_sa->rmconf);
	if (!conf)
		goto fail_nomem;
	new_sa = ikev2_allocate_sa(0, old_sa->local, old_sa->remote, conf);
	TRACE((PLOGLOC, "new_sa: %p\n", new_sa));
	if (!new_sa)
		goto fail_nomem;
	new_sa->is_rekeyed_sa = TRUE;
	conf = 0;
	old_sa->new_sa = new_sa;

	/* create SA */
	proplist = ikev2_conf_to_proplist(new_sa->rmconf, new_sa->index.i_ck);
	if (!proplist) {
		TRACE((PLOGLOC, "failed creating proplist\n"));
		goto fail;
	}
	sa = ikev2_pack_proposal(proplist);
	if (!sa) {
		TRACE((PLOGLOC, "failed creating SA payload\n"));
		goto fail;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		goto fail_nomem;
	ctx->child_sa = child_sa;
	ctx->old_sa = old_sa;
	ctx->new_sa = new_sa;
	ctx->serial = old_sa->serial_number;
	ctx->dhgrpdef = old_sa->negotiated_sa->dhdef;
	ctx->payl = payl;
	ctx->payl_inited = 1;
	ctx->sa = sa;
	sa = NULL;
	ctx->proplist = proplist;
	proplist = NULL;

	old_sa->crypto_pending = 1;
	if (oakley_dh_generate_submit((struct dhgroup *)ctx->dhgrpdef->definition,
	    &new_sa->dhpub, &new_sa->dhpriv,
	    ikev2_rekey_ikesa_init_dh_done, ctx) != 0) {
		old_sa->crypto_pending = 0;
		TRACE((PLOGLOC, "failed dh submit\n"));
		ctx->payl_inited = 0;	/* caller's fail: destroys payl once */
		ikev2_rekey_init_ctx_free(ctx);
		goto fail;
	}
	return;	/* resumed in ikev2_rekey_ikesa_init_recv_dh_done */

      done:
	ikev2_payloads_destroy(&payl);
	return;

      fail_nomem:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to allocate memory\n");
	++isakmpstat.fail_send_packet;
	ikev2_rekey_init_abort(old_sa, new_sa);
	goto done;

      fail:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to send REKEY IKE_SA\n");
	++isakmpstat.fail_send_packet;
	if (sa)
		rc_vfree(sa);
	if (proplist)
		proplist_discard(proplist);
	ikev2_rekey_init_abort(old_sa, new_sa);
	ikev2_payloads_destroy(&payl);
	return;
}

static void
ikev2_rekey_init_send_tail(struct ikev2_rekey_init_ctx *ctx)
{
	struct ikev2_sa *old_sa = ctx->old_sa;
	struct ikev2_sa *new_sa = ctx->new_sa;
	struct ikev2_child_sa *child_sa = ctx->child_sa;
	rc_vchar_t *ke = 0;
	rc_vchar_t *nonce;
	rc_vchar_t *pkt = 0;
	struct ikev2payl_ke_h dhgrp_hdr;
	int nonce_size;

	/* create KE */
	dhgrp_hdr.dh_group_id = htons(ctx->dhgrpdef->transform_id);
	dhgrp_hdr.reserved = 0;
	ke = rc_vprepend(new_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
	if (!ke)
		goto fail_nomem;

	/* create Ni */
	nonce_size = ikev2_nonce_size(new_sa->rmconf);
	nonce = random_bytes(nonce_size);
	if (!nonce)
		goto fail_nomem;
	new_sa->n_i = nonce;

	/*
	 * HDR, SK {SA, Ni, KEi}
	 */
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_SA, ctx->sa, FALSE);
	ctx->sa = NULL;
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NONCE, nonce, FALSE);
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_KE, ke, FALSE);

	{
		int t_i;
		for (t_i = 0; t_i < ctx->payl.num; t_i++)
			isakmp_log(old_sa, 0, 0, child_sa->message_id,
			    PLOG_INFO, PLOGLOC,
			    "REKEY_REQ payl[%d] type=%d len=%d\n",
			    t_i, ctx->payl.payloads[t_i].type,
			    ctx->payl.payloads[t_i].data ?
			    ctx->payl.payloads[t_i].data->l : -1);
	}

	pkt = ikev2_packet_construct(IKEV2EXCH_CREATE_CHILD_SA,
				     old_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0,
				     child_sa->message_id, old_sa, &ctx->payl);
	if (!pkt) {
		TRACE((PLOGLOC, "failed constructing packet\n"));
		goto fail;
	}

	if (ikev2_transmit(old_sa, pkt) != 0) {
		TRACE((PLOGLOC, "failed transmitting packet\n"));
		goto fail;
	}
	pkt = 0;

	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_REQUEST_SENT);

	if (pkt)
		rc_vfree(pkt);
	if (ke)
		rc_vfree(ke);
	ikev2_rekey_init_ctx_free(ctx);
	return;

      fail_nomem:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to allocate memory\n");
	++isakmpstat.fail_send_packet;
	ikev2_rekey_init_abort(old_sa, new_sa);
	goto done;

      fail:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to send REKEY IKE_SA\n");
	++isakmpstat.fail_send_packet;
	ikev2_rekey_init_abort(old_sa, new_sa);
      done:
	if (pkt)
		rc_vfree(pkt);
	if (ke)
		rc_vfree(ke);
	ikev2_rekey_init_ctx_free(ctx);
}
/**** async DH helpers (defined below) ****/
struct ikev2_rekey_responder_ctx {
	struct ikev2_sa *old_sa;
	struct ikev2_sa *new_sa;
	int serial;	/* old_sa->serial_number, for liveness check */
	struct algdef *dhdef;
	uint32_t message_id;
	struct sockaddr *local;
	struct sockaddr *remote;
	struct ikev2_payloads payl;
	int payl_inited;
	struct prop_pair **parsed_sa;
	rc_vchar_t *g_ir;
	rc_vchar_t *ke_r;
	rc_vchar_t *pkt;
};
static void ikev2_rekey_responder_ctx_free(struct ikev2_rekey_responder_ctx *);
static void ikev2_rekey_ikesa_responder_dh_done(int, void *);
void
ikev2_rekey_ikesa_responder(rc_vchar_t *request,
			    struct sockaddr *remote,
			    struct sockaddr *local,
			    struct ikev2_sa *old_sa,
			    struct ikev2_payload_header *sa_payload,
			    struct ikev2payl_ke *ke,
			    struct ikev2_payload_header *nonce)
{
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	int err;
	struct prop_pair **parsed_sa = 0;
	struct ikev2_isakmpsa *negotiated_sa = 0;
	isakmp_cookie_t initiator_spi;
	rc_vchar_t *n_i = 0;
	rc_vchar_t *n_r = 0;
	size_t nonce_size;
	rc_vchar_t *g_i;
	struct algdef *dhdef;
	size_t dhlen;
	struct rcf_remote *conf;
	struct ikev2_sa *new_sa = 0;
	struct ikev2_payloads payl;
	struct ikev2_rekey_responder_ctx *ctx;

	ikev2_payloads_init(&payl);

	ikehdr = (struct ikev2_header *)request->v;
	message_id = get_uint32(&ikehdr->message_id);

	switch (old_sa->state) {
	case IKEV2_STATE_ESTABLISHED:
	case IKEV2_STATE_DYING:
		break;
	default:
		isakmp_log(old_sa, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected rekey request (state %d)\n",
			   old_sa->state);
		err = IKEV2_INVALID_SYNTAX;	/* ??? */
		goto abort;
		break;
	}

	parsed_sa = ikev2_parse_sa(&ikev2_createchild_doi, sa_payload);
	if (!parsed_sa) {
		isakmp_log(old_sa, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "failed parsing SA payload for IKE_SA REKEY\n");
		goto malformed_payload;	/* or maybe nomem */
	}

	negotiated_sa =
		ikev2_find_match_ikesa(old_sa->rmconf, parsed_sa,
				       &initiator_spi);
	if (!negotiated_sa)
		goto no_proposal_chosen;
	dhdef = negotiated_sa->dhdef;
	if (!dhdef) {
		TRACE((PLOGLOC, "no DH choices for the peer\n"));
		goto no_proposal_chosen;
	}

	/* check KEi payload */
	if (get_uint16(&ke->ke_h.dh_group_id) != dhdef->transform_id) {
		uint16_t dhgrp_id;

		dhgrp_id = htons(dhdef->transform_id);

		(void)ikev2_respond_error(old_sa, request, remote, local,
					  0, 0, 0,
					  IKEV2_INVALID_KE_PAYLOAD,
					  &dhgrp_id, sizeof(uint16_t));
		++isakmpstat.invalid_ke_payload;
		goto done;
	}
	dhlen = get_payload_length(ke) - sizeof(struct ikev2payl_ke);
	if (dhlen != dh_value_len((struct dhgroup *)dhdef->definition))
		goto malformed_payload;

	/* Ni */
	n_i = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_i)
		goto fail_nomem;

	/* generate Nr */
	nonce_size = ikev2_nonce_size(old_sa->rmconf);
	n_r = random_bytes(nonce_size);
	if (!n_r)
		goto fail;

	/* create new ike_sa */
	conf = rcf_deepcopy_remote(old_sa->rmconf);
	if (! conf)
	    goto fail_nomem;
	new_sa = ikev2_create_sa(&initiator_spi, old_sa->local, old_sa->remote,
				 conf);
	TRACE((PLOGLOC, "new_sa: %p\n", new_sa));
	if (!new_sa)
		goto fail_nomem;
	new_sa->is_rekeyed_sa = TRUE;

	if (old_sa->rekey_inprogress) {
		TRACE((PLOGLOC, "rekey in progress already\n"));
		old_sa->rekey_duplicate = TRUE;
		old_sa->rekey_duplicate_serial = new_sa->serial_number;
	}
	old_sa->rekey_inprogress = TRUE;

	if (ikev2_set_negotiated_sa(new_sa, negotiated_sa) != 0)
		goto fail;
	negotiated_sa = 0;	/* to prevent deallocation */

	new_sa->n_i = n_i;
	new_sa->n_r = n_r;
	n_i = n_r = 0;

	g_i = rc_vnew((uint8_t *)(ke + 1), dhlen);
	if (!g_i)
		goto fail_nomem;
	new_sa->dhpub_p = g_i;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		goto fail_nomem;
	ctx->old_sa = old_sa;
	ctx->new_sa = new_sa;
	ctx->serial = old_sa->serial_number;
	ctx->dhdef = dhdef;
	ctx->message_id = message_id;
	ctx->local = rcs_sadup(local);
	ctx->remote = rcs_sadup(remote);
	if (!ctx->local || !ctx->remote) {
		ikev2_rekey_responder_ctx_free(ctx);
		goto fail_nomem;
	}
	ctx->payl = payl;
	ctx->payl_inited = 1;
	ctx->parsed_sa = parsed_sa;
	parsed_sa = NULL;

	/*
	 * Pin both SAs: old_sa is the conversation SA; new_sa is list-
	 * inserted with its own nego timer and may be aborted+disposed
	 * (periodic task) while the worker writes &new_sa->dhpub.
	 */
	old_sa->crypto_pending = 1;
	new_sa->crypto_pending = 1;
	/* generate + compute g^ir as one pool job */
	if (oakley_dh_gencmp_submit((struct dhgroup *)dhdef->definition,
	    new_sa->dhpub_p, &new_sa->dhpub, &new_sa->dhpriv,
	    &ctx->g_ir, ikev2_rekey_ikesa_responder_dh_done, ctx) != 0) {
		old_sa->crypto_pending = 0;
		new_sa->crypto_pending = 0;
		TRACE((PLOGLOC, "failed dh submit\n"));
		ctx->payl_inited = 0;	/* done: destroys payl once */
		ikev2_rekey_responder_ctx_free(ctx);
		goto fail;
	}
	return;	/* resumed in ikev2_rekey_ikesa_responder_dh_done */

      done:
	ikev2_payloads_destroy(&payl);
	if (n_r)
		rc_vfree(n_r);
	if (n_i)
		rc_vfree(n_i);
	if (negotiated_sa)
		racoon_free(negotiated_sa);
	if (parsed_sa)
		proplist_discard(parsed_sa);
	return;

      fail:
	/* failure; internal error; unable to respond, discard request */
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing IKE_SA rekey request\n");
	if (new_sa)
		ikev2_set_state(new_sa, IKEV2_STATE_DEAD);
	goto done;

      fail_nomem:
	TRACE((PLOGLOC, "failed allocating memory\n"));
	goto fail;

      no_proposal_chosen:
	err = IKEV2_NO_PROPOSAL_CHOSEN;
	goto abort;

      malformed_payload:
	err = IKEV2_INVALID_SYNTAX;
	goto abort;

      abort:
	/* send response with error */
	TRACE((PLOGLOC, "respond with error %d\n", err));
	(void)ikev2_respond_error(old_sa,
				  request, remote, local, 0, 0, 0, err, 0, 0);
	goto done;

#if 0
	/* (draft-17)
	 * The responder can be assured that the initiator is prepared to
	 * receive messages on an SA if either (1) it has received a
	 * cryptographically valid message on the new SA, or (2) the new SA
	 * rekeys an existing SA and it receives an IKE request to close the
	 * replaced SA.
	 */
#endif
}

/* async DH for ikev2_rekey_ikesa_responder (generate+compute g^ir) */

static void
ikev2_rekey_responder_ctx_free(struct ikev2_rekey_responder_ctx *ctx)
{
	if (ctx->local)
		rc_free(ctx->local);
	if (ctx->remote)
		rc_free(ctx->remote);
	if (ctx->parsed_sa)
		proplist_discard(ctx->parsed_sa);
	if (ctx->g_ir)
		rc_vfreez(ctx->g_ir);
	if (ctx->ke_r)
		rc_vfree(ctx->ke_r);
	if (ctx->pkt)
		rc_vfree(ctx->pkt);
	if (ctx->payl_inited)
		ikev2_payloads_destroy(&ctx->payl);
	rc_free(ctx);
}

/* runs on the IKE thread after the worker finished generate+compute */
static void
ikev2_rekey_responder_tail(struct ikev2_rekey_responder_ctx *ctx)
{
	struct ikev2_sa *old_sa = ctx->old_sa;
	struct ikev2_sa *new_sa = ctx->new_sa;
	struct ikev2payl_ke_h dhgrp_hdr;

	dhgrp_hdr.dh_group_id = htons(ctx->dhdef->transform_id);
	dhgrp_hdr.reserved = 0;
	ctx->ke_r = rc_vprepend(new_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
	if (!ctx->ke_r) {
		TRACE((PLOGLOC, "failed creating KE\n"));
		goto fail;
	}

	if (rekey_skeyseed(new_sa, old_sa, ctx->g_ir) != 0)
		goto fail;
	if (ikev2_compute_keys(new_sa) != 0)
		goto fail;
	ikev2_destroy_secret(new_sa);

	/* move children to new_sa */
	if (!old_sa->rekey_duplicate) {
		TRACE((PLOGLOC, "rekeyed ike_sa old %p new %p established\n", old_sa, new_sa));
		ikev2_child_adopt(old_sa, new_sa);
	} else {
		/* need to wait to determine which ike_sa to survive */
		TRACE((PLOGLOC, "duplicate rekeying, new ike_sa %p on hold\n",
		       new_sa));
	}

	ikev2_set_state(new_sa, IKEV2_STATE_ESTABLISHED);

	/* send response */
	/* HDR, SA, NONCE, KE */
	{
		rc_vchar_t *sa;

		sa = ikev2_ikesa_to_proposal(new_sa->negotiated_sa,
					     &new_sa->index.r_ck);
		if (!sa) {
			TRACE((PLOGLOC, "no proposal for the peer\n"));
			goto fail;
		}

		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_SA, sa, FALSE);
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NONCE, new_sa->n_r, FALSE);
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_KE, ctx->ke_r, FALSE);

		ctx->pkt = ikev2_packet_construct(IKEV2EXCH_CREATE_CHILD_SA,
					     IKEV2FLAG_RESPONSE |
					     (old_sa->is_initiator ?
					      IKEV2FLAG_INITIATOR : 0),
					     ctx->message_id, old_sa, &ctx->payl);
		if (!ctx->pkt)
			goto fail;

		if (ikev2_transmit_response(old_sa, ctx->pkt,
					    ctx->local, ctx->remote) != 0)
			goto fail;
		ctx->pkt = NULL;
	}

	/*
	 * Choose pending child_sa adopted by new ike_sa, if there is no
	 * rekey conflict. Otherwise, it would be done in
	 * ikev2_rekey_ikesa_init_recv().
	 */
	if (!old_sa->rekey_duplicate) {
	   struct ikev2_child_sa *child_sa;

	   TRACE((PLOGLOC, "choose pending child_sa adopted by new ike_sa %p\n",
		       new_sa));
	   child_sa = ikev2_choose_pending_child(new_sa, TRUE);
	   if (child_sa)
		ikev2_wakeup_child_sa(child_sa);
	}

	ikev2_rekey_responder_ctx_free(ctx);
	return;

fail:
	/* failure; internal error; unable to respond, discard request */
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing IKE_SA rekey request\n");
	if (new_sa)
		ikev2_set_state(new_sa, IKEV2_STATE_DEAD);
	ikev2_rekey_responder_ctx_free(ctx);
}

static void
ikev2_rekey_ikesa_responder_dh_done(int rc, void *arg)
{
	struct ikev2_rekey_responder_ctx *ctx = arg;
	struct ikev2_sa *old_sa;

	/*
	 * Validate old_sa liveness before clearing either pin: the
	 * worker wrote into new_sa->dhpub/dhpriv while both SAs were
	 * pinned (periodic task skips pending SAs).
	 */
	old_sa = ikev2_find_sa_by_serial(ctx->serial);
	if (old_sa == NULL || old_sa != ctx->old_sa) {
		/* old SA disposed while DH ran; nothing to resume */
		ctx->new_sa->crypto_pending = 0;
		ikev2_rekey_responder_ctx_free(ctx);
		return;
	}
	old_sa->crypto_pending = 0;
	ctx->new_sa->crypto_pending = 0;
	if (old_sa->state == IKEV2_STATE_DEAD ||
	    ctx->new_sa->state == IKEV2_STATE_DEAD) {
		ikev2_rekey_responder_ctx_free(ctx);
		return;
	}
	if (rc != 0) {
		TRACE((PLOGLOC, "failed dh_generate/compute\n"));
		isakmp_log(old_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "failed processing IKE_SA rekey request\n");
		if (ctx->new_sa)
			ikev2_set_state(ctx->new_sa, IKEV2_STATE_DEAD);
		ikev2_rekey_responder_ctx_free(ctx);
		return;
	}
	ikev2_rekey_responder_tail(ctx);
}

/**** async compute helpers (defined after ikev2_rekey_ikesa_init_recv) ****/
struct ikev2_rekey_init_recv_ctx {
	struct ikev2_sa *old_sa;
	struct ikev2_sa *new_sa;
	int serial;	/* old_sa->serial_number, for liveness check */
	struct prop_pair **parsed_sa;
	rc_vchar_t *g_ir;
};
static void ikev2_rekey_init_recv_ctx_free(struct ikev2_rekey_init_recv_ctx *);
static void ikev2_rekey_ikesa_init_recv_tail(struct ikev2_rekey_init_recv_ctx *);
static void ikev2_rekey_ikesa_init_recv_dh_done(int, void *);
static void
ikev2_rekey_ikesa_init_recv(struct ikev2_child_sa *child_sa, rc_vchar_t *msg)
{
	struct ikev2_sa *old_sa;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	struct ikev2_payload_header *p;
	int type;
	struct ikev2_payload_header *sa = 0;
	struct ikev2_payload_header *nonce = 0;
	struct ikev2payl_ke *ke = 0;
	struct prop_pair **parsed_sa = 0;
	struct ikev2_isakmpsa *negotiated_sa = 0;
	isakmp_cookie_t spi;
	unsigned int dhlen;
	rc_vchar_t *dhpub_p = 0;
	rc_vchar_t *n_r = 0;
	struct ikev2_sa *new_sa = 0;
	rc_vchar_t *g_ir = 0;
	struct ikev2_rekey_init_recv_ctx *ctx;

	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_EXPIRED);

	old_sa = child_sa->parent;

	/* expect HDR, SK {SA, Ni, KEi} */
	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	ikev2_update_message_id(old_sa, message_id, TRUE);
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_SA:
			if (sa)
				goto duplicate;
			sa = p;
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = p;
			break;
		case IKEV2_PAYLOAD_KE:
			if (ke)
				goto duplicate;
			ke = (struct ikev2payl_ke *)p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (ikev2_process_notify(old_sa, p, TRUE) != 0)
				goto done;
			break;
		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(old_sa, 0, 0, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto done;
			}
			isakmp_log(old_sa, 0, 0, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "payload type %d ignored\n", type);
			++isakmpstat.payload_ignored;
			break;
		}
	}

	if (!(sa && nonce && ke))
		goto malformed_message;

	/* process SA */
	parsed_sa = ikev2_parse_sa(&ikev2_rekey_doi, sa);
	if (!parsed_sa)
		goto malformed_payload;	/* ??? maybe nomem? */

	negotiated_sa = ikev2_find_match_ikesa(old_sa->rmconf, parsed_sa, &spi);
	if (!negotiated_sa)
		goto no_proposal_chosen;

	/* process KE */
	if (get_payload_length(&ke->header) < sizeof(struct ikev2payl_ke)
	    || get_uint16(&ke->ke_h.dh_group_id) != negotiated_sa->dhdef->transform_id) {
		TRACE((PLOGLOC, "KE id %d, negotiated %d.\n",
		       get_uint16(&ke->ke_h.dh_group_id),
		       negotiated_sa->dhdef->transform_id));
		/* send INVALID_SYNTAX ??? */
		goto malformed_payload;
	}
	dhlen = get_payload_length(&ke->header) - sizeof(struct ikev2payl_ke);
	if (dhlen != dh_value_len((struct dhgroup *)negotiated_sa->dhdef->definition)) {
		TRACE((PLOGLOC, "KE data length %u, should be %lu\n",
		       dhlen,
		       (unsigned long)dh_value_len((struct dhgroup *)negotiated_sa->dhdef->definition)));
		/* send INVALID_SYNTAX ??? */
		goto malformed_payload;
	}
	dhpub_p = rc_vnew((uint8_t *)(ke + 1), dhlen);
	if (!dhpub_p)
		goto fail;

	/* process Nr */
	n_r = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_r)
		goto fail;

	/* update new IKE_SA */
	new_sa = old_sa->new_sa;
	memcpy(&new_sa->index.r_ck, spi, sizeof(isakmp_cookie_t));
	ikev2_set_negotiated_sa(new_sa, negotiated_sa);
	new_sa->dhpub_p = dhpub_p;
	new_sa->n_r = n_r;

	negotiated_sa = 0;
	dhpub_p = n_r = 0;	/* so that they're not deallocated */

	/* g_ir = g^ir; (async) */
	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		goto fail;
	ctx->old_sa = old_sa;
	ctx->new_sa = new_sa;
	ctx->serial = old_sa->serial_number;
	ctx->parsed_sa = parsed_sa;
	parsed_sa = NULL;

	old_sa->crypto_pending = 1;
	if (oakley_dh_compute_submit(
	    (struct dhgroup *)new_sa->negotiated_sa->dhdef->definition,
	    new_sa->dhpub, new_sa->dhpriv, new_sa->dhpub_p, &ctx->g_ir,
	    ikev2_rekey_ikesa_init_recv_dh_done, ctx) != 0) {
		old_sa->crypto_pending = 0;
		TRACE((PLOGLOC, "failed dh submit\n"));
		ikev2_rekey_init_recv_ctx_free(ctx);
		goto fail;
	}
	return;	/* resumed in ikev2_rekey_ikesa_init_recv_dh_done */

      done:
	if (g_ir)
		rc_vfreez(g_ir);
	if (n_r)
		rc_vfree(n_r);
	if (dhpub_p)
		rc_vfree(dhpub_p);
	if (negotiated_sa)
		racoon_free(negotiated_sa);
	if (parsed_sa)
		proplist_discard(parsed_sa);
	return;

      fail:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed processing rekey response\n");
	++isakmpstat.fail_process_packet;
	goto done;

      no_proposal_chosen:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "no proposal chosen\n");
	++isakmpstat.no_proposal_chosen;
	goto done;
      malformed_message:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "packet lacks expected payload\n");
	++isakmpstat.malformed_message;
	goto done;
      duplicate:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "duplicated payload\n");
	++isakmpstat.malformed_message;
	goto done;
      malformed_payload:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC, "malformed payload\n");
	++isakmpstat.malformed_payload;
	/* send INVALID_SYNTAX */
	goto done;
}

/* async g^ir for ikev2_rekey_ikesa_init_recv (compute only) */

static void
ikev2_rekey_init_recv_ctx_free(struct ikev2_rekey_init_recv_ctx *ctx)
{
	if (ctx->parsed_sa)
		proplist_discard(ctx->parsed_sa);
	if (ctx->g_ir)
		rc_vfreez(ctx->g_ir);
	rc_free(ctx);
}

/* runs on the IKE thread after the worker computed g^ir */
static void
ikev2_rekey_ikesa_init_recv_tail(struct ikev2_rekey_init_recv_ctx *ctx)
{
	struct ikev2_sa *old_sa = ctx->old_sa;
	struct ikev2_sa *new_sa = ctx->new_sa;

	if (rekey_skeyseed(new_sa, old_sa, ctx->g_ir) != 0)
		goto fail;
	if (ikev2_compute_keys(new_sa) != 0)
		goto fail;
	ikev2_destroy_secret(new_sa);

	TRACE((PLOGLOC, "rekeyed ike_sa old %p new %p established\n", old_sa, new_sa));
	old_sa->new_sa = 0;
	ikev2_sa_insert(new_sa);
	ikev2_set_state(new_sa, IKEV2_STATE_ESTABLISHED);

	/* rekey conflict check */
	if (old_sa->rekey_duplicate) {
		struct ikev2_sa	*duplicate_sa;

		TRACE((PLOGLOC, "rekey conflict\n"));
		duplicate_sa = ikev2_find_sa_by_serial(old_sa->rekey_duplicate_serial);
		TRACE((PLOGLOC, "duplicate_sa: %p\n", duplicate_sa));
		if (!duplicate_sa) {
			TRACE((PLOGLOC, "can't find duplicate ike_sa\n"));
		} else {
			rc_vchar_t	*n1;
			rc_vchar_t	*n2;

			TRACE((PLOGLOC, "checking duplicate...\n"));
			n1 = (ikev2_noncecmp(new_sa->n_i, new_sa->n_r) < 0) ?
			    new_sa->n_i : new_sa->n_r;
			n2 = (ikev2_noncecmp(duplicate_sa->n_i, duplicate_sa->n_r) < 0) ?
			    duplicate_sa->n_i : duplicate_sa->n_r;
			if (ikev2_noncecmp(n1, n2) < 0) {
				/* initiate DELETE */
				TRACE((PLOGLOC, "initiating delete ike_sa %p\n", new_sa));
				ikev2_sa_delete(new_sa);
				TRACE((PLOGLOC, "children are adopted to %p\n", duplicate_sa));
				ikev2_child_adopt(old_sa, duplicate_sa);

				/* The duplicate_sa becomes the new ike_sa */
				new_sa = duplicate_sa;

				goto rekey_done;
			} else {
				TRACE((PLOGLOC, "leave it\n"));
			}
		}
	}

	/* move children */
	ikev2_child_adopt(old_sa, new_sa);

	/* rekey done successful */
      rekey_done:
	/* initiate DELETE IKE_SA */
	ikev2_sa_delete(old_sa);

	{
	   struct ikev2_child_sa *xchild_sa;

	   TRACE((PLOGLOC, "choose pending child_sa adopted by new ike_sa %p\n",
		       new_sa));
	   xchild_sa = ikev2_choose_pending_child(new_sa, TRUE);
	   if (xchild_sa)
		ikev2_wakeup_child_sa(xchild_sa);
	}

	ikev2_rekey_init_recv_ctx_free(ctx);
	return;

fail:
	isakmp_log(old_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed processing rekey response\n");
	++isakmpstat.fail_process_packet;
	ikev2_rekey_init_recv_ctx_free(ctx);
}

static void
ikev2_rekey_ikesa_init_recv_dh_done(int rc, void *arg)
{
	struct ikev2_rekey_init_recv_ctx *ctx = arg;
	struct ikev2_sa *old_sa;

	/*
	 * Validate old_sa liveness before touching it: the worker read
	 * new_sa->dhpub/dhpub_p while old_sa was pinned (periodic task
	 * skips pending SAs); new_sa is reachable only via the link.
	 * Release the pin as soon as the SA validates.
	 */
	old_sa = ikev2_find_sa_by_serial(ctx->serial);
	if (old_sa == NULL || old_sa != ctx->old_sa) {
		/* SA disposed while DH ran; nothing to resume */
		ikev2_rekey_init_recv_ctx_free(ctx);
		return;
	}
	old_sa->crypto_pending = 0;
	if (old_sa->new_sa != ctx->new_sa) {
		/* rekey was abandoned while DH ran */
		ikev2_rekey_init_recv_ctx_free(ctx);
		return;
	}

	if (old_sa->state == IKEV2_STATE_DYING ||
	    old_sa->state == IKEV2_STATE_DEAD) {
		ikev2_rekey_init_recv_ctx_free(ctx);
		return;
	}
	if (rc != 0) {
		TRACE((PLOGLOC, "failed dh_compute\n"));
		isakmp_log(old_sa, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC, "failed processing rekey response\n");
		++isakmpstat.fail_process_packet;
		ikev2_rekey_init_recv_ctx_free(ctx);
		return;
	}
	ikev2_rekey_ikesa_init_recv_tail(ctx);
}

static void
ikev2_child_adopt(struct ikev2_sa *old_sa, struct ikev2_sa *new_sa)
{
	struct ikev2_child_sa *child, *next_child;

	for (child = IKEV2_CHILD_LIST_FIRST(&old_sa->children);
	     !IKEV2_CHILD_LIST_END(child);
	     child = next_child) {
		next_child = IKEV2_CHILD_LIST_NEXT(child);
		TRACE((PLOGLOC, "child %p state %d\n", child, child->state));
		switch (child->state) {
		case IKEV2_CHILD_STATE_GETSPI:
		case IKEV2_CHILD_STATE_MATURE:
		default:		/* ??? */
			IKEV2_CHILD_LIST_REMOVE(&old_sa->children, child);
			IKEV2_CHILD_LIST_LINK(&new_sa->children, child);
			child->parent = new_sa;
			break;
		case IKEV2_CHILD_STATE_WAIT_RESPONSE:
		case IKEV2_CHILD_STATE_REQUEST_SENT:
				/* can't be moved */
			break;
		}
	}
}


/*
 * 	(RFC4306)
 * 	2.18 Rekeying IKE_SAs using a CREATE_CHILD_SA exchange
 *
 * 	      SKEYSEED = prf(SK_d (old), [g^ir (new)] | Ni | Nr)
 *
 * INPUT:
 *	new_sa:	new_sa->n_i, new_sa->n_r contains nonces from CREATE_CHID_SA
 *	old_sa:	old_sa->prf, old_sa->sk_d are used for calculation
 *	g_ir:	(g^i)^r if CREATE_CHILD_SA request had KE payload
 *
 * OUTPUT:
 *	returns 0 if successful, non-0 if fails
 *	if successful, new_sa->skeyseed holds new SKEYSEED
 */
static int
rekey_skeyseed(struct ikev2_sa *new_sa, struct ikev2_sa *old_sa, rc_vchar_t *g_ir)
{
	/* (draft-eronen-ipsec-ikev2-clarifications-09.txt)
	 * 5.5.  Changing PRFs when rekeying the IKE_SA
	 *
	 * When rekeying the IKE_SA, Section 2.18 says that "SKEYSEED for the
	 * new IKE_SA is computed using SK_d from the existing IKE_SA as
	 * follows:
	 *
	 * SKEYSEED = prf(SK_d (old), [g^ir (new)] | Ni | Nr)"
	 *
	 * If the old and new IKE_SA selected a different PRF, it is not totally
	 * clear which PRF should be used.
	 *
	 * Since the rekeying exchange belongs to the old IKE_SA, it is the old
	 * IKE_SA's PRF that is used.  This also follows the principle that the
	 * same key (the old SK_d) should not be used with multiple
	 * cryptographic algorithms.
	 *
	 * Note that this may work poorly if the new IKE_SA's PRF has a fixed
	 * key size, since the output of the PRF may not be of the correct size.
	 * This supports our opinion earlier in the document that the use of
	 * PRFs with a fixed key size is a bad idea.
	 */

	size_t hash_input_len;
	rc_vchar_t *hash_input;
	uint8_t *p;
	int retval = -1;

#ifdef notyet
	/* if the new IKE_SA's PRF has a fixed key size,
	 * and the output of old IKE_SA's PRF is not be of correct size */
	if (!new_sa->prf->is_variable_keylen
	    && new_sa->prf->preferred_key_len != old_sa->prf->output_len)
		fail ?;
#endif

	hash_input_len = new_sa->n_i->l + new_sa->n_r->l;
	if (g_ir)
		hash_input_len += g_ir->l;

	hash_input = rc_vmalloc(hash_input_len);
	if (!hash_input)
		goto fail;

	p = (uint8_t *)hash_input->v;
	if (g_ir)
		VCONCAT(hash_input, p, g_ir);
	VCONCAT(hash_input, p, new_sa->n_i);
	VCONCAT(hash_input, p, new_sa->n_r);

	new_sa->skeyseed = keyed_hash(old_sa->prf, old_sa->sk_d, hash_input);
	if (!new_sa->skeyseed)
		goto fail;
	retval = 0;
      done:
	if (hash_input)
		rc_vfree(hash_input);
	return retval;

      fail:
	TRACE((PLOGLOC,
	       "failed computing SKEYSEED while processing rekey request\n"));
	retval = -1;
	goto done;
}
