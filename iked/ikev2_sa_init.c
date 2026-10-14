/* $Id: ikev2_sa_init.c	$ */
/*
 * Copyright (C) 2004-2026 WIDE Project.
 * All rights reserved.
 *
 * IKE_SA_INIT exchange (RFC 7296 s2.6/s2.7), split out of ikev2.c so the
 * first-exchange boundary (initiator build + responder accept + both DH /
 * SKEYSEED async completions + cookie echo at INIT) lives in its own
 * translation unit, matching the per-protocol-feature module split.
 *
 * This file owns:
 *   initiator   ikev2_initiator_start, initiator_start_after_gen,
 *               initiator_skey_done, initiator_ike_sa_init_recv
 *   responder   responder_state0_recv, responder_state0_send,
 *               responder_state0_after_gen, responder_state0_after_skey
 *   shared      ikev2_check_new_request (new/IKE_SA_INIT request policy
 *               check incl. anti-DoS cookie handling)
 *
 * IKE_AUTH (initiator_state1_send + both auth recv/cont paths) stays in
 * ikev2.c.  Exports needed by ikev2.c dispatch are declared in
 * ikev2_impl.h; everything else here is static to this file.
 */

#include <config.h>
#include <assert.h>
#include <stdlib.h>
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
#include <openssl/crypto.h>	/* OPENSSL_cleanse for key material */
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "racoon.h"
#include "safefile.h"
#include "isakmp.h"
#include "ikev2.h"
#include "keyed_hash.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_notify.h"
#include "ikev2_drain.h"
#include "nattraversal.h"
#include "var.h"
#include "sockmisc.h"
#include "dhgroup.h"
#include "oakley.h"		/* for prototypes */
#include "crypto_impl.h"
#include "ike_conf.h"
#include "ratelimit.h"
#include "debug.h"
#ifdef WITH_PARSECOA
#    include "parse_coa.h"
#endif

/* RFC 7427 s4 SIG_HASH_ALGORITHMS (16431) DATA: the 2-byte hash IDs we
 * advertise for a method-14 (DS) seat.  RSASIG and ECDSA advertise the
 * SHA-2 set {256,384,512}; EdDSA (RFC 8420) advertises only the "Identity"
 * hash 0x0005.  Single shared tables + one push helper so the initiator
 * offer (below) and the responder echo can never drift — dedup of the
 * four identical copies that previously lived inline. */
static const uint8_t sig_hash_sha2[] = {
	0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
};
static const uint8_t sig_hash_identity[] = {
	0x00, 0x05,
};

static void
ikev2_push_sig_hash(struct ikev2_payloads *payl, const uint8_t *data,
		    size_t len, const char *what)
{
	TRACE((PLOGLOC, "SIG_HASH_ALGORITHMS (16431, %s)\n", what));
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(0, 0, 0,
						 IKEV2_SIG_HASH_ALGORITHMS,
						 (uint8_t *)data, len),
			    TRUE);
}

/* forward declarations (as in ikev2.c top; the DH/async callbacks are
 * referenced as function pointers before their bodies below). */
static void initiator_start_after_gen(int rc, void *arg);
static void initiator_skey_done(int rc, void *arg);
static void responder_state0_after_gen(int rc, void *arg);
static void responder_state0_after_skey(int rc, void *arg);
static void responder_state0_send(struct ikev2_sa *, struct sockaddr *,
				  struct sockaddr *);
void initiator_ike_sa_init_recv(struct ikev2_sa *, rc_vchar_t *,
				       struct sockaddr *, struct sockaddr *);

/* DH-computation context for the async IKE_SA_INIT completions. */
struct ikev2_dh_ctx {
	struct ikev2_sa *ike_sa;
	int serial;
	struct ikev2_payloads payl;
	rc_vchar_t *sa;
	rc_vchar_t *ke;
	struct algdef *dhdef;
	struct prop_pair **proplist;
	int payl_inited;
	uint32_t message_id;
};

/* SKEYSEED computation after the DH completion and the zero-SPI check live
 * in ikev2.c (shared with the IKE_AUTH key paths); exported for use here.
 * (declared locally: oakley_dh_done_t / oakley.h is not visible to
 *  ikev2_impl.h, which is included before it by main.c etc.) */

int compute_skeyseed_submit(struct ikev2_sa *, oakley_dh_done_t, void *);
int ikev2_spi_is_zero(isakmp_cookie_t *);

static struct ikev2_sa *
ikev2_dh_ctx_sa(struct ikev2_dh_ctx *ctx)
{
	struct ikev2_sa *sa;

	if (!ctx)
		return 0;
	sa = ikev2_find_sa_by_serial(ctx->serial);
	if (!sa || sa != ctx->ike_sa)
		return 0;
	return sa;
}

static void
ikev2_dh_ctx_free(struct ikev2_dh_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->payl_inited)
		ikev2_payloads_destroy(&ctx->payl);
	if (ctx->sa)
		rc_vfree(ctx->sa);
	if (ctx->ke)
		rc_vfree(ctx->ke);
	if (ctx->proplist)
		proplist_discard(ctx->proplist);
	free(ctx);
}

/*
 * IKE_SA_INIT exchange
 */
void
ikev2_initiator_start(struct ikev2_sa *ike_sa)
{
	struct ikev2_payloads payl;
	struct rcf_remote *conf;
	struct algdef *dhgrpdef;
	struct prop_pair **proplist = 0;
	rc_vchar_t *sa = 0;

	assert(ike_sa->state == IKEV2_STATE_IDLING
	       || ike_sa->state == IKEV2_STATE_INI_IKE_SA_INIT_SENT);
	assert(ike_sa->is_initiator);

	/* RFC 5723 s4.3.2: if we hold a stored, unexpired resumption ticket
	 * for this peer and session resumption is enabled, resume via
	 * IKE_SESSION_RESUME (exchange 38) instead of a full IKE_SA_INIT.
	 * That path owns the SA from here (it sets its own state and
	 * transmits); return so we never build an IKE_SA_INIT on top. */
	if (ike_msg_session_resume_available(ike_sa))
		return;

	ikev2_payloads_init(&payl);

	conf = ike_sa->rmconf;
	assert(conf != 0);
	/* assert(conf->initiator_kmp == RCT_KMP_NAME_IKEV2); */

	if (ike_sa->dh_choice != 0) {
		dhgrpdef = ike_sa->dh_choice;
	} else {
		struct rc_alglist *dhinfo;
		dhinfo = ike_conf_dhgrp(conf, IKEV2_MAJOR_VERSION);
		if (!dhinfo) {
			TRACE((PLOGLOC, "no DH group defined for peer\n"));
			goto fail;
		}
		dhgrpdef = ikev2_conf_to_dhdef(dhinfo->algtype);
	}
	if (!dhgrpdef)
		goto fail;

	proplist = ikev2_conf_to_proplist(conf, 0);
	if (!proplist)
		goto fail;
#ifdef WITH_INTERMEDIATE
	/* RFC 9370 s2.2.1: offer ADDKE (type-6) in the initial IKE_SA when
	 * we can run the IKE_INTERMEDIATE rounds it commits us to (the
	 * 16438 capability notify is sent alongside).  If the peer does not
	 * negotiate IKE_INTERMEDIATE, the ADDKE-bearing proposal is simply
	 * skipped to a classical fallback. */
	ikev2_maybe_offer_ikesa_addke(proplist);
#endif
	sa = ikev2_pack_proposal(proplist);
	if (!sa)
		goto fail;

	{
		struct ikev2_dh_ctx *ctx;

		ctx = calloc(1, sizeof(*ctx));
		if (!ctx)
			goto fail;
		ctx->ike_sa = ike_sa;
		ctx->serial = ike_sa->serial_number;
		ctx->payl = payl;
		ctx->payl_inited = 1;
		ctx->sa = sa;
		ctx->proplist = proplist;
		ctx->dhdef = dhgrpdef;
		sa = 0;
		proplist = 0;
		ike_sa->crypto_pending = 1;
		if (oakley_dh_generate_submit(
		    (struct dhgroup *)dhgrpdef->definition, &ike_sa->dhpub,
		    &ike_sa->dhpriv, initiator_start_after_gen, ctx) != 0) {
			ike_sa->crypto_pending = 0;
			ctx->payl_inited = 0;
			ctx->sa = 0;
			ctx->proplist = 0;
			free(ctx);
			goto fail;
		}
		return;
	}

      end:
	if (sa)
		rc_vfree(sa);
	if (proplist)
		proplist_discard(proplist);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to send IKE_SA_INIT\n");
	++isakmpstat.fail_send_packet;
	ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
	goto end;
}


static void
initiator_start_after_gen(int rc, void *arg)
{
	struct ikev2_dh_ctx *ctx = arg;
	struct ikev2_sa *ike_sa;
	rc_vchar_t *nonce;
	rc_vchar_t *pkt = 0;
	struct ikev2payl_ke_h dhgrp_hdr;
	int nonce_size;

	ike_sa = ikev2_dh_ctx_sa(ctx);
	if (!ike_sa) {
		ikev2_dh_ctx_free(ctx);
		return;
	}
	if (rc != 0)
		goto fail;

	dhgrp_hdr.dh_group_id = htons(ctx->dhdef->transform_id);
	dhgrp_hdr.reserved = 0;
	ctx->ke = rc_vprepend(ike_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
	if (!ctx->ke)
		goto fail;

	nonce_size = ikev2_nonce_size(ike_sa->rmconf);
	nonce = random_bytes(nonce_size);
	if (!nonce)
		goto fail;
	ike_sa->n_i = nonce;

	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_SA, ctx->sa, FALSE);
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_KE, ctx->ke, FALSE);
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NONCE, nonce, FALSE);

#ifdef ENABLE_NATT
	if ((ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON ||
	     ikev2_nat_traversal(ike_sa->rmconf) == RCT_NATT_FORCE) &&
	    SOCKADDR_FAMILY(ike_sa->remote) == AF_INET) {
		if (natt_create_natd
		    (ike_sa, &ctx->payl, ike_sa->remote, ike_sa->local) < 0) {
			goto fail;
		}
	}
#endif

	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(0, 0, 0,
						 IKEV2_FRAGMENTATION_SUPPORTED,
						 0, 0),
			    TRUE);
	/* RFC 5685 s3: an initiator willing to be redirected advertises
	 * REDIRECT_SUPPORTED (16406) in its IKE_SA_INIT.  Without it a
	 * responder that is draining/overloaded MUST NOT redirect us (the
	 * redirect decision is gated on this offer), so offering 16406 is
	 * REQUIRED for the initiator redirect-follow path (RFC 5685 s5.5)
	 * to ever be reachable.  This is a pure capability advertisement
	 * (same class as FRAGMENTATION_SUPPORTED above): it changes nothing
	 * for a normal negotiation — the responder only answers REDIRECT
	 * when ITS local policy (redirect_to / drain) says to. */
	/* Opt-in only (accept_redirect on): an IKE_SA_INIT REDIRECT is
	 * unauthenticated, so being steered to another gateway is an
	 * explicit operator decision.  After a redirect, REDIRECTED_FROM
	 * below is the support signal (s3) and 16406 is still sent. */
	if (ikev2_accept_redirect(ike_sa->rmconf) == RCT_BOOL_ON)
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
						 IKEV2_REDIRECT_SUPPORTED,
						 0, 0),
				    TRUE);
#ifdef WITH_INTERMEDIATE
	/* RFC 9242: offer the IKE_INTERMEDIATE exchange capability (the 16438
	 * notify).  Gated by the remote's 'offer_intermediate' config (default
	 * ON).  Turning it OFF still offers the type-6/ADDKE transform via
	 * ikev2_maybe_offer_ikesa_addke(), producing what a PQC-capable peer
	 * WITHOUT IKE_INTERMEDIATE sends (RFC 9370 s2.2.1); the responder then
	 * must fall back to a classical IKE_SA. */
	if (ikev2_offer_intermediate(ike_sa->rmconf) == RCT_BOOL_ON) {
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INTERMEDIATE_EXCHANGE_SUPPORTED,
							 0, 0),
				    TRUE);
	}
#endif
	/* RFC 8784 s2.2: offer PPK use.  Gated on the remote's 'use_ppk'
	 * config (default OFF).  The responder echoes N(USE_PPK) iff it
	 * holds a PPK for this peer; the mandatory/optional decision is
	 * resolved in initiator_ike_sa_init_recv(). */
	if (ikev2_use_ppk(ike_sa->rmconf) == RCT_BOOL_ON) {
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_USE_PPK,
							 0, 0),
				    TRUE);
	}
	/* RFC 7427 s4: offer N(SIG_HASH_ALGORITHMS) when this seat is RSASIG
	 * so a peer that supports method 14 can negotiate it.  Data = the
	 * SHA-2 hash IDs we can verify (never SHA-1; that stays on method 1).
	 * If the peer echoes, initiator notify sets sig_hash_algos_ds and we
	 * sign method 14; otherwise we fall back to method 1 / SHA-1.
	 * Gated by the remote's 'offer_sig_hash_algorithms' config (default
	 * ON).  Turning it OFF pins the legacy AUTH_RSA method-1 path (no
	 * 16431), so a modern strongSwan peer that would otherwise prefer
	 * RFC 7427 actually signs method 1 / SHA-1 — used by the
	 * i2iinit-*-rsa-sha1- interop rows to exercise iked's F6 method-1
	 * DigestInfo verification end-to-end. */
	{
		struct rc_alglist *_kmp = ikev2_kmp_auth_method(ike_sa->rmconf);
		if (_kmp && _kmp->algtype == RCT_ALG_RSASIG &&
		    ikev2_offer_sig_hash_algorithms(ike_sa->rmconf) == RCT_BOOL_ON) {
			TRACE((PLOGLOC, "offering SIG_HASH_ALGORITHMS (16431)\n"));
			ikev2_push_sig_hash(&ctx->payl, sig_hash_sha2,
					    sizeof(sig_hash_sha2), "RSASIG/SHA-2");
		} else if (_kmp && _kmp->algtype == RCT_ALG_EDDSA &&
		    ikev2_offer_sig_hash_algorithms(ike_sa->rmconf) == RCT_BOOL_ON) {
			/* RFC 8420 s4: an EdDSA seat must advertise the
			 * Identity hash (0x0005) in SIG_HASH_ALGORITHMS. */
			TRACE((PLOGLOC, "offering SIG_HASH_ALGORITHMS (16431, "
				"Identity/EdDSA)\n"));
			ikev2_push_sig_hash(&ctx->payl, sig_hash_identity,
					    sizeof(sig_hash_identity),
					    "Identity/EdDSA");
		} else if (_kmp && _kmp->algtype == RCT_ALG_ECDSA &&
		    ikev2_offer_sig_hash_algorithms(ike_sa->rmconf) == RCT_BOOL_ON) {
			/* RFC 7427 plan scope #4: an ECDSA seat also offers
			 * the SIG_HASH_ALGORITHMS (16431) with the SHA-2 IDs
			 * {2,3,4}, so a peer that supports method 14 can
			 * negotiate ECDSA via DS instead of the RFC 4754
			 * methods 9/10/11.  The DS signer emits the
			 * ecdsa-with-SHA2 AlgorithmIdentifier + DER
			 * Ecdsa-Sig-Value. */
			TRACE((PLOGLOC, "offering SIG_HASH_ALGORITHMS (16431, "
				"ECDSA)\n"));
			ikev2_push_sig_hash(&ctx->payl, sig_hash_sha2,
					    sizeof(sig_hash_sha2), "ECDSA/SHA-2");
		}
	}
	/* RFC 5685 s9.3: when re-running IKE_SA_INIT after a verified
	 * redirect, advertise REDIRECTED_FROM (16408) naming the gateway
	 * that redirected us (the peer that answered our original
	 * IKE_SA_INIT with N(REDIRECT)).  This both carries the original
	 * gateway's identity and signals redirect support to the new
	 * gateway (RFC 5685 s9.3).  ike_sa->redirected_from is a raw
	 * identity (IPv4/IPv6 literal) captured when the redirect was
	 * received. */
	if (ike_sa->redirect_follow && ike_sa->redirected_from) {
		rc_vchar_t *rfd;

		rfd = ikev2_build_redirected_from_data(
		    ike_sa->redirected_from_type, ike_sa->redirected_from);
		if (rfd) {
			TRACE((PLOGLOC,
			       "RFC5685: re-initiating against redirected gw, "
			       "advertising REDIRECTED_FROM\n"));
			ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
					    ikev2_notify_payload(
					    0, 0, 0, IKEV2_REDIRECT_FROM,
					    rfd->u, rfd->l),
					    TRUE);
			rc_vfree(rfd);
		}
	}
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_SA_INIT, IKEV2FLAG_INITIATOR,
				     0, ike_sa, &ctx->payl);
	if (!pkt)
		goto fail;

	if (ike_sa->my_first_message)
		rc_vfree(ike_sa->my_first_message);
	ike_sa->my_first_message = rc_vdup(pkt);
	if (!ike_sa->my_first_message)
		goto fail;

	ikev2_set_state(ike_sa, IKEV2_STATE_INI_IKE_SA_INIT_SENT);
	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	pkt = 0;
	ike_sa->crypto_pending = 0;
	if (pkt)
		rc_vfree(pkt);
	ikev2_dh_ctx_free(ctx);
	return;

      fail:
	if (pkt)
		rc_vfree(pkt);
	ike_sa->crypto_pending = 0;
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to send IKE_SA_INIT\n");
	++isakmpstat.fail_send_packet;
	ikev2_abort(ike_sa, ECONNREFUSED);
	ikev2_dh_ctx_free(ctx);
}

/*
 * check before responder accepting the IKE_SA_INIT
 * return 0 if OK, non-zero otherwise
 */
int
ikev2_check_new_request(rc_vchar_t *packet, struct sockaddr *remote,
			struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int is_response;
	uint32_t message_id;
	struct ikev2_payload_header *first_payload;

	ikehdr = (struct ikev2_header *)packet->v;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;
	message_id = get_uint32(&ikehdr->message_id);
	first_payload = (struct ikev2_payload_header *)(ikehdr + 1);

	/* (draft-17)
	 * If a node receives a message on UDP port 500 or 4500 outside the
	 * context of an IKE_SA known to it (and not a request to start one), it
	 * may be the result of a recent crash of the node.  If the message is
	 * marked as a response, the node MAY audit the suspicious event but
	 * MUST NOT respond. If the message is marked as a request, the node MAY
	 * audit the suspicious event and MAY send a response. If a response is
	 * sent, the response MUST be sent to the IP address and port from
	 * whence it came with the same IKE SPIs and the Message ID copied. The
	 * response MUST NOT be cryptographically protected and MUST contain a
	 * Notify payload indicating INVALID_IKE_SPI.
	 */
	if (is_response) {
		/* MAY audit */
		/* MUST NOT respond */
		isakmp_log(0, local, remote, packet,
			   PLOG_PROTOWARN, PLOGLOC,
			   "unexpected response packet\n");
		++isakmpstat.unexpected_packet;
		return -1;
	}
	if (!(ikev2_spi_is_zero(&ikehdr->responder_spi) &&
	      message_id == 0 &&
	      (ikehdr->exchange_type == IKEV2EXCH_IKE_SA_INIT ||
	       ikehdr->exchange_type == IKEV2EXCH_IKE_SESSION_RESUME))) {
		/* RFC 6290: unprotected QCD_TOKEN + INVALID_IKE_SPI */
		ikev2_qcd_respond(packet, remote, local);
		isakmp_log(0, local, remote, packet,
			   PLOG_PROTOWARN, PLOGLOC,
			   "message to a nonexistent ike_sa\n");
		++isakmpstat.invalid_ike_spi;
		return -1;
	}
	if (ikev2_spi_is_zero(&ikehdr->initiator_spi)) {
		isakmp_log(0, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC, "initiator SPI is zero\n");
		++isakmpstat.invalid_ike_spi;
		return -1;
	}

	if (ikehdr->next_payload == IKEV2_PAYLOAD_NOTIFY &&
	    get_payload_length(first_payload) > sizeof(struct ikev2payl_notify) &&
	    get_notify_type((struct ikev2payl_notify *)first_payload) == IKEV2_COOKIE) {
		if (ikev2_check_request_cookie(packet, remote, local) != 0) {
			isakmp_log(0, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "invalid IKEv2 cookie\n");
			++isakmpstat.ikev2_invalid_cookie;
			/* (draft-eronen-ipsec-ikev2-clarifications-06.txt)
   The correct action is to ignore the cookie, and process the message
   as if no cookie had been included (usually this means sending a
   response containing a new cookie).  This is shown in Section 2.6 when
   it says "The responder in that case MAY reject the message by sending
   another response with a new cookie [...]".
			*/
		}
	}
	return 0;
}

void
responder_state0_recv(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
		      struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	unsigned int type;
	struct ikev2_payload_header *sa = 0;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *nonce = 0;
	struct prop_pair **parsed_sa = 0;
	struct ikev2_isakmpsa *negotiated_sa = 0;
	struct rcf_remote *conf;
	unsigned int dhlen;
	rc_vchar_t *dhpub_p = 0;
	rc_vchar_t *n_i = 0;
	rc_vchar_t *n_r = 0;
	rc_vchar_t *message = 0;
	int nonce_size;

	ikehdr = (struct ikev2_header *)packet->v;
	/* ikehdr->responder_spi must be zero  (checked in ikev2_input) */
	if (ikehdr->exchange_type == IKEV2EXCH_IKE_SESSION_RESUME) {
		/* RFC 5723 s4.3.2: first message carries Ni and
		 * N(TICKET_OPAQUE); the SA comes from the ticket, so there is
		 * no SAi1/KEi to negotiate here.  Route to the resumption
		 * bookkeeper. */
		responder_ike_session_resume_recv(ike_sa, packet, remote, local);
		return;
	}
	if (ikehdr->exchange_type != IKEV2EXCH_IKE_SA_INIT) {
		/* unexpected; */
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected: exchange type IKE_SA_INIT (%d) expected, received %d\n",
			   IKEV2EXCH_IKE_SA_INIT, ikehdr->exchange_type);
		++isakmpstat.unexpected_packet;
		goto drop;
	}
	if (ikehdr->flags & IKEV2FLAG_RESPONSE) {
		/* unexpected; */
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected: flag 0x%02x has RESPONSE (0x%02x) bit set\n",
			   ikehdr->flags, IKEV2FLAG_RESPONSE);
		++isakmpstat.unexpected_packet;
		goto drop;
	}

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	/* len = get_uint32(&ikehdr->length) - sizeof(struct ikev2_header); */
	type = ikehdr->next_payload;

	/*
	 * expect HDR, SAi1, KEi, Ni [N(NAT_DET_SRC), N(NAT_DET_DST)]
	 * or
	 * HDR(A,0), N(COOKIE), SAi1, KEi, Ni [N(NAT_DET_SRC), N(NAT_DET_DST)]
	 */

	if (type == IKEV2_PAYLOAD_NOTIFY
	    /* && get_payload_length(p) > sizeof(struct ikev2payl_notify) */
	    && get_notify_type((struct ikev2payl_notify *)p) == IKEV2_COOKIE) {
		POINT_NEXT_PAYLOAD(p, type);
	}
	for (; type != IKEV2_NO_NEXT_PAYLOAD; POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_SA:
			if (sa)
				goto duplicate;
			sa = p;
			break;
		case IKEV2_PAYLOAD_KE:
			if (ke)
				goto duplicate;
			ke = (struct ikev2payl_ke *)p;
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (resp_state0_recv_notify
			    (ike_sa, packet, remote, local, p) < 0) {
				goto drop;
			}
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;

		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto done;
			}
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	if (!(sa && ke && nonce))
		goto malformed_message;

	conf = ike_sa->rmconf;

	/* RFC 5685 s3: if this peer advertised REDIRECT_SUPPORTED (16406)
	 * in its IKE_SA_INIT and the local policy has redirect_to set for
	 * this peer, answer with N(REDIRECT, <new gw>, echoed Ni) and NO SA
	 * (SPI_R=0) instead of negotiating — the client re-initiates
	 * against the listed gateway.  The redirect must be decided BEFORE
	 * SA/KE matching (the responder answers REDIRECT regardless of the
	 * initiator's proposal) but AFTER the redirect-support notify is
	 * parsed above.  The peer MUST have offered 16406 (RFC 5685 s3:
	 * a responder MUST NOT send REDIRECT to a client that did not). */
	if (ike_sa->peer_sent_redirect &&
	    (ikev2_redirect_to(conf) || ikev2_drain_lookup(remote))) {
		rc_vchar_t *gw;
		const char *drain;
		rc_vchar_t *ni_p;

		/* A runtime drain target for this peer wins over the config
		 * pool (ikedctl drain-sa): the operator has marked this
		 * concentrator for drain, redirect this NEW IKE_SA_INIT to
		 * the drain gateway.  Otherwise resolve the config target
		 * (single identity or pool). */
		drain = ikev2_drain_lookup(remote);
		if (drain) {
			gw = rc_vnew((unsigned char *)drain, (int)strlen(drain));
			if (!gw)
				goto no_redirect;
		} else {
			/* Config redirect intended (the gate above ensures
			 * redirect_to is set) but the selected pool slot is
			 * empty/malformed: fail CLOSED — do not silently
			 * negotiate a full SA against an overloaded/retiring
			 * node.  This is an operator config error (an empty
			 * slot in redirect_to); drop the IKE_SA_INIT. */
			gw = ikev2_redirect_resolve(conf, remote);
			if (!gw) {
				isakmp_log(ike_sa, local, remote, packet,
				    PLOG_PROTOERR, PLOGLOC,
				    "RFC5685: redirect_to set but empty "
				    "selected pool slot; refusing IKE_SA_INIT "
				    "(fail-closed)\n");
				goto drop;
			}
		}
		ni_p = (nonce) ? isakmp_p2v((struct isakmp_gen *)nonce) : NULL;
		if (ni_p) {
			TRACE((PLOGLOC, "RFC5685: redirecting this peer to "
				"%.*s (offered REDIRECT_SUPPORTED)%s\n",
				(int)gw->l, (char *)gw->u,
				drain ? " [drain]" : ""));
			ikev2_respond_redirect(packet, remote, local, gw, ni_p);
			rc_vfree(gw);
			rc_vfree(ni_p);
			++isakmpstat.payload_ignored;   /* no SA consumed */
			goto done;
		}
		rc_vfree(gw);
	}
	no_redirect:

	if ((ike_acceptable_kmp(conf) & RCF_ALLOW_IKEV2) == 0) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "ikev2 not acceptable by configuration\n");
		/* send response NO_PROPOSAL_CHOSEN ??? */
		++isakmpstat.no_proposal_chosen;	/* ??? */
		goto drop;
	}
	parsed_sa = ikev2_parse_sa(&ikev2_doi, sa);
	if (!parsed_sa)
		goto malformed_payload;

#ifdef WITH_INTERMEDIATE
	negotiated_sa = ikev2_find_match_ikesa(conf, parsed_sa, 0,
					       ike_sa->intermediate_negotiated);
#else
	negotiated_sa = ikev2_find_match_ikesa(conf, parsed_sa, 0, 0);
#endif
	if (!negotiated_sa)
		goto no_proposal_chosen;

	if (get_uint16(&ke->ke_h.dh_group_id) != negotiated_sa->dhdef->transform_id) {
		uint16_t dhgrp_id;
		static struct ratelimit r;

		/* send response INVALID_KE_PAYLOAD, negotiated_sa->dhgrp; */
		TRACE((PLOGLOC, "DH group id %d != %d, responding with INVALID_KE_PAYLOAD\n",
		       get_uint16(&ke->ke_h.dh_group_id),
		       negotiated_sa->dhdef->transform_id));
		if (ratelimit(&r, remote)) {
			dhgrp_id = htons(negotiated_sa->dhdef->transform_id);
			ikev2_respond_with_notify(packet, remote, local,
						  IKEV2_INVALID_KE_PAYLOAD,
						  (uint8_t *)&dhgrp_id,
						  sizeof(dhgrp_id));
		}
		++isakmpstat.invalid_ke_payload;
		goto done;
	}
	dhlen = get_payload_length(&ke->header) - sizeof(struct ikev2payl_ke);
	if (dhlen != dh_value_len((struct dhgroup *)negotiated_sa->dhdef->definition))
		goto malformed_payload;
	dhpub_p = rc_vnew((uint8_t *)(ke + 1), dhlen);
	if (!dhpub_p)
		goto fail;

	n_i = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_i)
		goto fail;

	message = rc_vdup(packet);
	if (!message)
		goto fail;

	nonce_size = ikev2_nonce_size(conf);
	n_r = random_bytes(nonce_size);
	if (!n_r)
		goto fail;

	/* So far so good.  Now update the sa state */

	ike_sa->negotiated_sa = negotiated_sa;
	ike_sa->dhpub_p = dhpub_p;
	ike_sa->n_i = n_i;
	ike_sa->n_r = n_r;
	ike_sa->peer_first_message = message;

	negotiated_sa = 0;
	dhpub_p = 0;
	n_i = n_r = 0;
	message = 0;

	ikev2_set_state(ike_sa, IKEV2_STATE_RES_IKE_SA_INIT_SENT);
	ikev2_update_message_id(ike_sa, get_uint32(&ikehdr->message_id), FALSE);

	/*
	 * send reply
	 */
	responder_state0_send(ike_sa, local, remote);

      done:
	if (message)
		rc_vfree(message);
	if (n_i)
		rc_vfree(n_i);
	if (n_r)
		rc_vfree(n_r);
	if (dhpub_p)
		rc_vfree(dhpub_p);
	if (negotiated_sa)
		racoon_free(negotiated_sa);
	if (parsed_sa)
		proplist_discard(parsed_sa);
	return;

      no_proposal_chosen:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "no proposal chosen\n");
	++isakmpstat.no_proposal_chosen;
	/* send notify NO_PROPOSAL_CHOSEN */
	goto done;

      malformed_message:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "packet lacks expected payload\n");
	++isakmpstat.malformed_message;
	goto done;

      duplicate:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "duplicated payload\n");
	++isakmpstat.malformed_message;
	goto done;

      malformed_payload:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "malformed payload\n");
	++isakmpstat.malformed_payload;
	/* send INVALID_SYNTAX */
	goto done;

      drop:
	/* log before goto */
	goto done;

      fail:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_INTERR, PLOGLOC, "failed to process packet\n");
	++isakmpstat.fail_process_packet;
	goto done;
}

static void
responder_state0_send(struct ikev2_sa *ike_sa, struct sockaddr *src,
		      struct sockaddr *dest)
{
	struct ikev2_dh_ctx *ctx;
	struct algdef *dhdef;

	(void)src;
	(void)dest;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		goto abort;
	ctx->ike_sa = ike_sa;
	ctx->serial = ike_sa->serial_number;
	ikev2_payloads_init(&ctx->payl);
	ctx->payl_inited = 1;

	ctx->sa = ikev2_ikesa_to_proposal(ike_sa->negotiated_sa, 0);
	if (!ctx->sa) {
		TRACE((PLOGLOC, "no proposal for the peer\n"));
		goto abort;
	}

	dhdef = ike_sa->negotiated_sa->dhdef;
	if (!dhdef) {
		TRACE((PLOGLOC, "no DH choices for the peer\n"));
		goto abort;
	}
	ctx->dhdef = dhdef;
	ike_sa->crypto_pending = 1;
	if (oakley_dh_generate_submit((struct dhgroup *)dhdef->definition,
	    &ike_sa->dhpub, &ike_sa->dhpriv, responder_state0_after_gen,
	    ctx) != 0) {
		ike_sa->crypto_pending = 0;
		TRACE((PLOGLOC, "failed dh_generate submit\n"));
		goto abort;
	}
	return;

      abort:
	ikev2_dh_ctx_free(ctx);
	ikev2_abort(ike_sa, ECONNREFUSED);
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "aborting the exchange for an internal failure\n");
}

static void
responder_state0_after_gen(int rc, void *arg)
{
	struct ikev2_dh_ctx *ctx = arg;
	struct ikev2_sa *ike_sa;
	rc_vchar_t *pkt = 0;
	struct ikev2payl_ke_h dhgrp_hdr;
	struct sockaddr *src;
	struct sockaddr *dest;

	ike_sa = ikev2_dh_ctx_sa(ctx);
	if (!ike_sa) {
		ikev2_dh_ctx_free(ctx);
		return;
	}
	if (rc != 0) {
		TRACE((PLOGLOC, "failed dh_generate\n"));
		goto abort;
	}

	src = ike_sa->local;
	dest = ike_sa->remote;
	dhgrp_hdr.dh_group_id = htons(ctx->dhdef->transform_id);
	dhgrp_hdr.reserved = 0;
	ctx->ke = rc_vprepend(ike_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
	if (!ctx->ke) {
		TRACE((PLOGLOC, "failed creating KE\n"));
		goto abort;
	}

	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_SA, ctx->sa, FALSE);
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_KE, ctx->ke, FALSE);
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NONCE, ike_sa->n_r, FALSE);

#ifdef ENABLE_NATT
	if ((ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON ||
	     ikev2_nat_traversal(ike_sa->rmconf) == RCT_NATT_FORCE) &&
	    SOCKADDR_FAMILY(dest) == AF_INET) {
		if (natt_create_natd(ike_sa, &ctx->payl, dest, src) < 0) {
			goto abort;
		}
	}
#endif

	/*
	 * [N(IKEV2_FRAGMENTATION_SUPPORTED)]
	 */
	if (ike_sa->frag_supported) {
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_FRAGMENTATION_SUPPORTED,
							 0, 0),
				    TRUE);
	}
#ifdef WITH_INTERMEDIATE
	/* RFC 9242: echo 16438 only when (a) the peer offered it
	 * (negotiated is set in resp_state0_recv_notify), (b) the SELECTED
	 * proposal actually carries type-6/ADDKE (addke != 0 -- echoing on a
	 * classical AEAD match would make the peer send exch 43 before any
	 * IKE_AUTH, which responder_ike_intermediate_recv would then drop
	 * because addke == 0 -> the connect stalls), AND (c) the negotiated
	 * IKE cipher is AEAD (IntAuth_A is only deterministic for AEAD;
	 * random CBC padding makes the wire Encrypted length
	 * unreconstructable).  A CBC peer that offered intermediate falls
	 * through to a classical IKE_AUTH instead. */
	if (ike_sa->intermediate_negotiated && ike_sa->negotiated_sa &&
	    ike_sa->negotiated_sa->addke != 0) {
		u_int16_t _ce = ike_sa->negotiated_sa->encr;
		if (ikev2_encr_is_aead(_ce)) {
			ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
					    ikev2_notify_payload(0, 0, 0,
						 IKEV2_INTERMEDIATE_EXCHANGE_SUPPORTED,
						 0, 0),
					    TRUE);
		}
	}
#endif
	/* RFC 8784 s2.2: echo N(USE_PPK) only when the peer offered it AND
	 * we are configured with a PPK for this peer (use_ppk on and a
	 * ppk_id set).  Once echoed we are committed: ikev2_compute_keys()
	 * re-derives SK_d/SK_pi/SK_pr with the PPK (ppk_active), and
	 * IKE_AUTH must then confirm the PPK_IDENTITY or the SA aborts. */
	if (ike_sa->peer_sent_use_ppk &&
	    ikev2_use_ppk(ike_sa->rmconf) == RCT_BOOL_ON &&
	    ikev2_ppk_id(ike_sa->rmconf) != NULL) {
		ike_sa->ppk_active = 1;
#ifdef WITH_INTERMEDIATE
		/* RFC 9867 s3.1.1: with an ADDKE intermediate round pending, defer
		 * the PPK mix -- the intermediate SKEYSEED(1)=prf(SK_d,...) must see
		 * the un-PPK'd SK_d (a responder cannot know the PPK until IKE_AUTH
		 * PPK_IDENTITY); ikev2_ppk_apply() runs on the final generation in
		 * responder_ike_intermediate_recv. */
		if (ike_sa->intermediate_negotiated && ike_sa->negotiated_sa &&
		    ike_sa->negotiated_sa->addke != 0)
			ike_sa->ppk_deferred = 1;
#endif
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_USE_PPK,
							 0, 0),
				    TRUE);
	}


	/* RFC 7427 s4: echo N(SIG_HASH_ALGORITHMS) only if the initiator
	 * offered it AND this responder's seat is a method-14 signer
	 * (RSASIG / ECDSA / EdDSA — only then can we honor the DS AUTH the
	 * notify commits both sides to).
	 * Data = the hash-algorithm IDs (16-bit) we can verify (RFC 7427
	 * s4): SHA2-256=2, SHA2-384=3, SHA2-512=4 (eay_rfc7427_verify);
	 * never SHA1=1 (RFC 8247 s3.2).  Our own method-14 AUTH signs the
	 * strongest mutually-supported SHA-2 (RSASSA-PKCS1 v1.5 / PSS /
	 * ECDSA-DER as configured); SHA-2 tables shared with the initiator
	 * offer via ikev2_push_sig_hash().
	 * Both initiator and responder offer/echo 16431 when RSASIG, so
	 * iked<->iked RSA (i2ipubkey-rsa) negotiates method 14; method 1 /
	 * SHA-1 remains the fallback when the peer does not echo.
	 * 'offer_sig_hash_algorithms off' (default ON) also suppresses the
	 * echo, pinning method 1 / SHA-1 even though the peer offered 16431
	 * (the i2iinit-*-rsa-sha1- interop rows). */
	if (ike_sa->peer_sent_sig_hash_algos &&
	    ikev2_offer_sig_hash_algorithms(ike_sa->rmconf) == RCT_BOOL_ON) {
		struct rc_alglist *_kmp = ikev2_kmp_auth_method(ike_sa->rmconf);
		/* RSASIG anywhere in the list qualifies: the responder's own
		 * seat may be rsasig even when the client authenticates via
		 * eap (RFC 7296 s2.16, kmp_auth_method { eap; rsasig; }). */
		int _has_rsa = 0;
		int _has_eddsa = 0;
		int _has_ecdsa = 0;
		for (; _kmp; _kmp = _kmp->next) {
			if (_kmp->algtype == RCT_ALG_RSASIG)
				_has_rsa = 1;
			if (_kmp->algtype == RCT_ALG_EDDSA)
				_has_eddsa = 1;
			if (_kmp->algtype == RCT_ALG_ECDSA)
				_has_ecdsa = 1;
		}
		if (_has_rsa) {
			ike_sa->sig_hash_algos_ds = 1;
			TRACE((PLOGLOC, "echoing SIG_HASH_ALGORITHMS (16431)\n"));
			ikev2_push_sig_hash(&ctx->payl, sig_hash_sha2,
					    sizeof(sig_hash_sha2), "RSASIG/SHA-2");
		} else if (_has_eddsa) {
			/* RFC 8420 s4: an EdDSA responder echoes the Identity
			 * hash; method 14 is the only way EdDSA is carried. */
			ike_sa->sig_hash_algos_ds = 1;
			TRACE((PLOGLOC, "echoing SIG_HASH_ALGORITHMS (16431, "
				"Identity/EdDSA)\n"));
			ikev2_push_sig_hash(&ctx->payl, sig_hash_identity,
					    sizeof(sig_hash_identity),
					    "Identity/EdDSA");
		} else if (_has_ecdsa) {
			/* RFC 7427 plan scope #4: an ECDSA responder echoes
			 * the SHA-2 IDs {2,3,4}; with 16431 exchanged the
			 * ECDSA seat uses method 14 (DS) + ecdsa-with-SHA2
			 * instead of the RFC 4754 methods 9/10/11. */
			ike_sa->sig_hash_algos_ds = 1;
			TRACE((PLOGLOC, "echoing SIG_HASH_ALGORITHMS (16431, "
				"ECDSA)\n"));
			ikev2_push_sig_hash(&ctx->payl, sig_hash_sha2,
					    sizeof(sig_hash_sha2), "ECDSA/SHA-2");
		}
	}
	/* RFC 6023 s4: advertise childless IKE_SA support when configured for
	 * this peer (protocol id 1 = IKE, spi size 0).  A supporting initiator
	 * MAY then send a modified IKE_AUTH request without SAi2/TSi/TSr,
	 * which responder_ike_sa_auth_cont() accepts and answers with an
	 * SA-less response, leaving an authenticated IKE_SA with zero
	 * children (liveness/DPD keep it alive; first CHILD_SA arrives via
	 * CREATE_CHILD_SA). */
	if (ikev2_childless(ike_sa->rmconf) == RCT_BOOL_ON) {
		TRACE((PLOGLOC, "advertising childless IKE_SA support (16418)\n"));
		ike_sa->childless_advertised = 1;
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(1, 0, 0,
							 IKEV2_CHILDLESS_IKEV2_SUPPORTED,
							 0, 0),
				    TRUE);
	}

	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_SA_INIT, IKEV2FLAG_RESPONSE,
				     0, ike_sa, &ctx->payl);
	if (!pkt) {
		TRACE((PLOGLOC, "failed creating packet\n"));
		goto abort;
	}

	if (ike_sa->my_first_message)
		rc_vfree(ike_sa->my_first_message);
	ike_sa->my_first_message = rc_vdup(pkt);
	if (!ike_sa->my_first_message) {
		TRACE((PLOGLOC, "failed rc_vdup\n"));
		goto abort;
	}

	if (ikev2_transmit_response(ike_sa, pkt, src, dest) != 0)
		goto fail;
	pkt = 0;

	if (ikev2_set_negotiated_sa(ike_sa, ike_sa->negotiated_sa) != 0)
		goto abort2;
	if (compute_skeyseed_submit(ike_sa, responder_state0_after_skey,
	    ctx) != 0)
		goto abort2;
	return;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to send packet\n");
	++isakmpstat.fail_send_packet;
	ike_sa->crypto_pending = 0;
	if (pkt)
		rc_vfree(pkt);
	ikev2_dh_ctx_free(ctx);
	return;

      abort2:
      abort:
	if (pkt)
		rc_vfree(pkt);
	ike_sa->crypto_pending = 0;
	ikev2_abort(ike_sa, ECONNREFUSED);
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "aborting the exchange for an internal failure\n");
	ikev2_dh_ctx_free(ctx);
}

static void
responder_state0_after_skey(int rc, void *arg)
{
	struct ikev2_dh_ctx *ctx = arg;
	struct ikev2_sa *ike_sa;

	ike_sa = ikev2_dh_ctx_sa(ctx);
	if (!ike_sa) {
		ikev2_dh_ctx_free(ctx);
		return;
	}
	if (rc != 0)
		goto abort2;
	if (ikev2_compute_keys(ike_sa) != 0)
		goto abort2;
	ikev2_destroy_secret(ike_sa);
	ike_sa->crypto_pending = 0;
	ikev2_dh_ctx_free(ctx);
	return;

      abort2:
	ike_sa->crypto_pending = 0;
	ikev2_abort(ike_sa, ECONNREFUSED);
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "aborting the exchange for an internal failure\n");
	ikev2_dh_ctx_free(ctx);
}

static void
initiator_skey_done(int rc, void *arg)
{
	struct ikev2_dh_ctx *ctx = arg;
	struct ikev2_sa *ike_sa;

	ike_sa = ikev2_dh_ctx_sa(ctx);
	if (!ike_sa) {
		ikev2_dh_ctx_free(ctx);
		return;
	}
	if (rc != 0)
		goto abort;
	if (ikev2_compute_keys(ike_sa) != 0)
		goto abort;
	ikev2_destroy_secret(ike_sa);
	ikev2_update_message_id(ike_sa, ctx->message_id, TRUE);
#ifdef WITH_INTERMEDIATE
	/* RFC 9370 s2.2.1: run the negotiated IKE_INTERMEDIATE ADDKE round(s)
	 * before IKE_AUTH when the IKE_SA proposal selected ADDKE. */
	if (ike_sa->intermediate_negotiated &&
	    ike_sa->negotiated_sa && ike_sa->negotiated_sa->addke != 0 &&
	    ike_sa->encryptor && encryptor_icv_length(ike_sa->encryptor) > 0) {
		ike_sa->intermediate_msgid = 1;
		initiator_ike_intermediate_send(ike_sa);
		ike_sa->crypto_pending = 0;
		ikev2_dh_ctx_free(ctx);
		return;
	}
#endif
	ikev2_set_state(ike_sa, IKEV2_STATE_INI_IKE_AUTH_SENT);
	initiator_state1_send(ike_sa, 0, ike_sa->remote);
	ike_sa->crypto_pending = 0;
	ikev2_dh_ctx_free(ctx);
	return;

      abort:
	ike_sa->crypto_pending = 0;
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed computing IKE keys\n");
	ikev2_abort(ike_sa, ECONNREFUSED);
	ikev2_dh_ctx_free(ctx);
}

void
initiator_ike_sa_init_recv(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
			   struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *payload;
	int type;
	int rc2;	/* redirect-follow retarget result */
	struct ikev2_payload_header *sa = 0;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *nonce = 0;
	unsigned int dhlen;
	rc_vchar_t *dhpub_p = 0;
	rc_vchar_t *n_r = 0;
	rc_vchar_t *message = 0;
	int http_cert_lookup_supported = FALSE;
	struct prop_pair **parsed_sa = 0;
	struct ikev2_isakmpsa *negotiated_sa = 0;

	ikehdr = (struct ikev2_header *)packet->v;

	if (!(ikehdr->exchange_type == IKEV2EXCH_IKE_SA_INIT
	      && !(ikehdr->flags & IKEV2FLAG_INITIATOR)
	      && (ikehdr->flags & IKEV2FLAG_RESPONSE))) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected or malformed packet\n");
		++isakmpstat.unexpected_packet;
		goto drop;
	}

	/* r_ck is needed to create hash for NAT-D comparison */
	memcpy(&ike_sa->index.r_ck, &ikehdr->responder_spi,
	       sizeof(isakmp_cookie_t));

	/*
	 * expect HDR, SAr1, KEr, Nr, [CERTREQ]
	 * or
	 * HDR, N(COOKIE)
	 * or
	 * HDR, N(INVALID_KE_PAYLOAD)
	 * or
	 * HDR, N(NO_PROPOSAL_CHOSEN) (or other error)
	 */

	payload = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(payload, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_SA:
			if (sa)
				goto duplicate;
			sa = payload;
			break;
		case IKEV2_PAYLOAD_KE:
			if (ke)
				goto duplicate;
			ke = (struct ikev2payl_ke *)payload;
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = payload;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (init_ike_sa_init_recv_notify
			    (ike_sa, packet, remote, local, payload,
			     &http_cert_lookup_supported) < 0) {
				goto drop;
			}
			break;

		case IKEV2_PAYLOAD_CERTREQ:
			/* CERTREQ: ignored; the initiator offers its own
			 * certificate selection via the online-cert
			 * lookup in IKE_AUTH, not by answering this. */
			break;

		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;

		default:
			if (payload_is_critical(payload)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				/* if (trust_unauthenticated_packet) {
				 *   goto abort;
				 * } else {
				 */
				goto drop;
			}
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	if (ike_sa->redirect_rx) {
		/* RFC 5685 s5.5: the responder redirected this IKE_SA_INIT
		 * and the echoed Ni was verified in the notify handler.  The
		 * response carries no SA/KE/Nr (SPI_R=0, msgid=0, one
		 * N(REDIRECT)); per s5.5 we MUST NOT run a key exchange with
		 * this gateway.  Follow the redirect: retarget this IKE_SA
		 * toward the new gateway and re-drive IKE_SA_INIT carrying
		 * N(REDIRECTED_FROM).  If the target is not resolvable (e.g.
		 * an FQDN, which this layer does not resolve), fall back to
		 * abort so we don't hang against an overloaded node. */
		rc2 = ikev2_initiator_redirect_follow(ike_sa, remote);
		if (rc2 == 0)
			goto done;
		isakmp_log(ike_sa, local, remote, packet, PLOG_INFO, PLOGLOC,
			   "redirect target not resolvable, aborting "
			   "IKE_SA_INIT\n");
		goto abort;
	}
	if (!(sa && ke && nonce)) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC,
			   "packet lacks expected payload\n");
		goto malformed_packet;
	}

	if (ikev2_spi_is_zero(&ikehdr->responder_spi)) {
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOERR, PLOGLOC, "responder SPI is zero\n");
		goto malformed_packet;
	}

	parsed_sa = ikev2_parse_sa(&ikev2_doi, sa);
	if (!parsed_sa)
		goto malformed_payload;	/* ??? maybe nomem? */

#ifdef WITH_INTERMEDIATE
	negotiated_sa = ikev2_find_match_ikesa(ike_sa->rmconf, parsed_sa, 0,
					       ike_sa->intermediate_negotiated);
#else
	negotiated_sa = ikev2_find_match_ikesa(ike_sa->rmconf, parsed_sa, 0, 0);
#endif
	/* negotiated_sa = ikev2_check_proposal(ike_sa, parsed_sa); */
	if (!negotiated_sa)
		goto no_proposal_chosen;

	if (get_payload_length(&ke->header) < sizeof(struct ikev2payl_ke) ||
	    get_uint16(&ke->ke_h.dh_group_id) != negotiated_sa->dhdef->transform_id) {
		TRACE((PLOGLOC, "KE id %d, negotiated %d.\n",
		       get_uint16(&ke->ke_h.dh_group_id),
		       negotiated_sa->dhdef->transform_id));
		/* send INVALID_SYNTAX ??? */
		goto malformed_payload;
	}
	dhlen = get_payload_length(&ke->header) - sizeof(struct ikev2payl_ke);
	if (dhlen != dh_value_len((struct dhgroup *)negotiated_sa->dhdef->definition)) {
		TRACE((PLOGLOC, "KE data length %u, should be %zu\n",
		       dhlen,
		       dh_value_len((struct dhgroup *)negotiated_sa->dhdef->definition)));
		/* send INVALID_SYNTAX ??? */
		goto malformed_payload;
	}
	dhpub_p = rc_vnew((uint8_t *)(ke + 1), dhlen);
	if (!dhpub_p)
		goto fail_nomem;

	n_r = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_r)
		goto fail_nomem;

	message = rc_vdup(packet);
	if (!message)
		goto fail_nomem;

	/* Now, update the sa state */
	ike_sa->negotiated_sa = negotiated_sa;
	ike_sa->dhpub_p = dhpub_p;
	ike_sa->n_r = n_r;
	ike_sa->peer_first_message = message;

	negotiated_sa = 0;
	dhpub_p = n_r = message = 0;	/* so that they're not deallocated */

#ifdef notyet
	/* (draft-17)
	 * There is a Denial of Service attack on the Initiator of an IKE_SA
	 * that can be avoided if the Initiator takes the proper care. Since the
	 * first two messages of an SA setup are not cryptographically
	 * protected, an attacker could respond to the Initiator's message
	 * before the genuine Responder and poison the connection setup attempt.
	 * To prevent this, the Initiator MAY be willing to accept multiple
	 * responses to its first message, treat each as potentially legitimate,
	 * respond to it, and then discard all the invalid half open connections
	 * when she receives a valid cryptographically protected response to any
	 * one of her requests.  Once a cryptographically valid response is
	 * received, all subsequent responses should be ignored whether or not
	 * they are cryptographically valid.
	 */
#endif

	/* RFC 8784 s2.2: we offered N(USE_PPK); the responder echoed it iff
	 * it holds a PPK for us.  mandatory==ON and no echo is a downgrade
	 * (quantum-vulnerable) and MUST abort the exchange; mandatory==OFF
	 * and no echo continues without a PPK (keys derived unmodified).
	 * This runs before the SKEYSEED compute, so ikev2_compute_keys()
	 * sees ppk_active and re-derives SK_d/SK_pi/SK_pr accordingly. */
	if (ikev2_use_ppk(ike_sa->rmconf) == RCT_BOOL_ON) {
		if (ike_sa->peer_sent_use_ppk) {
			ike_sa->ppk_active = 1;
#ifdef WITH_INTERMEDIATE
			/* RFC 9867 s3.1.1: defer the PPK mix until the final generation
			 * (after the ADDKE intermediate round), so both peers derive
			 * subsequent rounds from the un-PPK'd SK_d. */
			if (ike_sa->intermediate_negotiated && ike_sa->negotiated_sa &&
			    ike_sa->negotiated_sa->addke != 0)
				ike_sa->ppk_deferred = 1;
#endif
		} else if (ikev2_ppk_mandatory(ike_sa->rmconf) ==
			   RCT_BOOL_ON) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOERR, PLOGLOC,
				   "RFC 8784: mandatory USE_PPK not echoed "
				   "by responder, aborting\n");
			++isakmpstat.authentication_failed;
			goto abort;
		} else {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_INFO, PLOGLOC,
				   "RFC 8784: optional PPK not echoed by "
				   "responder; continuing without PPK\n");
		}
	}

	/* compute SKEYSEED */
	if (ikev2_set_negotiated_sa(ike_sa, ike_sa->negotiated_sa) != 0)
		goto abort;
	{
		struct ikev2_dh_ctx *sctx;

		sctx = calloc(1, sizeof(*sctx));
		if (!sctx)
			goto abort;
		sctx->ike_sa = ike_sa;
		sctx->serial = ike_sa->serial_number;
		sctx->message_id = get_uint32(&ikehdr->message_id);
		ike_sa->crypto_pending = 1;
		if (compute_skeyseed_submit(ike_sa, initiator_skey_done,
		    sctx) != 0) {
			ike_sa->crypto_pending = 0;
			ikev2_dh_ctx_free(sctx);
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_INTERR, PLOGLOC,
				   "failed computing SKEYSEED\n");
			goto abort;
		}
	}
	goto done;

      done:
      drop:
	/* dispose allocated memory */
	if (negotiated_sa)
		racoon_free(negotiated_sa);
	if (parsed_sa)
		proplist_discard(parsed_sa);
	if (message)
		rc_vfree(message);
	if (n_r)
		rc_vfree(n_r);
	if (dhpub_p)
		rc_vfree(dhpub_p);
	return;

      fail_nomem:
	/* transient failure, wait the peer to retransmit */
	/* log error */
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_INTERR, PLOGLOC,
		   "failed allocating memory, dropping packet\n");
	++isakmpstat.fail_process_packet;
	goto drop;

      malformed_payload:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOWARN, PLOGLOC,
		   "malformed unauthenticated packet, dropping\n");
	++isakmpstat.malformed_payload;
	goto done;

      malformed_packet:
      duplicate:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOWARN, PLOGLOC,
		   "malformed unauthenticated packet, dropping\n");
	/* just drop the packet since it's not authenticated yet */
	++isakmpstat.malformed_message;
	goto done;

      no_proposal_chosen:
	/* ??? just drop the packet since it's not authenticated yet */
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_PROTOERR, PLOGLOC, "no proposal chosen\n");
	++isakmpstat.no_proposal_chosen;
	goto done;

      abort:
	isakmp_log(ike_sa, local, remote, packet,
		   PLOG_INTERR, PLOGLOC, "discarding ike_sa\n");
	ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
	/* should send notify? */
	goto done;
}

/*
 * RFC 5685 initiator redirect follow.  Called from initiator_ike_sa_init_recv
 * after a verified N(REDIRECT): the responder the client first tried is
 * overloaded/retiring and pointed us at redirect_gw (recorded in
 * ike_sa->redirect_gw / redirect_gw_type).  Rather than abort-and-lose the
 * acquire/child intent, we keep this ike_sa, retarget its remote to the new
 * gateway, reset the in-flight IKE_SA_INIT state, and re-drive
 * ikev2_initiator_start() so the client re-sends IKE_SA_INIT to the new
 * gateway carrying N(REDIRECTED_FROM) with the original gateway's identity.
 *
 * Only IPv4/IPv6 literal redirect targets are supported here (FQDN has no
 * resolver at this layer): on an unresolvable target return non-zero so the
 * caller aborts instead of hanging.
 *
 * Returns 0 on success (re-initiation under way), non-zero if the target is
 * not resolvable or a transient failure before re-drive.
 */
int
ikev2_initiator_redirect_follow(struct ikev2_sa *ike_sa, struct sockaddr *remote)
{
	struct sockaddr *newpeer;
	uint8_t rfrom_type;
	rc_vchar_t *rfrom = 0;
	uint8_t *ap;
	size_t alen;

	assert(ike_sa != 0);
	assert(ike_sa->redirect_rx != 0);

	/* We are about to act on this verified redirect (re-drive against the
	 * new gateway).  Clear redirect_rx NOW so that the NEW gateway's
	 * normal IKE_SA_INIT response (a valid SAr1/KEr/Nr, not another
	 * REDIRECT) does not re-trigger this branch and loop IKE_SA_INIT
	 * forever.  If the new gateway also redirects us, its N(REDIRECT)
	 * re-arms redirect_rx via the notify handler (as does any fresh
	 * verified redirect). */
	ike_sa->redirect_rx = 0;

	/* RFC 5685 s7 (REVIEW_2026-10-18 M2): bound redirect loops. */
	if (ikev2_redirect_loop_check(&ike_sa->redirect_count,
	    &ike_sa->redirect_window, time(NULL),
	    ike_sa->rmconf ? ikev2_redirect_max(ike_sa->rmconf) : 5,
	    ike_sa->rmconf ? ikev2_redirect_period(ike_sa->rmconf) : 300)
	    != 0) {
		isakmp_log(ike_sa, 0, remote, 0, PLOG_PROTOWARN, PLOGLOC,
			   "RFC5685 s7: redirect loop limit exceeded "
			   "(%d redirects within %d s), not following\n",
			   ike_sa->redirect_count, ike_sa->rmconf ?
			   ikev2_redirect_period(ike_sa->rmconf) : 300);
		return -1;
	}

	/* Capture the ORIGINAL (redirecting) gateway identity from the peer
	 * we first tried (`remote`) for the REDIRECTED_FROM notify. */
	switch (remote->sa_family) {
	case AF_INET:
		rfrom_type = 1;
		ap = (uint8_t *)&((struct sockaddr_in *)remote)->sin_addr;
		alen = sizeof(struct in_addr);
		break;
	case AF_INET6:
		rfrom_type = 2;
		ap = (uint8_t *)&((struct sockaddr_in6 *)remote)->sin6_addr;
		alen = sizeof(struct in6_addr);
		break;
	default:
		return -1;
	}
	rfrom = rc_vnew(ap, alen);
	if (!rfrom)
		return -1;

	/* Resolve the redirect target to a fresh sockaddr. */
	newpeer = ikev2_redirect_gw_sadup(ike_sa->redirect_gw_type,
					   ike_sa->redirect_gw);
	if (!newpeer) {
		rc_vfree(rfrom);
		return -1;
	}

	/* Retarget this SA toward the new gateway. */
	if (ike_sa->remote)
		racoon_free(ike_sa->remote);
	ike_sa->remote = newpeer;

	/* Stash the redirecting gateway for the REDIRECTED_FROM emit. */
	if (ike_sa->redirected_from)
		rc_vfree(ike_sa->redirected_from);
	ike_sa->redirected_from = rfrom;
	ike_sa->redirected_from_type = rfrom_type;

	/* Free the first IKE_SA_INIT attempt's key/nonce material; both are
	 * re-minted by ikev2_initiator_start() for the new gateway. */
	if (ike_sa->n_i)
		rc_vfree(ike_sa->n_i);
	ike_sa->n_i = 0;
	if (ike_sa->n_r)
		rc_vfree(ike_sa->n_r);
	ike_sa->n_r = 0;
	if (ike_sa->dhpriv)
		rc_vfreez(ike_sa->dhpriv);
	ike_sa->dhpriv = 0;
	if (ike_sa->dhpub)
		rc_vfree(ike_sa->dhpub);
	ike_sa->dhpub = 0;

	/* Fresh IKE_SA_INIT to a fresh responder: reset the message-id
	 * window and zero the (redirect) responder's SPI.  The initiator
	 * cookie stays (it keys the acquire intent). */
	ike_sa->send_message_id = 0;
	ike_sa->recv_message_id = 0;
	memset(&ike_sa->index.r_ck, 0, sizeof(ike_sa->index.r_ck));

	ike_sa->redirect_follow = 1;
	TRACE((PLOGLOC,
	       "RFC5685: following redirect to gw, re-driving IKE_SA_INIT\n"));
	ikev2_initiator_start(ike_sa);
	return 0;
}
