/* $Id: ikev2_notify.c,v 1.17 2008/02/06 08:09:00 mk Exp $ */

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
#include <sys/socket.h>
#include <sys/errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "racoon.h"

#include "isakmp.h"
#include "ikev2.h"
#include "keyed_hash.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_notify.h"

#include "var.h"

#include "dhgroup.h"
#include "oakley.h"		/* for prototypes */
#include "crypto_impl.h"
#include "ike_conf.h"

#include "debug.h"

int
resp_state0_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
			struct sockaddr *remote, struct sockaddr *local,
			struct ikev2_payload_header *payload)
{
	struct ikev2payl_notify *notify;

	notify = (struct ikev2payl_notify *)payload;

	TRACE((PLOGLOC, "received Notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(notify))));

	if (notify->nh.spi_size != 0) {
		/* invalid notification message; */
		isakmp_log(ike_sa, local, remote, 0,
			   PLOG_PROTOWARN, PLOGLOC,
			   "dropping malformed unauthenticated notify payload (spi_size %d != 0)\n",
			   notify->nh.spi_size);
		++isakmpstat.malformed_payload;
		return -1;
	}

	switch (get_notify_type(notify)) {
#ifdef ENABLE_NATT
	case IKEV2_NAT_DETECTION_SOURCE_IP:
	case IKEV2_NAT_DETECTION_DESTINATION_IP:
		if (ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON ||
		    ikev2_nat_traversal(ike_sa->rmconf) == RCT_NATT_FORCE) {
			if (natt_process_natd(ike_sa, notify, FALSE) == 0) {
				break;
			}

			/* XXX error handlings */
			isakmp_log(ike_sa, local, remote, 0,
				   PLOG_PROTOWARN, PLOGLOC,
				   "dropping unexpected notify payload (protocol_id %d, type %d)\n",
				   notify->nh.protocol_id, get_notify_type(notify));
			++isakmpstat.unexpected_payload;
			return -1;
		}
#endif
		/* FALLTHROUGH */

	case IKEV2_FRAGMENTATION_SUPPORTED:
		ike_sa->frag_supported = 1;
		TRACE((PLOGLOC, "peer supports IKEv2 fragmentation\n"));
		break;
#ifdef WITH_INTERMEDIATE
	case IKEV2_INTERMEDIATE_EXCHANGE_SUPPORTED:
		/* RFC 9242: records that the PEER offered 16438.  NOT a two-sided
		 * negotiation -- the responder only commits to running exch 43
		 * when it echoes 16438 in SAr1 (gated on a selected AEAD+type-6
		 * proposal in resp_state0_recv).  A receive-side flag alone must
		 * never imply an intermediate round will (or can) run. */
		ike_sa->intermediate_negotiated = 1;
		TRACE((PLOGLOC, "peer offers IKE_INTERMEDIATE (16438)\n"));
		break;
#endif
	case IKEV2_SIG_HASH_ALGORITHMS:
		/* RFC 7427 s4: the PEER advertises its signature-hash support and
		 * thereby the Digital Signature AUTH method (14).  This side echoes
		 * 16431 (committing to method 14 AUTH) when its own seat is RSASIG
		 * -- see responder_state0_after_gen.  Remember the offered hash
		 * set so our method-14 signer can pick the strongest mutual hash. */
		ike_sa->peer_sent_sig_hash_algos = 1;
		ikev2_remember_sig_hashes(ike_sa, notify);
		TRACE((PLOGLOC, "peer offers SIG_HASH_ALGORITHMS (16431)\n"));
		break;
	case IKEV2_REDIRECT_SUPPORTED:
		/* RFC 5685 s3: the INITIATOR indicates it is willing to be
		 * redirected.  The responder MUST NOT answer REDIRECT to a peer
		 * that did not offer 16406; record it here so the redirect
		 * decision in responder_state0_send is gated on this. */
		ike_sa->peer_sent_redirect = 1;
		TRACE((PLOGLOC, "peer supports redirection (REDIRECT_SUPPORTED "
			"16406)\n"));
		break;
	case IKEV2_USE_PPK:
		/* RFC 8784 s2.2: the PEER (or, for the initiator view, the
		 * responder's echo of) N(USE_PPK).  The responder decides to echo
		 * and set ppk_active in its IKE_SA_INIT response build; the
		 * initiator resolves ppk_active from this echo + its
		 * mandatory/optional config in initiator_ike_sa_init_recv. */
		ike_sa->peer_sent_use_ppk = 1;
		TRACE((PLOGLOC, "peer uses RFC 8784 PPK (USE_PPK)\n"));
		break;

	case IKEV2_MOBIKE_SUPPORTED:
		ike_sa->mobike_supported = 1;
		TRACE((PLOGLOC, "peer supports MOBIKE\n"));
		break;

	default:
		/* else, unexpected unauthenticated notify */
#if 1
		isakmp_log(ike_sa, local, remote, packet,
			   PLOG_PROTOWARN, PLOGLOC,
			   "ignoring unauthenticated notify payload (%s)\n",
			   ikev2_notify_type_str(get_notify_type(notify)));
		++isakmpstat.payload_ignored;
#endif
		break;
	}

	return 0;
}

int
init_ike_sa_init_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
			     struct sockaddr *remote, struct sockaddr *local,
			     struct ikev2_payload_header *payload,
			     int *http_cert_lookup_supported)
{
	struct ikev2payl_notify *notify;
	struct algdef *proposed_grpdef;
	struct rc_alglist *my_choice;
	uint16_t grp;

	notify = (struct ikev2payl_notify *)payload;

	TRACE((PLOGLOC, "received Notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(notify))));

	if (notify->nh.spi_size != 0) {
		/* invalid notification message; */
		isakmp_log(ike_sa, local, remote, 0,
			   PLOG_PROTOWARN, PLOGLOC,
			   "dropping malformed unauthenticated notify payload (spi_size %d != 0)\n",
			   notify->nh.spi_size);
		++isakmpstat.malformed_payload;
		return -1;
	}

	switch (get_notify_type(notify)) {
	case IKEV2_COOKIE:
		/* retransmit with COOKIE; */
		TRACE((PLOGLOC, "received COOKIE; retransmitting\n"));
		ikev2_retransmit_add_cookie(ike_sa, notify);
		return -1;

	case IKEV2_INVALID_KE_PAYLOAD:
		if (get_payload_length(&notify->header) <
		    sizeof(struct ikev2payl_notify) + sizeof(uint16_t)) {
			/* malformed; */
			TRACE((PLOGLOC,
			       "malformed notify INVALID_KE_PAYLOAD (%d < %lu)\n",
			       get_payload_length(&notify->header),
			       (unsigned long)sizeof(struct ikev2payl_notify) +
			       sizeof(uint16_t)));
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "malformed unauthenticated packet, dropping\n");
			++isakmpstat.malformed_payload;
			return -1;
		}
		if (ike_sa->dh_choice) {
			/* already; */
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "ignoring extraneous packet with INVALID_KE_PAYLOAD\n");
			/* it may be a disruption attack...
			 * ignore this in hope that the first message was valid */
			++isakmpstat.packet_ignored;
			return -1;
		}
		grp = get_uint16(notify + 1);
		proposed_grpdef = ikev2_dhinfo(grp);
		if (!proposed_grpdef) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unknown dh group, dropping a packet with INVALID_KE_PAYLOAD\n");
			/* just ignore unauthenticated packet */
			++isakmpstat.packet_ignored;
			return -1;
		}
		for (my_choice =
		     ike_conf_dhgrp(ike_sa->rmconf, IKEV2_MAJOR_VERSION);
		     my_choice; my_choice = my_choice->next) {
			if (proposed_grpdef->racoon_code == my_choice->algtype)
				break;
		}
		if (!my_choice) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "peer's dh group choice does not match mine, dropping a packet with INVALID_KE_PAYLOAD\n");
			++isakmpstat.packet_ignored;
			return -1;
		}
#ifdef notyet
		/*
		 * XXX should remember both old and new values,
		 *     in case this is a disruption attack
		 */
#else
		ike_sa->dh_choice = proposed_grpdef;
#endif

		/* restart the exchange */
		ikev2_stop_retransmit(ike_sa);
		ikev2_initiator_start(ike_sa);
		return -1;

	case IKEV2_HTTP_CERT_LOOKUP_SUPPORTED:
		*http_cert_lookup_supported = TRUE;
		break;

#ifdef ENABLE_NATT
	case IKEV2_NAT_DETECTION_SOURCE_IP:
	case IKEV2_NAT_DETECTION_DESTINATION_IP:
		if (ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON ||
		    ikev2_nat_traversal(ike_sa->rmconf) == RCT_NATT_FORCE) {
			if (natt_process_natd(ike_sa, notify, TRUE) == 0) {
				break;
			}

			/* XXX error handlings */
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_INTERR, PLOGLOC, "discarding ike_sa\n");
			ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
			/* should send notify? */
			return -1;
		}
#endif
		/* FALLTHROUGH */

	case IKEV2_FRAGMENTATION_SUPPORTED:
		ike_sa->frag_supported = 1;
		TRACE((PLOGLOC, "peer supports IKEv2 fragmentation\n"));
		break;
#ifdef WITH_INTERMEDIATE
	case IKEV2_INTERMEDIATE_EXCHANGE_SUPPORTED:
		/* RFC 9242: records that the PEER offered 16438.  NOT a two-sided
		 * negotiation -- the responder only commits to running exch 43
		 * when it echoes 16438 in SAr1 (gated on a selected AEAD+type-6
		 * proposal in resp_state0_recv).  A receive-side flag alone must
		 * never imply an intermediate round will (or can) run. */
		ike_sa->intermediate_negotiated = 1;
		TRACE((PLOGLOC, "peer offers IKE_INTERMEDIATE (16438)\n"));
		break;
#endif
	case IKEV2_SIG_HASH_ALGORITHMS:
		/* RFC 7427 s4: peer echoed our 16431 offer (initiator view).
		 * Commit to method 14 AUTH on this seat — ikev2_auth_method
		 * keys off sig_hash_algos_ds. */
		ike_sa->peer_sent_sig_hash_algos = 1;
		ike_sa->sig_hash_algos_ds = 1;
		ikev2_remember_sig_hashes(ike_sa, notify);
		TRACE((PLOGLOC, "peer echoes SIG_HASH_ALGORITHMS (16431)\n"));
		break;
	case IKEV2_USE_PPK:
		/* RFC 8784 s2.2: the PEER (or, for the initiator view, the
		 * responder's echo of) N(USE_PPK).  The responder decides to echo
		 * and set ppk_active in its IKE_SA_INIT response build; the
		 * initiator resolves ppk_active from this echo + its
		 * mandatory/optional config in initiator_ike_sa_init_recv. */
		ike_sa->peer_sent_use_ppk = 1;
		TRACE((PLOGLOC, "peer uses RFC 8784 PPK (USE_PPK)\n"));
		break;

	case IKEV2_MOBIKE_SUPPORTED:
		ike_sa->mobike_supported = 1;
		TRACE((PLOGLOC, "peer supports MOBIKE\n"));
		break;

	case IKEV2_CHILDLESS_IKEV2_SUPPORTED:
		/* RFC 6023 s3: the initiator MAY send a modified (SA-less)
		 * IKE_AUTH only if the IKE_SA_INIT response carried this,
		 * and MUST NOT otherwise. */
		ike_sa->peer_childless = 1;
		TRACE((PLOGLOC, "peer supports childless IKE_SA (16418)\n"));
		break;

	case IKEV2_REDIRECT:
		/* RFC 5685 s3/s9: the responder answered our IKE_SA_INIT
		 * with N(REDIRECT,<new gw>) instead of an SA — it is
		 * overloaded, retiring, or dispatching us to a pool
		 * member.  The initiator MUST verify the echoed Nonce
		 * Data (s9.2: the Ni we sent rides in the redirect, so an
		 * off-path attacker cannot forge a redirect carrying our
		 * Ni), then abort this IKE_SA and re-run against the new
		 * gateway.  The SA-less nature (SPI_R=0, msgid=0) is
		 * checked in initiator_ike_sa_init_recv. */
		{
			rc_vchar_t *gw = 0, *ni = 0;
			uint8_t gwt = 0;
			uint8_t *nd;
			int dl = get_payload_length(payload) -
			    sizeof(struct ikev2payl_notify);

			if (dl < 0) {
				++isakmpstat.malformed_payload;
				return -1;
			}
			nd = get_notify_data(notify);
			{
				rc_vchar_t tmp;

				tmp.l = (size_t)dl;
				tmp.u = nd;
				if (ikev2_parse_redirect_notify_data(
				    &tmp, &gwt, &gw, &ni) != 0) {
					isakmp_log(ike_sa, local, remote,
						   packet,
						   PLOG_PROTOERR, PLOGLOC,
						   "malformed REDIRECT notify, dropping\n");
					++isakmpstat.malformed_payload;
					return -1;
				}
			}
			/* RFC 5685 s5.5: the echoed Ni MUST equal the Ni we
			 * sent.  Reject a redirect whose nonce we did not
			 * mint (off-path forgery / replay). */
			if (!ike_sa->n_i ||
			    ikev2_noncecmp(ni, ike_sa->n_i) != 0) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_PROTOWARN, PLOGLOC,
					   "REDIRECT echoed Ni does not match our Ni; "
					   "dropping\n");
				rc_vfree(gw);
				rc_vfree(ni);
				++isakmpstat.malformed_payload;
				return -1;
			}
			if (ike_sa->redirect_gw)
				rc_vfree(ike_sa->redirect_gw);
			if (ike_sa->redirect_ni)
				rc_vfree(ike_sa->redirect_ni);
			ike_sa->redirect_gw = gw;
			ike_sa->redirect_ni = ni;
			ike_sa->redirect_gw_type = gwt;
			ike_sa->redirect_rx = 1;
			TRACE((PLOGLOC,
			       "RFC5685: redirected by peer to gw type %u "
			       "(%.*s), echoed Ni verified\n",
			       (unsigned)gwt, (int)gw->l, (char *)gw->u));
		}
		break;

	default:
		/* else, unexpected unauthenticated notify */

		/*
		 * if (trust_unauthenticated_notify) {
		 *   rate-limit;
		 *   ikev2_process_notify(notify);
		 *   if (notify_type <= IKEV2_NOTIFYTYPE_ERROR_MAX)
		 *   goto abort;
		 * } else {
		 */
#if 1
		isakmp_log(ike_sa, local, remote, packet,
			   (get_notify_type(notify) <=
			    IKEV2_NOTIFYTYPE_ERROR_MAX ? PLOG_PROTOWARN :
			    PLOG_INFO), PLOGLOC,
			   "ignoring notification payload (type %s) inside unauthenticated response\n",
			   ikev2_notify_type_str(get_notify_type(notify)));
		++isakmpstat.payload_ignored;
#endif
		break;
	}

	return 0;
}

int
resp_ike_sa_auth_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local,
			     struct ikev2_payload_header *payload,
			     struct ikev2_child_param *child_param,
			     int *http_cert_lookup_supported)
{
	struct ikev2payl_notify *notify;
#ifdef notyet
	struct ikev2_header *ikehdr;
	uint32_t message_id;
#endif

#ifdef notyet
	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
#endif
	notify = (struct ikev2payl_notify *)payload;

	switch (get_notify_type(notify)) {
	case IKEV2_HTTP_CERT_LOOKUP_SUPPORTED:
		TRACE((PLOGLOC, "received Notify HTTP_CERT_LOOKUP_SUPPORTED\n"));
		*http_cert_lookup_supported = TRUE;
		break;

	case IKEV2_PPK_IDENTITY:
	{
		/* RFC 8784 s2.3: the initiator identifies the PPK it used.  We
		 * committed to this PPK when we echoed N(USE_PPK) in IKE_SA_INIT;
		 * confirm the received PPK_ID matches our configured ppk_id (the
		 * responder never echoes USE_PPK unless it holds the PPK, so a
		 * mismatch here is a genuine misconfiguration).  The post-loop
		 * gate in responder_ike_sa_auth_cont turns a missing/mismatched
		 * PPK_IDENTITY into IKEV2_AUTHENTICATION_FAILED. */
		size_t dlen = 0;
		const uint8_t *kt = NULL;
		rc_vchar_t *my_id = ikev2_ppk_id(ike_sa->rmconf);

		if (get_payload_length(&notify->header) >
		    sizeof(struct ikev2payl_notify)) {
			kt = (const uint8_t *)(notify + 1);
			dlen = get_payload_length(&notify->header) -
			    sizeof(struct ikev2payl_notify);
		}
		/* RFC 8784 s5.1: the initiator's PPK_ID has its first octet as the
		 * PPK_ID type (1=PPK_ID_OPAQUE, 2=PPK_ID_FIXED) with the remaining
		 * octets the configured value -- so a compliant peer (iOS,
		 * strongSwan) sends 1-octet type + ppk_id.  Accept BOTH that typed
		 * form and the bare-id form (what racoon2's own initiator sends;
		 * the iked<->iked matrix is self-consistent on the bare form and
		 * must keep passing).  Any other length/type mismatch rejects as
		 * before. */
		int ok = 0;
		if (my_id) {
			if (my_id->l == dlen && kt &&
			    memcmp(my_id->v, kt, dlen) == 0)
				ok = 1;	/* bare id (racoon2 initiator) */
			else if (dlen == my_id->l + 1 && kt &&
				 (kt[0] == 1 || kt[0] == 2) &&
				 memcmp(my_id->v, kt + 1, my_id->l) == 0)
				ok = 1;	/* RFC 8784 s5.1 typed (type + id) */
		}
		if (ok) {
			ike_sa->peer_ppk_identity_ok = 1;
			TRACE((PLOGLOC,
			       "RFC 8784: PPK_IDENTITY %s matches my ppk_id\n",
			       dlen == my_id->l ? "(bare)" : "(typed s5.1)"));
		} else {
			isakmp_log(ike_sa, 0, 0, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "RFC 8784: PPK_IDENTITY does not match my ppk_id\n");
			ike_sa->peer_ppk_identity_ok = 0;
		}
		break;
	}
	case IKEV2_NO_PPK_AUTH:
		/* RFC 8784 s2.3: the initiator signals that using the PPK is
		 * optional for it.  A responder that echoed N(USE_PPK) keeps
		 * using the PPK (RFC 8784 Table 1 row 7); the authentication-data
		 * swap this notification would enable for a non-PPK responder is
		 * unreachable here because we only echo USE_PPK when we hold the
		 * PPK.  Logged for parity with the peer. */
		TRACE((PLOGLOC,
		       "RFC 8784: peer advertises NO_PPK_AUTH (PPK optional)\n"));
		break;

	default:
		if (!ikev2_process_child_notify(notify, child_param)) {
			if (ikev2_process_notify(ike_sa, payload, TRUE)) {
				return -1;
			}
		}
		break;
	}

	return 0;
}

int
init_ike_sa_auth_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local,
			     struct ikev2_payload_header *payload,
			     struct ikev2_child_param *child_param,
			     int *acceptable)
{
	struct ikev2payl_notify *notify;
	struct ikev2_child_sa *child_sa;

	notify = (struct ikev2payl_notify *)payload;

	if (ikev2_process_child_notify(notify, child_param)) {
		return 0;
	}

	/* (draft-eronen-ipsec-ikev2-clarifications-05.tx)
	 * 4.2  Creating an IKE_SA without a CHILD_SA
	 *
	 * It is recommended that the responder set up an IKE_SA even if it is
	 * not possible to set up a CHILD_SA, as long as there is agreement on
	 * the cryptographic parts of the IKE_SA.  This might happen when the
	 * parties in the IKE_AUTH exchange agree on cryptographic protocols but
	 * fail to agree on IPsec issues.  The list of responses in the IKE_AUTH
	 * exchange that should not prevent an IKE_SA from being set up include
	 * NO_PROPOSAL_CHOSEN, SINGLE_PAIR_REQUIRED, INTERNAL_ADDRESS_FAILURE,
	 * FAILED_CP_REQUIRED, and TS_UNACCEPTABLE.
	 */
	switch (get_notify_type(notify)) {
	case IKEV2_SINGLE_PAIR_REQUIRED:
#ifdef notyet
		/*
		 * This error indicates that a CREATE_CHILD_SA request is
		 * unacceptable because its sender is only willing to accept
		 * traffic selectors specifying a single pair of addresses.
		 * The requestor is expected to respond by requesting an SA for
		 * only the specific traffic he is trying to forward.
		 */
		if (policy allows narrowing down) {
			obtain host addresses from pfkey request;
			reinitiate create_child exchange;
			*acceptable = TRUE;
			break;
		}
		/* FALLTHROUGH */
#endif
	case IKEV2_NO_PROPOSAL_CHOSEN:
	case IKEV2_INTERNAL_ADDRESS_FAILURE:
	case IKEV2_FAILED_CP_REQUIRED:
	case IKEV2_TS_UNACCEPTABLE:
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "received Notify type %s, failed establishing child_sa\n",
			   ikev2_notify_type_str(get_notify_type(notify)));
		/* the child_sa which initiated this exchange must have message_id 1 */
		child_sa = ikev2_find_request(ike_sa, 1);
		if (!child_sa) {
			/* somehow there were no child_sa */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "no child SA for received message\n");
			return -1;	/* do abort??? */
		}

		ikev2_child_abort(child_sa, ECONNREFUSED);	/* ??? */
		*acceptable = TRUE;
		break;

	case IKEV2_PPK_IDENTITY:
		/* RFC 8784 s2.3: responder echo of N(PPK_IDENTITY) (no data
		 * needed -- the content is ignored per RFC).  Confirms the
		 * responder honoured the USE_PPK agreement; the initiator's
		 * post-loop gate in initiator_ike_sa_auth_cont requires it when
		 * ppk_active. */
		ike_sa->peer_ppk_identity_ok = 1;
		TRACE((PLOGLOC,
		       "RFC 8784: responder confirmed PPK_IDENTITY\n"));
		break;

	case IKEV2_NO_ADDITIONAL_SAS:	/* ??? */
	default:
		if (ikev2_process_notify(ike_sa, payload, TRUE)) {
			ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
			return -1;
		}
		break;
	}

	return 0;
}

int
createchild_init_recv_notify(struct ikev2_sa *ike_sa,
			     struct ikev2_payload_header *payload,
			     struct ikev2_child_param *child_param,
			     struct ikev2_child_sa *child_sa)
{
	struct ikev2payl_notify *notify;

	notify = (struct ikev2payl_notify *)payload;

	TRACE((PLOGLOC, "received notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(notify))));

	if (ikev2_process_child_notify(notify, child_param)) {
		return 0;
	}

	switch (get_notify_type(notify)) {
#ifdef notyet
	case IKEV2_SINGLE_PAIR_REQUIRED:
		/*
		 * This error indicates that a CREATE_CHILD_SA request is
		 * unacceptable because its sender is only willing to accept
		 * traffic selectors specifying a single pair of addresses.
		 * The requestor is expected to respond by requesting an SA for
		 * only the specific traffic he is trying to forward.
		 */
		if (policy allows narrowing down) {
			obtain host addresses from pfkey request;
			reinitiate create_child exchange;
			goto done;
		} else
			goto abort;
		break;

	case IKEV2_NO_ADDITIONAL_SAS:	/* ??? */
		/* create new ike_sa and initiate? */
#endif

	case IKEV2_ADDITIONAL_KEY_EXCHANGE:
		/*
		 * RFC 9370 s2.2.4: when the CREATE_CHILD_SA response
		 * selected an ADDKE transform, the responder chose the
		 * link and returned it as N(16441).  Capture it now
		 * (the notify walk runs before ikev2_update_child) so
		 * the initiator's IKE_FOLLOWUP_KE echoes the
		 * responder-chosen link instead of minting a fresh
		 * random one that the responder cannot exact-match.
		 */
		if (child_sa && child_sa->addke_link == NULL) {
			struct ikev2payl_notify *nt =
			    (struct ikev2payl_notify *)payload;
			int dl;
			if (get_payload_length(payload) <
			    (int)(sizeof(struct ikev2payl_notify) +
				  nt->nh.spi_size))
				return -1;	/* truncated 16441 */
			dl = get_payload_length(payload) -
			     sizeof(struct ikev2payl_notify) -
			     nt->nh.spi_size;
			if (dl > 0 && dl <= 64) {
				child_sa->addke_link =
				    rc_vnew(get_notify_data(nt), (size_t)dl);
				if (!child_sa->addke_link)
					return -1;	/* ENOMEM */
			}
		}
		break;

	case IKEV2_INVALID_KE_PAYLOAD:
		/*
		 * We sent a KEi in some group, the responder rejects it.
		 * RFC 7296 §1.3: retry with the group the responder
		 * named (notify data = DH group code).  Gate on whether
		 * we actually sent KE, not the need_pfs configuration
		 * knob (default off would have made this a dead path).
		 */
		if (child_sa->dhgrp != 0 &&
		    child_sa->dhgrp->transform_id !=
		    get_uint16((uint16_t *)(notify + 1))) {
			child_sa->dhgrp =
				ikev2_dhinfo(get_uint16
					     ((uint16_t *)(notify + 1)));
			if (child_sa->dhgrp) {
				child_sa->message_id = 0;
				ikev2_child_state_set(child_sa,
						      IKEV2_CHILD_STATE_GETSPI_DONE);
				return -1;
			}
		}
		/* FALLTHROUGH */
		case IKEV2_NO_PROPOSAL_CHOSEN:
		case IKEV2_FAILED_CP_REQUIRED:
		case IKEV2_TS_UNACCEPTABLE:
		case IKEV2_TEMPORARY_FAILURE:
			/*
			 * RFC 7296 §2.25 (Exchange Collisions): a TEMPORARY_FAILURE
			 * reply means the responder received our CREATE_CHILD_SA but
			 * could not process it due to a temporary condition (e.g. a
			 * rekey it is busy with).  The recipient "MUST NOT immediately
			 * retry"; it "MAY retry the request one or more times over a
			 * period of several minutes".  For a rekey this exchange is the
			 * new child of an in-flight rekey, and ikev2_child_abort()
			 * below already encodes the right recovery: it finds the OLD
			 * child this new one rekeys, clears its stuck rekey_inprogress
			 * and re-arms the expire timer (30 s backoff), so a later pass
			 * rekeys it — the old SA survives the transient responder
			 * condition.  Aborting the in-flight NEW child (and telling the
			 * SPD its acquire errored) is exactly right: there is nothing
			 * installed for it yet.  We only need a distinct, diagnosable
			 * log line here, because the generic path below would misreport
			 * it as an "unrecognized error type".
			 */
			isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOWARN, PLOGLOC,
				   "RFC 7296 §2.25: peer answered TEMPORARY_FAILURE; "
				   "will retry the rekey later (backoff re-armed)\n");
		default:
			if (ikev2_process_notify(ike_sa, payload, TRUE)) {
				if (child_sa) {
					/* ??? */
					ikev2_child_abort(child_sa, ECONNREFUSED);
				}
				return -1;
			}
			break;
	}

	return 0;
}

int
createchild_resp_recv_notify(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local,
			     struct ikev2_payload_header *payload,
			     struct ikev2_child_param *child_param,
			     int *rekey_proto, uint32_t *rekey_spi)
{
	struct ikev2payl_notify *notify;

	notify = (struct ikev2payl_notify *)payload;

	TRACE((PLOGLOC, "received notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(notify))));

	switch (get_notify_type(notify)) {
	case IKEV2_NAT_DETECTION_SOURCE_IP:
	case IKEV2_NAT_DETECTION_DESTINATION_IP:
		/* iOS rides its ~10-min NAT recheck on the rekey
		 * request (and on plain INF2s).  RFC 4555 §3.8: the
		 * initiator compares the digests it RECEIVES in each
		 * reply with the value from the previous response
		 * (INIT or last UPDATE_SA_ADDRESSES) — a STABILITY
		 * check on what the responder reports.  We replay the
		 * INIT-pinned digests in every reply (see
		 * ikev2_push_natd_report), re-pinning only on
		 * UPDATE_SA_ADDRESSES.  Here we only remember what the
		 * peer itself computed, to warn if its own view of the
		 * binding changes between probes (same SPIs, different
		 * digest = unannounced binding remap, which our INIT
		 * pin would otherwise hide).  (RFC 7296 2.23.) */
		{
			uint8_t *dn;
			int dl = ntohs(
			    ((struct ikev2_payload_header *)notify)->
			    payload_length) - sizeof(struct ikev2payl_notify);
			if (dl >= 20) {
				dn = get_notify_data(notify);
				if (get_notify_type(notify) ==
				    IKEV2_NAT_DETECTION_SOURCE_IP) {
					if (ike_sa->natd_peer_seen &&
					    memcmp(ike_sa->natd_peer_prev_src,
						   dn, 20) != 0)
						plog(PLOG_INTERR, PLOGLOC,
						     NULL,
						     "peer NAT binding changed: "
						     "SRC digest differs from "
						     "previous probe\n");
					memcpy(ike_sa->natd_peer_prev_src,
					       dn, 20);
					memcpy(ike_sa->natd_dst_hash, dn, 20);
				} else {
					if (ike_sa->natd_peer_seen &&
					    memcmp(ike_sa->natd_peer_prev_dst,
						   dn, 20) != 0)
						plog(PLOG_INTERR, PLOGLOC,
						     NULL,
						     "peer NAT binding changed: "
						     "DST digest differs from "
						     "previous probe\n");
					memcpy(ike_sa->natd_peer_prev_dst,
					       dn, 20);
					memcpy(ike_sa->natd_src_hash, dn, 20);
					ike_sa->natd_report = 1;
					ike_sa->natd_peer_seen = 1;
				}
			}
		}
		if (natt_process_natd(ike_sa, notify, TRUE) == 0 &&
		    ike_sa->natd_report == 0)
			ike_sa->natd_report = 1;
		break;

	case IKEV2_REKEY_SA:
		TRACE((PLOGLOC, "received Notify REKEY_SA\n"));

		if (*rekey_proto != 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "unnecessary duplicated payload (type %d)\n",
				   IKEV2_PAYLOAD_NOTIFY);
			++isakmpstat.duplicate_payload;

			(void)ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0, IKEV2_INVALID_SYNTAX,
						  0, 0);
			return -1;
		}

		switch (notify->nh.protocol_id) {
		case IKEV2_NOTIFY_PROTO_AH:
		case IKEV2_NOTIFY_PROTO_ESP:
			if (notify->nh.spi_size != sizeof(uint32_t)) {
				TRACE((PLOGLOC,
				       "unexpected spi_size %d\n",
				       notify->nh.spi_size));

				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "malformed payload\n");
				++isakmpstat.malformed_payload;

				(void)ikev2_respond_error(ike_sa, msg, remote,
							  local, 0, 0, 0,
							  IKEV2_INVALID_SYNTAX,
							  0, 0);
				return -1;
			}

			*rekey_proto = notify->nh.protocol_id;
			*rekey_spi = get_uint32(notify + 1);

			TRACE((PLOGLOC,
			       "rekey_proto %d rekey_spi 0x%x\n",
			       *rekey_proto, *rekey_spi));
			break;

		default:
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "unsupported rekey_proto %d\n",
				   notify->nh.protocol_id);

			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC, "malformed payload\n");
			++isakmpstat.malformed_payload;

			(void)ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0, IKEV2_INVALID_SYNTAX,
						  0, 0);
			return -1;
		}
		break;

	default:
		if (!ikev2_process_child_notify(notify, child_param)) {
			if (ikev2_process_notify(ike_sa, payload, TRUE)) {
				/*
				 * no child_sa created yet,
				 * thus no SA to abort
				 */
				(void)ikev2_respond_null(ike_sa, msg, remote,
							 local);
				return -1;
			}
		}
		break;
	}

	return 0;
}

/*
 * RFC 7427 s3.2: remember the hash-algorithm set a peer offered in its
 * SIG_HASH_ALGORITHMS (16431) notification.  The data is a list of 2-byte
 * big-endian hash IDs (1=SHA1, 2=SHA2-256, 3=SHA2-384, 4=SHA2-512,
 * 5=Identity/EdDSA).  Our method-14 signer (DS) later picks the strongest
 * hash this side also supports from the resulting mask.  A malformed or
 * empty list leaves the mask 0 (the historical hardcoded SHA-256 is used).
 */
void
ikev2_remember_sig_hashes(struct ikev2_sa *ike_sa, struct ikev2payl_notify *notify)
{
	const uint8_t *d;
	size_t dlen;
	int mask = 0;

	if (!ike_sa || !notify)
		return;

	if (get_payload_length(&notify->header) <=
	    sizeof(struct ikev2payl_notify)) {
		ike_sa->peer_sig_hash_mask = 0;
		return;
	}
	d = (const uint8_t *)(notify + 1);
	dlen = get_payload_length(&notify->header) -
	    sizeof(struct ikev2payl_notify);

	while (dlen >= 2) {
		unsigned int id = (d[0] << 8) | d[1];
		if (id >= 1 && id <= 5 && id < (unsigned int)(sizeof(int) * 8))
			mask |= (1 << id);
		d += 2;
		dlen -= 2;
	}
	ike_sa->peer_sig_hash_mask = mask;
	TRACE((PLOGLOC, "RFC7427: peer sig-hash mask 0x%x\n", mask));
}

/*
 * processes a notify payload
 *
 * is_safe: non-0 if the message is authenticated
 *
 * returns 0 if the caller should continue processing payloads
 *         1 if it is recognized error type
 *         2 if unrecognized error type
 */
int
ikev2_process_notify(struct ikev2_sa *ike_sa,
		     struct ikev2_payload_header *p, int is_safe)
{
	struct ikev2payl_notify *n = (struct ikev2payl_notify *)p;
	unsigned int protocol_id = n->nh.protocol_id;
	unsigned int type = get_notify_type(n);

	/* (proto, SPI, type)
	 * proto == NONE:       no SPI
	 * proto == IKE_SA:     no SPI
	 * proto == CHILD:      child spi
	 *
	 * type ERROR:
	 * in response: MUST assume request has failed entirely
	 * in request: unrecognized error MUST be ignored, SHOULD be logged
	 * type STATUS:
	 * unrecognized MUST be ignored, SHOULD be logged
	 */

	/* (draft-17)
	 * Types in the range 0 - 16383 are intended for reporting errors.  An
	 * implementation receiving a Notify payload with one of these types
	 * that it does not recognize in a response MUST assume that the
	 * corresponding request has failed entirely. Unrecognized error types
	 * in a request and status types in a request or response MUST be
	 * ignored except that they SHOULD be logged.
	 */
	isakmp_log(ike_sa, 0, 0, 0,
		   (type <=
		    IKEV2_NOTIFYTYPE_ERROR_MAX ? PLOG_PROTOERR : PLOG_INFO),
		   PLOGLOC, "received Notify payload protocol %d type %s\n",
		   protocol_id, ikev2_notify_type_str(type));

#ifdef notyet
	/* (draft-17)
	 * Protocol ID
	 * For notifications which do not relate to an existing SA, this
	 * field MUST be sent as zero and MUST be ignored on receipt.
	 */

	/* (draft-ietf-ipsec-ikev2-17.txt)
	 * If a cryptographically protected message has been received
	 * from the other side recently, unprotected notifications MAY be
	 * ignored. Implementations MUST limit the rate at which they take
	 * actions based on unprotected messages.
	 */
#endif
	switch (type) {
	case IKEV2_INITIAL_CONTACT:
		/* RFC 7296 3.10.1: peer rebooted; flush its other SAs.
		 * Only trust an authenticated INITIAL_CONTACT (IKE_AUTH).
		 * ikev2_initial_contact() skips the SA this notify came on. */
		if (is_safe)
			ikev2_initial_contact(ike_sa);
		return 0;

	case IKEV2_MOBIKE_SUPPORTED:
		ike_sa->mobike_supported = 1;
		TRACE((PLOGLOC, "peer supports MOBIKE\n"));
		return 0;

	case IKEV2_UPDATE_SA_ADDRESSES:
		if (!is_safe)
			return 0;
		ike_sa->mobike_update = 1;
		TRACE((PLOGLOC, "UPDATE_SA_ADDRESSES\n"));
		return 0;

	case IKEV2_COOKIE2: {
		size_t tot, hdr, dlen;
		uint8_t *data;

		if (!is_safe)
			return 0;
		tot = get_payload_length(&n->header);
		hdr = sizeof(*n) + n->nh.spi_size;
		if (tot < hdr)
			return 0;
		dlen = tot - hdr;
		if (dlen < 8 || dlen > 64)
			return 0;
		data = get_notify_data(n);
		if (ike_sa->cookie2_sent) {
			if (ike_sa->cookie2_sent->l == dlen &&
			    CRYPTO_memcmp(ike_sa->cookie2_sent->v, data, dlen) == 0) {
				ike_sa->cookie2_matched = 1;
				return 0;
			}
			isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
				   "COOKIE2 mismatch\n");
			return 1;
		}
		if (ike_sa->cookie2_echo)
			rc_vfree(ike_sa->cookie2_echo);
		ike_sa->cookie2_echo = rc_vnew(data, dlen);
		return 0;
	}

	case IKEV2_ADDITIONAL_IP4_ADDRESS: {
		size_t tot, hdr, dlen;
		uint8_t *data;

		if (!is_safe)
			return 0;
		tot = get_payload_length(&n->header);
		hdr = sizeof(*n) + n->nh.spi_size;
		if (tot < hdr)
			return 0;
		dlen = tot - hdr;
		data = get_notify_data(n);
		if (dlen != 4)
			return 0;
		if (ike_sa->n_extra_addr4 < IKEV2_MAX_EXTRA_ADDR) {
			memcpy(ike_sa->extra_addr4[ike_sa->n_extra_addr4],
			       data, 4);
			ike_sa->n_extra_addr4++;
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
				   "stored additional IPv4 %u.%u.%u.%u\n",
				   data[0], data[1], data[2], data[3]);
		}
		return 0;
	}

	case IKEV2_ADDITIONAL_IP6_ADDRESS: {
		size_t tot, hdr, dlen;
		uint8_t *data;

		if (!is_safe)
			return 0;
		tot = get_payload_length(&n->header);
		hdr = sizeof(*n) + n->nh.spi_size;
		if (tot < hdr)
			return 0;
		dlen = tot - hdr;
		data = get_notify_data(n);
		if (dlen != 16)
			return 0;
		if (ike_sa->n_extra_addr6 < IKEV2_MAX_EXTRA_ADDR) {
			memcpy(ike_sa->extra_addr6[ike_sa->n_extra_addr6],
			       data, 16);
			ike_sa->n_extra_addr6++;
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
				   "stored additional IPv6\n");
		}
		return 0;
	}

	case IKEV2_NO_ADDITIONAL_ADDRESSES:
		if (!is_safe)
			return 0;
		ike_sa->n_extra_addr4 = 0;
		ike_sa->n_extra_addr6 = 0;
		return 0;

	case IKEV2_QCD_TOKEN: {
		size_t tot, hdr, dlen;
		uint8_t *data;

		tot = get_payload_length(&n->header);
		hdr = sizeof(*n) + n->nh.spi_size;
		if (tot < hdr)
			return 0;
		dlen = tot - hdr;
		data = get_notify_data(n);
		/* RFC 6290 5: 16..128 octets; 4.1: SPI Size MUST be zero */
		if (n->nh.spi_size != 0 ||
		    dlen < IKEV2_QCD_TOKEN_MIN || dlen > IKEV2_QCD_TOKEN_MAX)
			return 0;
		if (!is_safe) {
			if (ike_sa->qcd_token_peer &&
			    ike_sa->qcd_token_peer->l == dlen &&
			    CRYPTO_memcmp(ike_sa->qcd_token_peer->v, data, dlen) == 0) {
				isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
					   "QCD_TOKEN match, deleting IKE_SA\n");
				return 1;
			}
			return 0;
		}
		if (ike_sa->qcd_token_peer)
			rc_vfree(ike_sa->qcd_token_peer);
		ike_sa->qcd_token_peer = rc_vnew(data, dlen);
		return 0;
		}

	case IKEV2_TICKET_LT_OPAQUE: {
		/* RFC 5723 s7.1 / s4.2: the responder answers our N(TICKET_REQUEST)
		 * with N(TICKET_LT_OPAQUE) whose DATA is the 4-octet big-endian
		 * lifetime + opaque ticket.  As an INITIATOR we capture the ticket
		 * verbatim (it is opaque to us) so a later reconnect can present it
		 * via exchange 38; the from-ticket SA state needed to build that
		 * resumed exchange (SK_d, SAr, IDs) is taken from our own live SA and
		 * persisted at SA-disposal time.  A responder never issues itself a
		 * ticket, so only the initiator records it. */
		size_t tot, hdr, dlen;
		uint8_t *data;

		if (!is_safe || !ike_sa->is_initiator)
			return 0;
		tot = get_payload_length(&n->header);
		hdr = sizeof(*n) + n->nh.spi_size;
		if (tot < hdr || n->nh.spi_size != 0)
			return 0;
		dlen = tot - hdr;
		/* at least the 4-octet lifetime plus the ticket
		 * header (version+key_id+iv)=24 + GCM tag(16) */
		if (dlen < 4 + 24 + 16)
			return 0;
		data = get_notify_data(n);
		if (ike_sa->resume_ticket)
			rc_vfree(ike_sa->resume_ticket);
		ike_sa->resume_ticket = rc_vnew(data, dlen);
		if (!ike_sa->resume_ticket)
			return 1;
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
			   "RFC 5723: captured session-resumption ticket from peer "
			   "(%zu bytes)\n", dlen);
		return 0;
	}

	default:
		if (type <= IKEV2_NOTIFYTYPE_ERROR_MAX)
			return 2;	/* unrecognized error type */
		return 0;	/* status */
	}

	return 1;		/* error */
}

/*
 * processes Notify payload with CHILD_SA-negotiation notify type
 *
 * returns TRUE if it is CHILD_SA-negotiation type, FALSE otherwise
 */
int
ikev2_process_child_notify(struct ikev2payl_notify *n,
			   struct ikev2_child_param *param)
{
	/* int proto = n->nh.protocol_id; */

	/* (draft-17)
	 * Protocol ID
	 * For notifications which do not relate to an existing SA, this
	 * field MUST be sent as zero and MUST be ignored on receipt.
	 */

#ifdef notyet
	/* should process SPI */
#endif

	TRACE((PLOGLOC, "ikev2_process_child_notify(%p, %p)\n", n, param));
	TRACE((PLOGLOC, "notify type %s\n",
	       ikev2_notify_type_str(get_notify_type(n))));

	switch (get_notify_type(n)) {
	case IKEV2_IPCOMP_SUPPORTED:
		TRACE((PLOGLOC, "IPCOMP_SUPPORTED\n"));
		break;

	case IKEV2_ADDITIONAL_TS_POSSIBLE:
		param->additional_ts_possible = TRUE;
		break;

	case IKEV2_USE_TRANSPORT_MODE:
		param->use_transport_mode = TRUE;
		break;

	case IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED:
		param->esp_tfc_padding_not_supported = TRUE;
		break;

	default:
		TRACE((PLOGLOC, "not a child notify type\n"));
		return FALSE;
		break;
	}

	return TRUE;
}

/*
 * send IKE_SA_INIT response with Notify payload
 */
void
ikev2_respond_with_notify(rc_vchar_t *request, struct sockaddr *remote,
			  struct sockaddr *local, int msg_type, uint8_t *nmsg,
			  int nmsg_len)
{
	ikev2_respond_with_notify_exch(request, remote, local,
				       IKEV2EXCH_IKE_SA_INIT, msg_type, nmsg,
				       nmsg_len);
}

/*
 * send an unprotected, SA-less response with a single Notify payload in
 * the given exchange: IKE_SA_INIT (COOKIE, INVALID_KE_PAYLOAD, ...) or
 * IKE_SESSION_RESUME (RFC 5723 s4.3.2 TICKET_NACK, which is the response
 * to the exchange-38 request and so MUST carry exchange type 38).
 */
void
ikev2_respond_with_notify_exch(rc_vchar_t *request, struct sockaddr *remote,
			       struct sockaddr *local, int exch_type,
			       int msg_type, uint8_t *nmsg, int nmsg_len)
{
	struct ikev2_header *reqhdr;
	rc_vchar_t *reply = 0;
	struct ikev2_header *replyhdr;
	int notify_len;
	int reply_len;
	struct ikev2payl_notify *notify;

	/* can't use ikev2_packet_construct() when there's no ike_sa yet */

	notify_len = sizeof(struct ikev2payl_notify) + nmsg_len;
	reply_len = sizeof(struct ikev2_header) + notify_len;
	reply = rc_vmalloc(reply_len);
	if (!reply)
		goto fail;

	reqhdr = (struct ikev2_header *)request->v;
	replyhdr = (struct ikev2_header *)reply->v;
	memcpy(&replyhdr->initiator_spi, &reqhdr->initiator_spi,
	       sizeof(isakmp_cookie_t));
	memset(&replyhdr->responder_spi, 0, sizeof(isakmp_cookie_t));
	replyhdr->next_payload = IKEV2_PAYLOAD_NOTIFY;
	replyhdr->version = IKEV2_VERSION;
	replyhdr->exchange_type = exch_type;
	replyhdr->flags = IKEV2FLAG_RESPONSE;
	replyhdr->message_id = 0;
	replyhdr->length = htonl(reply_len);

	notify = (struct ikev2payl_notify *)(replyhdr + 1);
	set_payload_header(&notify->header, IKEV2_NO_NEXT_PAYLOAD, notify_len);

	/* (draft-eronen-ipsec-ikev2-clarifications-05)
	 * Protocol ID field should be non-zero only when the SPI field is non-empty.
	 */
	notify->nh.protocol_id = 0;
	notify->nh.spi_size = 0;
	put_uint16(&notify->nh.notify_message_type, msg_type);
	memcpy(notify + 1, nmsg, nmsg_len);

#ifdef HAVE_PRINT_ISAKMP_C
	isakmp_printpacket(reply, local, remote, 1);
#endif

	isakmp_sendto(reply, remote, local);

      end:
	if (reply)
		rc_vfree(reply);
	return;

      fail:
	plog(PLOG_INTERR, PLOGLOC, 0, "failed to construct packet\n");
	goto end;
}

/* RFC 5685 s3/s9.2: answer an IKE_SA_INIT whose initiator offered
 * N(REDIRECT_SUPPORTED, 16406) with N(REDIRECT, <new gateway>, echoed Ni)
 * and NO SA (SPI_R=0, message_id=0) so the client re-initiates against
 * the listed gateway.  gw is the raw config string from redirect_to — its
 * gateway-identity type (RFC 5685 s9.2) is derived here: a dotted-quad
 * IPv4 (type 1), a colon IPv6 (type 2), else an FQDN (type 3).  ni is the
 * byte-for-byte Nonce Data from the initiator's Ni payload, which the
 * client MUST match to accept the redirect (RFC 5685 s3).  The NOTIFY
 * data is: GW Ident Type (1) | GW Ident Len (1) | New Gateway Identity
 * [(1+1)+id] | Nonce Data.  GW Ident Len is a single octet (RFC 5685
 * s9.2; the diagram's '| GW Ident Type | GW Ident Len |' is one octet
 * each). */

/* build_redirect_notify: construct the redirect Notify DATA bytes
 * (rc_vchar_t, not including the notify header).  Exposed for the unit
 * harness; ikev2_respond_redirect sends it.  Returns NULL on alloc
 * failure. */
rc_vchar_t *
ikev2_build_redirect_notify_data(rc_vchar_t *gw, rc_vchar_t *ni)
{
	uint8_t idtype;
	uint8_t idbuf[16];
	char *gwc = 0;		/* NUL-terminated copy for inet_pton */
	size_t idlen = 0;
	rc_vchar_t *data;

	/* inet_pton() needs a NUL-terminated C string, but the config path
	 * (rcf_fix_string -> rc_str2vmem) holds the gateway identity without
	 * a trailing NUL (exactly gw->l bytes).  Copy + terminate so the
	 * IPv4/IPv6/FQDN classification never strlen()s past the buffer.
	 * The identity is re-read from gw->v afterward, so the copy is only
	 * for classification. */
	if (gw->l == 0 || gw->l > 4096)
		return NULL;
	gwc = racoon_malloc(gw->l + 1);
	if (!gwc)
		return NULL;
	memcpy(gwc, gw->v, gw->l);
	gwc[gw->l] = '\0';

	if (inet_pton(AF_INET, gwc, idbuf) == 1) {
		idtype = 1;	/* IPv4 */
		idlen = 4;
	} else if (inet_pton(AF_INET6, gwc, idbuf) == 1) {
		idtype = 2;	/* IPv6 */
		idlen = 16;
	} else {
		idtype = 3;	/* FQDN */
		idlen = gw->l;
		/* GW Ident Len is a single octet (max 255); a longer FQDN
		 * could not be encoded without truncating the wire length,
		 * so refuse it rather than emit a Len that disagrees with
		 * the identity we copy. */
		if (idlen > 255) {
			racoon_free(gwc);
			return NULL;
		}
	}
	racoon_free(gwc);

	/* RFC 5685 s9.2: GW Ident Type (1 octet) | GW Ident Len (1 octet)
	 * | New Responder Gateway Identity | Nonce Data.  Len is ONE octet
	 * (strongSwan's redirect_data_create writes it with write_data8). */
	data = rc_vmalloc(2 + idlen + ni->l);
	if (!data)
		return NULL;
	data->u[0] = idtype;
	data->u[1] = (uint8_t)idlen;
	if (idtype == 3)
		memcpy(data->u + 2, gw->v, idlen);
	else
		memcpy(data->u + 2, idbuf, idlen);
	memcpy(data->u + 2 + idlen, ni->v, ni->l);
	return data;
}

void
ikev2_respond_redirect(rc_vchar_t *request, struct sockaddr *remote,
		       struct sockaddr *local, rc_vchar_t *gw, rc_vchar_t *ni)
{
	rc_vchar_t *data;

	data = ikev2_build_redirect_notify_data(gw, ni);
	if (!data)
		return;
	TRACE((PLOGLOC, "RFC5685: responding REDIRECT to gw %.*s\n",
	       (int)gw->l, (char *)gw->v));
	ikev2_respond_with_notify(request, remote, local,
				  IKEV2_REDIRECT, data->u, data->l);
	rc_vfree(data);
}

/*
 * RFC 5685 redirect pool resolver core (pure): pick the member of a
 * comma-separated pool to redirect `remote` to.  Pools by a stable
 * per-peer hash (FNV-1a over the peer address bytes mod member count) so
 * a given client re-initiates to the SAME member every time — the member
 * that holds its resume ticket / crash-restart dump — while spreading
 * different clients across the pool (load balancing).  A single entry
 * (no comma) resolves to itself.  Returns a caller-freed rc_vchar_t of
 * the chosen identity, or NULL for an empty pool.  Exposed for the unit
 * harness. */
rc_vchar_t *
ikev2_redirect_pool_select(rc_vchar_t *pool, struct sockaddr *remote)
{
	const uint8_t *p;
	size_t len;
	size_t i;
	uint64_t h = UINT64_C(1469598103934665603);	/* FNV-1a 64 */
	size_t n = 0;
	size_t start;
	size_t sel;

	if (!pool || pool->l == 0)
		return NULL;
	for (i = 0; i < pool->l; i++)
		if (pool->u[i] == ',')
			n++;
	n++;
	if (n == 1) {
		/* single entry: return it, trimmed (a lone " 10.0.0.7 "
		 * would otherwise reach inet_pton with the spaces and be
		 * misclassified as an FQDN) */
		size_t cs = 0, ce = pool->l;
		while (cs < ce && (pool->u[cs] == ' ' || pool->u[cs] == '	'))
			cs++;
		while (ce > cs && (pool->u[ce-1] == ' ' ||
				    pool->u[ce-1] == '	'))
			ce--;
		if (ce == cs)
			return NULL;
		return rc_vnew(pool->u + cs, ce - cs);
	}
	if (!remote)
		return NULL;

	/* FNV-1a over the peer's IP ADDRESS bytes only (family + addr),
	 * NOT the port, NOT sin_zero/flowinfo/scope padding: a client
	 * re-initiating from a changed ephemeral port, or with different
	 * uninitialized padding, must still land on the SAME pool member
	 * — the one holding its resume ticket / crash-restart dump. */
	h ^= (uint8_t)remote->sa_family;
	h *= UINT64_C(1099511628211);
	if (remote->sa_family == AF_INET) {
		const struct in_addr *a =
		    &((struct sockaddr_in *)remote)->sin_addr;
		p = (const uint8_t *)a;
		len = sizeof(*a);
	} else if (remote->sa_family == AF_INET6) {
		const struct in6_addr *a =
		    &((struct sockaddr_in6 *)remote)->sin6_addr;
		p = (const uint8_t *)a;
		len = sizeof(*a);
	} else {
		p = NULL;
		len = 0;
	}
	for (i = 0; i < len; i++) {
		h ^= p[i];
		h *= UINT64_C(1099511628211);
	}
	sel = (size_t)(h % n);

	/* return the sel-th member (trimmed).  A NUL byte is treated as
	 * end-of-member too: rc_vnew from a config string copies the
	 * terminating NUL into the pool buffer, so a trailing "sp NUL"
	 * (where NUL is not whitespace) must still trim to the member. */
	for (i = 0, start = 0; i <= sel; i++) {
		size_t end = start;
		size_t cs, ce;
		while (end < pool->l && pool->u[end] != ',' &&
		       pool->u[end] != '\0')
			end++;
		if (i != sel) {
			start = end + 1;
			continue;
		}
		cs = start;
		while (cs < end && (pool->u[cs] == ' ' ||
				     pool->u[cs] == '	'))
			cs++;
		ce = end;
		while (ce > cs && (pool->u[ce-1] == ' ' ||
				   pool->u[ce-1] == '	'))
			ce--;
		if (ce == cs)
			return NULL;
		return rc_vnew(pool->u + cs, ce - cs);
	}
	return NULL;
}

/*
 * RFC 5685 redirect pool resolver (config view).  redirect_to config
 * holds a single gateway identity OR a comma-separated pool
 * ("10.0.0.7,10.0.0.8"); ikev2_redirect_pool_select() picks the member.
 * Returns a caller-freed rc_vchar_t of the chosen identity, or NULL if
 * redirect_to is unset/empty. */
rc_vchar_t *
ikev2_redirect_resolve(struct rcf_remote *conf, struct sockaddr *remote)
{
	return ikev2_redirect_pool_select(ikev2_redirect_to(conf), remote);
}

/*
 * RFC 5685 s9.2 parse: given the Notify DATA bytes of an N(REDIRECT)
 * (excluding the notify header, protocol/spi, and the 2-octet type),
 * extract the GW Ident Type (1 octet: 1=IPv4, 2=IPv6, 3=FQDN), GW
 * Ident Len (1 octet), Gateway Identity, and the echoed Nonce Data.
 * On success (*gwt != 0) *gw holds the identity bytes and *ni holds
 * the echoed nonce; the caller must rc_vfree() both.  Returns 0 on
 * success, -1 on a malformed/truncated/bounds-violating payload, or a
 * 0-octet identity / type that does not match the RFC 5685 cardinality
 * (IPv4 must be exactly 4 octets, IPv6 exactly 16).  Exposed for the
 * unit harness. */
int
ikev2_parse_redirect_notify_data(rc_vchar_t *data, uint8_t *gwt,
				 rc_vchar_t **gw, rc_vchar_t **ni)
{
	const uint8_t *p;
	size_t len;
	uint8_t type, idlen;

	*gwt = 0;
	*gw = 0;
	*ni = 0;
	if (!data || data->l < 2)
		return -1;
	p = data->u;
	len = data->l;
	type = p[0];
	idlen = p[1];
	/* RFC 5685 s9.2: at least Type + Len
	 *  + (4|16|>=1) identity + the echoed Ni. */
	if (idlen == 0 || len < (size_t)2 + idlen)
		return -1;
	switch (type) {
	case 1:
		if (idlen != 4)
			return -1;
		break;
	case 2:
		if (idlen != 16)
			return -1;
		break;
	case 3:
		break;	/* FQDN: any non-zero length */
	default:
		return -1;
	}
	*gw = rc_vnew(p + 2, idlen);
	if (!*gw)
		return -1;
	*ni = rc_vnew(p + 2 + idlen, len - 2 - idlen);
	if (!*ni) {
		rc_vfree(*gw);
		*gw = 0;
		return -1;
	}
	*gwt = type;
	return 0;
}

/*
 * RFC 5685 s9.3 build: given the recorded GW Ident Type + identity bytes
 * from a received N(REDIRECT) (or a configured redirect_from target),
 * emit the REDIRECTED_FROM (16408) Notify DATA: GW Ident Type (1) |
 * GW Ident Len (1) | Original Responder GW Identity.  Identical framing
 * to s9.2 except it carries the ORIGINAL (redirecting) gateway and NO
 * Nonce Data (the initiator sends it in the IKE_SA_INIT it re-sends to
 * the new gateway, so the new gateway knows it was redirected here).
 * type 1=IPv4 (4 octets), 2=IPv6 (16), 3=FQDN; 3 is only for
 * completeness — a redirect_to follow targets IPv4/IPv6 literals.
 * Returns NULL on malformed/Len>255 input. */
rc_vchar_t *
ikev2_build_redirected_from_data(uint8_t type, rc_vchar_t *ident)
{
	rc_vchar_t *data;

	if (!ident || ident->l == 0)
		return NULL;
	switch (type) {
	case 1:
		if (ident->l != 4)
			return NULL;
		break;
	case 2:
		if (ident->l != 16)
			return NULL;
		break;
	case 3:
		if (ident->l > 255)
			return NULL;
		break;
	default:
		return NULL;
	}
	data = rc_vmalloc(2 + ident->l);
	if (!data)
		return NULL;
	data->u[0] = type;
	data->u[1] = (uint8_t)ident->l;
	memcpy(data->u + 2, ident->u, ident->l);
	return data;
}

/*
 * RFC 5685 redirect follow: turn a recorded redirect target (GW Ident
 * Type + identity bytes from the responder's N(REDIRECT)) into a noun
 * struct sockaddr suitable as ike_sa->remote for re-initiation.  Only
 * IPv4 (type 1) and IPv6 (type 2) literal targets are resolvable here;
 * an FQDN (type 3) has no resolver hook at this layer and returns NULL.
 * Caller frees the result with racoon_free(). */
struct sockaddr *
ikev2_redirect_gw_sadup(uint8_t type, rc_vchar_t *ident)
{
	struct sockaddr_storage ss;

	if (!ident)
		return NULL;
	memset(&ss, 0, sizeof(ss));
	switch (type) {
	case 1:
		if (ident->l != 4)
			return NULL;
		ss.ss_family = AF_INET;
		memcpy(&((struct sockaddr_in *)&ss)->sin_addr,
		       ident->u, sizeof(struct in_addr));
		((struct sockaddr_in *)&ss)->sin_port = htons(isakmp_port_dest);
		break;
	case 2:
		if (ident->l != 16)
			return NULL;
		ss.ss_family = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)&ss)->sin6_addr,
		       ident->u, sizeof(struct in6_addr));
		((struct sockaddr_in6 *)&ss)->sin6_port =
		    htons(isakmp_port_dest);
		break;
	default:
		return NULL;
	}
	return rcs_sadup((struct sockaddr *)&ss);
}

/* returns string representation of Notify type
 */
const char *
ikev2_notify_type_str(int type)
{
#define S(x_)   case IKEV2_ ## x_ : return # x_ ;

	switch (type) {
		S(UNSUPPORTED_CRITICAL_PAYLOAD);
		S(INVALID_IKE_SPI);
		S(INVALID_MAJOR_VERSION);
		S(INVALID_SYNTAX);
		S(INVALID_MESSAGE_ID);
		S(INVALID_SPI);
		S(NO_PROPOSAL_CHOSEN);
		S(INVALID_KE_PAYLOAD);
		S(AUTHENTICATION_FAILED);
		S(SINGLE_PAIR_REQUIRED);
		S(NO_ADDITIONAL_SAS);
		S(INTERNAL_ADDRESS_FAILURE);
		S(FAILED_CP_REQUIRED);
		S(TS_UNACCEPTABLE);
		S(INVALID_SELECTORS);
		S(TEMPORARY_FAILURE);
		S(CHILD_SA_NOT_FOUND);
		S(INITIAL_CONTACT);
		S(SET_WINDOW_SIZE);
		S(ADDITIONAL_TS_POSSIBLE);
		S(IPCOMP_SUPPORTED);
		S(NAT_DETECTION_SOURCE_IP);
		S(NAT_DETECTION_DESTINATION_IP);
		S(COOKIE);
		S(USE_TRANSPORT_MODE);
		S(EAP_ONLY_AUTHENTICATION);
		S(HTTP_CERT_LOOKUP_SUPPORTED);
		S(REKEY_SA);
		S(ESP_TFC_PADDING_NOT_SUPPORTED);
		S(NON_FIRST_FRAGMENTS_ALSO);
		S(FRAGMENTATION_SUPPORTED);
		S(MOBIKE_SUPPORTED);
		S(ADDITIONAL_IP4_ADDRESS);
		S(ADDITIONAL_IP6_ADDRESS);
		S(NO_ADDITIONAL_ADDRESSES);
		S(UPDATE_SA_ADDRESSES);
		S(COOKIE2);
		S(NO_NATS_ALLOWED);
		S(AUTH_LIFETIME);
		S(QCD_TOKEN);
		S(USE_PPK);
		S(PPK_IDENTITY);
		S(NO_PPK_AUTH);
		S(CHILDLESS_IKEV2_SUPPORTED);
		S(IP4_ALLOWED);
		S(IP6_ALLOWED);
		S(REDIRECT_SUPPORTED);
		S(REDIRECT);
		S(REDIRECT_FROM);

	default:
		{
			rc_vchar_t *buf;

			buf = rbuf_getsb();
			if (!buf)
				return "unknown";

			snprintf(buf->v, buf->l, "%d", type);
			return buf->v;
		}
	}
#undef S
}

/* RFC 8983 s4 helpers.  IP4_ALLOWED / IP6_ALLOWED are empty status notifies
 * that tell a dual-stack initiator which address family the responder
 * SUPPORTS (Table 1), read from the configured addresspool
 * (ikev2_addresspool(rmconf) -> pool_list item afs).
 *
 * ikev2_build_ip_allowed(): emit the pool's supported-family notifies into
 *   an existing payload list, regardless of whether a CFG_REPLY was pushed.
 *   Used on the "assigned none" / family-mismatch failure path, where
 *   ikev2_process_config_request returns INTERNAL_ADDRESS_FAILURE: per RFC
 *   8983 s5.5 the responder still tells a dual-stack initiator which family
 *   IS supported so it can retry the other AF (the rows "requested v4 /
 *   supported v6 / assigned none -> IP6_ALLOWED").  No-op when no named
 *   pool is configured.
 *
 * ikev2_push_ip_allowed(): CFG_REPLY variant used by the childful IKE_AUTH
 *   responder and CREATE_CHILD_SA responder.  Prefers the pool-supported
 *   set; falls back to the assigned-lease AFs when no named pool resolves.
 *   No-op when the reply carries no config payload. */

static void
drop_ip_allowed(struct ikev2_payloads *payl, int has4, int has6)
{
	if (has4)
		ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_IP4_ALLOWED,
							 0, 0), TRUE);
	if (has6)
		ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_IP6_ALLOWED,
							 0, 0), TRUE);
	TRACE((PLOGLOC, "RFC8983: responder emits IP%s_ALLOWED%s%s\n",
	       has4 ? "4" : (has6 ? "6" : ""),
	       has4 && has6 ? " and IP6_ALLOWED" : "",
	       (has4 || has6) ? "" : " (none - no supported family)"));
}

void
ikev2_build_ip_allowed(struct ikev2_payloads *payl, struct ikev2_sa *ike_sa)
{
	int has4 = 0, has6 = 0;
	struct rcf_addresspool *pool;
	struct rcf_address_pool_item *pi;

	if (ike_sa == NULL || ike_sa->rmconf == NULL)
		return;
	pool = ikev2_addresspool(ike_sa->rmconf);
	if (pool == NULL)
		return;
	for (pi = LIST_FIRST(&pool->pool_list); pi;
	     pi = LIST_NEXT(pi, link)) {
		if (pi->af == AF_INET) has4 = 1;
		else if (pi->af == AF_INET6) has6 = 1;
	}
	drop_ip_allowed(payl, has4, has6);
}

void
ikev2_push_ip_allowed(struct ikev2_sa *ike_sa, struct ikev2_payloads *payl,
		      struct ikev2_child_sa *child_sa)
{
	struct rcf_address *a;
	int has4 = 0, has6 = 0;
	struct rcf_addresspool *pool;
	struct rcf_address_pool_item *pi;

	if (ike_sa == NULL || child_sa == NULL ||
	    child_sa->child_param.cfg_payload == NULL)
		return;

	/* preferred: the configured pool's supported families */
	pool = ikev2_addresspool(ike_sa->rmconf);
	if (pool) {
		for (pi = LIST_FIRST(&pool->pool_list); pi;
		     pi = LIST_NEXT(pi, link)) {
			if (pi->af == AF_INET) has4 = 1;
			else if (pi->af == AF_INET6) has6 = 1;
		}
	}
	if (pool == NULL) {
		/* no named pool: whatever was actually assigned */
		for (a = LIST_FIRST(&child_sa->lease_list); a;
		     a = LIST_NEXT(a, link_sa)) {
			if (a->af == AF_INET) has4 = 1;
			else if (a->af == AF_INET6) has6 = 1;
		}
	}
	drop_ip_allowed(payl, has4, has6);
}
