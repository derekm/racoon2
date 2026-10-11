/* $Id: ikev2.c,v 1.223 2010/02/01 10:30:51 fukumoto Exp $ */

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
#include "ikev2_resume_ticket.h"
#include "ikev2_eap_emit.h"
#include "ikev2_eap.h"
#include "ikev2_eap_relay.h"
#include "ikev2_eap_round.h"
#include "ikev2_eap_drive.h"
#include "ikev2_radius.h"
#include "ikev2_notify.h"
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

/* IPsec SA soft lifetime factor*/
double ikev2_lifetime_soft_factor = IKEV2_DEFAULT_LIFETIME_SOFT_FACTOR;
double ikev2_lifetime_soft_jitter = IKEV2_DEFAULT_LIFETIME_SOFT_JITTER;

/* window size for IPsec traffic */
int ikev2_ipsec_window_size = IKEV2_IPSEC_WINDOW_SIZE;

/* whether ESP Traffic Flow Confidentiality is not supported */
int ikev2_esp_tfc_padding_not_supported = FALSE;
/*
 * 0 = no cap (default).  Set >0 to force an early initiator rekey
 * on CP children.  Optional; not a racoon2.conf statement yet.
 */
int ikev2_child_rekey_floor = 0;

/* for IKE DoS prevention */
static int ikev2_under_attack = 0;
int ikev2_half_open_sa = 0;
int ikev2_attack_threshold = IKED_MAX_HALF_OPEN_SA;

/* map a child's preceding_satype to its rekey proposal protocol id;
 * used before ikev2_child_rekey_proto's definition */
static unsigned int ikev2_child_rekey_proto(struct ikev2_child_sa *);

/*
 * forward declarations
 */
int ikev2_responder_childless_auth_send(struct ikev2_sa *, uint32_t,
					rc_vchar_t *);

typedef void (*IKEV2INPUT) (struct ikev2_sa *, rc_vchar_t *, struct sockaddr *,
			    struct sockaddr *);

IKEV2INPUT ikev2_input_dispatch[] = {
	responder_state0_recv,	/* Responder idling state */
	initiator_ike_sa_init_recv,	/* Initiator IKE_SA_INIT sent */
	responder_ike_sa_auth_recv0,	/* Responder IKE_SA_INIT sent */
	initiator_ike_sa_auth_recv0,	/* Initiator IKE_SA_AUTH sent */
	responder_ike_sa_auth_recv,	/* Responder IKE_SA_AUTH received */
	initiator_ike_sa_auth_recv,	/* Initiator IKE_SA_AUTH received */
	ikev2_established_recv,	/* should be CREATE_CHILD_SA or INFORMATIONAL */
	ikev2_dying_recv,	/* same as established, except no initiating */
	ikev2_dead_recv,
	responder_ike_sa_auth_eap_recv,	/* Responder EAP in IKE_AUTH (RFC 7296 s2.16) */
#ifdef WITH_INTERMEDIATE
	initiator_ike_intermediate_recv, /* Initiator IKE_INTERMEDIATE sent */
#else
	ikev2_dead_recv, /* no state 10 without INTERMEDIATE: unreachable slot */
#endif
	responder_ike_sa_auth_eap_final_recv, /* Responder EAP [AUTH]-only final
						(RFC 5998) */
	ikev2_dead_recv, /* state 12 reserved (IKEV2_STATE_EAP is inert) */
	initiator_ike_session_resume_recv, /* Initiator IKE_SESSION_RESUME (RFC 5723)
					    exchange 38 sent, awaiting Nr */
};

/* The dispatch array is indexed by IKEV2_STATE_* value.  The enum uses
 * explicit values with a gap (10 exists only under WITH_INTERMEDIATE), so
 * the only safe invariant is that the array is large enough for the largest
 * state: a future state added to ikev2_state without growing this array must
 * fail the build here (the runtime assert at the dispatch site is a second
 * net). */
_Static_assert(
    ARRAYLEN(ikev2_input_dispatch) > IKEV2_STATE_INI_IKE_SESSION_RESUME_SENT,
    "ikev2_input_dispatch must cover IKEV2_STATE_INI_IKE_SESSION_RESUME_SENT");



struct ikev2_payloads;		/* forward decl */
int compute_skeyseed_submit(struct ikev2_sa *, oakley_dh_done_t, void *);

int ikev2_spi_is_zero(isakmp_cookie_t *);

struct ikev2_isakmpsa *ikev2_proppair_to_isakmpsa(struct prop_pair *);

/*
 * payload interpretation data
 */
struct isakmp_domain ikev2_doi = {
	/* informations for parse_sa */
	ikev2_check_spi_size,	/* check_spi_size */
	0,			/* ike_spi_size */
	FALSE,			/* check_reserved_fields */
	FALSE,			/* transform_number */
	ikev2_get_transforms,	/* get_transforms */
	ikev2_compare_transforms,
	ikev2_match_transforms
};

static void ikev2_periodic_task(void *);
static struct sched *ikev2_periodic_task_sched;
int ikev2_periodic_task_interval = 3;



int
ikev2_init(void)
{
	ikev2_sa_init();

	if (ikev2_cookie_init() < 0)
		return -1;
	if (ikev2_qcd_init() < 0)
		return -1;

	ikev2_periodic_task_sched =
		sched_new(ikev2_periodic_task_interval, ikev2_periodic_task, 0);
	if (!ikev2_periodic_task_sched)
		return -1;

	return 0;
}

/*ARGSUSED*/
static void
ikev2_periodic_task(void *param)
{
	/* TRACE((PLOGLOC, "ikev2_periodic_task()\n")); */

	ikev2_cookie_refresh();
	ikev2_sa_periodic_task();

	ikev2_periodic_task_sched =
		sched_new(ikev2_periodic_task_interval, ikev2_periodic_task, 0);
	if (!ikev2_periodic_task_sched)
		isakmp_log(0, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "failed to allocate memory\n");
}

int
ikev2_input(rc_vchar_t *packet, struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr = (struct ikev2_header *)packet->v;
	int is_response;
	uint32_t message_id;
	struct ikev2_payload_header *first_payload;
	struct ikev2_sa *ike_sa;
	struct rcf_remote *conf = 0;
	int reassembled = 0;

	++isakmpstat.v2input;

	/* ISAKMP_PRINTPACKET(msg, remote, local, 0); */
	TRACE((PLOGLOC, "ikev2_input(%p, %p, %p)\n", packet, remote, local));

	/* (RFC4306)
	   They MUST ignore the minor version number of received messages.
	*/
	TRACE((PLOGLOC, "processing message version %d.%03d\n",
	       ISAKMP_GETMAJORV(ikehdr->version), ISAKMP_GETMINORV(ikehdr->version)));

	ike_sa = ikev2_find_sa(packet);

	/* RFC 5723 s4.3.2: IKE_SESSION_RESUME (exchange 38) is accepted like a
	 * fresh IKE_SA_INIT -- SPIr is 0 and SPIi is new, and the resumption
	 * ticket travels in a N(TICKET_OPAQUE) notify.  So it is one of the two
	 * exchange types that may address a nonexistent SA. */
	if (!ike_sa && ikehdr->exchange_type != IKEV2EXCH_IKE_SA_INIT
	    && ikehdr->exchange_type != IKEV2EXCH_IKE_SESSION_RESUME) {
		ikev2_qcd_respond(packet, remote, local);
		isakmp_log(0, local, remote, packet, PLOG_PROTOWARN, PLOGLOC,
			   "message to a nonexistent ike_sa\n");
		++isakmpstat.invalid_ike_spi;
		goto end;
	}

#ifdef WITH_INTERMEDIATE
	/* R1 (review): a retransmitted gen-0 IKE_INTERMEDIATE request --
	 * whole packet or SKF fragment -- is encrypted under the pre-update
	 * keys, so once the responder advanced to gen-1 it can never be
	 * AEAD-decrypted.  Detect it by the cleartext outer exchange type +
	 * message_id and replay the cached gen-0 response (a lost-fragment
	 * recovery that the old H1 prev-gen-ICV retry could never reach).
	 * The trigger REQUIRES the packet to come from the SA's real peer
	 * (rcs_cmpsa against ike_sa->remote): a gen-0 retransmission can only
	 * be authenticated by its source, since it is undecryptable after the
	 * key advance.  An arbitrary source may not drive the cached-response
	 * replay; unmatched sources fall through to normal (which safely
	 * fails the AEAD check). */
	if (ike_sa != NULL &&
	    ikehdr->exchange_type == IKEV2EXCH_IKE_INTERMEDIATE &&
	    ike_sa->intermediate_replay != NULL &&
	    get_uint32(&ikehdr->message_id) == ike_sa->intermediate_replay_msgid &&
	    rcs_cmpsa(remote, ike_sa->remote) == 0) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_DEBUG, PLOGLOC,
			   "RT-REPLAY: retransmitted gen-0 intermediate req detected "
			   "(msgid=%u replay=%p)\n",
			   (unsigned)get_uint32(&ikehdr->message_id),
			   (void *)ike_sa->intermediate_replay);
		ikev2_replay_intermediate_response(ike_sa);
		goto end;
	}
#endif /* WITH_INTERMEDIATE */

	/*
	 * Handle IKEv2 fragment (SKF) reassembly BEFORE payload checking.
	 */

	if (ikehdr->next_payload ==
	    IKEV2_PAYLOAD_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT) {
		rc_vchar_t *reassembled_pkt;

		if (!ike_sa) {
			TRACE((PLOGLOC, "received fragment but no ike_sa\n"));
			goto end;
		}
		isakmp_log(ike_sa, local, remote, packet, PLOG_DEBUG, PLOGLOC,
			   "SKF fragment recv (next=SKF, msgid=%u, len=%zu)\n",
			   get_uint32(&ikehdr->message_id), (size_t)packet->l);
		reassembled_pkt = ikev2_frag_recv(ike_sa, packet, remote, local);
		if (!reassembled_pkt)
			goto end;

		rc_vfree(packet);
		packet = reassembled_pkt;
		ikehdr = (struct ikev2_header *)packet->v;
		ike_sa = ikev2_find_sa(packet);
		reassembled = 1;
	}

	if (ikev2_check_payloads(packet, TRUE) != 0) {
		isakmp_log(0, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
			   "malformed payload format\n");
		++isakmpstat.malformed_payload;
		goto end;
	}

	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;
	message_id = get_uint32(&ikehdr->message_id);
	first_payload = (struct ikev2_payload_header *)(ikehdr + 1);

	if (!ike_sa) {
		int need_cookie, has_cookie, invalid_cookie;

		TRACE((PLOGLOC, "no corresponding ike_sa\n"));
#ifdef HAVE_LIBPCAP
		if (ike_pcap_file)
			rc_pcap_push(remote, local, packet);
#endif
		if (ikev2_check_new_request(packet, remote, local) != 0)
			goto end;

		/* new request.  check config */
		conf = ikev2_conf_find(remote);
		if (!conf) {
			/* if no config with src addr, use default */
			TRACE((PLOGLOC, "no conf found\n"));
			if (rcf_default_head && rcf_default_head->remote) {
				TRACE((PLOGLOC, "using default\n"));
				conf = rcf_deepcopy_remote(rcf_default_head->remote);
			}
		}
		if (!conf) {
			isakmp_log(0, local, remote, packet, PLOG_PROTOWARN,
				   PLOGLOC, "unknown ikev2 peer\n");
			++isakmpstat.unknown_peer;
			goto end;
		}
		if (conf && !conf->ikev2) {
			isakmp_log(0, local, remote, packet,
				   PLOG_PROTOWARN, PLOGLOC,
				   "received IKEv2 request but no IKEv2 configuration for peer %s\n",
				   conf->rm_index ? rc_vmem2str(conf->rm_index) : "(default)");
			++isakmpstat.no_proposal_chosen;	/* ??? */
			/* XXX should send notify ??? */
			goto end;
		}

		/* Check if passive is set correctly
		   XXX This is a hack to help prevent an assertion in
		       ikev2_child.c:ikev2_child_getspi_done() */

		if (ikev2_passive(conf) == RCT_BOOL_OFF) {
			if (conf->ikev2->addresspool) { /* XXX more checks before triggering this warning ??? */
				isakmp_log(0, local, remote, packet,
					   PLOG_PROTOWARN, PLOGLOC,
					   "IKEv2 peer appears to be a client but passive is not set to on for peer %s\n",
					   conf->rm_index ? rc_vmem2str(conf->rm_index) : "(default)");
				isakmp_log(0, local, remote, packet,
					   PLOG_PROTOWARN, PLOGLOC,
					   "Setting passive to on for IKEv2 peer %s ...\n",
					   conf->rm_index ? rc_vmem2str(conf->rm_index) : "(default)");
				isakmp_log(0, local, remote, packet,
					   PLOG_PROTOWARN, PLOGLOC,
					   "Please set passive to on in your ikev2 configuration for peer %s to disable this warning.\n",
					   conf->rm_index ? rc_vmem2str(conf->rm_index) : "(default)");
				conf->ikev2->passive = RCT_BOOL_ON;
			}
		}

		need_cookie = (ikev2_under_attack ||
			(conf && conf->ikev2->cookie_required == RCT_BOOL_ON));
		has_cookie = (ikehdr->next_payload == IKEV2_PAYLOAD_NOTIFY &&
			get_notify_type((struct ikev2payl_notify*)first_payload) == IKEV2_COOKIE);
		if (has_cookie) {
			invalid_cookie = (ikev2_check_request_cookie(packet, remote, local) != 0);
		} else {
			invalid_cookie = FALSE;
		}
		if (invalid_cookie || (need_cookie && !has_cookie)) {
			static struct ratelimit r;

			if (invalid_cookie) {
				/* stat incremented in ikev2_check_request_cookie */
				TRACE((PLOGLOC, "invalid cookie\n"));
			}
			if (!has_cookie) {
				++isakmpstat.ikev2_cookie_required;
				TRACE((PLOGLOC, "no cookie\n"));
			}
			if (ratelimit(&r, remote)) {
				isakmp_log(0, local, remote, packet, PLOG_INFO, PLOGLOC,
					   "responding with cookie\n");
				++isakmpstat.ikev2_respond_with_cookie;
				ikev2_respond_with_cookie(packet, remote, local);
			}
			goto end;
		}

		/* create ikev2 sa as responder */
		ike_sa = ikev2_create_sa(&ikehdr->initiator_spi, local, remote,
					 conf);
		if (!ike_sa) {
			isakmp_log(0, local, remote, packet,
				   PLOG_INTERR, PLOGLOC,
				   "failed to create ike_sa\n");
			++isakmpstat.fail_create_sa;
			goto end;
		}
		conf = 0;	/* owned by ike_sa now */
		if (!ikev2_under_attack
		    && ikev2_half_open_sa >= ikev2_attack_threshold) {
			ikev2_under_attack = TRUE;
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "half-open ike_sa num (%d) exceeds threshold (%d)\n",
				   ikev2_half_open_sa, ikev2_attack_threshold);
		}
	}

	TRACE((PLOGLOC, "ike_sa: %p\n", ike_sa));
	assert(ike_sa != 0);
	assert((unsigned int)ike_sa->state < ARRAYLEN(ikev2_input_dispatch));

	/* drop unless message_id matches expected one (duplicate or unordered); */

	if (ikehdr->exchange_type == IKEV2EXCH_IKE_SA_INIT
	    || ikehdr->exchange_type == IKEV2EXCH_IKE_SESSION_RESUME) {
#ifdef HAVE_LIBPCAP
		if (ike_pcap_file)
			rc_pcap_push(remote, local, packet);
#endif
		if (ikev2_retransmit_forced(ike_sa, message_id, is_response) != 0) {
			goto end;
		}
		if (ikev2_check_message_ordering(ike_sa, message_id, is_response, local, remote) != 0) {
			isakmp_log(ike_sa, local, remote, packet,
				   PLOG_DEBUG, PLOGLOC,
				   "dropping unordered message (id %d)\n",
				   message_id);
			++isakmpstat.unordered;
			goto end;
		}
	} else {
		if (!reassembled) {
			if (ikehdr->next_payload == IKEV2_PAYLOAD_NOTIFY &&
			    ikehdr->exchange_type == IKEV2EXCH_INFORMATIONAL &&
			    (ikehdr->flags & IKEV2FLAG_RESPONSE) &&
			    ikev2_qcd_taker_recv(ike_sa, packet)) {
				ikev2_abort(ike_sa, ECONNRESET);
				goto end;
			}
			if (ikehdr->next_payload != IKEV2_PAYLOAD_ENCRYPTED
				&& ikehdr->next_payload != IKEV2_PAYLOAD_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_PROTOERR, PLOGLOC,
					   "unsupported message format: first payload is not ENCRYPTED payload\n");
				++isakmpstat.malformed_message;
				goto end;
			}
			if (ikev2_check_icv(ike_sa, packet) != 0) {
				if (ikev2_check_icv_prev_gen(ike_sa, packet) == 0) {
					/* H1: ICV validates against the PRE-update
					 * (gen-0) keys => this is a retransmitted
					 * IKE_INTERMEDIATE request we already
					 * answered.  Fall through so
					 * ikev2_retransmit_forced below replays the
					 * cached response instead of killing the SA
					 * on the current (gen-1) ICV mismatch. */
					isakmp_log(ike_sa, local, remote, packet,
					    PLOG_DEBUG, PLOGLOC,
					    "replayed: ICV ok against PREVIOUS gen\n");
				} else {
					isakmp_log(ike_sa, local, remote, packet,
						   PLOG_PROTOERR, PLOGLOC,
						   "ICV check failure\n");
					++isakmpstat.fail_integrity_check;
					goto end;
				}
			}
			if (ikev2_retransmit_forced(ike_sa, message_id, is_response) != 0) {
				goto end;
			}
			if (ikev2_check_message_ordering(ike_sa, message_id, is_response, local, remote) != 0) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_DEBUG, PLOGLOC,
					   "dropping unordered message (id %d)\n",
					   message_id);
				++isakmpstat.unordered;
				goto end;
			}
			if (ikev2_decrypt(ike_sa, packet) != 0) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_PROTOERR, PLOGLOC,
					   "failed to decrypt message\n");
				++isakmpstat.fail_decrypt;
				goto end;
			}
#ifdef HAVE_LIBPCAP
			if (ike_pcap_file)
				rc_pcap_push(remote, local, packet);
#endif
			if (ikev2_check_payloads(packet, FALSE) != 0) {
				isakmp_log(0, local, remote, packet,
					   PLOG_PROTOERR, PLOGLOC,
					   "malformed payload format\n");
				++isakmpstat.malformed_payload;
				goto end;
				}
				}

		/*
		 * A reassembled SKF message was authenticated and decrypted
		 * fragment by fragment in ikev2_frag_recv(), so it skipped the
		 * block above.  RFC 7383 s2.6: it "is processed as if it was
		 * received, verified, and decrypted as a regular IKE message",
		 * which includes the Message ID window (RFC 7296 s2.2).  A
		 * retransmission of the request we last answered replays the
		 * armed response; anything else outside the window is dropped,
		 * or a captured old fragment set would re-enter its handler.
		 */
		if (reassembled) {
			if (ikev2_retransmit_forced(ike_sa, message_id,
			    is_response) != 0)
				goto end;
			if (ikev2_check_message_ordering(ike_sa, message_id,
			    is_response, local, remote) != 0) {
				isakmp_log(ike_sa, local, remote, packet,
					   PLOG_DEBUG, PLOGLOC,
					   "dropping unordered message (id %d)\n",
					   message_id);
				++isakmpstat.unordered;
				goto end;
			}
		}

			/* (draft-17)
		 * Receipt of a fresh cryptographically protected message on an IKE_SA
		 * or any of its CHILD_SAs assures liveness of the IKE_SA and all of its
		 * CHILD_SAs.
		 */
		ikev2_sa_start_polling_timer(ike_sa);	/* restart */
	}

	/*
	 * call packet processing routine
	 */
	TRACE((PLOGLOC, "dispatching ike_sa %p state %d\n", ike_sa, ike_sa->state));
	(*ikev2_input_dispatch[ike_sa->state]) (ike_sa, packet, remote, local);

#ifdef notyet
	/* (draft-17)
	 * A node receiving such an unprotected Notify payload MUST NOT respond
	 * and MUST NOT change the state of any existing SAs. The message might
	 * be a forgery or might be a response the genuine correspondent was
	 * tricked into sending. A node SHOULD treat such a message (and also a
	 * network message like ICMP destination unreachable) as a hint that
	 * there might be problems with SAs to that IP address and SHOULD
	 * initiate a liveness test for any such IKE_SA. An implementation
	 * SHOULD limit the frequency of such tests to avoid being tricked into
	 * participating in a denial of service attack.
	 */

	/* (draft-17)
	 * A node receiving a suspicious message from an IP address with which
	 * it has an IKE_SA MAY send an IKE Notify payload in an IKE
	 * INFORMATIONAL exchange over that SA. The recipient MUST NOT change
	 * the state of any SA's as a result but SHOULD audit the event to aid
	 * in diagnosing malfunctions. A node MUST limit the rate at which it
	 * will send messages in response to unprotected messages.
	 */
#endif

      end:
	if (packet)
		rc_vfree(packet);
	if (conf)
		rcf_free_remote(conf);
	return 0;
}


/*
 * RFC 4555: echo a COOKIE2 the peer put on this request.  CREATE_CHILD
 * and INFORMATIONAL both carry it (iOS rides UPDATE_SA_ADDRESSES inside
 * the rekey).  Echoing only on INFORMATIONAL left the rekey reply with
 * no binding confirmation.
 */
void
ikev2_push_cookie2_echo(struct ikev2_sa *ike_sa, struct ikev2_payloads *payl)
{
	if (!ike_sa || !ike_sa->cookie2_echo || !payl)
		return;
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(0, 0, 0, IKEV2_COOKIE2,
						 ike_sa->cookie2_echo->v,
						 ike_sa->cookie2_echo->l),
			    TRUE);
	rc_vfree(ike_sa->cookie2_echo);
	ike_sa->cookie2_echo = 0;
}


/*
 * ikev2_timeout
 * called when retransmission count exceeds limit
 */
void
ikev2_timeout(struct transmit_info *info)
{
	struct ikev2_sa *ike_sa;

	ike_sa = (struct ikev2_sa *)info->callback_param;

	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_PROTOERR, PLOGLOC,
		   "retransmission count exceeded the limit\n");

	/* A COOKIE2 probe to an additional address failed.  Put the
	 * IKE endpoints back before trying the next one, so a later
	 * mobike_apply still sees the address the kernel SAs use. */
	if (ike_sa->mobike_rr_pending && ike_sa->mobike_rr_prev) {
		struct sockaddr *dead = ike_sa->remote;

		ike_sa->remote = ike_sa->mobike_rr_prev;
		ike_sa->mobike_rr_prev = NULL;
		ike_sa->mobike_rr_pending = 0;
		if (dead)
			rc_free(dead);
	}
	if (ikev2_mobike_probe_next(ike_sa))
		return;

	ikev2_abort(ike_sa, ETIMEDOUT);	/* ECONNREFUSED? */

	++isakmpstat.timeout;
}

/*
 * ikev2_verified
 * called when auth verification gives a result
 */
void
ikev2_verified(struct verified_info *info)
{
	struct ikev2_sa *ike_sa;

	ike_sa = (struct ikev2_sa *)info->callback_param;

	if (info->is_initiator)
		initiator_ike_sa_auth_cont(ike_sa, info->result, info->packet,
					   info->remote, info->local);
	else
		responder_ike_sa_auth_cont(ike_sa, info->result, info->packet,
					   info->remote, info->local);
}

/*
 * set SA state
 */
void
ikev2_set_state(struct ikev2_sa *sa, int state)
{
	int prev_state;

	prev_state = sa->state;
	sa->state = state;

	isakmp_log(sa, 0, 0, 0,
		   PLOG_DEBUG, PLOGLOC,
		   "ike_sa %p state %s -> %s\n", sa, ikev2_state_str(prev_state),
		   ikev2_state_str(state));

	if (!sa->is_initiator &&
	    prev_state != IKEV2_STATE_ESTABLISHED &&
	    (state == IKEV2_STATE_ESTABLISHED ||
	     state == IKEV2_STATE_DEAD)) {
		--ikev2_half_open_sa;
		if (ikev2_under_attack &&
		    ikev2_half_open_sa < ikev2_attack_threshold) {
			ikev2_under_attack = FALSE;
			isakmp_log(0, 0, 0, 0,
				   PLOG_INTWARN, PLOGLOC,
				   "half-open ike_sa num (%d) below threshold (%d)\n",
				   ikev2_half_open_sa, ikev2_attack_threshold);
		}
	}
	if (prev_state != IKEV2_STATE_ESTABLISHED &&
	    state == IKEV2_STATE_ESTABLISHED) {
		/* The IKE_INTERMEDIATE window is over once IKE_AUTH is
		 * accepted: a retransmitted intermediate request can no
		 * longer occur legitimately.  Drop the gen-0 response
		 * cache so it is not retained (and cannot be triggered as
		 * a stale replay/amplifier) for the life of the SA. */
#ifdef WITH_INTERMEDIATE
		ikev2_intermediate_clear_replay(sa);
#endif
		ikev2_sa_stop_timer(sa);
		ikev2_sa_start_lifetime_timer(sa);
		ikev2_sa_start_polling_timer(sa);
		if (sa->is_rekeyed_sa)
			ikev2_script_hook(sa, SCRIPT_PHASE1_REKEY);
		else
			ikev2_script_hook(sa, SCRIPT_PHASE1_UP);
		ikev2_resume_save(sa);
		/*
		 * INITIAL_CONTACT arrived during this exchange (IKE_AUTH
		 * of the replacement SA).  Flush the stale same-peer SA
		 * only now: we are fully established, the AUTH response
		 * has been sent or is about to be sent from this
		 * callback, so the teardown can't reap the exchange that
		 * carried the notify.  ikev2_initial_contact() schedules
		 * its own deferred teardown past this callback.
		 */
		if (sa->initial_contact_pending) {
			sa->initial_contact_pending = 0;
			ikev2_initial_contact(sa);
		}
	}
	if (prev_state == IKEV2_STATE_ESTABLISHED &&
	    state != IKEV2_STATE_ESTABLISHED) {
		ikev2_resume_forget(sa);
		if (!sa->rekey_inprogress)
			ikev2_script_hook(sa, SCRIPT_PHASE1_DOWN);
	}

	/*
	 * continue retrnasmission on SA expire (ESTABLISHED->DYING)
	 * otherwise stop retransmission
	 */
	if (!(prev_state == IKEV2_STATE_ESTABLISHED &&
	      state == IKEV2_STATE_DYING))
		ikev2_stop_retransmit(sa);
}

/*
 * payload types defined in the draft are all critical
 */
int
ikev2_payload_type_is_critical(unsigned int type)
{
	if (type >= IKEV2_PAYLOAD_SA && type <= IKEV2_PAYLOAD_EAP)
		return TRUE;
	else
		return FALSE;
}


/*
 * process ACQUIRE for IKEv2
 */
void
ikev2_initiate(struct isakmp_acquire_request *req,
	       struct rcf_policy *policy,
	       struct rcf_selector *selector,
	       struct rcf_remote *rm_info)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *child_sa;
	struct sockaddr *peer = 0;
	int	new_ike_sa = FALSE;

	if (ikev2_passive(rm_info) == RCT_BOOL_ON) {
		isakmp_log(0, req->src, req->dst, 0, PLOG_INFO, PLOGLOC,	/* ??? */
			   "remote %s passive mode specified, dropping acquire request\n",
			   (rm_info->rm_index ?
			    rc_vmem2str(rm_info->rm_index) : "(default)"));
		goto fail;
	}
	if (rm_info->ikev2->peers_ipaddr) {
		if (rm_info->ikev2->peers_ipaddr->type != RCT_ADDR_INET) {
			isakmp_log(0, req->src, req->dst, 0,
				   PLOG_INTERR, PLOGLOC,
				   "unsupported peers_ipaddr format in policy %.*s (%.*s)\n",
				   (int)policy->pl_index->l,
				   policy->pl_index->s,
				   (int)rm_info->ikev2->peers_ipaddr->a.vstr->l,
				   rm_info->ikev2->peers_ipaddr->a.vstr->s);
			goto fail;
		}
		peer = rcs_sadup(rm_info->ikev2->peers_ipaddr->a.ipaddr);
	} else if (req->dst) {
		peer = rcs_sadup(req->dst);
	} else {
		isakmp_log(0, req->src, req->dst, 0,
			   PLOG_INTERR, PLOGLOC,
			   "remote peer address is not known\n");
		goto fail;
	}

	ike_sa = ikev2_find_sa_by_addr(peer);
	if (!ike_sa
	    /* || ike_sa->do_not_reuse */ ) {
		struct sockaddr *myself;
		in_port_t *prt;

		TRACE((PLOGLOC, "creating new ike_sa\n"));
		new_ike_sa = TRUE;

		prt = rcs_getsaport(peer);
		if (!prt) {
			isakmp_log(0, req->src, req->dst, 0,
				   PLOG_INTERR, PLOGLOC,
				   "unsupported address family %d\n",
				   peer->sa_family);
			goto fail;
		}
		*prt = htons(isakmp_port_dest);

		if (req->src2 && ike_ipsec_mode(policy) == RCT_IPSM_TRANSPORT)
			myself = getlocaladdr(peer, req->src2, isakmp_port);
		else
			myself = getlocaladdr(peer, req->src, isakmp_port);
		if (!myself) {
			isakmp_log(0, req->src, req->dst, 0,
				   PLOG_INTERR, PLOGLOC,
				   "failed finding local sockaddr to connect with peer address %s\n",
				   rcs_sa2str(peer));
			goto fail;
		}

		ike_sa = ikev2_create_sa(0, myself, peer, rm_info);
		racoon_free(myself);
		if (!ike_sa) {
			TRACE((PLOGLOC,
			       "failed creating new ike_sa\n"));
			goto fail_nomem;
		}
	}
	assert(ike_sa != 0);
#ifdef WITH_PARSECOA
	if (rm_info->ikev2->use_coa) {
		if (ike_sa->local->sa_family == AF_INET6) {
			struct sockaddr_in6* sin6;
			sin6 = (struct sockaddr_in6*)ike_sa->local;
			memcpy(&sin6->sin6_addr, &coa, sizeof(coa));
		}
	}
#endif

	child_sa = ikev2_create_child_initiator(ike_sa);
	if (!child_sa) {
		TRACE((PLOGLOC, "failed creating child_sa\n"));
		goto fail_nomem;
	}
	TRACE((PLOGLOC, "child_sa: %p\n", child_sa));

	child_sa->selector = selector;
	selector = 0;	/* to stop deallocating */

	child_sa->my_proposal =
		ikev2_ipsec_conf_to_proplist(child_sa, !new_ike_sa);
	if (!child_sa->my_proposal) {
		TRACE((PLOGLOC,
		       "failed creating proposal list of initiator SA\n"));
		goto fail;
	}

	/* The GETSPI sent by ikev2_child_getspi() must carry its OWN unique
	 * request sequence for response correlation.  req->request_msg_seq is
	 * the ACQUIRE's seq — which the netlink XFRM backend never sets, so
	 * after the sadb_poll memset it is 0; if_xfrm.c then invents a
	 * netlink seq (++xfrm_seq) for the GETSPI and the reply never matches
	 * this request ("SADB_GETSPI ... does not have corresponding
	 * request"), stalling the initiator child before IKE_AUTH.  Mint a
	 * fresh seq here, exactly like the responder/initiator-rekey child
	 * paths do (ikev2_child.c ikev2_child_getspi callers). */
	sadb_request_initialize(&child_sa->sadb_request,
				req->callback_method,
				&ikev2_sadb_callback,
				sadb_new_seq(),
				child_sa);

	ikev2_child_getspi(child_sa);

	if (ike_sa->soft_expired && !ike_sa->rekey_inprogress)
		ikev2_rekey_ikesa_initiate(ike_sa);

 done:
	if (selector)
		rcf_free_selector(selector);
	if (peer)
		racoon_free(peer);
	return;

 fail_nomem:
	isakmp_log(0, req->src, req->dst, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
 fail:
	goto done;
}



/*
 * IKEv2 CREATE_CHILD_SA exchange
 */
struct ikev2_child_init_ctx {
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *child_sa;
	int serial;	/* ike_sa->serial_number, for liveness check */
	struct algdef *dhgrpdef;
	struct ikev2_payloads payl;
	int payl_inited;
	rc_vchar_t *sa;
	rc_vchar_t *ts_i;
	rc_vchar_t *ts_r;
	rc_vchar_t *ke;
	int pfs;
};

static void
ikev2_child_init_ctx_free(struct ikev2_child_init_ctx *ctx)
{
	if (ctx->sa)
		rc_vfree(ctx->sa);
	if (ctx->ts_i)
		rc_vfree(ctx->ts_i);
	if (ctx->ts_r)
		rc_vfree(ctx->ts_r);
	if (ctx->ke)
		rc_vfree(ctx->ke);
	if (ctx->payl_inited)
		ikev2_payloads_destroy(&ctx->payl);
	rc_free(ctx);
}

/* builds + transmits the CREATE_CHILD_SA request (IKE thread) */
static void
ikev2_createchild_initiator_send_tail(struct ikev2_child_init_ctx *ctx)
{
	struct ikev2_sa *ike_sa = ctx->ike_sa;
	struct ikev2_child_sa *child_sa = ctx->child_sa;
	rc_vchar_t *pkt = 0;
	struct ikev2payl_ke_h dhgrp_hdr;

	/*
	 * (draft-17)
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

	if (ctx->pfs) {
		dhgrp_hdr.dh_group_id = htons(ctx->dhgrpdef->transform_id);
		dhgrp_hdr.reserved = 0;
		ctx->ke = rc_vprepend(child_sa->dhpub, &dhgrp_hdr,
		    sizeof(dhgrp_hdr));
		if (!ctx->ke)
			goto fail;
	}

	/*
	 * [N(REKEY_SA)]
	 */
	if (child_sa->preceding_satype != 0) {
		uint32_t spi;

		put_uint32(&spi, child_sa->preceding_spi);
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload((child_sa->preceding_satype == RCT_SATYPE_ESP ?
							  IKEV2_NOTIFY_PROTO_ESP :
							  IKEV2_NOTIFY_PROTO_AH),
							 (uint8_t *)&spi,
							 sizeof(uint32_t),
							 IKEV2_REKEY_SA, 0, 0),
				    TRUE);
	}

#ifdef notyet
	/*
	 * [N(IPCOMP_SUPPORTED...)]
	 */
#endif

	/*
	 * [N(USE_TRANSPORT_MODE)]
	 */
	if (ike_ipsec_mode(child_sa->selector->pl) == RCT_IPSM_TRANSPORT) {
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_USE_TRANSPORT_MODE,
							 0, 0),
				    TRUE);
	}

	/*
	 * N(ESP_TFC_PADDING_NOT_SUPPORTED)
	 */
	if (ikev2_esp_tfc_padding_not_supported) {
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED,
							 0, 0),
				    TRUE);
	}

#ifdef notyet
	/*
	 * [N(NON_FIRST_FRAGMENTS_ALSO)]
	 */
#endif

	/*
	 * SA, Ni, [KEi], TSi, TSr
	 */
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_SA, ctx->sa, FALSE);
	ctx->sa = NULL;
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_NONCE,
			    child_sa->n_i, FALSE);
	/* if the SA offers include different  Diffie-Hellman groups */
	if (ctx->ke)
		ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_KE, ctx->ke, FALSE);
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_TS_I, ctx->ts_i, FALSE);
	ctx->ts_i = NULL;
	ikev2_payloads_push(&ctx->payl, IKEV2_PAYLOAD_TS_R, ctx->ts_r, FALSE);
	ctx->ts_r = NULL;

	{
		int t_i;
		for (t_i = 0; t_i < ctx->payl.num; t_i++) {
			rc_vchar_t *d = ctx->payl.payloads[t_i].data;
			isakmp_log(ike_sa, 0, 0, 0,
			    PLOG_DEBUG, PLOGLOC,
			    "REKEY_REQ payl[%d] type=%d len=%zu\n",
			    t_i, ctx->payl.payloads[t_i].type,
			    d ? d->l : 0);
			if (d && ctx->payl.payloads[t_i].type ==
			    IKEV2_PAYLOAD_SA) {
				/* dump proposal headers: each is
				 * isakmp_pl_p (8B) + spi (4B); the
				 * header length field covers proposal
				 * + spi only, transforms follow */
				size_t off = 0;
				while (off + 12 <= d->l) {
					uint8_t *p = d->v + off;
					uint16_t phdrlen =
					    get_uint16(p + 2);
					isakmp_log(ike_sa, 0, 0, 0,
					    PLOG_DEBUG, PLOGLOC,
					    "REKEY_REQ SA prop#%u type=%u proto=%u "
					    "spi=0x%08x hdrlen=%u\n",
					    p[4], p[5], p[6],
					    get_uint32(p + 8), phdrlen);
					off += 12;
				}
			}
		}
	}

	pkt = ikev2_packet_construct(IKEV2EXCH_CREATE_CHILD_SA,
				     ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0,
				     child_sa->message_id, ike_sa, &ctx->payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	pkt = 0;

	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_WAIT_RESPONSE);

	if (pkt)
		rc_vfree(pkt);
	ikev2_child_init_ctx_free(ctx);
	return;

fail:
	if (pkt)
		rc_vfree(pkt);
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending CREATE_CHILD_SA request for internal error\n");
	ikev2_child_abort(child_sa, ECONNREFUSED);	/* ??? */
	ikev2_child_init_ctx_free(ctx);
}

static void
ikev2_createchild_initiator_dh_done(int rc, void *arg)
{
	struct ikev2_child_init_ctx *ctx = arg;
	struct ikev2_sa *ike_sa;
	struct ikev2_child_sa *child_sa;

	/*
	 * Validate liveness before touching anything: the worker wrote
	 * child_sa->dhpub/dhpriv while ike_sa was pinned (periodic task
	 * skips pending SAs and their children).  Confirm the SA is a
	 * live list member, release its pin either way, then confirm
	 * the child is still a member.
	 */
	ike_sa = ikev2_find_sa_by_serial(ctx->serial);
	if (ike_sa == NULL || ike_sa != ctx->ike_sa) {
		ikev2_child_init_ctx_free(ctx);
		return;
	}
	ike_sa->crypto_pending = 0;
	child_sa = ctx->child_sa;
	if (!ikev2_child_sa_is_member(ike_sa, child_sa)) {
		ikev2_child_init_ctx_free(ctx);
		return;
	}
	if (ike_sa->state == IKEV2_STATE_DYING ||
	    ike_sa->state == IKEV2_STATE_DEAD ||
	    child_sa->state == IKEV2_CHILD_STATE_EXPIRED) {
		ikev2_child_init_ctx_free(ctx);
		return;
	}
	if (rc != 0) {
		TRACE((PLOGLOC, "failed generating DH values\n"));
		ikev2_child_abort(child_sa, ECONNREFUSED);	/* ??? */
		ikev2_child_init_ctx_free(ctx);
		return;
	}
	ikev2_createchild_initiator_send_tail(ctx);
}

int
ikev2_createchild_initiator_send(struct ikev2_sa *ike_sa,
				 struct ikev2_child_sa *child_sa)
{
	rc_vchar_t *sa = 0;
	rc_vchar_t *ts_i = 0;
	rc_vchar_t *ts_r = 0;
	struct ikev2_payloads payl;
	size_t nonce_size;
	struct ikev2_child_init_ctx *ctx;
	int pfs;

	/*assert(child_sa->message_id == 0); */
	ikev2_payloads_init(&payl);
	child_sa->message_id = ikev2_request_id(ike_sa);

	/*
	 * HDR, SK {[N(REKEY_SA)],
	 *          [N(IPCOMP_SUPPORTED)+],
	 *          [N(USE_TRANSPORT_MODE)],
	 *          [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
	 *          [N(NON_FIRST_FRAGMENTS_ALSO)],
	 *          SA, Ni, [KEi], TSi, TSr}
	 */

	sa = ikev2_construct_sa(child_sa);
	if (!sa)
		goto fail;

	ts_i = ikev2_construct_ts_i(child_sa);
	ts_r = ikev2_construct_ts_r(child_sa);
	if (!ts_i || !ts_r)
		goto fail;

	ikev2_create_config_request(child_sa);

	if (!child_sa->n_i) {
		nonce_size = ikev2_nonce_size(ike_sa->rmconf);
		child_sa->n_i = random_bytes(nonce_size);
		if (!child_sa->n_i)
			goto fail;
	}

	/*
	 * Offer KEi only when the proposal actually contains a DH
	 * transform.  Earlier code forced pfs=1 unconditionally
	 * ("Apple requires it") and sent a KEi payload even when the
	 * offered suite had no DH transform -- a peer (iOS) then
	 * correctly accepted the rekey PFS-less (no KEr in the
	 * response; RFC 7296 2.18) while our response parser
	 * required KEr because dhpriv was set, aborted the child,
	 * and iOS deleted the IKE_SA.  If the proposal has no DH
	 * transform, send no KEi and expect none back.
	 */
	pfs = (ikev2_child_dhdef(child_sa->my_proposal[1], NULL) != NULL);

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		goto fail;
	ctx->ike_sa = ike_sa;
	ctx->child_sa = child_sa;
	ctx->serial = ike_sa->serial_number;
	ctx->sa = sa;
	sa = NULL;
	ctx->ts_i = ts_i;
	ts_i = NULL;
	ctx->ts_r = ts_r;
	ts_r = NULL;
	ctx->payl = payl;
	ctx->payl_inited = 1;
	ctx->pfs = pfs;

	if (pfs) {
		struct algdef *dhgrpdef;

		if (child_sa->dhgrp)
			dhgrpdef = child_sa->dhgrp;
		else if (ike_sa->negotiated_sa)
			dhgrpdef = ike_sa->negotiated_sa->dhdef;
		else
			dhgrpdef = NULL;
		if (!dhgrpdef) {
			ctx->payl_inited = 0;	/* fail: destroys payl once */
			ikev2_child_init_ctx_free(ctx);
			goto fail;
		}
		ctx->dhgrpdef = dhgrpdef;

		/*
		 * Remember the group we sent KEi in, so the KEr check in
		 * ikev2_createchild_initiator_recv() compares against it
		 * instead of the group of the KEr payload itself (which
		 * would accept any mismatch silently).
		 */
		child_sa->dhgrp = dhgrpdef;

		ike_sa->crypto_pending = 1;
		if (oakley_dh_generate_submit(
		    (struct dhgroup *)dhgrpdef->definition,
		    &child_sa->dhpub, &child_sa->dhpriv,
		    ikev2_createchild_initiator_dh_done, ctx) != 0) {
			ike_sa->crypto_pending = 0;
			TRACE((PLOGLOC, "failed dh submit\n"));
			ctx->payl_inited = 0;	/* fail: destroys payl once */
			ikev2_child_init_ctx_free(ctx);
			goto fail;
		}
		return 0;	/* resumed in ikev2_createchild_initiator_dh_done */
	}

	ikev2_createchild_initiator_send_tail(ctx);
	return 0;

fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending CREATE_CHILD_SA request for internal error\n");
	ikev2_child_abort(child_sa, ECONNREFUSED);	/* ??? */
	if (sa)
		rc_vfree(sa);
	if (ts_i)
		rc_vfree(ts_i);
	if (ts_r)
		rc_vfree(ts_r);
	ikev2_payloads_destroy(&payl);
	return -1;
}

void
ikev2_createchild_responder_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
				 struct sockaddr *remote,
				 struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int type;
	struct ikev2_payload_header *p;
	struct ikev2_payload_header *nonce = 0;
	struct ikev2_payload_header *sa = 0;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	struct ikev2_payload_header *cfg = 0;
	rc_vchar_t *g_i = 0;
	rc_vchar_t *n_i = 0;
	int rekey_proto = 0;
	uint32_t rekey_spi = 0;
	struct ikev2_child_param child_param;
	struct ikev2_child_sa *old_child_sa = 0;
	unsigned int peer_grp = 0;	/* DH group of the KEi payload */
	uint32_t message_id;
	int err;

	ikev2_child_param_init(&child_param);

	/*
	 * expect
	 * HDR, SK {SA, Ni, [KEi], TSi, TSr}
	 *
	 * or (rekey IKE_SA)
	 * HDR, SK {SA(proposal proto=IKE), Ni, KEi}
	 *
	 * or (rekey CHILD_SA)
	 * HDR, SK {N(REKEY_SA), SA, Ni, [KEi]}
	 *
	 #ifdef notyet
	 * or
	 HDR, SK {IDi, [CERT,] [CERTREQ,]
	 [IDr,] AUTH, CP(CFG_REQUEST),
	 SAi2, TSi, TSr}
	 #endif
	 */
	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	ikev2_update_message_id(ike_sa, message_id, FALSE);

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = p;
			break;
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
		case IKEV2_PAYLOAD_TS_I:
			if (ts_i)
				goto duplicate;
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			if (ts_r)
				goto duplicate;
			ts_r = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (createchild_resp_recv_notify
			    (ike_sa, msg, remote, local, p, &child_param,
			     &rekey_proto, &rekey_spi)) {
				goto done;
			}
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
		case IKEV2_PAYLOAD_CONFIG:
			cfg = p;
			break;
		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto unsupported_critical_payload;
			}
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}

	if (ike_sa->mobike_update) {
		ike_sa->mobike_update = 0;
		ikev2_mobike_apply(ike_sa, remote, local);
	}

	{
		/* diagnostic: log the exact rekey request signature.
		 * peer_grp is only assigned below (in the `ke` block),
		 * so read the KEi group straight from the payload —
		 * printing the local here always shows 0 and has misled
		 * every reader into thinking iOS sent no KEi. */
		struct ikev2proposal *pr = 0;
		if (sa && get_payload_data_length(sa) > sizeof(struct ikev2proposal))
			pr = (struct ikev2proposal *)(((struct ikev2payl_sa *)sa) + 1);
		isakmp_log(ike_sa, local, remote, msg, PLOG_INFO, PLOGLOC,
		   "CREATE_CHILD_SA request: msgid=%u proto=%s rekey_proto=%d rekey_spi=0x%x KEi_grp=%u ts_i=%c ts_r=%c nonce=%c\n",
		   message_id,
		   (pr && pr->protocol_id == IKEV2PROPOSAL_IKE) ? "IKE" :
		   (pr && pr->protocol_id == IKEV2PROPOSAL_ESP) ? "ESP" : "?",
		   rekey_proto, rekey_spi,
		   ke ? get_uint16(&ke->ke_h.dh_group_id) : 0,
		   ts_i ? 'Y' : 'n', ts_r ? 'Y' : 'n', nonce ? 'Y' : 'n');
	}

	if (sa) {
		/* Request-side mirror of the response sa_hex diagnostic:
		 * the peer's exact proposal, so the next teardown can be
		 * diffed request vs response without reconstructing it
		 * from the pcap. */
		char hx[160];
		size_t hlen = get_payload_data_length(sa);
		size_t hl = hlen < sizeof(hx) / 2 ? hlen : sizeof(hx) / 2;
		size_t i;
		const u_char *dp = (const u_char *)(sa + 1);
		for (i = 0; i < hl && i * 2 + 2 < sizeof(hx); i++)
			snprintf(&hx[i * 2], 3, "%02x", dp[i]);
		hx[i * 2] = '\0';
		isakmp_log(ike_sa, local, remote, msg, PLOG_INFO, PLOGLOC,
			   "CREATE_CHILD_SA request SA_hex=%s\n", hx);
	}

	/* RFC 7296 1.3: every CREATE_CHILD_SA request carries SA and Ni;
	 * sa is dereferenced unconditionally below. */
	if (!sa || !nonce)
		goto malformed_message;

	/* check if rekeying IKE_SA */
	if (get_payload_data_length(sa) > sizeof(struct ikev2proposal) &&
	    ((struct ikev2proposal *)(((struct ikev2payl_sa *)sa) + 1))->protocol_id == IKEV2PROPOSAL_IKE) {
		isakmp_log(ike_sa, local, remote, msg, PLOG_INFO, PLOGLOC,
			   "received IKE_SA rekey request\n");
		if (!(sa && nonce && ke && !(ts_i || ts_r)))
			goto malformed_message;

		ikev2_rekey_ikesa_responder(msg, remote, local, ike_sa,
					    sa, ke, nonce);
		goto done;
	}

	/* otherwise, create or rekey child_sa */
	if (!(sa && nonce && ts_i && ts_r))
		goto malformed_message;

	if (ike_sa->state == IKEV2_STATE_DYING) {
		TRACE((PLOGLOC, "ike_sa expired already\n"));
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0,
					  IKEV2_NO_ADDITIONAL_SAS,
					  0, 0);
		goto done;
	}

	if (rekey_proto != 0) {
		/* rekey child_sa */

		/* (draft-eronen-ipsec-ikev2-clarifications-05.txt)
		 * NEW-1.3.3 Rekeying CHILD_SAs with the CREATE_CHILD_SA Exchange
		 *
		 * The CREATE_CHILD_SA request for rekeying a CHILD_SA is:
		 *
		 * Initiator                                 Responder
		 * -----------                               -----------
		 * HDR, SK {N, SA, Ni, [KEi],
		 * TSi, TSr}             -->
		 *
		 * The initiator sends SA offer(s) in the SA payload, a nonce in
		 * the Ni payload, optionally a Diffie-Hellman value in the KEi
		 * payload, and the proposed traffic selectors for the proposed
		 * CHILD_SA in the TSi and TSr payloads. When rekeying an existing
		 * CHILD_SA, the leading N payload of type REKEY_SA MUST be
		 * included and MUST give the SPI (as they would be expected in
		 * the headers of inbound packets) of the SAs being rekeyed.
		 *
		 * The CREATE_CHILD_SA response for rekeying a CHILD_SA is:
		 *
		 * <--    HDR, SK {SA, Nr, [KEr],
		 * TSi, TSr}
		 *
		 * The responder replies (using the same Message ID to respond)
		 * with the accepted offer in an SA payload, and a Diffie-Hellman
		 * value in the KEr payload if KEi was included in the request and
		 * the selected cryptographic suite includes that group.
		 *
		 * The traffic selectors for traffic to be sent on that SA are
		 * specified in the TS payloads in the response, which may be a
		 * subset of what the initiator of the CHILD_SA proposed.
		 */

		/* (draft-eronen-ipsec-ikev2-clarifications-05.txt)
		 * 5.4  SPI when rekeying a CHILD_SA
		 *
		 * Section 3.10.1 says that in REKEY_SA notifications, "The SPI field
		 * identifies the SA being rekeyed."
		 *
		 * Since CHILD_SAs always exist in pairs, there are two different SPIs.
		 * The SPI placed in the REKEY_SA notification is the SPI the exchange
		 * initiator would expect in inbound ESP or AH packets (just as in
		 * Delete payloads).
		 */

		old_child_sa =
			ikev2_find_child_sa_by_spi(ike_sa, rekey_proto,
						   rekey_spi, PEER);
		if (!old_child_sa) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "can't find corresponding child_sa for peer specified proto %d (%s) spi 0x%x\n",
				   rekey_proto,
				   (rekey_proto == IKEV2_NOTIFY_PROTO_AH ? "AH" :
				    rekey_proto == IKEV2_NOTIFY_PROTO_ESP ? "ESP" :
				    "(unknown)"),
				   rekey_spi);
		} else {
			/*
			 * RFC 9370 s2.2.4: if WE already rekeyed this
			 * child (CREATE_CHILD_SA completed) and our
			 * IKE_FOLLOWUP_KE series is still in progress,
			 * a concurrent peer rekey of the same SA must be
			 * answered with TEMPORARY_FAILURE (MUST).
			 */
			struct ikev2_child_sa *pending;

			for (pending = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
			     !IKEV2_CHILD_LIST_END(pending);
			     pending = IKEV2_CHILD_LIST_NEXT(pending)) {
#ifdef WITH_ADDKE
				{
					unsigned int rekey_proto;

					if (!pending->is_initiator ||
					    !pending->addke_pending)
						continue;
					/* RFC 9370 s2.2.4 MUST: if WE already
					 * rekeyed this child and our
					 * IKE_FOLLOWUP_KE series is still in
					 * progress, a concurrent peer rekey of
					 * the same SA must be answered
					 * TEMPORARY_FAILURE.  preceding_spi is
					 * OUR (MINE) inbound SPI; compare it in
					 * the same namespace by re-locking up
					 * the SA it replaces and testing it IS
					 * the child the peer rekey matched. */
					rekey_proto =
					    ikev2_child_rekey_proto(pending);
					if (rekey_proto != 0 &&
					    ikev2_find_child_sa_by_spi(ike_sa,
						rekey_proto,
						pending->preceding_spi,
						MINE) == old_child_sa) {
						isakmp_log(ike_sa, local, remote, msg,
						    PLOG_PROTOWARN, PLOGLOC,
						    "rekey collision: our ADDKE "
						    "rekey followup in progress for "
						    "spi 0x%x; TEMPORARY_FAILURE\n",
						    rekey_spi);
						(void)ikev2_respond_error(
						    ike_sa, msg, remote, local,
						    0, 0, 0,
						    IKEV2_TEMPORARY_FAILURE, 0, 0);
						goto done;
					}
				}
#endif
			}
			TRACE((PLOGLOC, "rekey request for child_sa %p\n",
			       old_child_sa));
			if (old_child_sa->rekey_inprogress) {
				TRACE((PLOGLOC, "rekey in progress already\n"));
				old_child_sa->rekey_duplicate = TRUE;
				old_child_sa->rekey_duplicate_message_id = message_id;
			}
			old_child_sa->rekey_inprogress = TRUE;
		}
	}

	if (ke) {
		struct algdef *dhdef;
		unsigned int dhlen;

		peer_grp = get_uint16(&ke->ke_h.dh_group_id);
		dhdef = ikev2_dhinfo(peer_grp);
		if (!dhdef) {
			/* Unsupported KEi group.  RFC 7296 3.3.2:
			 * tell the peer which group we would accept. */
			uint16_t code = 0;
			struct algdef *pref =
			    ike_sa->negotiated_sa ? ike_sa->negotiated_sa->dhdef : 0;

			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "KEi group %d not supported\n", peer_grp);
			++isakmpstat.invalid_ke_payload;
			if (pref)
				code = htons(pref->transform_id);
			(void)ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0,
						  IKEV2_INVALID_KE_PAYLOAD,
						  &code, sizeof(code));
			goto done;
		}

		dhlen = get_payload_length(&ke->header) -
			sizeof(struct ikev2payl_ke);
		if (dhlen != dh_value_len((struct dhgroup *)dhdef->definition)) {
			/* send repsonse INVALID_SYNTAX */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "invalid KE payload (data length %u != %zu)\n",
				   dhlen,
				   dh_value_len((struct dhgroup *)dhdef->definition));
			goto respond_invalid_syntax;
		}

		g_i = rc_vnew((uint8_t *)(ke + 1), dhlen);
	} else if (ikev2_need_pfs(ike_sa->rmconf) == RCT_BOOL_ON) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "PFS required but CREATE_CHILD_SA lacks KE payload\n");
		goto respond_invalid_syntax;
	}
	/* no KEi and PFS not required: KEYMAT = prf+(SK_d, Ni|Nr)
	 * (RFC 7296 2.17, 2.18) — dhdef binding is skipped below. */

	if (! old_child_sa &&
	    ikev2_config_required(ike_sa->rmconf) == RCT_BOOL_ON &&
	    !ike_sa->childless_established && !cfg) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "peer message lacks required Configuration payload\n");
		++isakmpstat.malformed_message;
		err = IKEV2_FAILED_CP_REQUIRED;
		goto fail;
	}
	if (old_child_sa && cfg) {
		/*
		 * I'm assuming that the allocated addresses are
		 * automatically inherited to the new child_sa.
		 */
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOWARN, PLOGLOC,
			   "rekey CHILD_SA request with Config payload is unsupported, ignoring Config payload\n");
		cfg = 0;
	}

	n_i = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_i)
		goto fail_nomem;

	/* responder-rekey diagnostic: dump the raw request nonce bytes
	 * so the exact Ni fed into KEYMAT (RFC 7296 2.17) is on record
	 * next to the CHILD keymat nonces fingerprint in
	 * ikev2_add_ipsec_sa.  A parse/length bug here would silently
	 * diverge KEYMAT from what iOS derives while every internal
	 * consistency check (DH recheck, nonce freshness) still
	 * passes -- matching the observed AUTH-child-works /
	 * every-rekey-fails signature. */
	if (n_i) {
		unsigned char hex[128];
		size_t i, off, n = n_i->l < 48 ? n_i->l : 48;
		for (i = 0, off = 0; i < n && off + 3 < sizeof(hex); i++) {
			snprintf((char *)&hex[off], 4, "%02x ",
			    ((u_char *)n_i->v)[i]);
			off += 3;
		}
		hex[off] = '\0';
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_DEBUG, PLOGLOC,
			   "CREATE_CHILD_SA request Ni len=%zu hex=%s\n",
			   n_i->l, hex);
	}

	/* responder-rekey diagnostic: dump the REQUEST's traffic
	 * selectors (SK-decrypted here) so a response TS mismatch is
	 * visible.  iOS rekeys with the selectors of the old child;
	 * if what we echo (lease/MY_NET) differs from what iOS asked
	 * for, iOS drops the new SA and deletes the IKE_SA. */
	if (ts_i && ts_r) {
		struct ikev2_payload_header *ph;
		uint8_t *p;
		unsigned char hex[128];
		size_t i, off, n;

		ph = (struct ikev2_payload_header *)ts_i;
		n = get_payload_length(ph);
		if (n > 64)
			n = 64;
		for (i = 0, off = 0, p = (uint8_t *)ph; i < n; i++) {
			if (off + 3 >= sizeof(hex))
				break;
			snprintf((char *)&hex[off], 4, "%02x ", p[i]);
			off += 3;
		}
		hex[off] = '\0';
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_DEBUG, PLOGLOC,
			   "CREATE_CHILD_SA request TSi hex=%s\n", hex);
		ph = (struct ikev2_payload_header *)ts_r;
		n = get_payload_length(ph);
		if (n > 64)
			n = 64;
		for (i = 0, off = 0, p = (uint8_t *)ph; i < n; i++) {
			if (off + 3 >= sizeof(hex))
				break;
			snprintf((char *)&hex[off], 4, "%02x ", p[i]);
			off += 3;
		}
		hex[off] = '\0';
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_DEBUG, PLOGLOC,
			   "CREATE_CHILD_SA request TSr hex=%s\n", hex);
	}

	/* responder-rekey diagnostic: dump the REQUEST's KEi bytes.
	 * g^ir is the one keymat input exclusive to rekeys; the AUTH
	 * child (which works) derives without it.  If iOS's KEi is not
	 * a valid P-256 point (or our g_ir does not match it), the
	 * derived ESP keys diverge -- iOS sends ESP that our kernel
	 * drops (observed: pcap shows ESP arriving on the new SPI,
	 * xfrm seq stays 0x0) and the data plane dies silently. */
	if (g_i) {
		unsigned char hex[256];
		size_t i, off;
		for (i = 0, off = 0; i < g_i->l && off + 3 < sizeof(hex); i++) {
			snprintf((char *)&hex[off], 4, "%02x ",
			    ((u_char *)g_i->v)[i]);
			off += 3;
		}
		hex[off] = '\0';
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_DEBUG, PLOGLOC,
			   "CREATE_CHILD_SA request KEi len=%zu hex=%s\n",
			   g_i->l, hex);
	}

	err = ikev2_create_child_responder(ike_sa, local, remote, message_id,
					   sa, ts_i, ts_r, cfg, g_i, n_i,
					   &child_param, TRUE,
					   peer_grp, old_child_sa);
	if (err) {
		/* ikev2_create_child_responder() increments isakmpstat */
		goto fail;
	}

	/*
	 * The new child_sa created by ikev2_create_child_responder()  must
	 * have its state set to GETSPI.  When the state transits to
	 * GETSPI_DONE, create_child_responder_send() gets called.
	 */

      done:
	if (g_i)
		rc_vfree(g_i);
	ikev2_child_param_destroy(&child_param);
	return;

      fail:
	if (err <= 0)
		err = IKEV2_INVALID_SYNTAX;
	/*
	 * The peer's rekey request failed — clear rekey_inprogress on
	 * the old child_sa (set in the REKEY_SA handling above), or it
	 * would never be rekeyed again (and its expire timer rescue
	 * paths all skip while the flag is stuck).
	 */
	if (old_child_sa && old_child_sa->rekey_inprogress) {
		old_child_sa->rekey_inprogress = FALSE;
		old_child_sa->rekey_duplicate = FALSE;
		ikev2_child_arm_expire(old_child_sa, 30);
	}
	if (err == IKEV2_INVALID_KE_PAYLOAD) {
		/*
		 * RFC 7296 §3.14.2: INVALID_KE_PAYLOAD carries the DH
		 * group we would accept in the Notify data.
		 */
		uint16_t code = htons((uint16_t)child_param.notify_code);
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0, err, &code, sizeof(code));
	} else
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0, err, 0, 0);
	goto done;

      fail_nomem:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	++isakmpstat.fail_process_packet;
	goto done;

      duplicate:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC,
		   "unnecessary duplicated payload (type %d)\n", type);
	++isakmpstat.duplicate_payload;

      respond_invalid_syntax:
	(void)ikev2_respond_error(ike_sa, msg, remote, local,
				  0, 0, 0, IKEV2_INVALID_SYNTAX, 0, 0);
	goto done;

      malformed_message:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC, "malforomed message\n");
	++isakmpstat.malformed_message;
	goto respond_invalid_syntax;

      unsupported_critical_payload:
	{
		uint8_t	code;

		code = type;
		(void)ikev2_respond_error(ike_sa, msg, remote, local,
					  0, 0, 0,
					  IKEV2_UNSUPPORTED_CRITICAL_PAYLOAD,
					  &code, sizeof(code));
	}
	goto done;
}

int
ikev2_push_natd_report(struct ikev2_sa *ike_sa, struct ikev2_payloads *payl)
{
	rc_vchar_t *n;
	int ret = -1;

	if (!ike_sa->natd_report)
		return 0;
	/*
	 * RFC 4555 §3.8: the initiator treats our NAT_DETECTION
	 * digests as a BINDING REPORT and compares the received
	 * DESTINATION_IP with the value from the previous response
	 * (INIT or last UPDATE_SA_ADDRESSES).  The check is a
	 * stability check on what we report we see - not a value
	 * equality check against the peer's own computation, and
	 * certainly not an echo of the peer's digests.
	 *
	 * Replay the digests we sent in the INIT reply unchanged,
	 * so a session that has not re-bound reports the same
	 * binding forever.  Recomputing per packet drifts when the
	 * NAT-T ports float 500->4500 (every probe then looks like
	 * a binding change); echoing the peer's own digests fails
	 * the same comparison, since the peer validates against OUR
	 * INIT values, not its own computation.  Honest change
	 * detection lives on the inbound side (peer-vs-previous-peer
	 * drift log); the outbound report exists to be STABLE.
	 *
	 * When the peer sent UPDATE_SA_ADDRESSES (an actual or
	 * suspected re-bind), re-pin the digests from the current
	 * endpoints before replaying: after a genuine address
	 * update the new baseline must track the new binding, and
	 * this message's reply carries the re-pinned values.
	 */
	if (ike_sa->mobike_update) {
		rc_vchar_t *hs, *hd;
		struct rc_addrlist *pub =
		    ikev2_natd_public_address(ike_sa->rmconf);

		if (!ike_sa->local || !ike_sa->remote)
			return -1;
		if (pub && pub->a.ipaddr)
			hs = natt_create_hash(ike_sa, pub->a.ipaddr, TRUE);
		else
			hs = natt_create_hash(ike_sa, ike_sa->local, TRUE);
		hd = natt_create_hash(ike_sa, ike_sa->remote, TRUE);
		if (!hs || !hd) {
			if (hs)
				rc_vfree(hs);
			if (hd)
				rc_vfree(hd);
			return -1;
		}
		memcpy(ike_sa->natd_init_src_hash, hs->v, 20);
		memcpy(ike_sa->natd_init_dst_hash, hd->v, 20);
		rc_vfree(hs);
		rc_vfree(hd);
		ike_sa->mobike_update = 0;
	}
	n = ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE, 0, 0,
				 IKEV2_NAT_DETECTION_SOURCE_IP,
				 ike_sa->natd_init_src_hash, 20);
	if (!n)
		goto end;
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY, n, TRUE);
	n = ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE, 0, 0,
				 IKEV2_NAT_DETECTION_DESTINATION_IP,
				 ike_sa->natd_init_dst_hash, 20);
	if (!n)
		goto end;
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY, n, TRUE);
	ret = 0;

      end:
	return ret;
}

void
ikev2_createchild_responder_send(struct ikev2_sa *ike_sa,
				 struct ikev2_child_sa *child_sa)
{
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
	   "CREATE_CHILD_SA response: msgid=%u child=%p dhgrp=%u dhpub=%s state=%d\n",
	   child_sa->message_id, child_sa,
	   child_sa->dhgrp ? child_sa->dhgrp->transform_id : 0,
	   child_sa->dhpub ? "Y" : "n", child_sa->state);

	rc_vchar_t *sa = 0;
	rc_vchar_t *ke = 0;
	struct ikev2_payloads payl;
	rc_vchar_t *pkt;

	/*
	 * send HDR, SK {[N(IPCOMP_SUPPORTED)],
	 *               [N(USE_TRANSPORT_MODE)],
	 *               [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
	 *               [N(NON_FIRST_FRAGMENTS_ALSO)],
	 *               SA, Nr, [KEr], TSi, TSr,
	 *               [N(ADDITIONAL_TS_POSSIBLE)]
	 */

	ikev2_payloads_init(&payl);

	if (ike_sa->natd_report &&
	    (ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON ||
	     ikev2_nat_traversal(ike_sa->rmconf) == RCT_NATT_FORCE)) {
		/* RFC 7296 §2.23: NAT_DETECTION over this packet's
		 * endpoints (SRC=local, DST=remote), same as INIT. */
		if (ikev2_push_natd_report(ike_sa, &payl) < 0)
			isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOWARN, PLOGLOC,
				   "failed to add NAT_DETECTION "
				   "report for CREATE_CHILD_SA reply\n");
		else
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INFO, PLOGLOC,
				   "NAT_DETECTION report in "
				   "CREATE_CHILD_SA reply\n");
		ike_sa->natd_report = 0;
	}

	if (child_sa->state != IKEV2_CHILD_STATE_MATURE) {
		TRACE((PLOGLOC, "child state %d, aborting exchange\n",
		       child_sa->state));
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INVALID_SYNTAX,
							 0, 0),
				    TRUE);
		goto send_response;
	}

	/* re-offer ADDKE (type-6) in the CREATE_CHILD response: the response
	 * SA is packed straight from my_proposal, and the rekey branch may not
	 * reach ikev2_create_child_responder's own reoffer; cover it here so a
	 * peer that offered ADDKE (or addke_unrequested) gets type-6 echoed. */
	ikev2_child_maybe_reoffer_addke(child_sa);

	sa = ikev2_construct_sa(child_sa);
	if (!sa)
		goto fail;

	if (child_sa->dhpub) {
		struct ikev2payl_ke_h dhgrp_hdr;

		dhgrp_hdr.dh_group_id = htons(child_sa->dhgrp->transform_id);
		dhgrp_hdr.reserved = 0;
		ke = rc_vprepend(child_sa->dhpub, &dhgrp_hdr, sizeof(dhgrp_hdr));
		if (!ke)
			goto fail;
	}

	/*
	 * [CP(CFG_REPLY)]
	 */
	if (child_sa->child_param.cfg_payload)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG,
				    child_sa->child_param.cfg_payload, FALSE);

#ifdef notyet
	/*
	 * [N(IPCOMP_SUPPORTED)]
	 */
#endif

	/*
	 * [N(USE_TRANSPORT_MODE)]
	 */
	if (child_sa->child_param.use_transport_mode) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_USE_TRANSPORT_MODE,
							 0, 0),
				    TRUE);
	}

	/*
	 * [N(ESP_TFC_PADDING_NOT_SUPPORTED)]
	 */
	if (ikev2_esp_tfc_padding_not_supported) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_ESP_TFC_PADDING_NOT_SUPPORTED,
							 0, 0),
				    TRUE);
	}

#ifdef notyet
	/*
	 * [N(NON_FIRST_FRAGMENTS_ALSO)]
	 */
#endif

	/*
	 * RFC 9370 s2.2.4: when the CREATE_CHILD_SA selected an ADDKE
	 * transform, the response MUST carry the ADDITIONAL_KEY_EXCHANGE
	 * notification (16441) with responder-chosen link data; the
	 * initiator echoes it in the IKE_FOLLOWUP_KE request so we can
	 * associate the followup with this child.
	 */
	if (child_sa->addke_pending && child_sa->addke_link) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_ADDITIONAL_KEY_EXCHANGE,
							 child_sa->addke_link->v,
							 child_sa->addke_link->l),
				    TRUE);
		TRACE((PLOGLOC,
		       "ADDKE: attached ADDITIONAL_KEY_EXCHANGE link "
		       "(%zu bytes) to CREATE_CHILD_SA response\n",
		       child_sa->addke_link->l));
	}

	/*
	 * SA, Nr, [KEr], TSi, TSr
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NONCE, child_sa->n_r, FALSE);
	if (ke)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ke, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_I, child_sa->child_param.ts_i, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_R, child_sa->child_param.ts_r, FALSE);

#ifdef notyet
	if (param.additional_ts_possible)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_...,
							 IKEV2_ADDITIONAL_TS_POSSIBLE,
							 0, 0),
				    TRUE);
#endif

      send_response:
	ikev2_push_cookie2_echo(ike_sa, &payl);
	{
		int t_i;
		for (t_i = 0; t_i < payl.num; t_i++)
			isakmp_log(ike_sa, child_sa->parent->local, child_sa->parent->remote,
			    0, PLOG_DEBUG, PLOGLOC,
			    "CHILD_RESP payl[%d] type=%d len=%zu\n",
			    t_i, payl.payloads[t_i].type,
			    payl.payloads[t_i].data ? payl.payloads[t_i].data->l : 0);
		/*
		 * Responder-rekey diagnostics: dump the exact SA proposal
		 * we packed (transform types/ids, DH group, SPI) and the
		 * keymat inputs, so an iOS-instantiated rekey that ends in
		 * DELETE IKE_SA can be compared byte-for-byte against the
		 * request's accepted proposal.  The 07:00:40 run on
		 * 0ead7d5 was wire-clean yet iOS tore the IKE_SA down
		 * without ever sending ESP on the new child.
		 */
		if (sa) {
			char hx[128];
			size_t hl = sa->l < 40 ? sa->l : 40;
			size_t i;
			for (i = 0; i < hl && i * 2 + 2 < sizeof(hx); i++)
				snprintf(&hx[i * 2], 3, "%02x",
				    ((u_char *)sa->v)[i]);
			hx[i * 2] = '\0';
			isakmp_log(ike_sa, child_sa->parent->local, child_sa->parent->remote,
			    0, PLOG_DEBUG, PLOGLOC,
			    "CHILD_RESP SA len=%zu spi(prop+1)=0x%08x dhgrp_id=%u "
			    "n_i.len=%zu n_r.len=%zu g_ir.len=%zu%s%s%s "
			    "sa_hex=%s\n",
			    sa->l,
			    child_sa->my_proposal && child_sa->my_proposal[1] &&
			    child_sa->my_proposal[1]->prop ?
			    (unsigned)get_uint32(child_sa->my_proposal[1]->prop + 1) : 0,
			    child_sa->dhgrp ? child_sa->dhgrp->transform_id : 0,
			    child_sa->n_i ? child_sa->n_i->l : 0,
			    child_sa->n_r ? child_sa->n_r->l : 0,
			    child_sa->g_ir ? child_sa->g_ir->l : 0,
			    child_sa->dhpub ? " dhpub=Y" : "",
			    child_sa->g_ir ? " g_ir=Y" : "",
			    child_sa->peer_proposal ? " peer_prop=Y" : "",
			    hx);
		}
		/*
		 * Dump the exact bytes we are about to put on the wire
		 * beyond the SA: KEr (dhgrp_hdr + dhpub), TSi, TSr.
		 * These are the only remaining unlogged response fields;
		 * a responder-rekey death (09:08 / 11:55) with clean SA
		 * and keymat hashes makes the TS/KEr content the last
		 * byte-level suspect.
		 */
		{
			char hx[160];
			size_t i;
			struct {
				const char *tag;
				rc_vchar_t *d;
			} dump[] = {
				{ "KEr", ke },
				{ "TSi", child_sa->child_param.ts_i },
				{ "TSr", child_sa->child_param.ts_r },
			};
			size_t d_i;
			for (d_i = 0; d_i < sizeof(dump) / sizeof(dump[0]);
			    d_i++) {
				rc_vchar_t *d = dump[d_i].d;
				size_t hl;
				if (!d) {
					isakmp_log(ike_sa,
					    child_sa->parent->local,
					    child_sa->parent->remote, 0,
					    PLOG_DEBUG, PLOGLOC,
					    "CHILD_RESP %s=NULL\n",
					    dump[d_i].tag);
					continue;
				}
				hl = d->l < (sizeof(hx) - 1) / 2 ? d->l
				    : (sizeof(hx) - 1) / 2;
				for (i = 0; i < hl && i * 2 + 2 < sizeof(hx);
				    i++)
					snprintf(&hx[i * 2], 3, "%02x",
					    ((u_char *)d->v)[i]);
				hx[i * 2] = '\0';
				isakmp_log(ike_sa, child_sa->parent->local,
				    child_sa->parent->remote, 0, PLOG_DEBUG,
				    PLOGLOC,
				    "CHILD_RESP %s len=%zu hex(<=%zu)=%s\n",
				    dump[d_i].tag, d->l, hl, hx);
			}
		}
		if (child_sa->peer_proposal) {
			struct prop_pair *pr;
			unsigned pn = 0;
			for (pr = child_sa->peer_proposal; pr;
			     pr = pr->next, pn++) {
				struct prop_pair *t2;
				isakmp_log(ike_sa, child_sa->parent->local,
				    child_sa->parent->remote, 0, PLOG_DEBUG,
				    PLOGLOC,
				    "CHILD_RESP peer_prop[%u] proto=%d "
				    "spi_size=%d trns:",
				    pn,
				    pr->prop ? pr->prop->proto_id : -1,
				    pr->prop ? pr->prop->spi_size : -1);
				for (t2 = pr->tnext; t2; t2 = t2->next) {
					struct ikev2transform *tr =
					    (struct ikev2transform *)t2->trns;
					if (!tr)
						continue;
					isakmp_log(ike_sa,
					    child_sa->parent->local,
					    child_sa->parent->remote, 0,
					    PLOG_DEBUG, PLOGLOC,
					    "  type=%u id=%u len=%u\n",
					    tr->transform_type,
					    get_uint16(&tr->transform_id),
					    get_uint16(&tr->transform_length));
				}
			}
		}
	}
	pkt = ikev2_packet_construct(IKEV2EXCH_CREATE_CHILD_SA,
				     (ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0) |
				     IKEV2FLAG_RESPONSE, child_sa->message_id,
				     ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, child_sa->parent->local, child_sa->parent->remote) != 0)
		goto fail;

      done:
	if (ke)
		rc_vfree(ke);
	if (sa)
		rc_vfree(sa);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending CREATE_CHILD response for internal error\n");
	++isakmpstat.fail_send_packet;
	/* no way to recover.  should abort? */
	goto done;
}

/*
 * compare nonce
 * (to determine lowest of nonces.  draft-17 section 2.8)
 */
int
ikev2_noncecmp(rc_vchar_t *n1, rc_vchar_t *n2)
{
	size_t len;
	int result;

	len = (n1->l < n2->l) ? n1->l : n2->l;
	result = memcmp(n1->v, n2->v, len);
	if (result != 0)
		return result;
	if (n1->l < n2->l)
		return -1;
	if (n1->l > n2->l)
		return 1;
	return 0;
}

/*
 * Map a child's preceding_satype (the SA it is rekeying) to the IKE v2
 * proposal protocol id used to look that SA up.  0 when the child is not a
 * rekey.  Shared by ikev2_initiator_rekey_finalize() and the RFC 9370
 * §2.2.4 rekey-collision check so the two never drift.
 */
static unsigned int
ikev2_child_rekey_proto(struct ikev2_child_sa *child_sa)
{
	if (child_sa->preceding_satype == 0)
		return 0;
	return (child_sa->preceding_satype == RCT_SATYPE_ESP ?
		IKEV2PROPOSAL_ESP : IKEV2PROPOSAL_AH);
}

/*
 * RFC 7296 §2.8 initiator rekey finalize, shared by the plain CREATE_CHILD
 * finalize path (ikev2_createchild_initiator_recv) and the ADDKE completion
 * (ikev2_initiator_followup_complete, after the IKE_FOLLOWUP_KE installs the
 * rekeyed child with the KEM keymat).  The replaced (preceding) SA is cleared
 * once the new child is live.  On a rekey collision it follows the draft-17
 * rule: keep both NEW SAs briefly and the one created with the lowest of the
 * four nonces is closed by the endpoint that created it — here we close our
 * just-rekeyed child if it loses, otherwise leave both (the duplicate's
 * creator clears its own).  The caller decides whether to call us at all:
 * the plain path defers while addke_pending so the followup can install the
 * KEM child first.
 */
void
ikev2_initiator_rekey_finalize(struct ikev2_sa *ike_sa,
			       struct ikev2_child_sa *child_sa)
{
	struct ikev2_child_sa *old_child_sa;
	struct ikev2_child_sa *duplicate_child_sa;

	if (ikev2_child_rekey_proto(child_sa) == 0)
		return;

	old_child_sa = ikev2_find_child_sa_by_spi(ike_sa,
	    ikev2_child_rekey_proto(child_sa),
	    child_sa->preceding_spi, MINE);
	if (old_child_sa == NULL) {
		TRACE((PLOGLOC,
		       "can't find preceding sa satype %d spi 0x%x\n",
		       child_sa->preceding_satype,
		       child_sa->preceding_spi));
		return;
	}

	if (old_child_sa->rekey_duplicate) {
		/*
		 * (draft-17) A rekey collision may temporarily create two
		 * similar SAs; accept packets through either, and the SA
		 * created with the lowest of the four nonces used in the two
		 * exchanges SHOULD be closed by the endpoint that created it.
		 */
		duplicate_child_sa =
		    ikev2_find_child_sa(ike_sa,
					TRUE,
					old_child_sa->rekey_duplicate_message_id);
		if (duplicate_child_sa == NULL) {
			TRACE((PLOGLOC,
			       "can't find duplicate child_sa (message_id 0x%08x\n",
			       old_child_sa->rekey_duplicate_message_id));
		} else {
			rc_vchar_t *n1;
			rc_vchar_t *n2;

			TRACE((PLOGLOC, "checking duplicate...\n"));
			n1 = (ikev2_noncecmp(child_sa->n_i, child_sa->n_r) < 0) ?
			    child_sa->n_i :
			    child_sa->n_r;
			n2 = (ikev2_noncecmp(duplicate_child_sa->n_i,
					     duplicate_child_sa->n_r) < 0) ?
			    duplicate_child_sa->n_i :
			    duplicate_child_sa->n_r;
			if (ikev2_noncecmp(n1, n2) < 0) {
				/* our just-rekeyed child has the lowest
				 * nonce: close it (RFC 7296 §2.8.2) */
				TRACE((PLOGLOC, "need initiating delete\n"));
				ikev2_child_delete(child_sa);
			} else {
				TRACE((PLOGLOC, "leave it\n"));
			}
		}
		return;
	}

	/*
	 * RFC 7296 2.8: "when the new one is established, delete the old
	 * one".  The rekey initiator deletes the replaced child SA once the
	 * new SA is live; ikev2_child_delete() sends the DELETE payload (old
	 * SPI) via an Informational exchange and removes the inbound SADB
	 * now, outbound when the response arrives.  Skipping this left the
	 * old SA resident and iOS deleted the IKE_SA ~30 s after every
	 * completed rekey.
	 */
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
	    "rekey complete: deleting old child spi=0x%08x\n",
	    child_sa->preceding_spi);
	ikev2_child_delete(old_child_sa);
}

void
ikev2_createchild_initiator_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
				 struct sockaddr *remote,
				 struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	struct ikev2_payload_header *p;
	int type;
	struct ikev2_payload_header *nonce = 0;
	struct ikev2_payload_header *sa = 0;
	struct ikev2payl_ke *ke = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	rc_vchar_t *n_r;
	rc_vchar_t *g_r = 0;
	struct ikev2_child_param child_param;
	struct ikev2_child_sa *child_sa;

	ikev2_child_param_init(&child_param);

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	child_sa = ikev2_find_request(ike_sa, message_id);
	if (child_sa && child_sa->state == IKEV2_CHILD_STATE_REQUEST_SENT) {
		if (child_sa->callback) {
			child_sa->callback(REQUEST_CALLBACK_RESPONSE,
					   child_sa, msg);
		} else {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTWARN, PLOGLOC,
				   "no callback defined for response\n");
		}
		goto done;
	}
	if (!child_sa
	    || child_sa->state != IKEV2_CHILD_STATE_WAIT_RESPONSE)
		goto unexpected;
	/* commit the window only on a real WAIT_RESPONSE match (mirrors the
	 * informational_initiator_recv fix in d627063): a duplicate or
	 * unknown CREATE_CHILD response must not stop retransmit of the
	 * request actually in flight (review 2026-09-24). */
	ikev2_update_message_id(ike_sa, message_id, TRUE);

#ifdef notyet
	if (Notify) {

	}
#endif

	/*
	 * expect HDR, SK {SA, Nr, [KEr], TSi, TSr}
	 */
	/* optional N(ADDITIONAL_TS_POSSIBLE) */
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_NONCE:
			if (nonce)
				goto duplicate;
			nonce = p;
			break;
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
		case IKEV2_PAYLOAD_TS_I:
			if (ts_i)
				goto duplicate;
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			if (ts_r)
				goto duplicate;
			ts_r = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (createchild_init_recv_notify
			    (ike_sa, p, &child_param, child_sa) < 0) {
				goto done;
			}
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;

		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto unsupported_critical_payload;
			}
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}

	if (!(sa && nonce && ts_i && ts_r))
		goto malformed_message;

	n_r = isakmp_p2v((struct isakmp_gen *)nonce);
	if (!n_r)
		goto fail;

	if (child_sa->n_r)
		goto fail;
	child_sa->n_r = n_r;

	if (child_sa->dhpriv) {
		struct algdef *dhdef;
		unsigned int dhlen;

		if (!ke)
			goto malformed_message;
		dhdef = child_sa->dhgrp;
		if (!dhdef)
			dhdef = ikev2_dhinfo(get_uint16(&ke->ke_h.dh_group_id));
		if (!dhdef)
			goto malformed_message;

		if (get_uint16(&ke->ke_h.dh_group_id) != dhdef->transform_id) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "received KE type %d, expected %d\n",
				   get_uint16(&ke->ke_h.dh_group_id),
				   dhdef->transform_id);
			++isakmpstat.unexpected_payload;	/* ??? */
			goto abort;
		}
		dhlen = get_payload_length(&ke->header) -
			sizeof(struct ikev2payl_ke);
		if (dhlen != dh_value_len((struct dhgroup *)dhdef->definition)) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_INTERR, PLOGLOC,
				   "invalid KE payload (data length %u != %zu)\n",
				   dhlen,
				   dh_value_len((struct dhgroup *)dhdef->definition));
			++isakmpstat.malformed_payload;
			goto abort;
		}

		dhlen = get_payload_length(&ke->header) -
			sizeof(struct ikev2payl_ke);
		g_r = rc_vnew((uint8_t *)(ke + 1), dhlen);
		if (oakley_dh_compute((struct dhgroup *)dhdef->definition,
				      child_sa->dhpub, child_sa->dhpriv,
				      g_r, &child_sa->g_ir) != 0) {
			TRACE((PLOGLOC, "failed dh_compute\n"));
			goto fail;
		}
	}

	ikev2_update_child(child_sa, sa, ts_i, ts_r, &child_param);

	/*
	 * RFC 9370 s2.2.4: an ADDKE child rekey defers the keymat/XFRM
	 * install inside ikev2_update_child() until the IKE_FOLLOWUP_KE
	 * supplies SK(1).  The rekey must NOT be finalized here while
	 * the child is still addke_pending: deleting the old child now
	 * would tear down the live SA before the followup installs the
	 * rekeyed one (SA interruption; and if the followup were lost
	 * the child would be left dead).  The old-child delete and
	 * "rekey complete" are deferred to the ADDKE completion
	 * (ikev2_initiator_followup_complete).
	 */
	if (child_sa->preceding_satype != 0 && !child_sa->addke_pending)
		ikev2_initiator_rekey_finalize(ike_sa, child_sa);

      done:
	if (g_r)
		rc_vfree(g_r);
	ikev2_child_param_destroy(&child_param);

	/* if there are still more pending request, start it */
	child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (child_sa)
		ikev2_wakeup_child_sa(child_sa);

	return;

      abort:
	if (child_sa)
		ikev2_child_abort(child_sa, ECONNREFUSED); /* ??? */
	goto done;

      malformed_message:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC, "packet lacks expected payload\n");
	++isakmpstat.malformed_message;
	goto abort;
      duplicate:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC, "unexpected duplicated payloads\n");
	++isakmpstat.duplicate_payload;
	goto abort;
      unexpected:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC, "unexpected message\n");
	++isakmpstat.unexpected_packet;
	goto abort;

      unsupported_critical_payload:
	goto abort;

      fail:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing CREATE_CHILD_SA response for internal error\n");
	++isakmpstat.fail_process_packet;
	goto abort;
}

/*
 * RFC 4555 §3.7: the peer listed additional addresses.  When the
 * current path's retransmits are exhausted, probe the next same-family
 * address with COOKIE2 before aborting the SA.  Do not migrate the
 * kernel SAs until that COOKIE2 comes back matching.
 * Returns 1 if a probe was armed, 0 if there is nothing left to try.
 */



/*
 * Dead Peer Detection
 */
void
ikev2_poll(struct ikev2_sa *ike_sa)
{
	struct ikev2_payloads *payl;

	TRACE((PLOGLOC, "ikev2_poll(%p)\n", ike_sa));

	payl = racoon_malloc(sizeof(struct ikev2_payloads));
	ikev2_payloads_init(payl);
	ikev2_informational_initiator_notify(ike_sa, payl);
}

/*
 * parse a SA payload
 */
struct prop_pair **
ikev2_parse_sa(struct isakmp_domain *doi,
	       struct ikev2_payload_header *sa_payload)
{
	struct ikev2payl_sa *sa = (struct ikev2payl_sa *)sa_payload;
	size_t proposal_bytes;
	uint8_t *prop;
	int err;

	proposal_bytes =
		get_payload_length(sa_payload) -
		sizeof(struct ikev2_payload_header);
	prop = (uint8_t *)(sa + 1);
	err = isakmp_check_proposal_syntax(doi, prop, proposal_bytes);
	if (err)
		return 0;

	return isakmp_parse_proposal(doi, prop, proposal_bytes);
}

/*
 * ikev2_check_spi_size() called from isakmp_check_proposal_syntax()
 * through ikev2_doi struct
 */
int
ikev2_check_spi_size(struct isakmp_domain *doi, int proto_id, int spi_size)
{
	/* (draft-ietf-ipsec-ikev2-17)
	 * o  SPI Size (1 octet) - For an initial IKE_SA negotiation,
	 * this field MUST be zero; the SPI is obtained from the
	 * outer header. During subsequent negotiations,
	 * it is equal to the size, in octets, of the SPI of the
	 * corresponding protocol (8 for IKE, 4 for ESP and AH).
	 */
	switch (proto_id) {
	case IKEV2PROPOSAL_IKE:
		if (spi_size != doi->ike_spi_size)
			return -1;
		break;

	case IKEV2PROPOSAL_AH:
	case IKEV2PROPOSAL_ESP:
		if (spi_size != sizeof(uint32_t))
			return -1;
		break;

	default:
		return -1;
	}

	return 0;
}

struct ikev2_isakmpsa *
ikev2_proppair_to_isakmpsa(struct prop_pair *prop)
{
	struct ikev2_isakmpsa *s;
	struct prop_pair *p;
	size_t attr_bytes;
	size_t attr_len;
	struct isakmp_data *attr;

	if (!prop)
		return 0;
	assert(prop->prop);
	assert(prop->prop->proto_id == IKEV2PROPOSAL_IKE);

	s = racoon_calloc(1, sizeof(struct ikev2_isakmpsa));
	if (!s)
		return 0;

	s->prop_no = prop->prop->p_no;
	/* s->trns_no = 0; *//* no transform # in IKEv2 */

	for (p = prop->tnext; p; p = p->next) {
		struct ikev2transform *transf =
			(struct ikev2transform *)p->trns;

		switch (transf->transform_type) {
		case IKEV2TRANSFORM_TYPE_ENCR:
			s->encr = get_uint16(&transf->transform_id);
			break;
		case IKEV2TRANSFORM_TYPE_PRF:
			s->prf = get_uint16(&transf->transform_id);
			/* XXX PRF may be variable key length? */
			/* (RFC4306)
			 * The only algorithms defined in this
			 * document that accept attributes are the
			 * AES-based encryption, integrity, and
			 * pseudo-random functions, which require a
			 * single attribute specifying key width.
			 */
			/*
			 * The only AES-based prf defined so far is
			 * PRF_AES128_XCBC (AES-XCBC-PRF-128), which
			 * is fixed (128bits) key length.
			 */
			/*
			 * RFC4434 redefined AES-XCBC-PRF-128 with
			 * arbitrary length key, with natural key
			 * length of 128bits.  It is similar to HMAC
			 * algorithms and key length attribute should
			 * not exist.
			 */
			break;
		case IKEV2TRANSFORM_TYPE_INTEGR:
			s->integr = get_uint16(&transf->transform_id);
			/* XXX key length? */
			/* AES-XCBC-MAC-96 is fixed key length (128bits) */
			break;
		case IKEV2TRANSFORM_TYPE_DH:
			s->dhdef =
				ikev2_dhinfo(get_uint16(&transf->transform_id));
			break;
		case IKEV2TRANSFORM_TYPE_ADDKE:
			/* RFC 9370: remember which ADDKE method the peer
			 * proposed so the IKE-rekey response can echo it. */
			s->addke = get_uint16(&transf->transform_id);
			break;
		default:
			isakmp_log(0, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "unknown transform type (%d)\n",
				   transf->transform_type);
			goto fail;
			break;
		}

		attr_bytes =
			get_uint16(&transf->transform_length) -
			sizeof(struct ikev2transform);
		if (attr_bytes > 0) {
			int keylen = 0;

			attr = (struct isakmp_data *)(transf + 1);
			for (; attr_bytes > 0; attr_bytes -= attr_len) {
				attr_len = ISAKMP_ATTRIBUTE_TOTALLENGTH(attr);
				switch (get_uint16(&attr->type)) {
				case IKEV2ATTRIB_KEY_LENGTH | IKEV2ATTRIB_SHORT:
					keylen = get_uint16(&attr->lorv);
					/* if (keylen == 0) ??? */
					break;
				default:
					/* unrecognized attribute. */
					plog(PLOG_PROTOERR, PLOGLOC, 0,
					     "unknown attribute type %d\n",
					     get_uint16(&attr->type));
					break;
				}
				attr = ISAKMP_NEXT_ATTRIB(attr);
			}

			if (transf->transform_type == IKEV2TRANSFORM_TYPE_ENCR
			    && keylen != 0) {
				switch (s->encr) {
					/* XXX CAST, BLOWFISH, RC5??? */
				case IKEV2TRANSF_ENCR_AES_CBC:
				case IKEV2TRANSF_ENCR_AES_CTR:
				case IKEV2TRANSF_ENCR_AES_GCM_ICV8:
				case IKEV2TRANSF_ENCR_AES_GCM_ICV12:
				case IKEV2TRANSF_ENCR_AES_GCM_ICV16:
				case IKEV2TRANSF_ENCR_AES_CCM_8:
				case IKEV2TRANSF_ENCR_AES_CCM_12:
				case IKEV2TRANSF_ENCR_AES_CCM_16:
					s->encrklen = keylen;
					break;
				default:
					/* should report error? */
					plog(PLOG_PROTOERR, PLOGLOC, 0,
					     "unexpected key-length attribute in proposal\n");
					break;
				}
			} else if (keylen != 0) {
				/* should report error */
				plog(PLOG_PROTOERR, PLOGLOC, 0,
				     "unexpected key-length attribute in proposal\n");
				goto fail;
			}
		}
	}

	return s;

      fail:
	racoon_free(s);
	return 0;
}

/*
 * compare proposals and return a matching one
 */
struct prop_pair *
ikev2_find_match(struct prop_pair **my_proposal,
		 struct prop_pair **peer_proposal, enum peer_mine which_spi)
{
	return isakmp_find_match(&ikev2_doi, my_proposal, peer_proposal,
				 which_spi);
}

/*
 * parse SA payload and return proposal that matches with remote_info
 *
 * XXX get_ph1approval()
 */
struct ikev2_isakmpsa *
ikev2_find_match_ikesa(struct rcf_remote *rminfo,
		       struct prop_pair **peer_proposal, isakmp_cookie_t *spi,
		       int allow_init_addke)
{
	struct ikev2_isakmpsa *result = 0;
	struct prop_pair **my_proposal = 0;
	struct prop_pair *matched_proposal = 0;

	my_proposal = ikev2_conf_to_proplist(rminfo, 0);
	if (!my_proposal)
		goto fail;

#ifdef WITH_INTERMEDIATE
	/* RFC 9370 s2.2.1: a peer type-6/ADDKE on the INITIAL IKE_SA is only
	 * actionable when IKE_INTERMEDIATE (16438) was negotiated
	 * (allow_init_addke).  Without it we must NOT select-and-strip ADDKE
	 * (which would answer a peer's ADDKE proposal with an SAr1 that drops
	 * type-6 -- the peer treats that as a failed exchange).  Skip such
	 * proposals so a later classical fallback (the peer's own #2/#3)
	 * matches and SAr1 stays classical.  Match against a filtered COPY so
	 * the caller's peer_proposal array is left untouched. */
	if (!spi && !allow_init_addke) {
		struct prop_pair *filtered[MAXPROPPAIRLEN];
		int fp;
		memset(filtered, 0, sizeof(filtered));
		for (fp = 0; fp < MAXPROPPAIRLEN; ++fp) {
			struct prop_pair *np = peer_proposal ? peer_proposal[fp] : NULL;
			struct prop_pair *tr;
			int has_addke = 0, has_classic = 0;
			if (!np)
				continue;
			/* RFC 9370 s2.2.1: the peer offered type-6/ADDKE on the
			 * initial IKE_SA but did NOT negotiate IKE_INTERMEDIATE
			 * (no 16438), so its ADDKE must not be actioned.  The
			 * ADDKE transform may be a *separate* proposal (drop it)
			 * or appended INTO the classical proposal (racoon2's
			 * ikev2_maybe_offer_ikesa_addke keeps it with the
			 * ENCR/PRF/DH); the latter must still match classically
			 * by ignoring the type-6 transform, or the whole SA is
			 * rejected with "no proposal chosen".  Keep any proposal
			 * that retains a usable non-ADDKE (classical) anchor;
			 * drop only pure-ADDKE proposals.  The addke-recording
			 * block below is gated on (spi || allow_init_addke), so
			 * a kept type-6 transform cannot arm ADDKE here. */
			for (tr = np->tnext; tr; tr = tr->next) {
				struct ikev2transform *t =
				    (struct ikev2transform *)tr->trns;
				unsigned int tt = t ? t->transform_type : 0;
				if (tt == IKEV2TRANSFORM_TYPE_ADDKE)
					has_addke = 1;
				else
					has_classic = 1;
			}
			if (has_classic)
				filtered[fp] = np; /* classical anchor: keep */
		}
		matched_proposal = ikev2_find_match(my_proposal, filtered, 0);
	} else
#endif
	matched_proposal = ikev2_find_match(my_proposal, peer_proposal, 0);
	if (!matched_proposal)
		goto no_match;

	if (spi) {
		if (matched_proposal->prop->spi_size != sizeof(isakmp_cookie_t)) {
			TRACE((PLOGLOC, "unexpected: no SPI in proposal\n"));
			goto done;
		}
		memcpy(spi, matched_proposal->prop + 1,
		       sizeof(isakmp_cookie_t));
	}

	result = ikev2_proppair_to_isakmpsa(matched_proposal);

#ifdef WITH_ADDKE
	/*
	 * The isakmpsa above was built from the MINE-side copy.  Type-6
	 * on the initial IKE_SA is offered only via
	 * ikev2_maybe_offer_ikesa_addke() when WITH_INTERMEDIATE is on;
	 * a classical IKE proposal still has no type-6.  If the peer
	 * offered ADDKE in this proposal, record the method so the
	 * IKE-rekey response echoes it and the SKEYSEED deferral arms.
	 */
	if (result && (spi != NULL || allow_init_addke)) {

		/* On the INITIAL IKE_SA (allow_init_addke), ADDKE/type-6
		 * requires the IKE_INTERMEDIATE round, which needs an AEAD
		 * IKE cipher (IntAuth_A is deterministic only for AEAD;
		 * without 16438 echoed, INIT stays classical).  When the
		 * negotiated ENCR is not AEAD (we matched a CBC proposal),
		 * do NOT echo type-6 -- keep the SA classical so iOS default
		 * profiles that offer interim + ADDKE as their preferred
		 * progressive path fall back to a plain IKE_AUTH instead of
		 * aborting a type-6-committed CBC SA.  The IKE_SA-rekey path
		 * (spi != NULL) records ADDKE independently (FOLLOWUP_KE).
		 */
		if (spi == NULL) {
			unsigned int _e = result->encr;
			if (!ikev2_encr_is_aead(_e))
				goto done;	/* keep INIT classical */
		}

		/* Type-6 on the INITIAL IKE_SA is recorded only when the
		 * caller passes allow_init_addke (16438 negotiated); the
		 * IKE_SA-rekey path (spi != NULL) records it independently so
		 * FOLLOWUP_KE can run.  Without 16438, INIT stays classical. */
		/* RFC 9370: record the SELECTED ADDKE method from the matched
		 * peer proposal only.  isakmp_find_match already decided it and
		 * stamped the ACCEPTED peer p_no (isakmp.c found_match, MINE
		 * case) into matched_proposal->prop->p_no (1-based).  CRITICAL:
		 * peer_proposal[] is indexed by prop->p_no DIRECTLY (1-based,
		 * from isakmp_parse_proposal); slot 0 is always the NULL
		 * sentinel.  peer_proposal[_pno-1] would read slot 0 for the
		 * first proposal and lose type-6 (regression: classical SAr1,
		 * no 16438 echo, no IKE_INTERMEDIATE round).  A type-6 on a
		 * NON-matched proposal must never seed result->addke -- it
		 * would grow SAr1 a type-6 the match never selected. */
		if (matched_proposal) {
			unsigned int _pno = matched_proposal->prop->p_no;
			if (_pno >= 1 && _pno < MAXPROPPAIRLEN) {
				struct prop_pair *mp = peer_proposal ?
				    peer_proposal[_pno] : NULL;
				struct prop_pair *tr;
				for (tr = mp ? mp->tnext : NULL; tr; tr = tr->next) {
					struct ikev2transform *t =
					    (struct ikev2transform *)tr->trns;
					if (t && t->transform_type ==
						    IKEV2TRANSFORM_TYPE_ADDKE) {
						result->addke =
						    get_uint16(&t->transform_id);
						break;
					}
				}
			}
		}
	}
#endif

      done:
	if (matched_proposal)
		proppair_discard(matched_proposal);
	if (my_proposal)
		proplist_discard(my_proposal);
	return result;

      fail:
      no_match:		/* should return error code */
	goto done;

	/* (draft-17)
	 * The responder MUST choose a single suite, which MAY be
	 * any subset of the SA proposal following the rules below:
	 *
	 *
	 * Each proposal contains one or more protocols. If a proposal is
	 * accepted, the SA response MUST contain the same protocols in the
	 * same order as the proposal. The responder MUST accept a single
	 * proposal or reject them all and return an error. (Example: if a
	 * single proposal contains ESP and AH and that proposal is accepted,
	 * both ESP and AH MUST be accepted. If ESP and AH are included in
	 * separate proposals, the responder MUST accept only one of them).
	 *
	 * Each IPsec protocol proposal contains one or more transforms. Each
	 * transform contains a transform type. The accepted cryptographic
	 * suite MUST contain exactly one transform of each type included in
	 * the proposal. For example: if an ESP proposal includes transforms
	 * ENCR_3DES, ENCR_AES w/keysize 128, ENCR_AES w/keysize 256,
	 * AUTH_HMAC_MD5, and AUTH_HMAC_SHA, the accepted suite MUST contain
	 * one of the ENCR_ transforms and one of the AUTH_ transforms. Thus
	 * six combinations are acceptable.
	 */
}

static uint8_t *
ikev2_transform_header(uint8_t *p, uint8_t *prev, int len, int type, int id)
{
	struct ikev2transform *t;

	if (prev)
		*prev = IKEV2TRANSFORM_MORE;
	t = (struct ikev2transform *)p;
	t->more = IKEV2TRANSFORM_LAST;
	t->reserved1 = 0;
	put_uint16(&t->transform_length, len);
	t->transform_type = type;
	t->reserved2 = 0;
	put_uint16(&t->transform_id, id);

	return &t->more;
}

static int
ikev2_ikesa_to_proposal_sub(rc_vchar_t *buf, struct ikev2_isakmpsa *sa,
			    isakmp_cookie_t *spi)
{
	uint8_t *p = 0;
	uint8_t *prev = 0;
	struct ikev2proposal *prop = 0;
	int num_transf = 0;

	if (buf) {
		p = (uint8_t *)buf->v;
		prop = (struct ikev2proposal *)p;
	}
	p += sizeof(struct ikev2proposal);
	if (spi)
		p += sizeof(isakmp_cookie_t);

	/* ENCR */
	if (sa->encr != 0) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sa->encrklen == 0 ?
							  sizeof(struct ikev2transform) :
							  sizeof(struct ikev2transform) +
							      sizeof(struct ikev2attrib),
						      IKEV2TRANSFORM_TYPE_ENCR,
						      sa->encr);
		p += sizeof(struct ikev2transform);
		if (sa->encrklen > 0) {
			if (buf) {
				struct ikev2attrib *attrib;
				attrib = (struct ikev2attrib *)p;
				put_uint16(&attrib->type,
					   IKEV2ATTRIB_SHORT | IKEV2ATTRIB_KEY_LENGTH);
				put_uint16(&attrib->l_or_v, sa->encrklen);
			}
			p += sizeof(struct ikev2attrib);
		}
		++num_transf;
	}

	/* PRF */
	if (sa->prf != 0) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sizeof(struct ikev2transform),
						      IKEV2TRANSFORM_TYPE_PRF,
						      sa->prf);
		p += sizeof(struct ikev2transform);
		++num_transf;
	}

	/* INTEGR */
	if (sa->integr != 0) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sizeof(struct ikev2transform),
						      IKEV2TRANSFORM_TYPE_INTEGR,
						      sa->integr);
		p += sizeof(struct ikev2transform);
		++num_transf;
	}

	if (sa->dhdef) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sizeof(struct ikev2transform),
						      IKEV2TRANSFORM_TYPE_DH,
						      sa->dhdef->transform_id);
		p += sizeof(struct ikev2transform);
		++num_transf;
	}

	/* RFC 9370: echo the negotiated ADDKE method in the response
	 * SA (only present when the peer proposed type-6). */
	if (sa->addke != 0) {
		if (buf)
			prev = ikev2_transform_header(p, prev,
						      sizeof(struct ikev2transform),
						      IKEV2TRANSFORM_TYPE_ADDKE,
						      sa->addke);
		p += sizeof(struct ikev2transform);
		++num_transf;
	}

	if (buf) {
		prop->more = IKEV2PROPOSAL_LAST;
		prop->reserved = 0;
		put_uint16(&prop->proposal_length, p - (uint8_t *)buf->v);
		prop->proposal_number = sa->prop_no;
		prop->protocol_id = IKEV2PROPOSAL_IKE;
		if (spi) {
			prop->spi_size = sizeof(isakmp_cookie_t);
			memcpy((uint8_t *)(prop + 1), spi,
			       sizeof(isakmp_cookie_t));
		} else {
			prop->spi_size = 0;
		}
		prop->num_transforms = num_transf;
		return p - (uint8_t *)buf->v;
	} else {
		return p - (uint8_t *)0;
	}
}

rc_vchar_t *
ikev2_ikesa_to_proposal(struct ikev2_isakmpsa *negotiated_sa,
			isakmp_cookie_t *spi)
{
	rc_vchar_t *buf = 0;
	int len;

	len = ikev2_ikesa_to_proposal_sub(0, negotiated_sa, spi);
	if (len == 0)
		goto fail;

	buf = rc_vmalloc(len);
	if (!buf)
		goto fail;
	(void)ikev2_ikesa_to_proposal_sub(buf, negotiated_sa, spi);

	return buf;

      fail:
	plog(PLOG_INTERR, PLOGLOC, 0,
	     "failed creating proposal payload data\n");
	return 0;
}

/* (draft-17)
2.14 Generating Keying Material for the IKE_SA

       SKEYSEED = prf(Ni | Nr, g^ir)

       {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr }
                 = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr )

*/

/*
 * compute SKEYSEED
 *
 * INPUT:
 *	ike_sa:	prf
 *		authenticator, encryptor
 *		n_i, n_r for nonces
 *		skeyseed must be 0
 *
 * return 0 if success, non-zero if failure
 */
struct skey_job {
	struct ikev2_sa *ike_sa;
	int serial;
	rc_vchar_t *nonces;
	rc_vchar_t *g_ir;
	oakley_dh_done_t done;
	void *arg;
};

static void
compute_skeyseed_after_dh(int rc, void *arg)
{
	struct skey_job *s = arg;
	struct ikev2_sa *ike_sa;
	int out = rc;

	ike_sa = ikev2_find_sa_by_serial(s->serial);
	if (!ike_sa || ike_sa != s->ike_sa)
		out = -1;
	else if (rc == 0) {
		IF_TRACE({
			TRACE((PLOGLOC, "SKEYSEED inputs are nonces\n"));
			plogdump(PLOG_DEBUG, PLOGLOC, 0, s->nonces->v,
			    s->nonces->l);
			/* g_ir = g^ix is the DH shared secret from which
			 * SKEYSEED derives -- NEVER plogdump. */
		});
		ike_sa->skeyseed = keyed_hash(ike_sa->prf, s->nonces, s->g_ir);
		if (!ike_sa->skeyseed)
			out = -1;
		IF_TRACE({
			if (ike_sa->skeyseed) {
				TRACE((PLOGLOC,
				    "SKEYSEED = prf(nonces, g_ir)\n"));
				plogdump(PLOG_DEBUG, PLOGLOC, 0,
				    ike_sa->skeyseed->v, ike_sa->skeyseed->l);
			}
		});
	}
	if (out != 0 && ike_sa && ike_sa == s->ike_sa)
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		    "failed to calculate skeyseed\n");
	if (s->nonces)
		rc_vfree(s->nonces);
	if (s->g_ir)
		rc_vfreez(s->g_ir);
	{
		oakley_dh_done_t d = s->done;
		void *u = s->arg;

		free(s);
		if (d)
			d(out, u);
	}
}

int
compute_skeyseed_submit(struct ikev2_sa *ike_sa, oakley_dh_done_t done,
    void *arg)
{
	struct skey_job *s;
	struct keyed_hash *prf;
	size_t prf_keylen;
	size_t i_len;
	size_t r_len;
	uint8_t *p;
	struct dhgroup *dhgrpinfo;

	assert(ike_sa->n_i && ike_sa->n_r
	       && ike_sa->prf && ike_sa->authenticator && ike_sa->encryptor
	       && !ike_sa->skeyseed);

	s = calloc(1, sizeof(*s));
	if (!s)
		return -1;
	s->ike_sa = ike_sa;
	s->serial = ike_sa->serial_number;
	s->done = done;
	s->arg = arg;

	prf = ike_sa->prf;
	prf_keylen = prf->method->preferred_key_len;

	if ((!prf->method->is_variable_keylen ||
	     (prf->method == (struct keyed_hash_method *)&aes_xcbc_hash_method ||
	      prf->method == (struct keyed_hash_method *)&aes_cmac_hash_method))
	    && ike_sa->n_i->l + ike_sa->n_r->l != prf_keylen) {
		assert(prf_keylen % 2 == 0);
		i_len = prf_keylen / 2;
		r_len = prf_keylen / 2;
		assert(ike_sa->n_i->l >= i_len && ike_sa->n_r->l >= r_len);
	} else {
		i_len = ike_sa->n_i->l;
		r_len = ike_sa->n_r->l;
	}
	s->nonces = rc_vmalloc(i_len + r_len);
	if (!s->nonces)
		goto fail;
	p = (uint8_t *)s->nonces->v;
	memcpy(p, ike_sa->n_i->v, i_len);
	p += i_len;
	memcpy(p, ike_sa->n_r->v, r_len);

	dhgrpinfo = (struct dhgroup *)ike_sa->negotiated_sa->dhdef->definition;
	if (!dhgrpinfo)
		goto fail;

	if (oakley_dh_compute_submit(dhgrpinfo, ike_sa->dhpub, ike_sa->dhpriv,
	    ike_sa->dhpub_p, &s->g_ir, compute_skeyseed_after_dh, s) != 0)
		goto fail;
	return 0;

      fail:
	if (s->nonces)
		rc_vfree(s->nonces);
	free(s);
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to calculate skeyseed\n");
	return -1;
}

/* H2: free + cleanse a prior key-generation buffer before re-derivation.
 * rc_vfreez alone neither clears the bytes in -DDEBUG nor nulls the caller's
 * pointer (it is by-value and rc_free()s the container), so secret key
 * material must be OPENSSL_cleanse'd and the pointer explicitly nulled. */
static void
ikev2_cleanse_key_gen(rc_vchar_t **p)
{
	if (*p) {
		OPENSSL_cleanse((*p)->v, (*p)->l);
		rc_vfreez(*p);
		*p = 0;
	}
}

/*
 * compute SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
 *
 * INPUT:
 *	ike_sa:	ike_sa->prf
 *		ike_sa->{authenticator, encryptor} for key length requirement
 *		ike_sa->{n_i, n_r} for nonces
 *		ike_sa->index for SPIi, SPIr
 *		ike_sa->skeyseed
 *
 * OUTPUT:
 *	returns 0 if successful, non-0 if fails
 *	if successful, ike_sa->{sk_d,sk_a_i,sk_a_r,sk_e_i,sk_e_r,sk_p_i,sk_p_r} holds keys
 *	if fails, ike_sa does not change
 */

/* RFC 8784 s4.2: apply the PPK to an ALREADY-DERIVED key generation,
 * re-deriving SK_d/SK_pi/SK_pr as prf+(PPK, key).  Used only on the
 * FINAL generation, after all IKE_INTERMEDIATE ADDKE rounds have updated
 * SKEYSEED/SK_* (RFC 9867 s3.1.1: the PPK application is the LAST key
 * action before the keys are used in IKE_AUTH).  Skipped while
 * ppk_deferred is set so intermediate SKEYSEED(1)=prf(SK_d, ...) sees the
 * UN-PPK'd SK_d -- a responder cannot know the PPK until it sees
 * PPK_IDENTITY in IKE_AUTH.  Returns 0 on success, -1 on failure (SA must
 * be aborted).  ppk_active is never set on a rekeyed/resumed SA, so the
 * apply path is initial-SA only. */
int
ikev2_ppk_apply(struct ikev2_sa *ike_sa)
{
	rc_vchar_t *ppk = 0, *sk_d2 = 0, *sk_pi2 = 0, *sk_pr2 = 0;
	int sk_d_len, sk_p_len;

	if (!ike_sa->ppk_active)
		return 0;
	if (!ike_sa->sk_d || !ike_sa->sk_p_i || !ike_sa->sk_p_r)
		return -1;
	sk_d_len = ike_sa->sk_d->l;
	sk_p_len = ike_sa->sk_p_i->l;
	ppk = ikev2_ppk_load(ike_sa->rmconf);
	if (!ppk) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "RFC 8784: failed to load PPK for the "
			   "negotiated USE_PPK session\n");
		return -1;
	}
	sk_d2 = ikev2_prf_plus(ike_sa, ppk, ike_sa->sk_d, sk_d_len);
	sk_pi2 = ikev2_prf_plus(ike_sa, ppk, ike_sa->sk_p_i, sk_p_len);
	sk_pr2 = ikev2_prf_plus(ike_sa, ppk, ike_sa->sk_p_r, sk_p_len);
	OPENSSL_cleanse(ppk->v, ppk->l);
	rc_vfreez(ppk);
	ppk = 0;
	if (!sk_d2 || !sk_pi2 || !sk_pr2)
		goto fail;
	rc_vfreez(ike_sa->sk_d); ike_sa->sk_d = sk_d2;
	rc_vfreez(ike_sa->sk_p_i); ike_sa->sk_p_i = sk_pi2;
	rc_vfreez(ike_sa->sk_p_r); ike_sa->sk_p_r = sk_pr2;
	return 0;
fail:
	if (sk_d2)
		rc_vfreez(sk_d2);
	if (sk_pi2)
		rc_vfreez(sk_pi2);
	if (sk_pr2)
		rc_vfreez(sk_pr2);
	return -1;
}

int
ikev2_compute_keys(struct ikev2_sa *ike_sa)
{
	int sk_d_len, sk_a_len, sk_e_len, sk_p_len;
	int preferred_key_len;
	int required_len;
	rc_vchar_t *prfinput = 0;
	rc_vchar_t *keys = 0;
	int retval = -1;
	rc_vchar_t *sk_d, *sk_ai, *sk_ar, *sk_ei, *sk_er, *sk_pi, *sk_pr;
	uint8_t *p;

	sk_d = sk_ai = sk_ar = sk_ei = sk_er = sk_pi = sk_pr = 0;

	/*
	 * keys = prf+(skeyseed, Ni | Nr | SPIi | SPIr);
	 * {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr } = keys
	 */
	preferred_key_len = ike_sa->prf->method->preferred_key_len;
	sk_d_len = preferred_key_len;	/* actually, it's prf+ key len */
	sk_a_len = auth_key_length(ike_sa->authenticator);
	sk_e_len = encryptor_key_length(ike_sa->encryptor);
	sk_p_len = preferred_key_len;
	required_len = sk_d_len + 2 * sk_a_len + 2 * sk_e_len + 2 * sk_p_len;

	prfinput =
		rc_vmalloc(ike_sa->n_i->l + ike_sa->n_r->l +
			2 * sizeof(isakmp_cookie_t));
	if (!prfinput)
		goto fail;
	p = (uint8_t *)prfinput->v;
	VCONCAT(prfinput, p, ike_sa->n_i);
	VCONCAT(prfinput, p, ike_sa->n_r);
	memcpy(p, &ike_sa->index, sizeof(isakmp_index_t));

	keys = ikev2_prf_plus(ike_sa, ike_sa->skeyseed, prfinput, required_len);
	if (!keys)
		goto fail;

	p = (uint8_t *)keys->v;
	sk_d = rc_vnew(p, sk_d_len);
	if (!sk_d)
		goto fail;
	p += sk_d_len;
	sk_ai = rc_vnew(p, sk_a_len);
	if (!sk_ai)
		goto fail;
	p += sk_a_len;
	sk_ar = rc_vnew(p, sk_a_len);
	if (!sk_ar)
		goto fail;
	p += sk_a_len;
	sk_ei = rc_vnew(p, sk_e_len);
	if (!sk_ei)
		goto fail;
	p += sk_e_len;
	sk_er = rc_vnew(p, sk_e_len);
	if (!sk_er)
		goto fail;
	p += sk_e_len;
	sk_pi = rc_vnew(p, sk_p_len);
	if (!sk_pi)
		goto fail;
	p += sk_p_len;
	sk_pr = rc_vnew(p, sk_p_len);
	if (!sk_pr)
		goto fail;

	/* RFC 8784 s4.2: when the USE_PPK session is active (ppk_active,
	 * negotiated in IKE_SA_INIT only), re-derive the three keys the
	 * PPK protects.  SK_ai/ar/ei/er are deliberately left from the
	 * un-PPK'ed prf+ output -- they already protected IKE_SA_INIT and
	 * IKE_AUTH (the PPK is unknown to the responder until IKE_AUTH).
	 * All IKEv2 PRFs have output length == preferred key length, so a
	 * single prf+ iteration (T1 = prf(PPK, key | 0x01)) suffices.
	 * ppk_active is never set on a rekeyed/resumed SA (RFC 8784 s2.2:
	 * PPK for the initial SA only), so rekeys derive classically. */
	if (ike_sa->ppk_active && !ike_sa->ppk_deferred) {
		rc_vchar_t *ppk = 0, *sk_d2 = 0, *sk_pi2 = 0, *sk_pr2 = 0;

		ppk = ikev2_ppk_load(ike_sa->rmconf);
		if (!ppk) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "RFC 8784: failed to load PPK for the "
				   "negotiated USE_PPK session\n");
			goto fail;
		}
		sk_d2 = ikev2_prf_plus(ike_sa, ppk, sk_d, sk_d_len);
		sk_pi2 = ikev2_prf_plus(ike_sa, ppk, sk_pi, sk_p_len);
		sk_pr2 = ikev2_prf_plus(ike_sa, ppk, sk_pr, sk_p_len);
		OPENSSL_cleanse(ppk->v, ppk->l);
		rc_vfreez(ppk);
		ppk = 0;
		if (!sk_d2 || !sk_pi2 || !sk_pr2) {
			if (sk_d2)
				rc_vfreez(sk_d2);
			if (sk_pi2)
				rc_vfreez(sk_pi2);
			if (sk_pr2)
				rc_vfreez(sk_pr2);
			goto fail;
		}
		rc_vfreez(sk_d);
		rc_vfreez(sk_pi);
		rc_vfreez(sk_pr);
		sk_d = sk_d2;
		sk_pi = sk_pi2;
		sk_pr = sk_pr2;
	}

	/* Free + cleanse any PRIOR generation before overwriting -- the RFC 9370
	 * intermediate key update calls this a second time per SA; never orphan
	 * secret key bytes (H2). */
	ikev2_cleanse_key_gen(&ike_sa->sk_d);
	ikev2_cleanse_key_gen(&ike_sa->sk_a_i);
	ikev2_cleanse_key_gen(&ike_sa->sk_a_r);
	ikev2_cleanse_key_gen(&ike_sa->sk_e_i);
	ikev2_cleanse_key_gen(&ike_sa->sk_e_r);
	ikev2_cleanse_key_gen(&ike_sa->sk_p_i);
	ikev2_cleanse_key_gen(&ike_sa->sk_p_r);

	ike_sa->sk_d = sk_d;
	ike_sa->sk_a_i = sk_ai;
	ike_sa->sk_a_r = sk_ar;
	ike_sa->sk_e_i = sk_ei;
	ike_sa->sk_e_r = sk_er;
	ike_sa->sk_p_i = sk_pi;
	ike_sa->sk_p_r = sk_pr;
	retval = 0;
      done:
	if (keys)
		rc_vfreez(keys);
	if (prfinput)
		rc_vfree(prfinput);
	return retval;

      fail:
	if (sk_d)
		rc_vfreez(sk_d);
	if (sk_ai)
		rc_vfreez(sk_ai);
	if (sk_ar)
		rc_vfreez(sk_ar);
	if (sk_ei)
		rc_vfreez(sk_ei);
	if (sk_er)
		rc_vfreez(sk_er);
	if (sk_pi)
		rc_vfreez(sk_pi);
	if (sk_pr)
		rc_vfreez(sk_pr);
	goto done;
}

void
ikev2_destroy_secret(struct ikev2_sa *sa)
{
	if (sa->dhpriv) {
		rc_vfreez(sa->dhpriv);
		sa->dhpriv = 0;
	}
	if (sa->skeyseed) {
		rc_vfreez(sa->skeyseed);
		sa->skeyseed = 0;
	}
}


/*
 * compute prf+
 */
rc_vchar_t *
ikev2_prf_plus(struct ikev2_sa *sa, rc_vchar_t *key, rc_vchar_t *msg_bytes,
	       ssize_t need_len)
{
	struct keyed_hash *prf = sa->prf;
	struct keyed_hash_method *m = prf->method;
	rc_vchar_t *t = 0;
	uint8_t byte_value;
	rc_vchar_t byte;
	rc_vchar_t *result = 0;
	uint8_t *result_ptr;
	rc_vchar_t *prf_output = 0;
	size_t prf_output_len;

	/*
	 * (draft-17)
	 prf+ (K,S) = T1 | T2 | T3 | T4 | ...

	 where:
	 T1 = prf (K, S | 0x01)
	 T2 = prf (K, T1 | S | 0x02)
	 T3 = prf (K, T2 | S | 0x03)
	 T4 = prf (K, T3 | S | 0x04)
	 */

	byte.v = (caddr_t)&byte_value;	/* XXX */
	byte.l = 1;

	prf_output_len = m->result_len;
	if ((size_t)need_len > prf_output_len * 255) {
		/* shouldn't happen */
		isakmp_log(sa, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "requrired key length %zd exceeds 255 times the output of PRF %zu\n",
			   need_len, prf_output_len);
		return 0;
	}

	result = rc_vmalloc(need_len);
	if (!result)
		goto fail;

	/*
	 * initial T0 = empty
	 */
	t = 0;
	result_ptr = (uint8_t *)result->v;
	for (byte_value = 1; need_len > 0; ++byte_value) {
		/*
		 * prf_output = prf(K, Ti-1 | S | byte)
		 */
		m->key(prf, key);
		m->start(prf);
		if (t)
			m->update(prf, t);
		m->update(prf, msg_bytes);
		m->update(prf, &byte);
		prf_output = m->finish(prf);
		if (!prf_output)
			goto fail;

	/*
	 * responder-rekey diagnostic: independently recompute the
	 * first prf+ block (T1 = prf(K, S | 0x01)) via the
	 * one-shot HMAC path and compare, so a keyed-hash
	 * method-chain bug (key/start/update/finish wiring) in
	 * prf+ itself is caught -- the last unexamined KEYMAT
	 * component now that DH, nonces, SK_d and point formats
	 * are all value-verified.  Only logs T1's first 8 bytes.
	 */
	if (byte_value == 1) {
		rc_vchar_t *check = NULL;
		rc_vchar_t *ref = NULL;
		if (prf->method->result_len == 32) {
			/* build S | 0x01 and recompute */
			check = rc_vmalloc(msg_bytes->l + 1);
			if (check) {
				memcpy(check->v, msg_bytes->v,
				    msg_bytes->l);
				((u_char *)check->v)[msg_bytes->l] =
				    byte_value;
				check->l = msg_bytes->l + 1;
				ref = eay_hmacsha2_256_one(key, check);
			}
			if (ref) {
				int match = (ref->l == prf_output->l &&
				    memcmp(ref->v, prf_output->v,
				    ref->l) == 0);
				isakmp_log(sa, 0, 0, 0,
				    PLOG_DEBUG, PLOGLOC,
				    "PRF_PLUS T1 recompute %s "
				    "(S len=%zu keylen=%zu)\n",
				    match ? "MATCH" : "MISMATCH",
				    msg_bytes->l,
				    key ? key->l : 0);
				rc_vfreez(ref);
			}
			if (check)
				rc_vfreez(check);
		}
	}

		/*
		 * concat prf_output to result
		 */
		memcpy(result_ptr, prf_output->v,
		       prf_output_len > (size_t)need_len ? (size_t)need_len : prf_output_len);
		result_ptr += prf_output_len;
		need_len -= prf_output_len;

		/*
		 * Ti = prf_output
		 */
		if (t)
			rc_vfreez(t);
		t = prf_output;
	}
	if (t)
		rc_vfreez(t);
	return result;

      fail:
	if (t)
		rc_vfreez(t);
	if (result)
		rc_vfreez(result);
	return 0;
}

/*
 * ikev2_spi_is_zero
 * returns TRUE if IKE SPI is zero
 * otherwise returns FALSE
 */
int
ikev2_spi_is_zero(isakmp_cookie_t *c)
{
	unsigned int i;
	for (i = 0; i < sizeof(isakmp_cookie_t); ++i) {
		if ((*c)[i])
			return FALSE;
	}
	return TRUE;
}

const char *
ikev2_state_str(int type)
{
#define	S(x_)	case IKEV2_STATE_ ## x_ : return # x_ ;
	switch (type) {
		S(IDLING);
		S(INI_IKE_SA_INIT_SENT);
		S(RES_IKE_SA_INIT_SENT);
		S(INI_IKE_AUTH_SENT);
		S(RES_IKE_AUTH_RCVD);
		S(INI_IKE_AUTH_RCVD);
		S(RES_IKE_AUTH_EAP);
		S(RES_IKE_AUTH_EAP_FINAL);
		S(ESTABLISHED);
		S(DYING);
		S(DEAD);
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

const char *
ikev2_child_state_str(int type)
{
#define	S(x_)	case IKEV2_CHILD_STATE_ ## x_ : return # x_ ;
	switch (type) {
		S(IDLING);
		S(GETSPI);
		S(GETSPI_DONE);
		S(WAIT_RESPONSE);
		S(MATURE);
		S(EXPIRED);
		S(REQUEST_PENDING);
		S(REQUEST_SENT);
		S(NUM);
		S(INVALID);
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



