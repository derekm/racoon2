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

	/* RFC 5723 s4.3.2: an unanswered IKE_SESSION_RESUME (the responder
	 * may not implement exchange 38 at all) falls back to a regular
	 * IKE_SA_INIT instead of failing the SA, and forgets the ticket so
	 * later attempts do not present it again. */
	if (ike_sa->is_initiator &&
	    ike_sa->state == IKEV2_STATE_INI_IKE_SESSION_RESUME_SENT) {
		ike_msg_session_resume_fallback(ike_sa,
		    "no IKE_SESSION_RESUME response");
		++isakmpstat.timeout;
		return;
	}

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
				/* RFC 7296 s3.3.5 / RFC 2451: variable-key
				 * CBC ciphers carry KEY_LENGTH too; keep it so
				 * the IKE_SA_INIT response echoes the offer
				 * (strongSwan rejects an attribute-less reply
				 * to its CAST_CBC_128 / BLOWFISH_CBC_128 offer
				 * as "peer's proposal selection invalid") */
				case IKEV2TRANSF_ENCR_RC5:
				case IKEV2TRANSF_ENCR_CAST:
				case IKEV2TRANSF_ENCR_BLOWFISH:
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

	/* allow_nsa_deprecated / allow_rfc_deprecated: a disallowed peer
	 * transform is never selectable (IKE_SA_INIT both roles, IKE_SA
	 * rekey both roles), also not as a carried ADDKE round. */
	ikev2_proplist_filter_deprecated(rminfo, peer_proposal);

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



