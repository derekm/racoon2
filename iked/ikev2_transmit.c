/* $Id: ikev2_transmit.c	$ */

/*
 * Copyright (C) 2004-2026 WIDE Project.
 * All rights reserved.
 *
 * IKEv2 message transmission / retransmission / message-ID window helpers,
 * split out of ikev2.c (Phase 3 of the modularization).  Every exchange
 * transmits through these, so the transmit + retransmit + msgid-window
 * machinery lives in its own translation unit:
 *
 *   ikev2_transmit / ikev2_transmit_response   (send request / response)
 *   ikev2_retransmit_forced / ikev2_stop_retransmit / ikev2_request_id /
 *   ikev2_update_message_id                     (retransmit + msgid window)
 *   ikev2_check_message_ordering                (incoming msgid validation)
 *   ikev2_check_icv_prev_gen                    (H1 gen-0 ICV re-check)
 *
 * All are exported via ikev2_impl.h (used by every exchange); nothing here
 * is static.  The retransmit scheduling records stay on the ikev2_sa
 * (transmit_info / retransmit_info) so no SA structure moves.
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

/*
 * check whether the received message id matches expected one
 * return 0 if acceptable, non-zero if otherwise
 */
/*ARGSUSED*/
int
ikev2_check_message_ordering(struct ikev2_sa *ike_sa, uint32_t message_id,
			     int is_response, struct sockaddr *local,
			     struct sockaddr *remote)
{
#ifdef notyet
	/* unordered with window */
#else
	if (is_response) {
		/*
		 * A response echoes the id of a request we sent.  The
		 * id was either reserved (send_message_id advanced past
		 * it at mint time) or one of the protocol-fixed initial
		 * ids (IKE_SA_INIT=0, IKE_AUTH=1) which the counter
		 * catches up to in ikev2_update_message_id().  Accept
		 * only the OUTSTANDING response id (== send_message_id
		 * while the fixed initial ids / a not-yet-advanced
		 * intermediate round pend, == send_message_id-1 after
		 * the counter advanced past it); reject messages any
		 * older than that.  Blanket-accepting the whole window
		 * let a stale/cleartext replay (e.g. an IKE_SA_INIT
		 * reply) be dispatched to a later state's handler and
		 * abort the SA (review R2).  The per-message handler
		 * still re-guards on exchange type.
		 */
		if (message_id <= ike_sa->send_message_id &&
		    (ike_sa->send_message_id == 0 ||
		     message_id >= ike_sa->send_message_id - 1))
			return 0;
		TRACE((PLOGLOC, "response message_id %d, sent through %d\n",
		       message_id, ike_sa->send_message_id));
	} else {
		if (ike_sa->recv_message_id == message_id)
			return 0;
		TRACE((PLOGLOC, "request message_id %d expected %d\n",
		       message_id, ike_sa->recv_message_id));
	}

	return -1;
#endif
}

/*
 * H1: validate an incoming request's ICV against the PRE-update (gen-0)
 * receive keys, so a retransmitted gen-0 IKE_INTERMEDIATE request -- whose
 * ICV the post-update (gen-1) keys can no longer verify -- is not dropped.
 * The keys are swapped in only for the check (read-only) and restored; on
 * success ikev2_retransmit_forced (recv_message_id-1 == message_id) replays
 * the cached response and the SA survives a lost intermediate reply.
 */
int
/* CONCURRENCY (F3): ikev2_check_icv_prev_gen() temporarily swaps
 * ike_sa->sk_a_r/sk_e_r to the retained gen-0 keys while it re-checks
 * the ICV.  This is only safe because the receive path runs one
 * ICV+decrypt per SA synchronously on this thread.  If per-message
 * crypto is ever offloaded to worker threads concurrently with the
 * receive loop, guard the key swap (mutex or copy the buffer) -- an
 * unsynchronized swap would let a worker decrypt with the wrong-gen
 * keys.
 */
ikev2_check_icv_prev_gen(struct ikev2_sa *ike_sa, rc_vchar_t *packet)
{
	rc_vchar_t *oa = ike_sa->sk_a_r, *oe = ike_sa->sk_e_r;
	int rc;

	if (!ike_sa->prev_sk_a_r || !ike_sa->prev_sk_e_r)
		return -1;
	ike_sa->sk_a_r = ike_sa->prev_sk_a_r;
	ike_sa->sk_e_r = ike_sa->prev_sk_e_r;
	rc = ikev2_check_icv(ike_sa, packet);
	ike_sa->sk_a_r = oa;
	ike_sa->sk_e_r = oe;
	return rc;
}

int
ikev2_retransmit_forced(struct ikev2_sa *ike_sa, uint32_t message_id,
                        int is_response)
{
	struct timeval t, diff;

	if (is_response) {
		return 0;
	}

	/* Retransmission of a request we already answered.  Two equivalent
	 * signals: the window's last request (recv-1), or the exact
	 * message_id the armed response was minted for.  The second case
	 * matters for REASSEMBLED retransmits: a fragmented exchange
	 * (e.g. an ML-KEM IKE_FOLLOWUP_KE) never advanced recv_message_id,
	 * so recv-1 never matches and without this the retransmit would
	 * fall through into the handler and re-encapsulate (re-entering
	 * ikev2_followup_ke_recv doubles the addke_sk append). */
	if (!(ike_sa->response_info.message_id == message_id &&
	      (ike_sa->response_info.packet || ike_sa->response_info.frags))) {
		/* RFC 7296 2.10: only the response armed for THIS message id may
		 * be replayed.  A recv-window match against a stale cache (the
		 * previous response still armed while a CREATE_CHILD response
		 * is being built asynchronously) answered the retransmit with
		 * the wrong Message ID; fall through so the real response is
		 * built instead (review 2026-09-24). */
		return 0;
	}

	/*
	 * initiator is retransmitting the request,
	 * need to retransmit the response. rate limit
	 * is 1 sec for now.
	 */
	gettimeofday(&t, 0);
	timersub(&t, &ike_sa->response_info.sent_time, &diff);
	if (diff.tv_sec >= 1) {
		TRACE((PLOGLOC, "force retransmit\n"));
		isakmp_force_retransmit(&ike_sa->response_info);
		isakmp_log(ike_sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
			   "R2 replay: re-sent armed response (message_id %u)\n",
			   message_id);
	} else {
		TRACE((PLOGLOC, "rcv retransmit within 1sec, ignoring\n"));
	}

	return -1;
}

/* R1 (review): replay the cached gen-0 IKE_INTERMEDIATE response verbatim,
 * rate-limited to 1/sec.  Called from ikev2_input() when a retransmitted
 * gen-0 request is detected by its cleartext outer message_id.  The cached
 * bytes were authenticated under the pre-update (gen-0) keys -- which is
 * exactly what a peer still retransmitting is on -- so no re-encryption is
 * needed.  (Old H1 tried to re-validate the request ICV with retained
 * prev-gen keys, but that was dead for AEAD and never saw the fragmented/
 * decrypt-failed path; verbatim replay of the response is the working fix.) */

uint32_t
ikev2_request_id(struct ikev2_sa *ike_sa)
{
	uint32_t id;

	/*
	 * RFC 7296 §2.2: Message IDs are independent per direction.
	 * IKE_SA_INIT is 0 and IKE_AUTH is 1 from the original
	 * initiator.  The original responder's first request is
	 * msgid 0.  Do not heal to 2 (that was an Apple workaround
	 * while the SA body was also malformed).  linux-matrix
	 * ikev2-netns-r2rekey is the charon proof.
	 */

	/* reserve the id BEFORE handing it out so concurrent / async
	 * mints (rekey while informational in flight, etc.) can never
	 * collide on the same Message ID */
	id = ike_sa->send_message_id;
	if (id == 0xFFFFFFFF) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
		    "message_id reached 0xFFFFFFFF\n");
		ikev2_set_state(ike_sa, IKEV2_STATE_DEAD);
		/* continue: the SA is dying, the id is the best we have */
		++ike_sa->request_pending;
		return id;
	}
	++ike_sa->send_message_id;
	++ike_sa->request_pending;
	ike_sa->resume_dirty = 1;	/* window advanced (mint); persist */
	return id;
}

void
ikev2_update_message_id(struct ikev2_sa *ike_sa, uint32_t message_id,
			int is_response)
{
#ifdef notyet
	/* window */
#else
	if (is_response) {
		TRACE((PLOGLOC, "update response message_id 0x%x\n",
		       message_id));
		/* a response echoes the request's id; the request was minted
		 * by ikev2_request_id() (or was one of the hardcoded initial
		 * ids 0/1), so the counter was already reserved.  Allow the
		 * matching echo, and any retransmitted response of it. */
		if (message_id >= ike_sa->send_message_id) {
			/*
			 * Not an id we minted.  The initial exchanges
			 * (IKE_SA_INIT=0, IKE_AUTH=1) are the exception --
			 * they are fixed by the protocol, not minted.
			 * Bring the counter up so the next mint is valid.
			 */
			ike_sa->send_message_id = message_id + 1;
		}
		if (ike_sa->request_pending > 0)
			--ike_sa->request_pending;
		ikev2_stop_retransmit(ike_sa);
	} else {
		TRACE((PLOGLOC, "update request message_id 0x%x\n",
		       message_id));
		/* ikev2_input() checks the window for SK and reassembled
		 * SKF messages alike, so a stale id should not get here; if
		 * one does, it must NOT abort the daemon: drop it and leave
		 * recv_message_id untouched (review R2). */
		if (ike_sa->recv_message_id != message_id) {
			plog(PLOG_PROTOERR, PLOGLOC, NULL,
			     "update_message_id: request id %u != expected %u; dropping (unordered) request\n",
			     message_id, ike_sa->recv_message_id);
			return;
		}
		if (ike_sa->recv_message_id == 0xFFFFFFFF) {
			isakmp_log(ike_sa, 0, 0, 0,
			    PLOG_PROTOERR, PLOGLOC,
			    "message_id reached 0xFFFFFFFF\n");
			/* ikev2_abort(ike_sa, ECONNREFUSED); */
			ikev2_set_state(ike_sa, IKEV2_STATE_DEAD);
		} else {
			++ike_sa->recv_message_id;
		}
	}
	ike_sa->resume_dirty = 1;	/* window advanced; persist */
#endif
}

/*
 * Transmit a message
 */

#define IPV4_MAX_FRAGMENT_SIZE 576
#define IPV6_MAX_FRAGMENT_SIZE 1280


/* RFC 9329: an IKE SA carried over TCP never uses RFC 7383 fragmentation.
 * The stream already carries messages up to 65529 bytes, and the SKF path
 * writes each fragment with sendfromto() on the UDP socket.  That bypasses
 * isakmp_try_tcp_send(), so a large message (an ML-KEM IKE_FOLLOWUP_KE)
 * leaked onto UDP 4500 and the peer answered over UDP to the TCP source
 * port. */
static int
ikev2_frag_allowed(struct ikev2_sa *ike_sa)
{
	if (!ike_sa->frag_supported)
		return 0;
	if (ike_sa->rmconf != NULL &&
	    ikev2_tcp_encap(ike_sa->rmconf) == RCT_BOOL_ON)
		return 0;
	return 1;
}

int
ikev2_transmit(struct ikev2_sa *ike_sa, rc_vchar_t *packet)
{
	TRACE((PLOGLOC, "ikev2_transmit(%p, %p) len %d\n",
	       ike_sa, packet, (int)packet->l));

	if (ike_sa != NULL && ikev2_frag_allowed(ike_sa))
	{
	    int want_frag;
	    if (SOCKADDR_FAMILY(ike_sa->remote) == AF_INET)
		want_frag = (packet->l >= IPV4_MAX_FRAGMENT_SIZE);
	    else
		want_frag = (packet->l >= IPV6_MAX_FRAGMENT_SIZE);
	    if (want_frag) {
		/* Cache the EXACT fragment datagrams that go out and arm a
		 * retransmit of THOSE (fragment-list replay, R-c84373b8 #1):
		 * a fragment stream is only recoverable by re-sending the
		 * same SKF datagrams (each already carries its RFC 3948
		 * marker; the peer reassembles by message_id and drops
		 * duplicates).  Trusting a pre-fragment whole packet -- or
		 * later re-fragmenting it -- is wrong: a raw whole over 576
		 * bytes dies on a 576-MTU path and re-fragmenting
		 * re-encrypts under different keys. */
		rc_vchar_t **frags = NULL;
		int nfrags = 0;
		uint32_t tmsgid = get_uint32(
		    &((struct ikev2_header *)packet->v)->message_id);
		if (ikev2_frag_send(ike_sa, &packet, &frags, &nfrags) == 0) {
		    if (frags && nfrags > 0) {
			int r = isakmp_schedule_retransmit_frags(
			    &ike_sa->transmit_info, frags, nfrags,
			    ike_sa->local, ike_sa->remote);
			/* A fragmented request that cannot be retransmitted
			 * leaves the SA with NO lost-message recovery during
			 * the window: a lost reply would deadlock it.  The
			 * packet is already on the wire, so fail loud
			 * rather than pretend recovery is armed. */
			if (r != 0)
			    isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR,
				       PLOGLOC,
				       "RT-ARM: FAILED to arm fragmented-request retransmit (ret=%d): lost-message recovery disabled for this exchange\n",
				       r);
		    } else {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
				   "RT-ARM: no fragment datagrams captured, no retransmit copy kept: lost-message recovery disabled for this exchange\n");
		    }
		    ike_sa->transmit_info.message_id = tmsgid;
		    return 0;	/* packet was fragmented and sent */
		}
		/* fragmentation failed before any send: fall through to the
		 * original datagram */
	    }
		/* fragmentation not needed or failed, send original */
	}

	if (packet->l > IKEV2_SHOULD_SUPPORT_PACKET_SIZE) {
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INFO, PLOGLOC,
			   "packet size (%d) larger than recommended implementation minimum (%d)\n",
			   (int)packet->l, IKEV2_SHOULD_SUPPORT_PACKET_SIZE);
	}

	return isakmp_transmit(&ike_sa->transmit_info, packet, ike_sa->local,
			       ike_sa->remote);
}

int
ikev2_transmit_response(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
			struct sockaddr *local, struct sockaddr *remote)
{
	struct transmit_info	*info;
	uint32_t msgid;

	TRACE((PLOGLOC, "ikev2_transmit_response(%p, %p) len %d\n",
	       ike_sa, packet, (int)packet->l));

	/* The response echoes the request's Message ID; record which
	 * request this cache answers so a reassembled retransmit can be
	 * replayed by message_id even when the fragmented path never
	 * advanced recv_message_id. */
	msgid = get_uint32(&((struct ikev2_header *)packet->v)->message_id);

	if (ikev2_frag_allowed(ike_sa)) {
	    int over;
	    rc_vchar_t **frags = NULL;
	    int nfrags = 0;

	    if (SOCKADDR_FAMILY(ike_sa->remote) == AF_INET)
		over = (packet->l >= IPV4_MAX_FRAGMENT_SIZE);
	    else
		over = (packet->l >= IPV6_MAX_FRAGMENT_SIZE);
	    if (over) {
		struct sockaddr *nsrc, *ndest;
		int i;

		/* Resolve the replay endpoints BEFORE any fragment goes to
		 * the wire: on failure nothing was sent and the caller
		 * still owns *packet (its frame frees pkt on -1 -- a
		 * dangling pointer here would double-free).  Fragments are
		 * the replay form (each is a self-contained SKF with the
		 * RFC 3948 marker baked in) and a retransmitted request
		 * must be answered by re-sending those exact datagrams --
		 * never by re-sending the pre-fragment whole as one
		 * oversized datagram (576-MTU hole in review). */
		nsrc = rcs_sadup(local);
		ndest = rcs_sadup(remote);
		if (!nsrc || !ndest) {
		    if (nsrc)
			rc_free(nsrc);
		    if (ndest)
			rc_free(ndest);
		    isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			       "response send aborted (rcs_sadup)\n");
		    return -1;
		}

		if (ikev2_frag_send(ike_sa, &packet, &frags, &nfrags) == 0) {
		    info = &ike_sa->response_info;
		    if (info->packet)
			rc_vfree(info->packet);
		    if (info->frags) {
			for (i = 0; i < info->nfrags; i++)
			    if (info->frags[i])
				rc_vfree(info->frags[i]);
			racoon_free(info->frags);
		    }
		    if (info->src)
			rc_free(info->src);
		    if (info->dest)
			rc_free(info->dest);
		    info->packet = NULL;
		    info->frags = frags;
		    info->nfrags = nfrags;
		    ike_sa->resume_dirty = 1;	/* frag response armed; persist */
		    info->src = nsrc;
		    info->dest = ndest;
		    info->message_id = msgid;
		    gettimeofday(&info->sent_time, 0);
		    return 0;
		}
		/* fragmentation failed before any fragment went to the
		 * wire: *packet is still owned by the caller; fall through
		 * to a plain (non-fragmented) send of the original. */
		rc_free(nsrc);
		rc_free(ndest);
	    }
	}

	if (packet->l > IKEV2_SHOULD_SUPPORT_PACKET_SIZE) {
		INFO((PLOGLOC,
		      "packet size (%zu) larger than recommended implementation minimum (%d)\n",
		      packet->l, IKEV2_SHOULD_SUPPORT_PACKET_SIZE));
	}

	info = &ike_sa->response_info;
	/* response_info outlives the transmit path (peer may retransmit
	 * the request and force a replay), so own private copies of the
	 * endpoints instead of borrowing the caller's.  The IKE_SA rekey
	 * responder hands over ctx->local/ctx->remote which it frees on
	 * completion; borrowing them left a use-after-free that made
	 * isakmp_find_socket() read garbage on the first forced
	 * retransmit after an address change (LTE->WiFi transition). */
	if (info->src)
		rc_free(info->src);
	if (info->dest)
		rc_free(info->dest);
	info->src = rcs_sadup(local);
	info->dest = rcs_sadup(remote);
	if (!info->src || !info->dest) {
		if (info->src)
			rc_free(info->src);
		if (info->dest)
			rc_free(info->dest);
		info->src = info->dest = NULL;
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "response replay-arm failed (rcs_sadup)\n");
		return -1;
	}

	/* Replace any previous cache (fragmented or whole) BEFORE taking
	 * ownership of the new packet; the old response was already sent
	 * and must not leak. */
	if (info->packet)
		rc_vfree(info->packet);
	if (info->frags) {
		int i;

		for (i = 0; i < info->nfrags; i++)
			if (info->frags[i])
				rc_vfree(info->frags[i]);
		racoon_free(info->frags);
	}
	info->packet = packet;
	info->frags = NULL;
	info->nfrags = 0;
	info->message_id = msgid;
	ike_sa->resume_dirty = 1;	/* response armed; persist */
	gettimeofday(&info->sent_time, 0);

	isakmp_transmit_noretry(&ike_sa->response_info, packet, info->src,
				info->dest);
	return 0;
}

void
ikev2_stop_retransmit(struct ikev2_sa *sa)
{
	isakmp_stop_retransmit(&sa->transmit_info);
}

