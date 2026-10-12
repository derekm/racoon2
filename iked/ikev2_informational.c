/* $Id: ikev2_informational.c	$ */

/*
 * Copyright (C) 2004-2026 WIDE Project.
 * All rights reserved.
 *
 * INFORMATIONAL exchange handling (RFC 7296 smoderate 2.8 / DELETE / DPD),
 * split out of ikev2.c.  This translation unit owns the ESTABLISHED-state
 * dispatch and the whole INFORMATIONAL message path:
 *
 *   established    ikev2_established_recv, ikev2_dying_recv, ikev2_dead_recv
 *   initiator      ikev2_informational_initiator_notify/_delete/_transmit,
 *                  ikev2_info_init_notify_recv, ikev2_info_init_delete_recv,
 *                  info_init_notify/delete_callback,
 *                  ikev2_request_initiator_start
 *   responder      informational_responder_recv, ikev2_process_delete
 *   errors         ikev2_respond_null, ikev2_respond_error (shared by the
 *                  other exchanges too; exported via ikev2_impl.h)
 *
 * CREATE_CHILD_SA (initiator/responder + rekey) stays in ikev2.c, which the
 * established dispatch calls into through exported entry points.  The generic
 * ikev2_request_initiator_start (an INFORMATIONAL-specific request helper) is
 * also exported since ikev2_child/ike_sa/ikev2_rekey use it for their own
 * notify/DELETE requests.  Everything else here is static to this file.
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

/* forward declarations (as in ikev2.c top) */
static void informational_responder_recv(struct ikev2_sa *, rc_vchar_t *,
					 struct sockaddr *, struct sockaddr *);
static void informational_initiator_recv(struct ikev2_sa *, rc_vchar_t *,
					 struct sockaddr *, struct sockaddr *);
static void info_init_notify_callback(enum request_callback, struct ikev2_child_sa *, void *);
static void info_init_delete_callback(enum request_callback, struct ikev2_child_sa *, void *);
void ikev2_process_delete(struct ikev2_sa *, struct ikev2_payload_header *,
			  struct ikev2_payloads *);

/* Cookie-echo + NAT-D-report builders live in ikev2.c (shared with the
 * CREATE_CHILD_SA/other exchanges); exported for use here. */
void ikev2_push_cookie2_echo(struct ikev2_sa *, struct ikev2_payloads *);
int ikev2_push_natd_report(struct ikev2_sa *, struct ikev2_payloads *);

void
ikev2_established_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		       struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int exch_type;
	int is_response;

	ikehdr = (struct ikev2_header *)msg->v;
	exch_type = ikehdr->exchange_type;
	is_response = (ikehdr->flags & IKEV2FLAG_RESPONSE) != 0;

	/*
	 * RFC 4555 implicit mobility: an integrity-verified message from a
	 * different source (ip or port) for a MOBIKE-negotiated SA is an
	 * implicit update. Carrier CGNAT rotates the UDP port on radio
	 * handoff without sending UPDATE_SA_ADDRESSES; without this the
	 * kernel ESP stays pinned to the dead mapping while IKE is alive.
	 * ikev2_mobike_apply no-ops when the endpoints are unchanged and
	 * refuses DYING/DEAD SAs.
	 */
	if (ike_sa->state == IKEV2_STATE_ESTABLISHED &&
	    ike_sa->mobike_supported && remote && ike_sa->remote &&
	    rcs_cmpsa(remote, ike_sa->remote) != 0) {
		ikev2_mobike_apply(ike_sa, remote, local);
	}

	TRACE((PLOGLOC, "%s exch type %d\n",
	       (is_response ? "response" : "request"), exch_type));

	/* expect CREATE_CHILD_SA or INFORMATIONAL */
	switch (exch_type) {
	case IKEV2EXCH_CREATE_CHILD_SA:
		if (is_response) {
			ikev2_createchild_initiator_recv(ike_sa, msg, remote,
							 local);
		} else {
			ikev2_createchild_responder_recv(ike_sa, msg, remote,
							 local);
		}
		break;
	case IKEV2EXCH_INFORMATIONAL:
		if (is_response) {
			informational_initiator_recv(ike_sa, msg, remote,
						     local);
		} else {
			informational_responder_recv(ike_sa, msg, remote,
						     local);
		}
		break;
	case IKEV2EXCH_IKE_FOLLOWUP_KE:
#ifdef WITH_ADDKE
		/* RFC 9370 s2.2.4: additional key exchange data follows
		 * a CREATE_CHILD_SA that negotiated ADDKE.  The response
		 * must echo the ADDITIONAL_KEY_EXCHANGE notification
		 * (16441) that links back to the CREATE_CHILD_SA. */
		ikev2_followup_ke_recv(ike_sa, msg, remote, local);
#else
		/* No ADDKE support compiled in: an IKE_FOLLOWUP_KE must
		 * never arrive, because we never accept ADDKE proposals
		 * (ikev2_compare_transforms rejects type-6). */
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected IKE_FOLLOWUP_KE without ADDKE "
			   "negotiation\n");
		++isakmpstat.unexpected_exchange_type;
		if (!is_response) {
			int err;
			uint32_t message_id;
			message_id = get_uint32(&ikehdr->message_id);
			err = ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0,
						  IKEV2_INVALID_SYNTAX, 0, 0);
			if (!err)
				ikev2_update_message_id(ike_sa, message_id,
							FALSE);
		}
#endif
		break;
	default:
		/* unexpected message type */
		/* should respond with error message */
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected Exchange Type (%d)\n", exch_type);
		++isakmpstat.unexpected_exchange_type;
		if (!is_response) {
			int err;
			uint32_t message_id;
			message_id = get_uint32(&ikehdr->message_id);
			err = ikev2_respond_error(ike_sa, msg, remote, local,
						  0, 0, 0,
						  IKEV2_INVALID_SYNTAX, 0, 0);
			if (!err)
				ikev2_update_message_id(ike_sa, message_id,
							FALSE);
		}
		break;
	}
}

void
ikev2_dying_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg, struct sockaddr *remote,
		 struct sockaddr *local)
{
	ikev2_established_recv(ike_sa, msg, remote, local);
}

void
ikev2_dead_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg, struct sockaddr *remote,
		struct sockaddr *local)
{
	/* received a message to a dead IKE SA */
	/* just ignore  */
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOWARN, PLOGLOC,
		   "received a message to a dead IKE SA\n");
	++isakmpstat.unexpected_packet;	/* ??? */
}


/*
 * prepares a child_sa for sending Notify payload with Informational exchange
 */
void
ikev2_informational_initiator_notify(struct ikev2_sa *ike_sa,
				     struct ikev2_payloads *payl)
{
	(void) ikev2_request_initiator_start(ike_sa, info_init_notify_callback,
					     payl);
}

/*
 * RFC 7296 §2.3: when a request's Message ID is outside the (window-1)
 * supported window, the receiver MUST NOT acknowledge it; instead it
 * informs the peer by initiating its own INFORMATIONAL carrying
 * N(INVALID_MESSAGE_ID, data=the 4-octet invalid id).  Sending is optional
 * but MUST be rate limited, so we allow at most one per SA per second.
 * The caller (ikev2_input) calls this only after ICV validation, so we are
 * not answering an unauthenticated packet — we are starting a fresh
 * authenticated exchange of our own.  Returns 1 if an INFORMATIONAL was
 * initiated, 0 if rate-limited/skipped.
 */
int
ikev2_send_invalid_message_id(struct ikev2_sa *ike_sa, uint32_t message_id)
{
	struct ikev2_payloads *payl;
	uint8_t idbuf[4];

	if (ike_sa->invalid_msgid_last_sent &&
	    time(NULL) - ike_sa->invalid_msgid_last_sent < 1) {
		/* RFC 7296 §2.3: notifications of this type MUST be rate
		 * limited.  Drop the out-of-window request silently (it was
		 * never going to be acknowledged anyway) rather than fan
		 * out one INVALID_MESSAGE_ID per packet a storm sends. */
		isakmp_log(ike_sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
			   "INVALID_MESSAGE_ID rate-limited (last %lds ago)\n",
			   (long)(time(NULL) - ike_sa->invalid_msgid_last_sent));
		return 0;
	}

	payl = racoon_malloc(sizeof(*payl));
	if (!payl)
		return 0;
	ikev2_payloads_init(payl);
	put_uint32(idbuf, message_id);
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(0, 0, 0,
						 IKEV2_INVALID_MESSAGE_ID,
						 idbuf, sizeof(idbuf)),
			    TRUE);
	isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
		   "Message ID %u outside window: initiating INVALID_MESSAGE_ID\n",
		   message_id);
	ike_sa->invalid_msgid_last_sent = time(NULL);
	ikev2_informational_initiator_notify(ike_sa, payl);
	return 1;
}

static void
info_init_notify_callback(enum request_callback action,
			  struct ikev2_child_sa *child_sa, void *data)
{
	TRACE((PLOGLOC, "info_init_notify_callback(%d, %p, %p)\n", action,
	       child_sa, data));
	switch (action) {
	case REQUEST_CALLBACK_CONTINUE:
		ikev2_informational_initiator_transmit(child_sa->parent,
						       child_sa,
						       (struct ikev2_payloads *)data);
		break;
	case REQUEST_CALLBACK_TRANSMIT_ERROR:
		/* none here */
		break;
	case REQUEST_CALLBACK_RESPONSE:
		ikev2_info_init_notify_recv(child_sa, (rc_vchar_t *)data);
		break;
	default:
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unknown action code %d\n", (int)action);
		break;
	}
}

static void info_init_delete_callback(enum request_callback action,
				      struct ikev2_child_sa *child_sa,
				      void *data);

void
ikev2_informational_initiator_delete(struct ikev2_sa *ike_sa,
				     struct ikev2_payloads *payl)
{
	(void) ikev2_request_initiator_start(ike_sa, info_init_delete_callback,
					     payl);
}

static void
info_init_delete_callback(enum request_callback action,
			  struct ikev2_child_sa *child_sa, void *data)
{
	TRACE((PLOGLOC,
	       "info_init_delete_callback(%d, %p, %p)\n", action, child_sa,
	       data));
	switch (action) {
	case REQUEST_CALLBACK_CONTINUE:
		ikev2_informational_initiator_transmit(child_sa->parent,
						       child_sa,
						       (struct ikev2_payloads *)data);
		break;
	case REQUEST_CALLBACK_TRANSMIT_ERROR:
		/* none here */
		break;
	case REQUEST_CALLBACK_RESPONSE:
		ikev2_info_init_delete_recv(child_sa, (rc_vchar_t *)data);
		break;
	default:
		isakmp_log(child_sa->parent, 0, 0, 0,
			   PLOG_INTERR, PLOGLOC,
			   "unknown action code %d\n", (int)action);
		break;
	}
}

void
ikev2_info_init_delete_recv(struct ikev2_child_sa *child_sa, rc_vchar_t *msg)
{
	ikev2_info_init_notify_recv(child_sa, msg);
}

/*
 * prepares a child_sa for sending request (initiator of exchange)
 */
struct ikev2_child_sa *
ikev2_request_initiator_start(struct ikev2_sa *ike_sa,
    void (*callback)(enum request_callback, struct ikev2_child_sa *, void *),
    void *callback_param)
{
	struct ikev2_child_sa *child_sa;
	struct ikev2_child_sa *next_child_sa;

	child_sa = ikev2_create_child_sa(ike_sa, FALSE);
	if (!child_sa)
		goto fail;

	TRACE((PLOGLOC, "child_sa %p\n", child_sa));
	child_sa->is_initiator = TRUE;
	child_sa->state = IKEV2_CHILD_STATE_REQUEST_PENDING;
	child_sa->callback = callback;
	child_sa->callback_param = callback_param;
	sadb_request_initialize(&child_sa->sadb_request, &sadb_null_method,
				&ikev2_sadb_callback, 0, child_sa);

	next_child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (next_child_sa)
		ikev2_wakeup_child_sa(next_child_sa);

	return child_sa;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	++isakmpstat.fail_send_packet;
	return 0;
}

/*
 * transmits initiator message of Informational exchange
 * (called from ikev2_wakeup_child_sa() through info_init_notify_callback())
 */
void
ikev2_informational_initiator_transmit(struct ikev2_sa *ike_sa,
				       struct ikev2_child_sa *child_sa,
				       struct ikev2_payloads *payl)
{
	rc_vchar_t *pkt = 0;

	TRACE((PLOGLOC, "ikev2_informational_initiator_transmit(%p, %p, %p)\n",
	       ike_sa, child_sa, payl));

	/*
	 * send HDR, SK {[N,] [D,] [CP,] ...}
	 */

	child_sa->message_id = ikev2_request_id(ike_sa);
	TRACE((PLOGLOC, "message_id: 0x%08x\n", child_sa->message_id));

	pkt = ikev2_packet_construct(IKEV2EXCH_INFORMATIONAL,
				     (ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0),
				     child_sa->message_id, ike_sa, payl);
	ikev2_payloads_destroy(payl);
	racoon_free(payl);
	if (!pkt)
		goto fail;
	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_REQUEST_SENT);
	pkt = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	return;

      fail:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending Informational Exchange for internal error\n");
	++isakmpstat.fail_send_packet;
	if (child_sa && child_sa->callback)
		child_sa->callback(REQUEST_CALLBACK_TRANSMIT_ERROR,
				   child_sa, 0);
	if (child_sa)
		ikev2_destroy_child_sa(child_sa);
	goto done;
}

static void
informational_responder_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_payloads payl;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	struct ikev2_payload_header *p;
	int type;
	rc_vchar_t *pkt = 0;
	struct ikev2_child_param child_param; /* for CONFIG */
	int nat_detect = 0;

	/*
	 * expect HDR SK { N ... }
	 */

	ikev2_payloads_init(&payl);

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
		case IKEV2_PAYLOAD_NOTIFY:
			if (ikev2_process_notify(ike_sa, p, TRUE) != 0)
				goto abort;
			/*
			 * iOS (nwikev2) re-validates its NAT binding by
			 * sending NAT_DETECTION notifies in an
			 * INFORMATIONAL request on the established SA
			 * (RFC 7296 2.23 semantics, normally used in
			 * IKE_SA_INIT).  It expects the responder's
			 * computed NAT_DETECTION notifies back in the
			 * reply; an empty reply is treated as "binding
			 * not confirmed" and iOS silently deletes the
			 * SA a short time later.  Remember this so we
			 * can push our NAT-DETECTION notifies below.
			 */
			if (get_notify_type((struct ikev2payl_notify *)p) ==
			    IKEV2_NAT_DETECTION_SOURCE_IP ||
			    get_notify_type((struct ikev2payl_notify *)p) ==
			    IKEV2_NAT_DETECTION_DESTINATION_IP) {
				nat_detect = 1;
				/* nwikev2 computes these digests over ITS
				 * OWN view of the endpoints (its LAN addr
				 * behind the home router, and the public IP
				 * it dials).  Behind hairpin NAT our socket
				 * addresses differ from the peer's view, so
				 * recomputing the digests here can never
				 * match: iOS validates the reply, rejects
				 * it, retransmits once and silently deletes
				 * the IKE_SA.  Echo the received hash bytes
				 * VERBATIM instead -- that confirms the
				 * binding exactly as the peer computed it. */
				{
					uint8_t *dn;
					int dl = ntohs(((struct ikev2_payload_header *)p)->payload_length)
					    - sizeof(struct ikev2payl_notify);
					if (dl >= 20) {
						dn = get_notify_data(
						    (struct ikev2payl_notify *)p);
						/* swap: peer validates our
						 * reply SRC against the reply
						 * source it observes (the addr
						 * it dialed = its request DST)
						 * and reply DST against its
						 * own source (= request SRC). */
						if (get_notify_type(
						    (struct ikev2payl_notify *)p) ==
						    IKEV2_NAT_DETECTION_SOURCE_IP)
							memcpy(
							    ike_sa->natd_dst_hash,
							    dn, 20);
						else {
							memcpy(
							    ike_sa->natd_src_hash,
							    dn, 20);
							ike_sa->natd_report = 1;
						}
					}
				}
			}
			break;
		case IKEV2_PAYLOAD_DELETE:
			ikev2_process_delete(ike_sa, p, &payl);
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
		case IKEV2_PAYLOAD_CONFIG:
			if (ikev2_process_config_informational(ike_sa, p, &child_param)) {
				isakmp_log(ike_sa, 0, 0, msg,
					   PLOG_PROTOWARN, PLOGLOC,
					   "failed processing CONFIG payload, ignored\n");
				++isakmpstat.payload_ignored; /* ??? */
			} else if (ikev2_create_config_reply(ike_sa, NULL, &child_param)) {
				isakmp_log(ike_sa, 0, 0, msg,
					   PLOG_PROTOWARN, PLOGLOC,
					   "failed to create CONFIG payload, continuing\n");
				++isakmpstat.payload_ignored; /* ??? */
			} else {
				assert(child_param.cfg_payload != NULL);
				ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG,
						    child_param.cfg_payload, FALSE);
			}
			break;
		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, 0, 0, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto fail;
			}
			isakmp_log(ike_sa, 0, 0, msg,
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

	if (ike_sa->cookie2_echo)
		ikev2_push_cookie2_echo(ike_sa, &payl);

	if (nat_detect &&
	    (ikev2_nat_traversal(ike_sa->rmconf) == RCT_BOOL_ON ||
	     ikev2_nat_traversal(ike_sa->rmconf) == RCT_NATT_FORCE)) {
		/*
		 * RFC 7296 §2.23: NAT_DETECTION over this packet's
		 * endpoints, same construction as IKE_SA_INIT.
		 * An empty reply leaves the peer without binding
		 * confirmation.
		 */
		if (ikev2_push_natd_report(ike_sa, &payl) < 0)
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOWARN, PLOGLOC,
				   "failed to add NAT_DETECTION notifies "
				   "for INFORMATIONAL reply\n");
		else
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INFO, PLOGLOC,
				   "NAT_DETECTION digests in "
				   "INFORMATIONAL reply\n");
		ike_sa->natd_report = 0;
	}

	{
		int t_i;
		for (t_i = 0; t_i < payl.num; t_i++)
			isakmp_log(ike_sa, local, remote, 0, PLOG_INFO, PLOGLOC,
			    "INFO_RESP payl[%d] type=%d len=%zu\n",
			    t_i, payl.payloads[t_i].type,
			    payl.payloads[t_i].data ? payl.payloads[t_i].data->l : 0);
	}

	{
		/* RFC 4555 3.3.1: responder enables/disables NAT-T per the
		 * NATD digests; log our computed digests vs the peer's so a
		 * drift at DPD time (the ~10-min liveness exchange) is
		 * visible.  natd_src_hash/dst_hash hold the VERBATIM received
		 * digests (NOT the swapped reply).  natt_create_hash() is the
		 * same SHA1(i_ck | r_ck | addr | port) computation the
		 * informational handler uses for its own check. */
		rc_vchar_t *c_src = NULL, *c_dst = NULL;
		char h_ps[64], h_pd[64], h_cs[64], h_cd[64];
		int i;
		for (i = 0; i < 20; i++) {
			snprintf(&h_ps[i * 2], 3, "%02x", ike_sa->natd_src_hash[i]);
			snprintf(&h_pd[i * 2], 3, "%02x", ike_sa->natd_dst_hash[i]);
		}
		h_cs[0] = '\0';
		h_cd[0] = '\0';
		if (ike_sa->remote && ike_sa->local) {
			c_src = natt_create_hash(ike_sa, ike_sa->remote, TRUE);
			c_dst = natt_create_hash(ike_sa, ike_sa->local, TRUE);
		}
		if (c_src && c_dst) {
			for (i = 0; i < 20; i++) {
				snprintf(&h_cs[i * 2], 3, "%02x",
				    ((u_char *)c_src->v)[i]);
				snprintf(&h_cd[i * 2], 3, "%02x",
				    ((u_char *)c_dst->v)[i]);
			}
			isakmp_log(ike_sa, local, remote, 0,
			    PLOG_INFO, PLOGLOC,
			    "NATD_CMP msgid=%u peer_src=%s peer_dst=%s "
			    "computed_src=%s computed_dst=%s natd_report=%d\n",
			    message_id, h_ps, h_pd, h_cs, h_cd,
			    ike_sa->natd_report);
		}
		if (c_src)
			rc_vfree(c_src);
		if (c_dst)
			rc_vfree(c_dst);
	}
	pkt = ikev2_packet_construct(IKEV2EXCH_INFORMATIONAL,
				     (ike_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0) |
				     IKEV2FLAG_RESPONSE, message_id, ike_sa,
				     &payl);
	if (!pkt)
		goto fail_send;
	if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0)
		goto fail;
	pkt = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	goto done;

      fail_send:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending Informational Exchange for internal error\n");
	++isakmpstat.fail_send_packet;
	goto done;

      abort:
	if (ikev2_respond_null(ike_sa, msg, remote, local) == 0) {
		ikev2_abort(ike_sa, ECONNREFUSED);
	}
	goto done;
}

static void
informational_initiator_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			     struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_child_sa *child_sa;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	struct ikev2_child_sa *next_child_sa;

	/* HDR, SK {[N,] [D,] [CP], ... } */

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
	child_sa = ikev2_find_request(ike_sa, message_id);
	if (!child_sa || child_sa->state != IKEV2_CHILD_STATE_REQUEST_SENT) {
		struct ikev2_child_sa *s;

		/* In-flight request untracked: enumerate children so the
		 * next occurrence shows which state/msgid the exchange
		 * actually died in (a REQUEST_SENT child is removed by
		 * expiry/abort while the peer's response is in flight). */
		plog(PLOG_DEBUG, PLOGLOC, NULL, "tracked children after miss:\n");
		for (s = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
		     !IKEV2_CHILD_LIST_END(s);
		     s = IKEV2_CHILD_LIST_NEXT(s)) {
			plog(PLOG_DEBUG, PLOGLOC, NULL,
			     "  child %p ini=%d state=%d msgid=0x%08x\n",
			     (void *)s, s->is_initiator,
			     s->state, s->message_id);
		}
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected response (message_id 0x%08x) "
			   "-- no request in REQUEST_SENT/WAIT_RESPONSE\n",
			   message_id);
		++isakmpstat.unexpected_packet;
		goto done;
	}
	/* Only a real REQUEST_SENT match commits the window: an EXPIRED
	 * duplicate (or unknown msgid) must not stop retransmit or
	 * decrement request_pending for the request actually in flight.
	 * (review 2026-09-24: window was committed on the miss path.) */
	ikev2_update_message_id(ike_sa, message_id, TRUE);
	if (child_sa->callback) {
		child_sa->callback(REQUEST_CALLBACK_RESPONSE, child_sa,
				   msg);
	} else {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_INTWARN, PLOGLOC,
			   "no callback defined for response\n");
	}
	ikev2_child_state_set(child_sa, IKEV2_CHILD_STATE_EXPIRED);

      done:
	next_child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (next_child_sa)
		ikev2_wakeup_child_sa(next_child_sa);

	return;
}

void
ikev2_info_init_notify_recv(struct ikev2_child_sa *child_sa, rc_vchar_t *msg)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;

	/* HDR, SK {[N,] [D,] [CP], ... } */

	if (child_sa == NULL || msg == NULL || msg->v == NULL) {
		isakmp_log(0, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		    "ikev2_info_init_notify_recv: null child_sa/msg\n");
		return;
	}
	ike_sa = child_sa->parent;
	if (ike_sa == NULL) {
		isakmp_log(0, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		    "ikev2_info_init_notify_recv: null parent\n");
		return;
	}
	ikehdr = (struct ikev2_header *)msg->v;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (ikev2_process_notify(ike_sa, p, TRUE) != 0) {
				ikev2_abort(ike_sa, ECONNREFUSED);
				/* abort marked the SA DYING then DEAD (and
				 * expired its children); stop the walk. */
				return;
			}
			break;
		case IKEV2_PAYLOAD_DELETE:
			ikev2_process_delete(ike_sa, p, 0);
			/*
			 * RFC 7296 §1.4 allows {[N,] [D,] [CP,] ...};
			 * §3.11 allows multiple Delete payloads.
			 * Only stop if DELETE IKE_SA aborted the SA.
			 */
			if (ike_sa->state == IKEV2_STATE_DYING ||
			    ike_sa->state == IKEV2_STATE_DEAD)
				return;
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, 0, 0, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				isakmp_log(ike_sa, 0, 0, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;
				goto fail;
			}
			isakmp_log(ike_sa, 0, 0, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	if (ike_sa->cookie2_matched && ike_sa->mobike_rr_pending &&
	    ike_sa->mobike_rr_prev && ike_sa->remote) {
		struct sockaddr *probe = ike_sa->remote;

		/* Restore the address the kernel SAs still use, then
		 * migrate to the address that just proved routable. */
		ike_sa->remote = ike_sa->mobike_rr_prev;
		ike_sa->mobike_rr_prev = NULL;
		ike_sa->mobike_rr_pending = 0;
		ike_sa->cookie2_matched = 0;
		ike_sa->mobike_alt_idx = 0;
		isakmp_log(ike_sa, ike_sa->local, probe, 0, PLOG_INFO, PLOGLOC,
			   "MOBIKE responder-follow COOKIE2 matched, migrating\n");
		ikev2_mobike_apply(ike_sa, probe, ike_sa->local);
		rc_free(probe);
	}
	return;

      fail:
	return;
}

/*
 * respond with no payloads (except ENCRYPTED)
 * primarily for minimum response of Informational exchange
 * returns 0 if the packet sent successfully, otherwise -1
 */
int
ikev2_respond_null(struct ikev2_sa *ike_sa, rc_vchar_t *request,
		   struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_payloads payl;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	rc_vchar_t *pkt = 0;
	int retval;

	ikev2_payloads_init(&payl);

	ikehdr = (struct ikev2_header *)request->v;
	message_id = get_uint32(&ikehdr->message_id);

	pkt = ikev2_packet_construct(ikehdr->exchange_type,
				     IKEV2FLAG_RESPONSE | (ike_sa->is_initiator
							   ? IKEV2FLAG_INITIATOR
							   : 0),
				     message_id, ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0)
		goto fail;
	pkt = 0;
	retval = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	ikev2_payloads_destroy(&payl);
	return retval;

      fail:
	isakmp_log(ike_sa, local, remote, request,
		   PLOG_INTERR, PLOGLOC, "failed sending response\n");
	retval = -1;
	goto done;
}

int
ikev2_respond_error(struct ikev2_sa *ike_sa,
		    rc_vchar_t *request,
		    struct sockaddr *remote,
		    struct sockaddr *local,
		    unsigned int notify_proto,
		    uint8_t *spi,
		    int spilen, unsigned int notify_type, void *data, size_t datalen)
{
	struct ikev2_payloads payl;
	struct ikev2_header *ikehdr;
	uint32_t message_id;
	rc_vchar_t *pkt = 0;
	int retval;

	ikev2_payloads_init(&payl);

	ikehdr = (struct ikev2_header *)request->v;
	message_id = get_uint32(&ikehdr->message_id);

	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(notify_proto,
						 spi, spilen,
						 notify_type,
						 data, datalen),
			    TRUE);

	pkt = ikev2_packet_construct(ikehdr->exchange_type,
				     IKEV2FLAG_RESPONSE | (ike_sa->is_initiator
							   ? IKEV2FLAG_INITIATOR
							   : 0),
				     message_id, ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0)
		goto fail;
	pkt = 0;
	retval = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	ikev2_payloads_destroy(&payl);
	return retval;

      fail:
	isakmp_log(ike_sa, local, remote, request,
		   PLOG_INTERR, PLOGLOC, "failed sending response\n");
	retval = -1;
	goto done;
}

/*
 * process a DELETE payload
 *
 * if response_payloads is non-null, this payload is a request, and a response payload must be constructed and pushed into response_payloads
 */
void
ikev2_process_delete(struct ikev2_sa *ike_sa, struct ikev2_payload_header *p,
		     struct ikev2_payloads *response_payloads)
{
	struct ikev2payl_delete *d;
	unsigned int protocol_id;
	unsigned int spi_size;
	unsigned int num_spi;
	uint8_t *spi_ptr;
	int this_is_request;
	rc_vchar_t *response = 0;
	uint8_t *response_spi = 0;
	int i;
	uint32_t spi;
	struct ikev2_child_sa *child_sa;
#if 0
	struct rcf_policy *policy;
#endif

	d = (struct ikev2payl_delete *)p;
	protocol_id = d->dh.protocol_id;
	spi_size = d->dh.spi_size;
	num_spi = get_uint16(&d->dh.num_spi);

	TRACE((PLOGLOC,
	       "ikev2_process_delete: protocol_id 0x%02x spi_size %u num_spi %u\n",
	       protocol_id, spi_size, num_spi));

	if (response_payloads) {
		/* this is request and need response */
		this_is_request = TRUE;
		response = rc_vmalloc(spi_size * num_spi);
		if (!response)
			goto fail_nomem;
		response_spi = (uint8_t *)response->v;
	} else {
		this_is_request = FALSE;
	}

	switch (protocol_id) {
	case IKEV2_DELETE_PROTO_IKE:
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_INFO, PLOGLOC, "received DELETE IKE_SA\n");
		if (spi_size != 0) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "delete payload protocol_id is IKE but spi_size is non-zero (%u)\n",
				   d->dh.spi_size);
			++isakmpstat.malformed_payload;
			goto fail_invalid_syntax;
		}
		switch (ike_sa->state) {
		case IKEV2_STATE_DYING:
		case IKEV2_STATE_DEAD:
			TRACE((PLOGLOC, "already dying\n"));
			break;
		default:
			ikev2_abort(ike_sa, ETIMEDOUT);
			break;
		}
		break;

	case IKEV2_DELETE_PROTO_AH:
	case IKEV2_DELETE_PROTO_ESP:
		if (spi_size != sizeof(uint32_t)) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_PROTOERR, PLOGLOC,
				   "delete payload protocol_id is %d but spi_size is %d\n",
				   protocol_id, spi_size);
			++isakmpstat.malformed_payload;
			goto fail_invalid_syntax;
		}

		/* for each SPI in DELETE payload */
		for (i = 0, spi_ptr = (uint8_t *)(d + 1);
		     (unsigned int)i < num_spi;
		     ++i, spi_ptr += sizeof(uint32_t)) {
			struct prop_pair *proposal;

			spi = get_uint32(spi_ptr);
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INFO, PLOGLOC,
				   "delete proto %s spi 0x%08x\n",
				   (protocol_id == IKEV2_DELETE_PROTO_AH ?  "AH" :
				    protocol_id == IKEV2_DELETE_PROTO_ESP ? "ESP" :
				    "(unknown)"), spi);

			/* find corresponding child_sa */
			child_sa =
				ikev2_find_child_sa_by_spi(ike_sa, protocol_id,
							   spi, PEER);
			if (!child_sa) {
				isakmp_log(ike_sa, 0, 0, 0,
					   PLOG_PROTOWARN, PLOGLOC,
					   "can't find sa for proto %s spi 0x%08x\n",
					   (protocol_id == IKEV2_DELETE_PROTO_AH ? "AH" :
					    protocol_id == IKEV2_DELETE_PROTO_ESP ? "ESP" :
					    "(unknown)"), spi);
				/* RFC 7296 §2.8.2: a Delete naming an SA we do
				 * not hold must be answered with INVALID_SPI
				 * echoing the protocol + SPI the peer named,
				 * rather than a generic delete echo (which
				 * would silently claim we deleted it) or a
				 * silent drop.  Only on a request (we are the
				 * responder to an INFORMATIONAL). */
				if (this_is_request &&
				    (protocol_id == IKEV2_DELETE_PROTO_ESP ||
				     protocol_id == IKEV2_DELETE_PROTO_AH)) {
					uint8_t spi_buf[sizeof(uint32_t)];
					put_uint32(spi_buf, spi);
					ikev2_payloads_push(response_payloads,
					    IKEV2_PAYLOAD_NOTIFY,
					    ikev2_notify_payload(protocol_id,
						spi_buf, sizeof(spi_buf),
						IKEV2_INVALID_SPI, 0, 0),
					    TRUE);
					isakmp_log(ike_sa, 0, 0, 0,
					    PLOG_PROTOWARN, PLOGLOC,
					    "responding INVALID_SPI proto %d spi 0x%08x\n",
					    protocol_id, spi);
				}
				continue;
			}
			switch (child_sa->state) {
			case IKEV2_CHILD_STATE_WAIT_RESPONSE:
			case IKEV2_CHILD_STATE_MATURE:
				break;
			case IKEV2_CHILD_STATE_EXPIRED:
				TRACE((PLOGLOC,
				       "child_sa %p state expired, skipping\n",
				       child_sa));
				continue;
			default:
				TRACE((PLOGLOC,
				       "unexpected child_sa %p state (%d), skipping\n",
				       child_sa, child_sa->state));
				continue;
				break;
			}

#if 0
			policy = child_sa->selector->pl;
#endif

			/* (draft-17)
			 * If by chance both ends of a set
			 * of SAs independently decide to close them, each may send a delete
			 * payload and the two requests may cross in the network. If a node
			 * receives a delete request for SAs for which it has already issued a
			 * delete request, it MUST delete the outgoing SAs while processing the
			 * request and the incoming SAs while processing the response. In that
			 * case, the responses MUST NOT include delete payloads for the deleted
			 * SAs, since that would result in duplicate deletion and could in
			 * theory delete the wrong SA.
			 */
			/*
			 * ??? hard to interpret
			 */

			ikev2_child_delete_outbound(child_sa);
			if (!child_sa->delete_sent && this_is_request)
				ikev2_child_delete_inbound(child_sa);

			if (!(child_sa->delete_sent && this_is_request))
				ikev2_child_state_set(child_sa,
						      IKEV2_CHILD_STATE_EXPIRED);

			if (response && !child_sa->delete_sent) {
				/* return DELETE payload */
				TRACE((PLOGLOC, "response delete payload\n"));

				/* find corresponding my proposal information.
				 * RFC 7296 1.4.1: the DELETE request lists the SPI
				 * the peer expects in its inbound headers - that is
				 * OUR outbound direction, the SPI the peer chose.
				 * The response must carry Delete payloads for the
				 * paired SAs going the other direction - the peer's
				 * outbound = OUR chosen SPI, held in my_proposal[1].
				 * Echoing peer_proposal returns the same SPI the
				 * request already closed (duplicate deletion; seen
				 * live in DEL_REPLY echo==req, and pre-fix deaths
				 * occurred with the correct echo too, so the echo
				 * value is not the rekey killer). */
				for (proposal = child_sa->my_proposal[1];
				     proposal;
				     proposal = proposal->next) {
					struct isakmp_pl_p *prop;
					prop = proposal->prop;
					if (prop->proto_id == protocol_id) {
						uint32_t inbound_spi;

						inbound_spi =
							get_uint32(prop + 1);
						isakmp_log(ike_sa, 0, 0, 0,
						   PLOG_INFO, PLOGLOC,
						   "DEL_REPLY: echoing spi 0x%08x for req spi 0x%08x proto %d child_state=%d delete_sent=%d\n",
						   inbound_spi, spi, protocol_id,
						   child_sa->state, child_sa->delete_sent);
						if (inbound_spi != 0) {
							TRACE((PLOGLOC,
							       "spi 0x%x\n",
							       inbound_spi));
							put_uint32(response_spi,
								   inbound_spi);
							response_spi += sizeof(uint32_t);
						} else {
							TRACE((PLOGLOC,
							       "inbound spi is zero\n"));
						}
						break;
					}
				}
				if (!proposal)
					TRACE((PLOGLOC,
					       "failed to find spi for inbound spi\n"));
			}
		}
		break;

	default:
		isakmp_log(ike_sa, 0, 0, 0,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected protocold id (%d) in DELETE payload\n",
			   protocol_id);
		++isakmpstat.malformed_payload;
		goto fail_invalid_syntax;
		break;
	}

	/* create notify payload for response message */
	if (response && response_spi != (uint8_t *)response->v) {
		ikev2_payloads_push(response_payloads,
				    IKEV2_PAYLOAD_DELETE,
				    ikev2_delete_payload(protocol_id,
							 spi_size,
							 (response_spi -
							  (uint8_t *)response->v) / spi_size,
							 (uint8_t *)response->v),
				    TRUE);
	}
      done:
	if (response)
		rc_vfree(response);
	return;

      fail_nomem:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed allocating memory\n");
	goto done;

      fail_invalid_syntax:
	if (response_payloads) {
		ikev2_payloads_push(response_payloads,
				    IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INVALID_SYNTAX,
							 0, 0),
				    TRUE);
	}
	goto done;
}

