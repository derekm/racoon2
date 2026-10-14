/* $Id: ikev2_sa_auth.c	$ */

/*
 * Copyright (C) 2004-2026 WIDE Project.
 * All rights reserved.
 *
 * IKE_AUTH exchange (RFC 7296 §2.9), split out of ikev2.c so the full
 * authentication core lives in its own translation unit (Phase 2 of the
 * modularization).  This file owns:
 *
 *   initiator    initiator_state1_send, initiator_ike_sa_auth_recv0/_cont/_recv
 *   responder    responder_ike_sa_auth_recv0/_recv/_cont,
 *                ikev2_responder_state1_send,
 *                ikev2_responder_childless_auth_send
 *   EAP          the responder EAP arm (responder_ike_sa_auth_eap_*) and the
 *                two responder_EAP send builders that drive the EAP relay
 *   shared       ikev2_peer_id_ok (fresh + resumed IDi policy check)
 *
 * The IKE_AUTH family in ikev2.c was already EAP-interleaved; it moves as a
 * coherent unit so the non-EAP AUTH core and the EAP responder arm stay
 * together.  Exports needed by ikev2.c dispatch + ikev2_verified + the SA_INIT /
 * session_resume / child200 modules are declared in ikev2_impl.h; everything
 * else here is static.
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

/* Forward declarations (original ikev2.c top-block, moved with the seam). */
static void responder_ike_sa_auth_eap_cont(struct ikev2_sa *, uint32_t,
					   struct ikev2_payload_header *,
					   struct sockaddr *);
void responder_ike_sa_auth_eap_final_recv(struct ikev2_sa *,
					  rc_vchar_t *,
					  struct sockaddr *, struct sockaddr *);
static void responder_ike_sa_auth_eap_resume(struct ikev2_eap_round *, int);
static int ikev2_responder_eap_send(struct ikev2_sa *, uint32_t, rc_vchar_t *);
static int ikev2_eap_sig_configured(struct ikev2_sa *);
static int ikev2_responder_eap_auth_send(struct ikev2_sa *, uint32_t,
					 rc_vchar_t *);

void
initiator_state1_send(struct ikev2_sa *ike_sa, void *certreq,
		      struct sockaddr *dest)
{
	struct rc_idlist *my_id;
	rc_vchar_t *my_cert = 0;
	int need_cert = FALSE;	/* whether to send CERTREQ */
	rc_vchar_t *req = 0;	/* CERTREQ data */
	rc_vchar_t *id_i;
	rc_vchar_t *id_r = 0;
	rc_vchar_t *auth = 0;
	rc_vchar_t *sa_i2 = 0;
	rc_vchar_t *ts_i = 0;
	rc_vchar_t *ts_r = 0;
	struct ikev2_payloads payl;
	struct ikev2_child_sa *child_sa;
	rc_vchar_t *pkt = 0;
#ifdef WITH_INTERMEDIATE
	uint32_t auth_msgid = (uint32_t)(1 + ike_sa->intermediate_rounds);
#else
	uint32_t auth_msgid = 1;
#endif

	/*
	 * send message 3
	 *
	 * type 1:
	 * HDR, SK {IDi, [CERT+],
	 *          [N(INITIAL_CONTACT)],
	 *          [[N(HTTP_CERT_LOOKUP_SUPPORTED)], CERTREQ+],
	 *          [IDr],
	 *          AUTH,
	 *          [CP(CFG_REQUEST)],
	 *          [N(IPCOMP_SUPPORTED)+],
	 *          [N(USE_TRANSPORT_MODE)],
	 *          [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
	 *          [N(NON_FIRST_FRAGMENTS_ALSO)],
	 *          SA, TSi, TSr,
	 *          [V+]}
	 *
	 *   ??? [N(SET_WINDOW_SIZE),]
	 */

	ikev2_payloads_init(&payl);

#ifdef notyet
	if (certreq) {
		my_cert = find_cert(certreq);
		/* (draft-17)
		 * If no certificates exist then the CERTREQ is ignored. This
		 * is not an error condition of the protocol.
		 */
	}
#endif

	my_id = ikev2_my_id(ike_sa->rmconf);
	if (!my_id)
		goto fail_no_my_id;
	id_i = ikev2_identifier(my_id);
	if (!id_i)
		goto fail;
	ike_sa->id_i = id_i;

	if (ikev2_send_peers_id(ike_sa->rmconf) == RCT_BOOL_ON) {
		struct rc_idlist *peers_id;
		peers_id = ikev2_peers_id(ike_sa->rmconf);
		if (! peers_id) {
			isakmp_log(ike_sa, 0, 0, 0,
				   PLOG_INTERR, PLOGLOC,
				   "configuration lacks peers_id\n");
			++isakmpstat.fail_send_packet;
			goto done;
		}
		id_r = ikev2_identifier(peers_id);
		if (!id_r)
			goto fail;
	}

	auth = ikev2_auth_calculate(ike_sa, TRUE);
	if (!auth)
		goto fail;	/* no authentication information, or transient error */

	child_sa = ikev2_choose_pending_child(ike_sa, FALSE);
	if (!child_sa)
		goto fail;	/* normally it shouldn't happen */

	assert(child_sa->is_initiator);

	ikev2_create_config_request(child_sa);

	/* initial IKE_AUTH child: no ADDKE/type-6 (RFC 9370 s2.2; CREATE_CHILD only) */
	child_sa->in_ike_auth = 1;
	sa_i2 = ikev2_construct_sa(child_sa);
	ts_i = ikev2_construct_ts_i(child_sa);
	ts_r = ikev2_construct_ts_r(child_sa);
	if (!(sa_i2 && ts_i && ts_r))
		goto fail_create_payload;

	/* (draft-17)
	 * The initiator asserts its identity with the IDi payload, proves
	 * knowledge of the secret corresponding to IDi and integrity protects
	 * the contents of the first message using the AUTH payload (see section
	 * 2.15).  It might also send its certificate(s) in CERT payload(s) and
	 * a list of its trust anchors in CERTREQ payload(s). If any CERT
	 * payloads are included, the first certificate provided MUST contain
	 * the public key used to verify the AUTH field.  The optional payload
	 * IDr enables the initiator to specify which of the responder's
	 * identities it wants to talk to. This is useful when the machine on
	 * which the responder is running is hosting multiple identities at the
	 * same IP address.  The initiator begins negotiation of a CHILD_SA
	 * using the SAi2 payload. The final fields (starting with SAi2) are
	 * described in the description of the CREATE_CHILD_SA exchange.
	 */

	/*
	 * IDi
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_I, id_i, FALSE);

	/*
	 * [CERT+]
	 */
	if (my_cert)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CERT, my_cert, FALSE);

	/*
	 * [N(INITIAL_CONTACT)]
	 */
	if (ikev2_send_initial_contact(ike_sa))
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INITIAL_CONTACT,
							 0, 0),
				    TRUE);

	/* RFC 5723 s4.1: as an INITIATOR, ask the peer (a resumption
	 * responder) to issue us a session-resumption ticket when session
	 * resumption is enabled for this remote.  A resumed IKE_AUTH must
	 * NOT re-request (the ticket that resumed this SA is already held);
	 * that would mint a second unrelated ticket. */
	if (ikev2_use_session_resumption(ike_sa->rmconf) == RCT_BOOL_ON
	    && !ike_sa->resumed) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_TICKET_REQUEST,
							 0, 0),
				    TRUE);
	}

        /*
	 * [[N(HTTP_CERT_LOOKUP_SUPPORTED)], CERTREQ+]
	 */
	if (need_cert)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CERTREQ, req, FALSE);

	/*
	 * [IDr]
	 */
	if (id_r)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_R, id_r, FALSE);

	/*
	 * AUTH
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_AUTH, auth, FALSE);

	/*
	 * [CP(CFG_REQUEST)]
	 */
	if (child_sa->child_param.cfg_payload)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG,
				    child_sa->child_param.cfg_payload, FALSE);

#ifdef notyet
	/*
	 * [N(IPCOMP_SUPPORTED)+]
	 */
#endif

	/*
	 * [N(USE_TRANSPORT_MODE)]
	 */
	if (ike_ipsec_mode(child_sa->selector->pl) == RCT_IPSM_TRANSPORT)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
							 0, 0,
							 IKEV2_USE_TRANSPORT_MODE,
							 0, 0),
				    TRUE);

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

	/* RFC 8784 s2.3: in IKE_AUTH, identify the PPK we used (the
	 * configured ppk_id).  When using the PPK is merely optional for
	 * us, also advertise N(NO_PPK_AUTH) so a peer that cannot honour
	 * this PPK may continue classically; this only reaches a responder
	 * that already echoed N(USE_PPK) (ppk_active set at IKE_SA_INIT). */
	if (ike_sa->ppk_active) {
		rc_vchar_t *ppk_id = ikev2_ppk_id(ike_sa->rmconf);
		if (ppk_id && ppk_id->l > 0) {
			/* RFC 8784 s5.1: the PPK_ID we send has its first octet as the
			 * PPK_ID type (2=PPK_ID_FIXED) with the remaining octets the
			 * configured ppk_id -- a strict responder (iOS, strongSwan)
			 * derives the identifier from the octets AFTER the type byte
			 * and would not match a bare id. */
			rc_vchar_t *typed = rc_vmalloc(ppk_id->l + 1);
			if (typed) {
				((uint8_t *)typed->v)[0] = 2;	/* PPK_ID_FIXED */
				memcpy((uint8_t *)typed->v + 1, ppk_id->v, ppk_id->l);
				ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
						    ikev2_notify_payload(0, 0, 0,
									 IKEV2_PPK_IDENTITY,
									 typed->v, typed->l),
						    TRUE);
				rc_vfree(typed);
			}
			if (ikev2_ppk_mandatory(ike_sa->rmconf) ==
			    RCT_BOOL_OFF)
				ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
						    ikev2_notify_payload(0, 0, 0,
									 IKEV2_NO_PPK_AUTH,
									 0, 0),
						    TRUE);
		}
	}

	/*
	 * SA, TSi, TSr -- RFC 6023 s3: a childless initiator sends a MODIFIED
	 * (SA-less) IKE_AUTH that MUST NOT carry SAi2/TSi/TSr; the first child is
	 * added afterwards via a separate CREATE_CHILD_SA (woken at ESTABLISHED).
	 * It MAY do so only if the IKE_SA_INIT response carried
	 * CHILDLESS_IKEV2_SUPPORTED and MUST NOT otherwise.  The remote's
	 * "childless on" or the policy's "initial_child_ke childless" asks for
	 * it; without the peer's 16418 send a normal IKE_AUTH (and, for
	 * initial_child_ke childless, rekey that child right away instead).
	 */
	{
		int want_childless =
		    ikev2_childless(ike_sa->rmconf) == RCT_BOOL_ON ||
		    ikev2_initial_child_ke(child_sa) == RCT_ICKE_CHILDLESS;

		ike_sa->childless_requested =
		    want_childless && ike_sa->peer_childless;
		if (want_childless && !ike_sa->peer_childless)
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
				   "childless requested but the responder did "
				   "not send CHILDLESS_IKEV2_SUPPORTED; sending "
				   "a normal IKE_AUTH (RFC 6023 s3)\n");
	}
	if (!ike_sa->childless_requested) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa_i2, FALSE);
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_I, ts_i, FALSE);
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_R, ts_r, FALSE);
	} else {
		TRACE((PLOGLOC, "childless IKE_AUTH (initiator): sending modified (SA-less) IKE_AUTH, no SAi2/TS (RFC 6023)\n"));
	}

	assert(ike_sa->sk_e_i);
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_AUTH, IKEV2FLAG_INITIATOR,
				     auth_msgid,
				     ike_sa, &payl);
	if (!pkt)
		goto fail;

#ifdef ENABLE_NATT
	if (ike_sa->behind_nat || ike_sa->peer_behind_nat ||
	    ikev2_nat_traversal(ike_sa->rmconf) == RCT_NATT_FORCE) {
		if (natt_float_ports(ike_sa->remote, ike_sa->local,
				     IKEV2_UDP_PORT_NATT) < 0) {
			goto fail;
		}
	}
#endif

	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	pkt = 0;

	if (ike_sa->childless_requested) {
		/* reserve the IKE_AUTH Message ID; the child did not ride
		 * in this request, so it stays GETSPI_DONE and is sent as
		 * CREATE_CHILD_SA once the IKE SA is ESTABLISHED */
		(void)ikev2_request_id(ike_sa);
	} else {
		child_sa->message_id = ikev2_request_id(ike_sa);
		ikev2_child_state_next(child_sa);
	}

      done:
	if (pkt)
		rc_vfree(pkt);
	if (id_r)
		rc_vfree(id_r);
	if (ts_r)
		rc_vfree(ts_r);
	if (ts_i)
		rc_vfree(ts_i);
	if (sa_i2)
		rc_vfree(sa_i2);
	if (auth)
		rc_vfree(auth);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	/* transient failure */
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed to create IKE_AUTH message\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_no_my_id:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "configuration lacks my_id\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_create_payload:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed creating %s payload for IKE_SA message\n",
		   (!sa_i2 ? "SA" : !ts_i ? "TSi" : !ts_r ? "TSr" :
		    "(shouldn't happen)"));
	++isakmpstat.fail_send_packet;
	goto done;

#ifdef notyet
	/*
	 * type 2: EAP case
	 * An initiator indicates a desire to use extended authentication by
	 * leaving out the AUTH payload from message 3.
	 */
	/*
	 * HDR, SK {IDi, [CERTREQ,] [IDr,] SAi2, TSi, TSr}
	 */

	/*
	 * type 3: requesting internal address on a remote network
	 *
	 * A request for such a temporary address can be included in
	 * any request to create a CHILD_SA (including the implicit request in
	 * message 3) by including a CP payload.
	 *
	 * HDR, SK {IDi, [CERT,] [CERTREQ,]
	 * [IDr,] AUTH, CP(CFG_REQUEST),
	 * SAi2, TSi, TSr}              -->
	 */
#endif

#ifdef notyet
	/*
	 * optional:
	 * Negotiation of IP compression is separate from the negotiation of
	 * cryptographic parameters associated with a CHILD_SA. A node
	 * requesting a CHILD_SA MAY advertise its support for one or more
	 * compression algorithms though one or more Notify payloads of type
	 * IPCOMP_SUPPORTED. The response MAY indicate acceptance of a single
	 * compression algorithm with a Notify payload of type IPCOMP_SUPPORTED.
	 * These payloads MUST NOT occur messages that do not contain SA
	 * payloads.
	 *
	 * send N(IPCOMP_SUPPORTED transfs...)
	 */
#endif

}




/*
 * Shared peer-identity validation: does the initiator's asserted IDi
 * (as an IKEv2 id value + rc type, i.e. the payload after the
 * Identification-Data length header) match one of this remote's
 * configured peers_id entries?  Used by BOTH a fresh IKE_AUTH accept
 * (responder_ike_sa_auth_recv0, RFC 7296 s3.5) and the resumed
 * (ticket) accept (responder_ike_session_resume_recv), so the same
 * identity policy is enforced on a reseated SA as on a first exchange.
 * Returns 0 on a match, -1 when no configured peers_id matches (or the
 * remote has no peers_id constraint).
 */
static int
ikev2_peer_id_ok(struct ikev2_sa *ike_sa, rc_type rc_id_type,
		 rc_vchar_t *id_data)
{
	struct rc_idlist *peers_id;

	if (!id_data)
		return -1;
	for (peers_id = ikev2_peers_id(ike_sa->rmconf);
	     peers_id; peers_id = peers_id->next) {
		if (ike_compare_id(rc_id_type, id_data, peers_id) == 0)
			return 0;
	}
	return -1;
}




void
responder_ike_sa_auth_recv0(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			    struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;
	struct ikev2_payload_header *id_i = 0;
	struct ikev2_payload_header *id_r = 0;
	struct ikev2payl_auth *auth = 0;
	struct ikev2_payload_header *sa_i2 = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	rc_vchar_t *id_data = 0;
	uint32_t message_id;
	int error;

	/*
	 * expect:  HDR, SK {IDi, [CERT,] [CERTREQ,] [IDr,], AUTH, SAi2, TSi, TSr}
	 * or
	 * IRAS case: HDR, SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, CP(CFG_REQUEST), SAi2, TSi, TSr}
	 * or
	 * error case:  HDR, SK {IDi, AUTH, N}
	 */
#ifdef notyet
	/*
	 * or
	 * EAP case:  HDR, SK {IDi, [CERTREQ,] [IDr,] SAi2, TSi, TSr}
	 */
#endif
	/*
	 * optional:
	 * [N(IPCOMP_SUPPORTED...),]
	 * [N(USE_TRANSPORT_MODE),]
	 * [N(INITIAL_CONTACT),]
	 * [N(SET_WINDOW_SIZE),]
	 * [N(HTTP_CERT_LOOKUP_SUPPORTED),]
	 * [N(ESP_TFC_PADDING_NOT_SUPPORTED),]
	 */

#ifdef notyet
	/* (draft-17)
	 * In the case where the IRAS's configuration
	 * requires that CP be used for a given identity IDi, but IRAC has
	 * failed to send a CP(CFG_REQUEST), IRAS MUST fail the request, and
	 * terminate the IKE exchange with a FAILED_CP_REQUIRED error.
	 */
#endif

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);
#ifdef WITH_INTERMEDIATE
	/* RFC 9242: inbound IKE_INTERMEDIATE between IKE_SA_INIT and IKE_AUTH
	 * is handled by the responder's intermediate round (pre-AUTH). */
	isakmp_log(ike_sa, local, remote, msg, PLOG_DEBUG, PLOGLOC,
		   "state2(responder) recv exch=%d msgid=%u\n",
		   ikehdr->exchange_type, message_id);
	if (ikehdr->exchange_type == IKEV2EXCH_IKE_INTERMEDIATE) {
		responder_ike_intermediate_recv(ike_sa, msg, remote, local);
		return;
	}
#endif

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_ID_I:
			if (id_i)
				goto duplicate;
			id_i = p;
			break;
		case IKEV2_PAYLOAD_CERT:
#ifdef notyet
			/* (draft-17)
			 * Implementations MUST be capable of being configured to send and
			 * accept up to four X.509 certificates in support of authentication,
			 */
#endif
			break;
		case IKEV2_PAYLOAD_CERTREQ:
			break;
		case IKEV2_PAYLOAD_ID_R:
			if (id_r)
				goto duplicate;
			id_r = p;
			break;
		case IKEV2_PAYLOAD_AUTH:
			if (auth)
				goto duplicate;
			auth = (struct ikev2payl_auth *)p;
			break;
		case IKEV2_PAYLOAD_SA:
			if (sa_i2)
				goto duplicate;
			sa_i2 = p;
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
		case IKEV2_PAYLOAD_NOTIFY: {
			struct ikev2payl_notify *n = (struct ikev2payl_notify *)p;
			TRACE((PLOGLOC, "received notify type %s\n",
			       ikev2_notify_type_str(get_notify_type(n))));
			/* RFC 5998 s3: an EAP client that does not want the
			 * responder to authenticate with its public-key AUTH/CERT
			 * sends N(EAP_ONLY_AUTHENTICATION) (16417) in the first
			 * IKE_AUTH (message 3).  Record it; whether it is
			 * honored is decided by ikev2_eap_only_policy() (only
			 * an eap-only kmp_auth_method config honors it, and
			 * then only an RFC 5998 s4 safe method may finish). */
			if (get_notify_type(n) == IKEV2_EAP_ONLY_AUTHENTICATION &&
			    ikev2_eap_remote(ike_sa))
				ike_sa->eap_only = 1;
			/* RFC 5723 s4.1: a client requests a session-resumption
			 * ticket with N(TICKET_REQUEST) in the first IKE_AUTH
			 * (or a CREATE_CHILD / Informational it initiates).
			 * Record the request here; on a successful
			 * authentication the responder answers with
			 * N(TICKET_LT_OPAQUE) (issued in
			 * ikev2_message_issue_prf / the IKE_AUTH response
			 * build). */
			if (get_notify_type(n) == IKEV2_TICKET_REQUEST)
				ike_sa->ticket_requested = 1;
			/* process later */
			break;
		}
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;
		case IKEV2_PAYLOAD_CONFIG:
			/* process later */
			break;

		default:
			if (payload_is_critical(p)
			    || ikev2_payload_type_is_critical(type)) {
				uint8_t code;

				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "unexpected critical payload (type %d)\n",
					   type);
				++isakmpstat.unexpected_payload;

				code = type;
				if (ikev2_respond_error(ike_sa, msg, remote, local,
							0, 0, 0,
							IKEV2_UNSUPPORTED_CRITICAL_PAYLOAD,
							&code, sizeof(code)) == 0) {
					ikev2_update_message_id(ike_sa, message_id, FALSE);
					ikev2_abort(ike_sa, ECONNREFUSED);
				}
				goto done;
			}
			isakmp_log(ike_sa, local, remote, msg, PLOG_PROTOWARN,
				   PLOGLOC,
				   "unexpected noncritical payload (type %d) ignored\n",
				   type);
			++isakmpstat.payload_ignored;
			break;
		}
	}
	if (!(id_i && auth)) {
		/* RFC 7296 s2.16: an eap-configured remote with IDi and no
		 * AUTH starts the EAP exchange instead of failing syntax.
		 * Begin the relay with an EAP-Identity request and park the
		 * SA in the EAP state; the peer's EAP Response IKE_AUTH
		 * re-enters via responder_ike_sa_auth_eap_recv. */
		if (id_i && !auth && ikev2_eap_remote(ike_sa)) {
			struct ikev2_eap_relay *relay;
			rc_vchar_t *identity_req;

			/* RFC 7296 s2.16 / RFC 5998 s3: a responder may omit
			 * its AUTH only when the initiator asked for EAP-only
			 * authentication.  An eap-only config (no signature
			 * method, so nothing that could make rmethod nonzero)
			 * facing a peer that did not send
			 * N(EAP_ONLY_AUTHENTICATION) has no AUTH to send:
			 * refuse rather than emit an AUTH-less response the
			 * peer never agreed to. */
			if (ikev2_eap_only_policy(0,
				ikev2_eap_sig_configured(ike_sa),
				ike_sa->eap_only) == IKEV2_EAPONLY_REFUSE) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOERR, PLOGLOC,
					   "EAP-only responder (no signature "
					   "method) but the initiator did not "
					   "send N(EAP_ONLY_AUTHENTICATION) "
					   "(RFC 5998 s3); refusing\n");
				++isakmpstat.authentication_failed;
				error = IKEV2_AUTHENTICATION_FAILED;
				goto notify;
			}

			relay = racoon_calloc(1, sizeof(*relay));
			if (!relay)
				goto fail_nomem;
			identity_req = ikev2_eap_relay_start(relay, 1);
			if (!identity_req) {
				racoon_free(relay);
				goto fail_nomem;
			}
			/* store the SA's id_i before parking */
			if (ike_sa->id_i)
				rc_vfree(ike_sa->id_i);
			ike_sa->id_i = rc_vnew((uint8_t *)(id_i + 1),
					       get_payload_data_length(id_i));
			if (!ike_sa->id_i) {
				rc_vfree(identity_req);
				ikev2_eap_relay_free(relay);
				racoon_free(relay);
				goto fail_nomem;
			}
			ike_sa->eap_relay = relay;
			/* Retain the peer's child offer (SAi2/TSi/TSr[/CFG]) from
			 * this first IKE_AUTH: after EAP-Success the peer's RFC
			 * 5998 final message carries ONLY AUTH, so the child
			 * must be built here, from the offer stored now.  Each is
			 * copied whole (header+data, get_payload_length) so a
			 * later handler can cast it back to a payload header. */
			if (sa_i2) {
				ike_sa->eap_sa_i2 =
				    rc_vnew((uint8_t *)sa_i2,
					    get_payload_length(sa_i2));
			}
			if (ts_i) {
				ike_sa->eap_ts_i =
				    rc_vnew((uint8_t *)ts_i,
					    get_payload_length(ts_i));
			}
			if (ts_r) {
				ike_sa->eap_ts_r =
				    rc_vnew((uint8_t *)ts_r,
					    get_payload_length(ts_r));
			}
			/* RFC 7296 s2.16 auth checks peers_id like the AUTH path
			 * below: a road-warrior remote names the identities it
			 * accepts, and EAP must not start for an IDi the remote
			 * is configured to refuse.  Apply the same verify_id gate. */
			if (ikev2_verify_id(ike_sa->rmconf) == RCT_BOOL_ON) {
				rc_type rc_id_type;
				struct rc_idlist *peers_id;
				rc_vchar_t *id_data =
				    ikev2_id2rct_id(id_i, &rc_id_type);
				if (!id_data) {
					/* Unsupported IDi type (ikev2_id2rct_id
					 * returns NULL for that, not only OOM).
					 * eap_relay was already assigned above;
					 * null it before freeing so the SA (which
					 * stays alive) never holds a dangling
					 * pointer for dispose to double-free.
					 * Mirrors the no-match path's ikev2_abort
					 * so the SA and its relay are torn down. */
					rc_vfree(identity_req);
					ikev2_eap_relay_free(relay);
					racoon_free(relay);
					ike_sa->eap_relay = NULL;
					++isakmpstat.authentication_failed;
					/* the AUTH path replies
					 * AUTHENTICATION_FAILED; EAP has no
					 * AUTH to fail yet, so abort. */
					ikev2_abort(ike_sa, ECONNREFUSED);
					return;
				}
				for (peers_id = ikev2_peers_id(ike_sa->rmconf);
				     peers_id; peers_id = peers_id->next) {
					if (ike_compare_id(rc_id_type, id_data, peers_id) == 0)
						break;
				}
				rc_vfree(id_data);
				if (!peers_id) {
					isakmp_log(ike_sa, local, remote, msg,
						   PLOG_PROTOERR, PLOGLOC,
						   "received ID_I (type %s) does not match "
						   "peers id (EAP)\n",
						   rct2str(rc_id_type));
					rc_vfree(identity_req);
					ikev2_eap_relay_free(relay);
					racoon_free(relay);
					ike_sa->eap_relay = NULL;
					++isakmpstat.authentication_failed;
					/* the AUTH path replies AUTHENTICATION_FAILED; EAP
					 * has no AUTH to fail yet, so abort the IKE exchange. */
					ikev2_abort(ike_sa, ECONNREFUSED);
					return;
				}
			}

			/* park in the EAP continuation state and send the
			 * EAP-Identity request (first IKE_AUTH response: the
			 * responder authenticates itself here under RFC 7296
			 * s2.16 when a signature method is configured). */
			ikev2_set_state(ike_sa, IKEV2_STATE_RES_IKE_AUTH_EAP);
			ikev2_responder_eap_auth_send(ike_sa, message_id,
						      identity_req);
			rc_vfree(identity_req);
			/* each EAP round is a fresh IKE_AUTH request with a new
			 * message id; advance so the peer's next EAP-Response
			 * (msgid = this request + 1) passes the window. */
			ikev2_update_message_id(ike_sa, message_id, FALSE);
			TRACE((PLOGLOC, "responder EAP: started, state EAP\n"));
			return;
		}
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "received message lacks %s payload\n",
			   (!id_i ? "IDi" : !auth ? "AUTH" :
			    "(shouldn't happen)"));
		++isakmpstat.malformed_message;
		error = IKEV2_INVALID_SYNTAX;
		goto notify;
	}
	if (ike_sa->id_i)
		rc_vfree(ike_sa->id_i);
	ike_sa->id_i =
	    rc_vnew((uint8_t *)(id_i + 1), get_payload_data_length(id_i));

	IF_TRACE(ikev2_id_dump("ID_i", id_i));

	/*
	 * when receiving IKE_SA_INIT,
	 *   find conf by src addr,
	 *   if no conf then use default
	 * when receiving IKE_AUTH
	 *   if using default, search conf by ID_I and peers_id
	 *   if not default, compare ID_I with peers_id
	 */
	if (ike_sa->rmconf->rm_index == 0) {	/* default config clause */
		/* remote config was not found by src address */
		/* search by id_i */
		struct rcf_remote *conf;
		conf = ikev2_conf_find_by_id(id_i);
		if (conf) {
			TRACE((PLOGLOC, "using config remote %s\n",
			       rc_vmem2str(conf->rm_index)));
			ikev2_set_rmconf(ike_sa, conf);
		}
	} else if (ikev2_verify_id(ike_sa->rmconf) == RCT_BOOL_ON) {
		rc_type rc_id_type;

		/* compare id_i and conf->peers_id (shared with the resumed
		 * accept path, ikev2_peer_id_ok) */
		id_data = ikev2_id2rct_id(id_i, &rc_id_type);
		if (!id_data)
			goto fail_nomem;
		if (ikev2_peer_id_ok(ike_sa, rc_id_type, id_data) != 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "received ID_I (type %s [%s]) does not match peers id\n",
				   rct2str(rc_id_type),
				   ike_id_str(rc_id_type, id_data));
			++isakmpstat.authentication_failed;
			error = IKEV2_AUTHENTICATION_FAILED;
			goto notify;
		}
	}

	ike_sa->verified_info.packet = rc_vdup(msg);
	if (!ike_sa->verified_info.packet)
		goto fail_nomem;
	ike_sa->verified_info.result = VERIFIED_WAITING;
	ike_sa->verified_info.remote = remote;
	ike_sa->verified_info.local = local;
	ike_sa->verified_info.verify_param = (void *)auth;

	ikev2_set_state(ike_sa, IKEV2_STATE_RES_IKE_AUTH_RCVD);

	ikev2_verify(&ike_sa->verified_info);

      done:
	if (id_data)
		rc_vfree(id_data);

	return;

      fail_nomem:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing IKE_SA_AUTH packet\n");
	++isakmpstat.fail_process_packet;
	goto done;

      duplicate:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC,
		   "unnecessary duplicated payload (type %d)\n", type);
	++isakmpstat.duplicate_payload;
	error = IKEV2_INVALID_SYNTAX;
      notify:
	if (ikev2_respond_error(ike_sa, msg, remote, local,
				0, 0, 0, error, 0, 0) == 0) {
		ikev2_update_message_id(ike_sa, message_id, FALSE);
		ikev2_abort(ike_sa, ECONNREFUSED);
	}
	goto done;

#ifdef notyet
      unknown_peer:
	isakmp_log(ike_sa, local, remote, msg, PLOG_PROTOERR, PLOGLOC, "received ID_I is unknown\n");	/* XXX should display it */
	error = IKEV2_AUTHENTICATION_FAILED;
	goto notify;
#endif
}

void
responder_ike_sa_auth_eap_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			       struct sockaddr *remote, struct sockaddr *local)
{
	/* EAP continuation (IKEV2_STATE_RES_IKE_AUTH_EAP).  The peer's EAP
	 * Response IKE_AUTH re-enters here by dispatch; run it through one
	 * RADIUS round and either emit the next EAP or, on success, drive the
	 * MSK into the SA and complete the exchange. */
	struct ikev2_header *ikehdr = (struct ikev2_header *)msg->v;
	struct ikev2_payload_header *p;
	int type;
	struct ikev2_payload_header *eap = 0;
	uint32_t message_id;
	(void)local;

	message_id = get_uint32(&ikehdr->message_id);
	/* remember the peer's request msgid for this round so our EAP
	 * response echoes it (IKEv2 responses always echo the request id). */
	ike_sa->eap_message_id = message_id;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_EAP:
			if (eap)
				goto malformed;
			eap = p;
			break;
		default:
			break;
		}
	}
	if (!eap) {
		isakmp_log(ike_sa, remote, (struct sockaddr *)0, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "EAP continuation: missing EAP payload\n");
		goto malformed;
	}
	/* resume path handled by the worker bridge (see
	 * responder_ike_sa_auth_eap_resume below). */
	responder_ike_sa_auth_eap_cont(ike_sa, message_id, eap, remote);
	return;

      malformed:
	if (ikev2_respond_error(ike_sa, msg, remote, local,
				0, 0, 0, IKEV2_INVALID_SYNTAX, 0, 0) == 0)
		ikev2_update_message_id(ike_sa, message_id, FALSE);
	ikev2_abort(ike_sa, ECONNREFUSED);
	return;
}

/* Run one RADIUS round for the peer's EAP Response. */
static void
responder_ike_sa_auth_eap_cont(struct ikev2_sa *ike_sa, uint32_t message_id,
			       struct ikev2_payload_header *eap,
			       struct sockaddr *remote)
{
	struct ikev2_radius_opt opt;
	rc_vchar_t eapmsg, *secret = 0;
	struct sockaddr_storage server;
	socklen_t servlen;
	rc_vchar_t *radius_server;
	const char *server_str, *secret_path;
	int radius_port;
	uint8_t rid;
	FILE *fp;
	(void)remote;

	memset(&opt, 0, sizeof(opt));
	memset(&server, 0, sizeof(server));

	/* echo the Access-Challenge State the relay captured on the prior
	 * round (NULL on the first/identity round).  FreeRADIUS refuses to
	 * run EAP without it from the second Access-Request onward. */
	if (ike_sa->eap_relay) {
		struct ikev2_eap_relay *rel =
		    (struct ikev2_eap_relay *)ike_sa->eap_relay;
		opt.state = rel->state;
	}

	eapmsg.v = (uint8_t *)(eap + 1);
	eapmsg.l = get_payload_data_length(eap);

	/* RFC 3748 s4.1: the EAP-Response Identifier must echo the
	 * Identifier of the EAP-Request we most recently sent the peer
	 * (relay->eap_pending, unless it has already been consumed).  A
	 * stale or replayed Response with a mismatched Identifier must
	 * not open a new RADIUS round - drop it and let the peer's
	 * retransmission of the correct one proceed. */
	if (ike_sa->eap_relay) {
		struct ikev2_eap_relay *rel =
		    (struct ikev2_eap_relay *)ike_sa->eap_relay;
		if (rel->eap_pending && eapmsg.l >= 2 &&
		    rel->eap_pending->l >= 2 &&
		    ((uint8_t *)eapmsg.v)[1] != ((uint8_t *)rel->eap_pending->v)[1]) {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
				   "EAP: Response Identifier %u does not echo last Request "
				   "Identifier %u; dropping (RFC 3748 s4.1)\n",
				   (unsigned)((uint8_t *)eapmsg.v)[1],
				   (unsigned)((uint8_t *)rel->eap_pending->v)[1]);
			return;
		}
	}


	/* A retransmit of the final EAP-Response after a FAILED EAP-Success
	 * transmit (or a failed Success build) re-enters here with the MSK
	 * already stored and the relay finished.  Opening a new RADIUS round
	 * would hit the relay's finished guard and abort a completed Accept.
	 * Re-synthesize and re-send Success from the peer id, no new round.
	 * Mirror the resume path: on a successful send advance the message id
	 * AND park in RES_IKE_AUTH_EAP_FINAL, so the peer's RFC 5998 [AUTH]-only
	 * final is dispatched to responder_ike_sa_auth_eap_final_recv (slot 11),
	 * not re-entered here where an AUTH-only message would be misread as a
	 * missing EAP payload.  On send failure stay in EAP for the next
	 * retransmit. */
	if (ike_sa->eap_msk && ike_sa->eap_msk->l == 64) {
		rc_vchar_t *succ = ikev2_eap_build_success(
		    ike_sa->eap_last_peer_id);
		if (succ) {
			if (ikev2_responder_eap_send(
				ike_sa, message_id, succ) == 0) {
				ikev2_update_message_id(
				    ike_sa, message_id, FALSE);
				ikev2_set_state(
				    ike_sa,
				    IKEV2_STATE_RES_IKE_AUTH_EAP_FINAL);
			} else {
				isakmp_log(ike_sa, 0, 0, 0,
					   PLOG_PROTOERR, PLOGLOC,
					   "EAP: recovery Success transmit "
					   "failed; staying in EAP\n");
			}
			rc_vfree(succ);
		} else {
			/* do not open a new RADIUS round: the relay is finished,
			 * so only the (already sent) Success may answer the peer.
			 * A build failure here means OOM - log so a persistent
			 * failure is not mistaken for a hung exchange. */
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
				   "EAP: recovery could not build EAP-Success "
				   "(OOM); staying in EAP\n");
		}
		return;
	}

	/* Capture the EAP Identity (first round, Type=1) and carry it as
	 * RADIUS User-Name so the server can match the account to a stored
	 * secret (FreeRADIUS files authorize keys on it).  Store once on the
	 * SA; later rounds re-send the same identity. */
	if (!ike_sa->eap_user) {
		char *id = ikev2_eap_identity_string(&eapmsg);
		if (id)
			ike_sa->eap_user = id;
	}
	if (ike_sa->eap_user)
		opt.user_name = ike_sa->eap_user;
	/* a RADIUS User-Name attr holds at most IKEV2_RADIUS_MAX_VALUE octets;
	 * a longer identity would fail inside radius_put_attr and the failed
	 * round would abort the SA with a misleading 'submit failed'.  Reject
	 * with a log that names the actual length. */
	if (ike_sa->eap_user &&
	    strlen(ike_sa->eap_user) > IKEV2_RADIUS_MAX_VALUE) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "EAP: identity too long for RADIUS User-Name "
			   "(l=%zu, max %d)\n",
			   strlen(ike_sa->eap_user),
			   IKEV2_RADIUS_MAX_VALUE);
		goto fail_syntax;
	}

	/* remote RADIUS options from the SA's rmconf. */
	radius_server = ikev2_radius_server(ike_sa->rmconf);
	radius_port = ikev2_radius_port(ike_sa->rmconf);
	if (!radius_server || radius_server->l == 0) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "EAP: no radius_server for eap remote\n");
		goto fail_syntax;
	}
	server_str = rc_vmem2str(radius_server);
	if (!server_str)
		goto fail_nomem;
	if (inet_pton(AF_INET, server_str,
		      &((struct sockaddr_in *)&server)->sin_addr) != 1) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "EAP: radius_server '%s' not an IPv4 address\n",
			   server_str);
		goto fail_syntax;
	}
	((struct sockaddr_in *)&server)->sin_family = AF_INET;
	((struct sockaddr_in *)&server)->sin_port =
	    htons((radius_port > 0) ? radius_port : IKEV2_RADIUS_DEFAULT_PORT);
	servlen = sizeof(struct sockaddr_in);

	secret_path = rc_vmem2str(ikev2_radius_secret_file(ike_sa->rmconf));
	if (!secret_path) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "EAP: no radius_secret_file for eap remote\n");
		goto fail_syntax;
	}
	fp = fopen(secret_path, "r");
	if (!fp) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "EAP: cannot open radius_secret_file %s\n",
			   secret_path);
		goto fail_syntax;
	}
	secret = rc_vmalloc(256);
	if (!secret) { fclose(fp); goto fail_nomem; }
	secret->l = fread(secret->v, 1, 255, fp);
	fclose(fp);
	while (secret->l &&
	       (((uint8_t *)secret->v)[secret->l - 1] == '\n' ||
		((uint8_t *)secret->v)[secret->l - 1] == '\r' ||
		((uint8_t *)secret->v)[secret->l - 1] == ' '))
		secret->l--;

	if (secret->l == 0) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "EAP: empty radius_secret_file %s\n", secret_path);
		rc_vfreez(secret);
		goto fail_syntax;
	}

	opt.secret = secret;
	opt.retries = 2;
	opt.timeout_ms = 1000;
	if (!ike_sa->eap_rid)
		ike_sa->eap_rid = 1;
	rid = ike_sa->eap_rid;

	/* the worker round deep-copies opt/secret; we free ours after. */
	{
		int sr = ikev2_eap_round_submit(ike_sa, ike_sa->serial_number,
					       &eapmsg,
					       (struct sockaddr *)&server,
					       servlen, &opt,
					       &ike_sa->eap_rid,
					       responder_ike_sa_auth_eap_resume);
		if (sr == 1) {
			/* a round is already in flight on this SA: this is a
			 * retransmit of the in-flight EAP-Response.  Drop the
			 * duplicate - the original round's resume() will answer
			 * it.  Do NOT treat a re-entered round as a config
			 * failure (localhost RADIUS hides this; a slow server
			 * or a 1s peer retransmit would otherwise kill a good
			 * exchange). */
			isakmp_log(ike_sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
				   "EAP: dropping duplicate round (in flight)\n");
			rc_vfreez(secret);
			return;
		}
		if (sr != 0) {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
				   "EAP: round submit failed\n");
			rc_vfreez(secret);
			goto fail_syntax;
		}
		/* submit accepted this round: remember its EAP Response
		 * Identifier byte (wire offset 1).  RFC 3748 s4.2: the
		 * EAP-Success we synthesize after Acceptance must echo THIS
		 * id (a strict peer discards a misidentified Success).  The
		 * server's own Success packet forwarded from the Accept is
		 * preferred when the Accept carries one - only that has
		 * authority over the id.  Captured here (not before the
		 * in-flight drop) so a non-compliant retransmit cannot
		 * overwrite the id of the round that actually answers. */
		if (eapmsg.l >= 2)
			ike_sa->eap_last_peer_id =
			    ((uint8_t *)eapmsg.v)[1];
		/* remember the EAP method the peer is running (RFC 5998 s4
		 * check at Acceptance); Identity (1), Notification (2) and
		 * Nak (3) are not methods. */
		{
			int et = ikev2_eap_response_type(&eapmsg);
			if (et > 3)
				ike_sa->eap_method = et;
		}
	}
	(void)rid;
	rc_vfreez(secret);
	return;

      fail_nomem:
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		   "EAP: out of memory in continuation\n");
	++isakmpstat.fail_process_packet;
	return;

      fail_syntax:
	/* the recv-level handler already reports the malformed message; here
	 * we just tear the exchange down (no msg/remote to echo into). */
	ikev2_abort(ike_sa, ECONNREFUSED);
	return;
}

/* Worker-round resume: drive the decoded response into the relay and either
 * emit the next EAP Request / EAP-Success or, on Acceptance, complete. */
static void
responder_ike_sa_auth_eap_resume(struct ikev2_eap_round *r, int rc)
{
	struct ikev2_sa *ike_sa;
	struct ikev2_radius_response *resp;
	const rc_vchar_t *secret;
	rc_vchar_t *out_eap = NULL;
	enum ikev2_eap_drive_result dr;

	(void)rc;
	ike_sa = ikev2_eap_round_sa(r);
	if (!ike_sa)
		return;
	resp = ikev2_eap_round_response(r);
	secret = ikev2_eap_round_secret(r);

	dr = ikev2_eap_drive_advance(ike_sa,
				     (struct ikev2_eap_relay *)ike_sa->eap_relay,
				     resp, secret, &out_eap);
	/* RFC 5998 s4: when the responder omitted its AUTH (EAP-only
	 * honored), the EAP method itself must have authenticated the
	 * responder: it must be a listed safe (mutual, key-generating,
	 * dictionary-resistant) method AND have produced an MSK.  Anything
	 * else is answered with EAP-Failure. */
	if (dr == IKEV2_EAP_DRIVE_SUCCESS && ike_sa->eap_only_honored &&
	    (!ike_sa->eap_msk || ike_sa->eap_msk->l == 0 ||
	     !ikev2_eap_rfc5998_safe_method(ike_sa->eap_method))) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "EAP-only (RFC 5998): method %d is not a safe "
			   "mutual key-generating method or produced no MSK; "
			   "failing\n", ike_sa->eap_method);
		++isakmpstat.authentication_failed;
		dr = IKEV2_EAP_DRIVE_FAILURE;
	}
	switch (dr) {
	case IKEV2_EAP_DRIVE_CONTINUE:
		/* emit the next EAP Request to the client; stay in EAP, and
		 * advance the request window only once the response was
		 * actually transmitted, so the peer's next round
		 * (msgid = eap_message_id + 1) is accepted.  A failed send
		 * must not advance: the peer retransmits the old id. */
		if (ikev2_responder_eap_send(ike_sa, ike_sa->eap_message_id,
					    out_eap) == 0)
			ikev2_update_message_id(ike_sa,
						ike_sa->eap_message_id, FALSE);
		if (out_eap) rc_vfree(out_eap);
		return;
	case IKEV2_EAP_DRIVE_SUCCESS:
		/* MSK now stored on ike_sa->eap_msk.  Send EAP-Success to the
		 * client (payload 48, code 3) so it knows the method
		 * succeeded, then park in RES_IKE_AUTH_EAP_FINAL and await
		 * the peer's final RFC 5998 [AUTH]-only IKE_AUTH (carries no
		 * IDi), which responder_ike_sa_auth_eap_final_recv completes
		 * from the retained first-IKE_AUTH child offer (ab84fdb). */
		isakmp_log(ike_sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
			   "EAP: Acceptance, MSK stored (l=%u); sending "
			   "EAP-Success\n",
			   ike_sa->eap_msk ? (unsigned)ike_sa->eap_msk->l : 0u);
		{
			rc_vchar_t *succ = NULL;
			/* Only forward the server's own Success packet when it
			 * is a well-formed EAP-Success and its Identifier equals
			 * the peer EAP-Response id we proxied (RFC 3748 s2/s4.2):
			 * Code=3, Length field == 4 (Success is exactly 4 octets,
			 * no trailing attribute bytes) AND buffer length == 4.
			 * Anything else (non-Success, over-short, trailing data,
			 * mismatched id) is NOT forwarded - synthesize instead. */
			if (out_eap && out_eap->l == 4 &&
			    ((uint8_t *)out_eap->v)[0] == 3 &&
			    ((uint8_t *)out_eap->v)[1] == ike_sa->eap_last_peer_id &&
			    ((uint8_t *)out_eap->v)[2] == 0 &&
			    ((uint8_t *)out_eap->v)[3] == 4)
				succ = out_eap;
			/* Otherwise synthesize a Success echoing that same id -
			 * never eap_rid (the RADIUS Identifier). */
			if (!succ)
				succ = ikev2_eap_build_success(
				    ike_sa->eap_last_peer_id);
			/* The SA is parked (RES_IKE_AUTH_EAP_FINAL) ONLY once the
			 * Success was actually transmitted.  On a failed send,
			 * stay in the EAP continuation state: the peer retransmits
			 * the old msgid, which must be answered by re-sending the
			 * built Success, not by opening another RADIUS round. */
			if (succ) {
				if (ikev2_responder_eap_send(
					ike_sa, ike_sa->eap_message_id,
					succ) == 0) {
					ikev2_update_message_id(
					    ike_sa,
					    ike_sa->eap_message_id, FALSE);
					ikev2_set_state(
					    ike_sa,
					    IKEV2_STATE_RES_IKE_AUTH_EAP_FINAL);
				} else {
					isakmp_log(ike_sa, 0, 0, 0,
						   PLOG_PROTOERR, PLOGLOC,
						   "EAP: Success transmit failed; "
						   "staying in EAP\n");
				}
				if (succ != out_eap)
					rc_vfree(succ);
			}
		}
		if (out_eap) rc_vfree(out_eap);
		return;
	case IKEV2_EAP_DRIVE_FAILURE:
	default:
		/* RFC 3748 s4.2 + RFC 7296 s2.16: answer the outstanding
		 * IKE_AUTH with EAP-Failure (Code=4) so the peer's
		 * retransmission is not met with silence, then tear the
		 * exchange down.  The identifier echoes the peer EAP
		 * Response id we proxied (eap_last_peer_id). */
		isakmp_log(ike_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "EAP: RADIUS Reject/error (dr=%d); sending "
			   "EAP-Failure\n", dr);
		{
			rc_vchar_t *fail = ikev2_eap_build_failure(
			    ike_sa->eap_last_peer_id);
			if (fail) {
				ikev2_responder_eap_send(
				    ike_sa, ike_sa->eap_message_id, fail);
				rc_vfree(fail);
			}
		}
		if (out_eap) rc_vfree(out_eap);
		ikev2_abort(ike_sa, EACCES);
		return;
	}
}

/* RFC 5998 EAP-only final: after the responder sends EAP-Success the peer
 * sends a last IKE_AUTH carrying ONLY AUTH (no IDi, no child payloads - the
 * child offer was retained from the first IKE_AUTH).  This handler verifies
 * that MSK-based AUTH and completes the child from the retained offer,
 * reaching ESTABLISHED.  The message is already SK-authenticated (ICV passed
 * in ikev2_input); EAP final AUTH is SHARED_KEY, verified synchronously. */
void
responder_ike_sa_auth_eap_final_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
				     struct sockaddr *remote,
				     struct sockaddr *local)
{
	struct ikev2_header *ikehdr = (struct ikev2_header *)msg->v;
	struct ikev2_payload_header *p;
	struct ikev2payl_auth *auth = 0;
	struct ikev2_child_param child_param;
	struct ikev2_payload_header *sa_i2, *ts_i, *ts_r;
	uint32_t message_id;
	int type, error, result;

	message_id = get_uint32(&ikehdr->message_id);
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	/* the RFC 5998 final must be AUTH-only (no IDi, no child payloads).
	 * Like every decrypted-message handler below, skip the ENCRYPTED
	 * payload header (type 46) - its next_payload field surfaces the
	 * first inner (decrypted) payload type. */
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		if (type == IKEV2_PAYLOAD_ENCRYPTED)
			continue;
		if (type != IKEV2_PAYLOAD_AUTH) {
			isakmp_log(ike_sa, remote, local, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "EAP final: unexpected payload type %d "
				   "(want AUTH only)\n", type);
			goto fail;
		}
		if (auth)
			goto fail;
		auth = (struct ikev2payl_auth *)p;
	}
	if (!auth)
		goto fail;

	/* fail closed: no 64-octet MSK, nothing to verify/complete against */
	if (!ike_sa->eap_msk || ike_sa->eap_msk->l != 64) {
		isakmp_log(ike_sa, remote, local, msg,
			   PLOG_INTERR, PLOGLOC,
			   "EAP final: no 64-octet MSK to verify AUTH\n");
		goto fail;
	}

	/* verify the peer's MSK-based AUTH.  i_to_r=TRUE: the initiator
	 * (this peer) signs the I-to-R direction, covering its own IDi and
	 * the cached IKE_SA_INIT message - so no child payload is needed
	 * here, exactly what the [AUTH]-only message provides. */
	result = ikev2_auth_verify(ike_sa, TRUE, auth);
	if (result != VERIFIED_SUCCESS) {
		++isakmpstat.authentication_failed;
		isakmp_log(ike_sa, remote, local, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "EAP final: peer MSK-AUTH verification failed\n");
		error = IKEV2_AUTHENTICATION_FAILED;
		goto notify;
	}

	/* complete the child from the retained first-IKE_AUTH offer */
	if (!ike_sa->eap_sa_i2 || !ike_sa->eap_ts_i || !ike_sa->eap_ts_r) {
		isakmp_log(ike_sa, remote, local, msg,
			   PLOG_INTERR, PLOGLOC,
			   "EAP final: missing retained child offer\n");
		goto fail;
	}
	sa_i2 = (struct ikev2_payload_header *)ike_sa->eap_sa_i2->v;
	ts_i  = (struct ikev2_payload_header *)ike_sa->eap_ts_i->v;
	ts_r  = (struct ikev2_payload_header *)ike_sa->eap_ts_r->v;

	ikev2_child_param_init(&child_param);
	/* the child state machine (create_child_responder_cont ->
	 * responder_state1_send) drives to ESTABLISHED and installs the ESP
	 * SA; g_i/n_i=0 (no child DH at IKE_AUTH), mirroring the non-EAP
	 * responder_ike_sa_auth_cont call.  No cfg was retained (recv0
	 * defers CP to cont; an EAP remote has no config requirement).
	 * create_child_responder_cont must see RES_IKE_AUTH_RCVD (the state
	 * the non-EAP final send uses) to route to responder_state1_send,
	 * so move off the EAP_FINAL dispatch state first. */
	ikev2_set_state(ike_sa, IKEV2_STATE_RES_IKE_AUTH_RCVD);
	error = ikev2_create_child_responder(ike_sa, local, remote,
					     message_id,
					     sa_i2, ts_i, ts_r, 0,
					     0, 0, &child_param,
					     FALSE, 0, 0);
	if (error) {
		++isakmpstat.fail_process_packet;
		ikev2_child_param_destroy(&child_param);
		goto notify;
	}
	/* the child parsed the offer synchronously; release the retained copy */
	if (ike_sa->eap_sa_i2) { rc_vfreez(ike_sa->eap_sa_i2); ike_sa->eap_sa_i2 = NULL; }
	if (ike_sa->eap_ts_i) { rc_vfreez(ike_sa->eap_ts_i); ike_sa->eap_ts_i = NULL; }
	if (ike_sa->eap_ts_r) { rc_vfreez(ike_sa->eap_ts_r); ike_sa->eap_ts_r = NULL; }
	ikev2_update_message_id(ike_sa, message_id, FALSE);
	ikev2_child_param_destroy(&child_param);
	return;

      fail:
	isakmp_log(ike_sa, remote, local, msg,
		   PLOG_PROTOERR, PLOGLOC,
		   "EAP final: malformed final message\n");
	error = IKEV2_INVALID_SYNTAX;
	/* fall through */
      notify:
	if (ikev2_respond_error(ike_sa, msg, remote, local,
				0, 0, 0, error, 0, 0) == 0)
		ikev2_update_message_id(ike_sa, message_id, FALSE);
	ikev2_abort(ike_sa, ECONNREFUSED);
	return;
}

void
responder_ike_sa_auth_cont(struct ikev2_sa *ike_sa, int result, rc_vchar_t *msg,
			   struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	int type;
	struct ikev2_child_param child_param;
	int http_cert_lookup_supported = FALSE;
	struct ikev2_payload_header *id_r = 0;
	struct ikev2_payload_header *sa_i2 = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	struct ikev2_payload_header *cfg = 0;
	rc_vchar_t *id_data = 0;
	uint32_t message_id;
	int error;

	ikev2_child_param_init(&child_param);

	ikehdr = (struct ikev2_header *)msg->v;
	message_id = get_uint32(&ikehdr->message_id);

	switch (result) {
	case VERIFIED_WAITING:
		goto done;

	case VERIFIED_SUCCESS:
		/* RFC 5723 s4.3.4: the resumed IKE_AUTH succeeded; the old
		 * SA the client resumed from (if it is still live) is now
		 * redundant and MUST be silently deleted along with its
		 * children - no DELETE informational.  Only meaningful on a
		 * resumed SA (resume_old_spi_* set from the ticket). */
		if (ike_sa->resumed &&
		    (ike_sa->resume_old_spi_i || ike_sa->resume_old_spi_r))
			ikev2_silently_delete_old_resumed_sa(ike_sa,
			    ike_sa->resume_old_spi_i,
			    ike_sa->resume_old_spi_r);
		break;

	case VERIFIED_FAILURE:
	default:
		error = IKEV2_AUTHENTICATION_FAILED;
		goto notify;
	}

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_ID_R:
			id_r = p;
			break;
		case IKEV2_PAYLOAD_SA:
			sa_i2 = p;
			break;
		case IKEV2_PAYLOAD_TS_I:
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			ts_r = p;
			break;
		default:
			break;
		}
	}

	if (id_r) {
		/* compare id_r and conf->my_id */
		rc_type rc_id_type;
		struct rc_idlist *my_id;

		id_data = ikev2_id2rct_id(id_r, &rc_id_type);
		if (!rc_id_type) {
			++isakmpstat.authentication_failed;
			ike_sa->verified_info.result = VERIFIED_FAILURE;
			error = IKEV2_AUTHENTICATION_FAILED;
			goto notify;
		}
		if (!id_data)
			goto fail_nomem;

		my_id = ikev2_my_id(ike_sa->rmconf);
		for (; my_id; my_id = my_id->next) {
			if (my_id->idtype != rc_id_type)
				continue;
			if (ike_compare_id(rc_id_type, id_data, my_id) == 0)
				break;
		}
		if (!my_id) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "received ID_R (type %s [%s]) does not match my id\n",
				   rct2str(rc_id_type), ike_id_str(rc_id_type,
								   id_data));
			++isakmpstat.authentication_failed;
			ike_sa->verified_info.result = VERIFIED_FAILURE;
			error = IKEV2_AUTHENTICATION_FAILED;
			goto notify;
		}
		ike_sa->id_r = ikev2_identifier(my_id);
		if (!ike_sa->id_r)
			goto fail_nomem;
	}

	/*
	 * peer auth confirmed.
	 * process payloads with side-effects
	 */
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_NOTIFY:
			if (resp_ike_sa_auth_recv_notify
			    (ike_sa, msg, remote, local, p, &child_param,
			     &http_cert_lookup_supported) < 0) {
				goto abort;
			}
			break;

		case IKEV2_PAYLOAD_CONFIG:
			cfg = p;
			break;

		default:
			break;
		}
	}

	/* RFC 8784 s2.3: we echoed N(USE_PPK), so we MUST see a matching
	 * N(PPK_IDENTITY) in the IKE_AUTH request (a missing or mismatching
	 * PPK_ID is AUTHENTICATION_FAILED -- see resp_ike_sa_auth_recv_notify). */
	if (ike_sa->ppk_active && !ike_sa->peer_ppk_identity_ok) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "RFC 8784: USE_PPK negotiated but no matching "
			   "PPK_IDENTITY in IKE_AUTH; aborting\n");
		++isakmpstat.authentication_failed;
		error = IKEV2_AUTHENTICATION_FAILED;
		goto notify;
	}

	if (!(sa_i2 || ts_i || ts_r)) {
		/* RFC 6023 modified IKE_AUTH: all of SAi2/TSi/TSr are absent,
		 * which is only legal when we advertised CHILDLESS_IKEV2_SUPPORTED
		 * in the IKE_SA_INIT response (s3: MUST NOT send modified IKE_AUTH
		 * without it).  Accept: establish the IKE_SA with zero children.
		 */
		if (!ike_sa->childless_advertised) {
			/* RFC 6023 s3: we did not advertise 16418 in our
			 * IKE_SA_INIT response, so behave as a non-supporting
			 * responder.  Decide on what was sent, not on the
			 * remote config now selected (IKE_AUTH may have
			 * switched rmconf by peer ID). */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "received modified (SA-less) IKE_AUTH but childless support was not advertised\n");
			++isakmpstat.malformed_message;
			error = IKEV2_INVALID_SYNTAX;
			goto notify;
		}
		/* RFC 6023 s5: [CP(CFG_REQUEST)] is permitted in the modified request.
		 * Mirror the childful gate: a config-handling responder that requires a
		 * config payload MUST NOT accept a request that omits it. */
		if (ikev2_config_required(ike_sa->rmconf) == RCT_BOOL_ON && !cfg) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "childless peer message lacks required config payload\n");
			++isakmpstat.malformed_message;
			error = IKEV2_FAILED_CP_REQUIRED;
			goto notify;
		}
		if (cfg) {
			if (ikev2_process_config_informational(ike_sa, cfg, &child_param)) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOWARN, PLOGLOC,
					   "childless: failed processing CONFIG payload, ignored\n");
				++isakmpstat.payload_ignored;
			} else if (ikev2_create_config_reply(ike_sa, NULL, &child_param)) {
				isakmp_log(ike_sa, local, remote, msg,
					   PLOG_PROTOWARN, PLOGLOC,
					   "childless: failed to create CONFIG payload, continuing\n");
				++isakmpstat.payload_ignored;
			}
		}
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_INFO, PLOGLOC,
			   "received childless (SA-less) IKE_AUTH, establishing IKE_SA with zero children\n");
		ike_sa->childless_established = 1;	/* config requirement settled at SA-less IKE_AUTH */
		ikev2_update_message_id(ike_sa, message_id, FALSE);
		if (ikev2_responder_childless_auth_send(ike_sa, message_id,
						    child_param.cfg_payload) != 0) {
			++isakmpstat.fail_send_packet;
			error = IKEV2_INVALID_SYNTAX;
			goto notify;
		}
		goto done;
	}
	if (!(sa_i2 && ts_i && ts_r)) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "unexpected message format\n");
		++isakmpstat.malformed_message;
		error = IKEV2_INVALID_SYNTAX;
		goto notify;
	}
	if (ikev2_config_required(ike_sa->rmconf) == RCT_BOOL_ON &&
	    ! cfg) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "peer message lacks required config payload\n");
		++isakmpstat.malformed_message;
		error = IKEV2_FAILED_CP_REQUIRED;
		goto notify;
	}
#if 0
	conf = ikev2_conf_find_by_id(id_i);
	if (!conf)
		goto unknown_peer;
	ikev2_set_rmconf(ike_sa, conf);
#endif

	error = ikev2_create_child_responder(ike_sa, local, remote, message_id,
					     sa_i2, ts_i, ts_r, cfg, 0, 0,
					     &child_param, FALSE, 0, 0);
	if (error) {
		++isakmpstat.fail_process_packet; /* ??? */
		goto notify;
	}

	ikev2_update_message_id(ike_sa, message_id, FALSE);

	/*
	 * The new child_sa created by ikev2_create_child_responder()  must
	 * have its state set to GETSPI.  When the state transits out of GETSPI,
	 * ikev2_create_child_responder_cont() is called, and it
	 * calls responder_state1_send()
	 */

      done:
	if (id_data)
		rc_vfree(id_data);
	ikev2_child_param_destroy(&child_param);

	return;

      fail_nomem:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing IKE_SA_AUTH packet\n");
	++isakmpstat.fail_process_packet;
	goto done;

      abort:
	/* acknowledge with null response and abort exchange */
	if (ikev2_respond_null(ike_sa, msg, remote, local) == 0) {
		ikev2_update_message_id(ike_sa, message_id, FALSE);
		ikev2_abort(ike_sa, ECONNREFUSED);
	}
	goto done;

      notify:
	if (ikev2_respond_error(ike_sa, msg, remote, local,
				0, 0, 0, error, 0, 0) == 0) {
		ikev2_update_message_id(ike_sa, message_id, FALSE);
		ikev2_abort(ike_sa, ECONNREFUSED);
	}
	goto done;

#ifdef notyet
      unknown_peer:
	isakmp_log(ike_sa, local, remote, msg, PLOG_PROTOERR, PLOGLOC, "received ID_I is unknown\n");	/* XXX should display it */
	error = IKEV2_AUTHENTICATION_FAILED;
	goto notify;
#endif
}

/* RFC 6023: build + send the modified IKE_AUTH response for a childless
 * (SA-less) request: IDr, [CERT], AUTH, [N+]/[V+] but NO SAr2/TSi/TSr.
 * The IKE_SA is marked ESTABLISHED with zero children; DPD/liveness
 * (ikev2_sa_start_polling_timer) keeps it alive until the peer adds the
 * first child via CREATE_CHILD_SA.  Returns 0 on success.
 */


int
ikev2_responder_childless_auth_send(struct ikev2_sa *ike_sa,
			      uint32_t message_id,
			      rc_vchar_t *cfg_payload)
{
	rc_vchar_t *id_r = 0;
	rc_vchar_t *auth = 0;
	rc_vchar_t *my_cert = 0;
	struct ikev2_payloads payl;
	rc_vchar_t *pkt = 0;
	struct rc_idlist *my_id;
	int status = 0;

	ikev2_payloads_init(&payl);

	if (ike_sa->id_r) {
		id_r = ike_sa->id_r;
	} else {
		my_id = ikev2_my_id(ike_sa->rmconf);
		if (!my_id)
			goto fail;
		id_r = ikev2_identifier(my_id);
		if (!id_r)
			goto fail;
		ike_sa->id_r = id_r;
	}

	auth = ikev2_auth_calculate(ike_sa, FALSE);
	if (!auth)
		goto fail;

	/* [CERT+] under RSA-signature AUTH (mirror the childful responder). */
	{
		struct rc_alglist *kmp_auth_method =
		    ike_sa->rmconf->ikev2->kmp_auth_method;
		while (kmp_auth_method) {
			if (kmp_auth_method->algtype == RCT_ALG_RSASIG) {
				const char *filename = 0;
				int err;
				struct rc_pklist *pk =
				    ike_sa->rmconf->ikev2->my_pubkey;
				while (pk) {
					if (pk->ftype == RCT_FTYPE_X509PEM)
						filename = rc_vmem2str(pk->pubkey);
					pk = pk->next;
				}
				if (!filename || (err = rc_safefile(filename, FALSE)) != 0) {
					status = -1;
					goto fail;
				}
					if (err == 0) {
						rc_vchar_t *my_cert_data =
						    eay_get_x509cert(filename);
						uint8_t value = IKEV2_CERT_X509_SIGN;
						void *cert_encoding = &value;
						my_cert = rc_vprepend(my_cert_data,
								       cert_encoding,
								       sizeof(value));
						if (!my_cert) {
							rc_vfree(my_cert_data);
							status = -1;
							goto fail;
						}
						err = eay_check_x509cert(my_cert_data,
									 NULL);
						rc_vfree(my_cert_data);
						if (err) {
							rc_vfree(my_cert);
							my_cert = 0;
							status = -1;
							goto fail;
						}
					}
			}
			kmp_auth_method = kmp_auth_method->next;
		}
	}
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_R, id_r, FALSE);
	if (my_cert) {
		TRACE((PLOGLOC, "childless IKE_AUTH (responder): pushing CERT+ (X509)\n"));
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CERT, my_cert, FALSE);
	}
	if (ikev2_send_initial_contact(ike_sa))
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INITIAL_CONTACT,
							 0, 0), TRUE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_AUTH, auth, FALSE);

	/* [CP(CFG_REPLY)] RFC 6023 s5: answer a permitted CP(CFG_REQUEST). */
	if (cfg_payload) {
		TRACE((PLOGLOC, "childless IKE_AUTH (responder): pushing [CP(CFG_REPLY)]\n"));
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG, cfg_payload, FALSE);
	}

	/* RFC 8784 s2.3: acknowledge the PPK session (as in the childful path). */
	if (ike_sa->ppk_active)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_PPK_IDENTITY, 0, 0), TRUE);

	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_AUTH, IKEV2FLAG_RESPONSE,
				     message_id, ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, ike_sa->local, ike_sa->remote) != 0)
		goto fail;
	pkt = 0;

	ikev2_set_state(ike_sa, IKEV2_STATE_ESTABLISHED);
	natt_start_natk(ike_sa);

      done:
	if (pkt)
		rc_vfree(pkt);
	if (auth)
		rc_vfree(auth);
	if (my_cert)
		rc_vfree(my_cert);
	ikev2_payloads_destroy(&payl);
	return status;

      fail:
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		   "failed building childless IKE_AUTH response\n");
	status = -1;
	goto done;
}

/*
 * Send a responder EAP IKE_AUTH response: IDr + EAP Request (payload 48),
 * NO responder AUTH - used for continuation and EAP-Success rounds.  The
 * responder authenticates itself only in the FIRST IKE_AUTH response
 * (ikev2_responder_eap_auth_send, RFC 7296 s2.16 responder-cert case);
 * every later round (peer EAP-Response -> next EAP-Request, and the final
 * EAP-Success) is EAP-only.  Uses the hermetic composition from
 * ikev2_eap_emit_request().  The SA stays in its current IKE_AUTH responder
 * state so the peer's next EAP Response re-enters the responder dispatch.
 * eap_req is NOT consumed.  Returns 0 on success.
 */
static int
ikev2_responder_eap_send(struct ikev2_sa *ike_sa, uint32_t message_id,
			 rc_vchar_t *eap_req)
{
	struct ikev2_payloads payl;
	rc_vchar_t *pkt = 0;
	int status = 0;

	ikev2_payloads_init(&payl);

	if (ikev2_eap_emit_request(ike_sa, &payl, eap_req) != 0)
		goto fail;

	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_AUTH, IKEV2FLAG_RESPONSE,
				     message_id, ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, ike_sa->local,
				    ike_sa->remote) != 0)
		goto fail;
	pkt = 0;

	TRACE((PLOGLOC, "responder EAP: sent EAP Request (48) in IKE_AUTH "
	       "response (EAP-only round, no AUTH)\n"));

      done:
	if (pkt) rc_vfree(pkt);
	ikev2_payloads_destroy(&payl);
	return status;

      fail:
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		   "failed building responder EAP IKE_AUTH response\n");
	status = -1;
	goto done;
}

/* nonzero iff kmp_auth_method lists a non-EAP (signature/PSK) method */
static int
ikev2_eap_sig_configured(struct ikev2_sa *ike_sa)
{
	struct rc_alglist *m;

	for (m = ikev2_kmp_auth_method(ike_sa->rmconf); m; m = m->next)
		if (m->algtype != RCT_ALG_EAP)
			return 1;
	return 0;
}

/*
 * Send the FIRST responder EAP IKE_AUTH response (the EAP-Identity request).
 * RFC 7296 s2.16 responder-cert case: when a signature method is configured
 * beside eap, the responder authenticates itself to the client in this first
 * response - IDr + [CERT] + AUTH(responder signature) + EAP.  For an EAP-ONLY
 * responder (no signature method) this is IDr + EAP, identical to a
 * continuation round.  ikev2_eap_emit_request() is NOT used here for the
 * responder-cert branch because it also emits IDr; this variant composes
 * IDr + CERT + AUTH + EAP itself.  eap_req is NOT consumed.  Returns 0 on
 * success.
 */
static int
ikev2_responder_eap_auth_send(struct ikev2_sa *ike_sa, uint32_t message_id,
			      rc_vchar_t *eap_req)
{
	struct ikev2_payloads payl;
	rc_vchar_t *pkt = 0;
	rc_vchar_t *auth = 0, *my_cert = 0;
	struct rc_idlist *my_id;
	rc_vchar_t *id_r = 0;
	int rmethod;
	int status = 0;

	ikev2_payloads_init(&payl);

	rmethod = ikev2_eap_responder_method(ike_sa);
	switch (ikev2_eap_only_policy(rmethod, ikev2_eap_sig_configured(ike_sa),
				      ike_sa->eap_only)) {
	case IKEV2_EAPONLY_SIGN:
		break;
	case IKEV2_EAPONLY_SIGFAIL:
		/* rmethod==0 with a signature method configured means
		 * resolution FAILED (key missing/unreadable, unsupported
		 * ECDSA curve).  Never degrade to an AUTH-less response. */
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		   "EAP responder: signature method configured but "
		   "method resolution failed; aborting (no CERT+AUTH "
		   "downgrade)\n");
		ikev2_payloads_destroy(&payl);
		ikev2_abort(ike_sa, ECONNREFUSED);
		return -1;
	case IKEV2_EAPONLY_HONOR:
		/* RFC 5998 s3: eap-only config AND the initiator sent
		 * N(EAP_ONLY_AUTHENTICATION): IDr + EAP, no AUTH.  The
		 * method is checked for RFC 5998 s4 safety at Acceptance. */
		ike_sa->eap_only_honored = 1;
		ikev2_payloads_destroy(&payl);
		return ikev2_responder_eap_send(ike_sa, message_id, eap_req);
	case IKEV2_EAPONLY_REFUSE:
	default:
		/* the caller refuses this before parking; never send an
		 * AUTH-less response the initiator did not ask for. */
		ikev2_payloads_destroy(&payl);
		ikev2_abort(ike_sa, ECONNREFUSED);
		return -1;
	}

	/* responder-cert (RFC 7296 s2.16): IDr + [CERT] + AUTH + EAP. */
	if (ike_sa->id_r) {
		id_r = ike_sa->id_r;
	} else {
		my_id = ikev2_my_id(ike_sa->rmconf);
		if (!my_id)
			goto fail;
		id_r = ikev2_identifier(my_id);
		if (!id_r)
			goto fail;
		ike_sa->id_r = id_r;
	}
	auth = ikev2_auth_calculate_method(ike_sa, FALSE, rmethod);
	if (!auth)
		goto fail;

	/* [CERT+] under signature AUTH (mirror the childful responder):
	 * RSA (1/14) and ECDSA (9/10/11) both sign with a X.509 private
	 * key, so attach the peer's configured CERT for all of them. */
	if (rmethod == IKEV2_AUTH_RSASIG || rmethod == IKEV2_AUTH_DS ||
	    rmethod == IKEV2_AUTH_ECDSA_SHA256_P256 ||
	    rmethod == IKEV2_AUTH_ECDSA_SHA384_P384 ||
	    rmethod == IKEV2_AUTH_ECDSA_SHA512_P521) {
		const char *filename = 0;
		struct rc_pklist *pk = ike_sa->rmconf->ikev2->my_pubkey;
		while (pk) {
			if (pk->ftype == RCT_FTYPE_X509PEM)
				filename = rc_vmem2str(pk->pubkey);
			pk = pk->next;
		}
		/* fail closed like the childful responder (fail_no_my_cert):
		 * a signature AUTH must carry its CERT; never send a
		 * signature AUTH the peer cannot verify. */
		if (!filename || rc_safefile(filename, FALSE) != 0) {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "EAP responder: signature method configured but no "
			   "readable X.509 CERT (%s); aborting\n",
			   filename ? filename : "(none)");
			ikev2_payloads_destroy(&payl);
			ikev2_abort(ike_sa, ECONNREFUSED);
			return -1;
		}
		rc_vchar_t *my_cert_data = eay_get_x509cert(filename);
		if (!my_cert_data) {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "EAP responder: failed to read X.509 CERT (%s); "
			   "aborting\n", filename);
			ikev2_payloads_destroy(&payl);
			ikev2_abort(ike_sa, ECONNREFUSED);
			return -1;
		}
		uint8_t value = IKEV2_CERT_X509_SIGN;
		my_cert = rc_vprepend(my_cert_data, &value, sizeof(value));
		rc_vfree(my_cert_data);
		if (!my_cert) {
			ikev2_payloads_destroy(&payl);
			ikev2_abort(ike_sa, ECONNREFUSED);
			return -1;
		}
	}

	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_R, id_r, FALSE);
	if (my_cert)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CERT, my_cert, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_AUTH, auth, FALSE);
	/* EAP payload last (RFC 7296: EAP is the final payload of the
	 * IKE_AUTH response).  Can't use ikev2_eap_emit_request() here - it
	 * pushes its own IDr, which would duplicate the one above. */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_EAP, eap_req, FALSE);

	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_AUTH, IKEV2FLAG_RESPONSE,
				     message_id, ike_sa, &payl);
	if (!pkt)
		goto fail;
	if (ikev2_transmit_response(ike_sa, pkt, ike_sa->local,
				    ike_sa->remote) != 0)
		goto fail;
	pkt = 0;

	TRACE((PLOGLOC, "responder EAP: sent first IKE_AUTH response with "
	       "responder AUTH (rmethod %d) + EAP\n", rmethod));

      done:
	if (my_cert) rc_vfree(my_cert);
	if (auth) rc_vfree(auth);
	if (pkt) rc_vfree(pkt);
	ikev2_payloads_destroy(&payl);
	return status;

      fail:
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		   "failed building first responder EAP IKE_AUTH response\n");
	status = -1;
	goto done;
}

void
ikev2_responder_state1_send(struct ikev2_sa *ike_sa,
			    struct ikev2_child_sa *child_sa)
{
	rc_vchar_t *id_r;
	rc_vchar_t *my_cert = 0;
	rc_vchar_t *auth = 0;
	rc_vchar_t *sa_r2 = 0;
	struct ikev2_payloads payl;
	rc_vchar_t *pkt = 0;

	ikev2_payloads_init(&payl);

	if (child_sa->state != IKEV2_CHILD_STATE_MATURE) {
		/* something went wrong */

		TRACE((PLOGLOC, "child state %d, aborting exchange\n",
		       child_sa->state));
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INVALID_SYNTAX,
							 0, 0), TRUE);
		goto send_response;
	}

	ikev2_set_state(ike_sa, IKEV2_STATE_ESTABLISHED);
	/* NAT-T keepalive starts after the float, on the 4500 ports */
	natt_start_natk(ike_sa);
	/*
	 * XXX
	 * with current code, retransmission data may be lost if the
	 * IKE_SA_AUTH response is lost while the responder starts
	 * CREATECHILD exchange at the same time
	 */

	if (ike_sa->id_r) {
		id_r = ike_sa->id_r;
	} else {
		struct rc_idlist *my_id;
		my_id = ikev2_my_id(ike_sa->rmconf);
		if (!my_id)
			goto fail_no_my_id;
		id_r = ikev2_identifier(my_id);
		if (!id_r)
			goto fail;
		ike_sa->id_r = id_r;
	}

	auth = ikev2_auth_calculate(ike_sa, FALSE);
	if (!auth)
		goto fail;

	/* Get my_cert from the remote configuration
	 * if we can use the rsasig authentication method */

	/* XXX	This is based on ikev2_public_key from ike_conf.c,
	 *	which is very incomplete but this should work with
	 *	the sample vals.conf and the other sample *.conf files
	 *	if the public key is stored in a certificate file
	 *	using the x509 PEM format */

	struct rc_alglist *kmp_auth_method = ike_sa->rmconf->ikev2->kmp_auth_method;
	while (kmp_auth_method) {
		if (kmp_auth_method->algtype == RCT_ALG_RSASIG) {
			const char *filename = 0;
			int err;
			struct rc_pklist *pk = ike_sa->rmconf->ikev2->my_pubkey;
			while (pk) {
				if (pk->ftype == RCT_FTYPE_X509PEM)
					filename = rc_vmem2str(pk->pubkey);
				pk = pk->next;
			}
			if (!filename) {
				plog(PLOG_INTERR, PLOGLOC, 0,
					   "failed obtaining filename string\n");
				goto fail_no_my_cert;
			}
			err = rc_safefile(filename, FALSE);
			if (err == -1) {
				plog(PLOG_INTERR, PLOGLOC, 0,
					   "failed accessing file %s: %s\n",
					   filename, strerror(errno));
				goto fail_no_my_cert;
			} else if (err != 0) {
				plog(PLOG_INTERR, PLOGLOC, 0,
					   "file %s is not safe, code %d: %s\n",
					   filename, err,
					   rc_safefile_strerror(err));
				goto fail_no_my_cert;
			}
			plog(PLOG_INFO, PLOGLOC, 0,
				   "reading cert (%s)\n",
				   filename);
			rc_vchar_t *my_cert_data = eay_get_x509cert(filename);
			uint8_t value = IKEV2_CERT_X509_SIGN;
			void *cert_encoding = &value;
			my_cert = rc_vprepend(my_cert_data, cert_encoding, sizeof(value));
			if (!my_cert) {
				plog(PLOG_INTERR, PLOGLOC, 0,
					   "failed reading cert (%s)\n",
					   filename);
				goto fail_no_my_cert;
			}
			err = eay_check_x509cert(my_cert_data, NULL);
			rc_vfree(my_cert_data);
			if (err) {
				plog(PLOG_INTERR, PLOGLOC, 0,
				     "failed validating my certificate (%s)\n",
				     filename);
				rc_vfree(my_cert);
					goto fail_no_my_cert;
				}
				}
				kmp_auth_method = kmp_auth_method->next;
				}

				/* initial IKE_AUTH child: no ADDKE/type-6 (RFC 9370 s2.2; CREATE_CHILD only) */
				child_sa->in_ike_auth = 1;
				sa_r2 = ikev2_construct_sa(child_sa);
				if (!sa_r2)
				goto fail_create_sa;

	/* ts_i, ts_r are passed through child_param */
	if (!child_sa->child_param.ts_i || !child_sa->child_param.ts_r)
		goto fail_no_ts;

	/*
	 * send message 4
	 * HDR, SK {IDr, [CERT+],
	 *          AUTH,
	 *          [CP(CFG_REPLY)],
	 *          [N(IPCOMP_SUPPORTED)],
	 *          [N(USE_TRANSPORT_MODE)],
	 *          [N(ESP_TFC_PADDING_NOT_SUPPORTED)],
	 *          [N(NON_FIRST_FRAGMENTS_ALSO)],
	 *          SA, TSi, TSr,
	 *          [N(ADDITIONAL_TS_POSSIBLE)],
	 *          [V+]}
	 *
	 * ??? [N(INITIAL_CONTACT)]
	 */

	/* (draft-17)
	 * The responder asserts its identity with the IDr payload, optionally
	 * sends one or more certificates (again with the certificate containing
	 * the public key used to verify AUTH listed first), authenticates its
	 * identity and protects the integrity of the second message with the
	 * AUTH payload, and completes negotiation of a CHILD_SA with the
	 * additional fields described below in the CREATE_CHILD_SA exchange.
	 */
#ifdef notyet
	/* (draft-17)
	 * If the responder is willing to use an
	 * extensible authentication method, it will place an EAP payload in
	 * message 4 and defer sending SAr2, TSi, and TSr until initiator
	 * authentication is complete in a subsequent IKE_AUTH exchange.
	 */
#endif

	/*
	 * IDi
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_ID_R, id_r, FALSE);

	/*
	 * [CERT+]
	 */
	if (my_cert)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CERT, my_cert, FALSE);

#if 1
	/* send INITIAL_CONTACT if necessary */
	if (ikev2_send_initial_contact(ike_sa)) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_INITIAL_CONTACT,
							 0, 0), TRUE);
	}
#endif

	/*
	 * AUTH
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_AUTH, auth, FALSE);

	/*
	 * [CP(CFG_REPLY)]
	 */
	if (child_sa->child_param.cfg_payload)
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_CONFIG,
				    child_sa->child_param.cfg_payload, FALSE);

	/* RFC 8983 s4: IP4_ALLOWED / IP6_ALLOWED status notifies (no data).
	 * After assigning internal addresses, tell a dual-stack initiator which
	 * address family the responder actually assigned/supports (Table 1).
	 * Emit one notify per AF that carries a lease in this reply. */
	if (child_sa->child_param.cfg_payload) {
		struct rcf_address *a;
		int has4 = 0, has6 = 0;
		for (a = LIST_FIRST(&child_sa->lease_list); a;
		     a = LIST_NEXT(a, link_sa)) {
			if (a->af == AF_INET) has4 = 1;
			else if (a->af == AF_INET6) has6 = 1;
		}
		if (has4)
			ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
					    ikev2_notify_payload(0, 0, 0,
								 IKEV2_IP4_ALLOWED,
								 0, 0), TRUE);
		if (has6)
			ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
					    ikev2_notify_payload(0, 0, 0,
								 IKEV2_IP6_ALLOWED,
								 0, 0), TRUE);
		TRACE((PLOGLOC, "RFC8983: responder emits IP%s_ALLOWED%s%s\n",
		       has4 ? "4" : (has6 ? "6" : ""),
		       has4 && has6 ? " and IP6_ALLOWED" : "",
		       (has4 || has6) ? "" : " (none - no lease)"));
	}

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
	 * [N(MOBIKE_SUPPORTED)] RFC 4555
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(0, 0, 0,
						 IKEV2_MOBIKE_SUPPORTED,
						 0, 0),
			    TRUE);

	/*
	 * RFC 6290 QCD_TOKEN in IKE_AUTH (encrypted).
	 */
	{
		rc_vchar_t *qcd;

		qcd = ikev2_qcd_token(&ike_sa->index.i_ck, &ike_sa->index.r_ck);
		if (qcd) {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
				   "sending QCD_TOKEN\n");
			ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
					    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_IKE,
								 0, 0,
								 IKEV2_QCD_TOKEN,
								 qcd->v, qcd->l),
					    TRUE);
			rc_vfree(qcd);
		}
	}

	/* RFC 8784 s2.3: acknowledge the PPK session with an empty
	 * N(PPK_IDENTITY) -- the initiator's post-loop gate requires it
	 * when ppk_active, and the content is ignored per RFC 8784. */
	if (ike_sa->ppk_active) {
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ikev2_notify_payload(0, 0, 0,
							 IKEV2_PPK_IDENTITY,
							 0, 0),
				    TRUE);
	}

	/* RFC 5723: answer a TICKET_REQUEST with N(TICKET_LT_OPAQUE) now
	 * that the client has authenticated (final IKE_AUTH response). */
	ikev2_maybe_issue_ticket(ike_sa, &payl);

	/*
	 * SA, TSi, TSr
	 */
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_SA, sa_r2, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_I, child_sa->child_param.ts_i, FALSE);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_TS_R, child_sa->child_param.ts_r, FALSE);

#ifdef notyet
	/* [N(IPCOMP_SUPPORTED...),] */
	/*   [N(SET_WINDOW_SIZE),]
	 *   [N(HTTP_CERT_LOOKUP_SUPPORTED),]
	 */
#endif

      send_response:
	/* RFC 9242: when IKE_INTERMEDIATE (exch 43) runs between IKE_SA_INIT
	 * and IKE_AUTH, the AUTH request's Message ID is no longer 1 (the
	 * intermediate round consumed it); the response must echo the
	 * request's actual Message ID.  ikev2_create_child_responder()
	 * stashed that in child_sa->message_id.  (This was hardcoded to 1,
	 * which looked right without IKE_INTERMEDIATE but left the phone
	 * rejecting the response forever once the intermediate round
	 * shifted ids.) */
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_AUTH, IKEV2FLAG_RESPONSE,
				     child_sa->message_id,
				     ike_sa, &payl);
	if (!pkt)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, child_sa->parent->local,
				    child_sa->parent->remote) != 0)
		goto fail;
	pkt = 0;

      done:
	if (pkt)
		rc_vfree(pkt);
	if (sa_r2)
		rc_vfree(sa_r2);
	if (auth)
		rc_vfree(auth);
	if (my_cert)
		rc_vfree(my_cert);
	ikev2_payloads_destroy(&payl);
	return;

      fail:
	/* transient failure */
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed sending responder IKE_AUTH message\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_no_my_id:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "configuration lacks my_id\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_no_my_cert:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "configuration lacks my valid certificate\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_create_sa:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC, "failed creating SA payload\n");
	++isakmpstat.fail_send_packet;
	goto done;

      fail_no_ts:
	isakmp_log(ike_sa, 0, 0, 0,
		   PLOG_INTERR, PLOGLOC,
		   "failed creating IKE_SA_AUTH response (no %s parameter)\n",
		   (!child_sa->child_param.ts_i ? "TSi" : "TSr"));
	++isakmpstat.fail_send_packet;
	goto done;
}

void
responder_ike_sa_auth_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
		   struct sockaddr *remote, struct sockaddr *local)
{
	/* RFC 5723 s4.3.3: a RESUMED IKE_SA's AUTH is a fresh
	 * AUTH = prf(SK_px, <message>) MAC over the IKE_SESSION_RESUME
	 * exchange, not a trust-the-ticket pass.  The ticket authenticated
	 * the peer's identity once; the AUTH payload must still be verified
	 * on the resumed IKE_AUTH (RealMessage1 = the initiator's resume
	 * request, keyed with the resumed SK_pi).  Route it through the
	 * normal verify arm (which dispatches on sa->resumed) so a forged or
	 * stale AUTH is rejected here, exactly as the RFC requires. */
	if (ike_sa->resumed) {
		struct ikev2_header *ikehdr =
		    (struct ikev2_header *)msg->v;
		struct ikev2_payload_header *p;
		struct ikev2payl_auth *auth = NULL;
		struct ikev2_payload_header *id_i = NULL;
		struct ikev2_payload_header *id_r = NULL;
		int type;
		int result;

		p = (struct ikev2_payload_header *)(ikehdr + 1);
		for (type = ikehdr->next_payload;
		     type != IKEV2_NO_NEXT_PAYLOAD;
		     POINT_NEXT_PAYLOAD(p, type)) {
			/* RFC 5723 s4.3.3: a resuming client typically
			 * requests a NEW ticket in the resumed IKE_AUTH so
			 * it can resume again after a second failure.  Open
			 * the notify and set ticket_requested so the
			 * resumed IKE_AUTH response (via
			 * responder_ike_sa_auth_cont ->
			 * ikev2_maybe_issue_ticket) re-issues one. */
			if (type == IKEV2_PAYLOAD_NOTIFY) {
				if (get_notify_type(
				    (struct ikev2payl_notify *)p) ==
				    IKEV2_TICKET_REQUEST) {
					ike_sa->ticket_requested = 1;
					continue;
				}
			}
			switch (type) {
			case IKEV2_PAYLOAD_AUTH:
				if (auth) {	/* duplicate */
					ikev2_abort(ike_sa, ECONNREFUSED);
					return;
				}
				auth = (struct ikev2payl_auth *)p;
				break;
			case IKEV2_PAYLOAD_ID_I:
				if (id_i) {	/* duplicate */
					ikev2_abort(ike_sa, ECONNREFUSED);
					return;
				}
				id_i = p;
				break;
			case IKEV2_PAYLOAD_ID_R:
				if (id_r) {	/* duplicate */
					ikev2_abort(ike_sa, ECONNREFUSED);
					return;
				}
				id_r = p;
				break;
			}
		}
		if (!auth) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "RFC 5723: resumed IKE_AUTH lacks AUTH "
				   "payload\n");
			++isakmpstat.authentication_failed;
			ikev2_abort(ike_sa, ECONNREFUSED);
			return;
		}
		/* RFC 5723 s4.3.3: on a resumed SA the initiator sends
		 * IDi/IDr in the resumed IKE_AUTH; the AUTH MAC covers only
		 * the IKE_SESSION_RESUME exchange octets, so a mismatched,
		 * unauthenticated identity would otherwise slip through.  The
		 * resumed identity adopted from the ticket is the one bound
		 * at mint time (ike_sa->id_i); the IDi the initiator now
		 * asserts must equal it byte-for-byte (header-stripped data,
		 * same form as id_i is stored on a fresh exchange). */
		if (!id_i ||
		    get_payload_data_length(id_i) != ike_sa->id_i->l ||
		    memcmp(id_i + 1, ike_sa->id_i->v,
			   ike_sa->id_i->l) != 0) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "RFC 5723: resumed IKE_AUTH IDi does not "
				   "match the ticket identity\n");
			++isakmpstat.authentication_failed;
			ikev2_abort(ike_sa, ECONNREFUSED);
			return;
		}
		/* RFC 5723 s4.3.3: the IDr a client sends in the resumed
		 * IKE_AUTH (optional — the responder sends it) MUST ALSO be
		 * identical to the ticket's IDr; a new IDr cannot be
		 * negotiated on a resume (it would not be authenticated by
		 * the AUTH MAC).  Absent IDr is fine (client omits it); a
		 * present one that differs is refused. */
		if (id_r && ike_sa->id_r &&
		    (get_payload_data_length(id_r) != ike_sa->id_r->l ||
		     memcmp(id_r + 1, ike_sa->id_r->v,
			    ike_sa->id_r->l) != 0)) {
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOERR, PLOGLOC,
				   "RFC 5723: resumed IKE_AUTH IDr does not "
				   "match the ticket identity\n");
			++isakmpstat.authentication_failed;
			ikev2_abort(ike_sa, ECONNREFUSED);
			return;
		}
		/* RFC 5723 s4.4 / RFC 7296 s3.5: the ticket bound IDi must
		 * still satisfy this remote's configured peers_id — the SAME
		 * check a fresh IKE_AUTH runs, via the shared
		 * ikev2_peer_id_ok().  This refuses a ticket whose identity
		 * no longer matches policy (e.g. peers_id changed since the
		 * ticket was minted, or the ticket key is shared and the
		 * ticket was replayed onto a gateway with a different peer
		 * set). */
		if (ikev2_verify_id(ike_sa->rmconf) == RCT_BOOL_ON) {
			rc_type rc_id_type;
			rc_vchar_t *idin;

			idin = ikev2_id2rct_id(id_i, &rc_id_type);
			if (idin) {
				if (ikev2_peer_id_ok(ike_sa,
				    rc_id_type, idin) != 0) {
					isakmp_log(ike_sa, local, remote,
					    msg, PLOG_PROTOERR, PLOGLOC,
					    "RFC 5723: resumed IKE_AUTH IDi "
					    "does not match peers id\n");
					rc_vfree(idin);
					++isakmpstat.authentication_failed;
					ikev2_abort(ike_sa, ECONNREFUSED);
					return;
				}
				rc_vfree(idin);
			}
		}
		/* i_to_r=TRUE: verify the initiator's AUTH over the resume
		 * request with the resumed SK_pi (the ikev2_auth_verify
		 * resumed arm keys with sk_p_i / sk_p_r by direction). */
		result = ikev2_auth_verify(ike_sa, TRUE, auth);
		responder_ike_sa_auth_cont(ike_sa, result,
					   msg, remote, local);
		return;
	}

	responder_ike_sa_auth_cont(ike_sa, ike_sa->verified_info.result,
				   msg, remote, local);
}

void
initiator_ike_sa_auth_recv0(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			    struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int type;
	struct ikev2_payload_header *p;
	struct ikev2_payload_header *id_r = 0;
	struct ikev2payl_auth *auth = 0;
	struct ikev2_payload_header *sa_r2 = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;

	/*
	 * expect HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
	 */

	ikehdr = (struct ikev2_header *)msg->v;
	/* Robustness: an ICV-valid response for a different exchange type
	 * arriving while we await the IKE_AUTH response is a stale/duplicate
	 * retransmit from an already-completed exchange (e.g. a duplicate
	 * IKE_INTERMEDIATE or a delayed IKE_SA_INIT response).  Our receive
	 * ordering accepts any response id <= the high-water, so these do
	 * reach here; drop them rather than parse as IKE_AUTH and abort (F1). */
	if (ikehdr->exchange_type != IKEV2EXCH_IKE_AUTH) {
		isakmp_log(ike_sa, remote, local, msg, PLOG_DEBUG, PLOGLOC,
			   "IKE_AUTH: ignoring stale exch %d response\n",
			   ikehdr->exchange_type);
		return;
	}
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_ID_R:
			if (id_r)
				goto duplicate;
			id_r = p;
			break;
		case IKEV2_PAYLOAD_CERT:
#ifdef notyet
			/* (draft-17)
			 * Implementations MUST be capable of being configured to send and
			 * accept up to four X.509 certificates in support of authentication,
			 */
#endif
			break;
		case IKEV2_PAYLOAD_AUTH:
			if (auth)
				goto duplicate;
			auth = (struct ikev2payl_auth *)p;
			break;
		case IKEV2_PAYLOAD_SA:
			if (sa_r2)
				goto duplicate;
			sa_r2 = p;
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
			TRACE((PLOGLOC, "received notify type %s\n",
			       ikev2_notify_type_str(get_notify_type
						     ((struct ikev2payl_notify *)p))));
			/* process later */
			/* what to do if authentication fails? */
			break;
		case IKEV2_PAYLOAD_VENDOR_ID:
			/* A Vendor ID payload may be sent as part of any message. */
			isakmp_log(ike_sa, local, remote, msg,
				   PLOG_PROTOWARN, PLOGLOC,
				   "vendor id payload ignored\n");
			++isakmpstat.payload_ignored;
			break;

		case IKEV2_PAYLOAD_CONFIG:
			/* process it later */
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
	if (!(id_r && auth)) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "message lacks %s payload\n",
			   (!id_r ? "IDr" : "AUTH"));
		++isakmpstat.malformed_message;
		goto malformed_message;
	}
	assert(!ike_sa->id_r);
	ike_sa->id_r =
		rc_vnew((uint8_t *)(id_r + 1), get_payload_data_length(id_r));;
	if (!ike_sa->id_r)
		goto fail_nomem;

	ike_sa->verified_info.packet = rc_vdup(msg);
	if (!ike_sa->verified_info.packet)
		goto fail_nomem;
	ike_sa->verified_info.result = VERIFIED_WAITING;
	ike_sa->verified_info.remote = remote;
	ike_sa->verified_info.local = local;
	ike_sa->verified_info.verify_param = (void *)auth;

	ikev2_set_state(ike_sa, IKEV2_STATE_INI_IKE_AUTH_RCVD);

	ikev2_verify(&ike_sa->verified_info);

      done:
	return;

      fail_nomem:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC,
		   "failed processing IKE_SA_AUTH request for internal error\n");
	++isakmpstat.fail_process_packet;
	goto done;		/* expect peer's retransmission */

      abort:
	ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
	goto done;

      duplicate:
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_PROTOERR, PLOGLOC,
		   "unnecessary duplicated payload (type %d)\n", type);
	++isakmpstat.duplicate_payload;
        /*FALLTHROUGH*/
      malformed_message:
	/* send INVALID_SYNTAX ??? */
	goto abort;

      unsupported_critical_payload:
	/* send UNSUPPORTED_CRITICAL_PAYLOAD ??? */
	goto abort;
}

void
initiator_ike_sa_auth_cont(struct ikev2_sa *ike_sa, int result, rc_vchar_t *msg,
			   struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	int type;
	struct ikev2_payload_header *p;
	struct ikev2_payload_header *cfg = 0;
	struct ikev2_payload_header *sa_r2 = 0;
	struct ikev2_payload_header *ts_i = 0;
	struct ikev2_payload_header *ts_r = 0;
	rc_vchar_t *peer_auth = 0;
	struct ikev2_child_param child_param;
	struct ikev2_child_sa *child_sa;
	int acceptable = FALSE;

	/*
	 * expect HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}
	 */

	ikev2_child_param_init(&child_param);

	ikehdr = (struct ikev2_header *)msg->v;

	switch (result) {
	case VERIFIED_WAITING:
		goto done;

	case VERIFIED_SUCCESS:
		break;

	case VERIFIED_FAILURE:
	default:
		goto authentication_failed;
	}

	/*
	 * peer auth confirmed.
	 * process payloads with side-effects
	 */
	ikev2_update_message_id(ike_sa, get_uint32(&ikehdr->message_id), TRUE);

	p = (struct ikev2_payload_header *)(ikehdr + 1);
	for (type = ikehdr->next_payload;
	     type != IKEV2_NO_NEXT_PAYLOAD;
	     POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_ENCRYPTED:
			break;
		case IKEV2_PAYLOAD_ID_R:
			break;
		case IKEV2_PAYLOAD_SA:
			sa_r2 = p;
			break;
		case IKEV2_PAYLOAD_TS_I:
			ts_i = p;
			break;
		case IKEV2_PAYLOAD_TS_R:
			ts_r = p;
			break;
		case IKEV2_PAYLOAD_NOTIFY:
			if (init_ike_sa_auth_recv_notify
			    (ike_sa, msg, remote, local, p, &child_param,
			     &acceptable) < 0) {
				goto done;
			}
			break;
		case IKEV2_PAYLOAD_CONFIG:
			cfg = p;
			break;
		default:
			break;
		}
	}

	/* RFC 8784 s2.3: when we are using the PPK, the responder MUST
	 * have echoed N(PPK_IDENTITY) in its IKE_AUTH response; its absence
	 * while ppk_active means the peer did not actually use the PPK. */
	if (ike_sa->ppk_active && !ike_sa->peer_ppk_identity_ok) {
		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "RFC 8784: PPK active but responder did not "
			   "echo N(PPK_IDENTITY); aborting\n");
		++isakmpstat.authentication_failed;
		goto authentication_failed;
	}

	if (!(sa_r2 && ts_i && ts_r)) {
		/* RFC 6023 s3: a childless initiator sent no SAi2/TSi/TSr, so the
		 * responder SA-less IKE_AUTH response legitimately carries no SAr2/TS.
		 * Accept it and establish the IKE_SA with zero children (the pending
		 * child is then created via CREATE_CHILD_SA below). */
		if (ike_sa->childless_requested) {
			ike_sa->childless_established = 1;	/* childless_established_init */
			TRACE((PLOGLOC, "childless IKE_AUTH (initiator): accepted SA-less response (no SAr2), establishing IKE_SA\n"));
			goto established;
		}
		if (acceptable)
			goto established;

		isakmp_log(ike_sa, local, remote, msg,
			   PLOG_PROTOERR, PLOGLOC,
			   "message lacks %s payload\n",
			   (!sa_r2 ? "SA" :
			    !ts_i ? "TSi" :
			    !ts_r ? "TSr" :
			    "(shouldn't happen)"));
		++isakmpstat.malformed_message;
		goto malformed_message;
	}

	/* With IKE_INTERMEDIATE rounds the IKE_AUTH message id is > 1
	 * (INIT=0, intermediate=1, AUTH=2, ...).  The pending child request
	 * was registered under ikev2_request_id() (= the AUTH msgid), so
	 * look it up by the message id echoed in the AUTH response rather
	 * than a hardcoded 1 (classical IKE_AUTH only). */
	child_sa = ikev2_find_request(ike_sa, get_uint32(&ikehdr->message_id));
	if (!child_sa)
		goto unexpected;

	if (cfg) {
		ikev2_process_config_reply(ike_sa, child_sa, cfg);
	}
	ikev2_update_child(child_sa, sa_r2, ts_i, ts_r, &child_param);

      established:
	ikev2_set_state(ike_sa, IKEV2_STATE_ESTABLISHED);

	/* RFC 5723 s4.1: persist the responder-minted resumption ticket +
	 * from-ticket state now that the initial IKE_AUTH has succeeded, so
	 * a later establish to this peer can resume via exchange 38. */
	ike_msg_resume_store_save_from_sa(ike_sa);

	/* RFC 6023: the child held back from the modified IKE_AUTH is now
	 * negotiated with CREATE_CHILD_SA; give it a CREATE_CHILD proposal */
	if (ike_sa->childless_established) {
		struct ikev2_child_sa *c;

		for (c = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
		     !IKEV2_CHILD_LIST_END(c); c = IKEV2_CHILD_LIST_NEXT(c))
			if (c->is_initiator && c->in_ike_auth &&
			    c->state == IKEV2_CHILD_STATE_GETSPI_DONE)
				(void)ikev2_child_childless_prepare(c);
	}

	/* if there are any pending child_sa requests, start it */
	child_sa = ikev2_choose_pending_child(ike_sa, TRUE);
	if (child_sa)
		ikev2_wakeup_child_sa(child_sa);

      done:
	if (peer_auth)
		rc_vfree(peer_auth);
	ikev2_child_param_destroy(&child_param);
	return;

      abort:
	ikev2_abort(ike_sa, ECONNREFUSED);	/* ??? */
	goto done;

      malformed_message:
	/* send INVALID_SYNTAX ??? */
	goto abort;

      authentication_failed:
	/* send AUTHENTICATION_FAILED ??? */
	goto abort;

      unexpected:
	/* somehow there were no child_sa */
	isakmp_log(ike_sa, local, remote, msg,
		   PLOG_INTERR, PLOGLOC, "no child SA for received message\n");
	goto done;		/* ??? goto abort; */
}

#ifdef notyet
/*
 * EAP
 */
initiator_state1_send_eap()
{
	/*
	 * An initiator indicates a desire to use extended authentication by
	 * leaving out the AUTH payload from message 3. By including an IDi
	 * payload but not an AUTH payload, the initiator has declared an
	 * identity but has not proven it.
	 *
	 * HDR, SK {IDi, [CERTREQ,] [IDr,]
	 * SAi2, TSi, TSr}   -->
	 *
	 * <--    HDR, SK {IDr, [CERT,] AUTH,
	 * EAP }
	 *
	 * HDR, SK {EAP, AUTH}     -->
	 *
	 * <--    HDR, SK {EAP, AUTH,
	 * SAr2, TSi, TSr }
	 */

}

/*
   The Initiator of an IKE_SA using EAP SHOULD be capable of extending
   the initial protocol exchange to at least ten IKE_AUTH exchanges in
   the event the Responder sends notification messages and/or retries
   the authentication prompt. The protocol terminates when the Responder
   sends the Initiator an EAP payload containing either a success or
   failure type. In such an extended exchange, the EAP AUTH payloads
   MUST be included in the first message each end sends after having
   sufficient information to compute the key. This will usually be in
   the last two messages of the exchange.
*/
#endif

void
initiator_ike_sa_auth_recv(struct ikev2_sa *ike_sa, rc_vchar_t *msg,
			   struct sockaddr *remote, struct sockaddr *local)
{
	initiator_ike_sa_auth_cont(ike_sa, ike_sa->verified_info.result,
				   msg, remote, local);
}
