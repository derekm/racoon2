/* $Id: ikev2_session_resume.c	$ */

/*
 * Copyright (C) 2004-2026 WIDE Project.
 * All rights reserved.
 *
 * RFC 5723 IKEv2 session resumption surface, split out of ikev2.c.
 *
 * This translation unit owns the session-resumption seam:
 *   initiator  - the per-peer ticket store helpers (store/available) and the
 *                IKE_SESSION_RESUME (exchange 38) send/recv path
 *   responder  - the exchange-38 accept path that rebuilds the negotiated SA
 *                from the presented ticket and derives the resumed keys
 *   issue      - ikev2_ticket_lt_opaque() (mint TICKET_LT_OPAQUE DATA) and
 *                ikev2_maybe_issue_ticket() (push it into the final IKE_AUTH
 *                response) used by every responder IKE_AUTH builder
 *
 * The ticket codec/crypto lives in ikev2_resume_ticket.c; the legacy
 * crash-resume loader lives in ikev2_resume.c.  Exports needed by ikev2.c
 * (dispatch table entry, IKE_AUTH arms, auth_cont paths) are declared in
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
#include "ikev2_resume_ticket.h"
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

/* Shared proposal→isakmpsa conversion used by the resumed-IKE_AUTH SA build;
 * defined in ikev2.c and exported for use here. */
struct ikev2_isakmpsa *ikev2_proppair_to_isakmpsa(struct prop_pair *);

static void initiator_ike_session_resume_send(struct ikev2_sa *);
/*
 * RFC 5723 initiator present path.  The responder side (mint + accept + Nr +
 * resumed IKE_AUTH) is complete and cross-vendor proven; this mirrors it so
 * racoon2 iked can itself resume to a peer that issued it a ticket.
 *
 * A prior, successful initial IKE_AUTH to the peer that returned
 * N(TICKET_LT_OPAQUE) is persisted by ike_msg_resume_store_save_from_sa() at
 * IKE_AUTH completion.  On a later establish for the same peer, if that
 * stored ticket is still unexpired, ikev2_initiator_start() diverts here:
 * we send IKE_SESSION_RESUME (exchange 38, RFC 5723 s4.3.2) instead of
 * IKE_SA_INIT and, on Nr, derive the resumed keying material (s5.1) and
 * send the resumed IKE_AUTH.  Tickets fail closed: an absent, expired,
 * corrupt, or NACKed ticket falls back to a normal IKE_SA_INIT.
 */

/* Filesystem-safe key for the initiator ticket store, from the peer address.
 * Returns a malloc'd hex string (caller racoon_free), or NULL. */
static char *
ike_msg_resume_store_key(const struct sockaddr *remote)
{
	const uint8_t *ap;
	size_t alen, i;
	char *key;
	static const char hex[] = "0123456789abcdef";

	if (!remote)
		return NULL;
	if (remote->sa_family == AF_INET) {
		ap = (const uint8_t *)&((const struct sockaddr_in *)remote)->sin_addr;
		alen = 4;
	} else if (remote->sa_family == AF_INET6) {
		ap = (const uint8_t *)&((const struct sockaddr_in6 *)remote)->sin6_addr;
		alen = 16;
	} else {
		return NULL;
	}
	key = racoon_malloc(alen * 2 + 1);
	if (!key)
		return NULL;
	for (i = 0; i < alen; i++) {
		key[i * 2]     = hex[ap[i] >> 4];
		key[i * 2 + 1] = hex[ap[i] & 0xf];
	}
	key[alen * 2] = '\0';
	return key;
}

/* Dir for the initiator ticket store: the RACOON2_RESUME_TICKET_DIR override
 * when set else the compiled default.  Deliberately SEPARATE from
 * RACOON2_RESUME_DIR (the legacy crash-resume dir): the legacy loader scans
 * that dir for its own dumps and treating a r2tkt-* file as a dump would
 * both fail and never present our ticket. */
static const char *
ike_msg_resume_store_dir(void)
{
	const char *e = getenv("RACOON2_RESUME_TICKET_DIR");
	return (e && *e) ? e : "/var/lib/racoon2/resume-tickets";
}

/* Carry a stored session-resumption ticket from one gateway to another.
 * RFC 5685 redirect-follow: the initiator is retargeted from the
 * redirecting gateway (A) to a sibling (C) in the same shared-trust pool
 * — the ticket was persisted under A's address-key, but after the retarget
 * ike_msg_session_resume_available() will look it up under C's address-key
 * and miss, forcing a full IKE_SA_INIT on C.  Migrating the stored ticket
 * (load under old, re-save under new, clear the old) lets the initiator
 * present exchange 38 at C, which validates it under the shared cluster
 * session_resume_ticket_key — the "resume on the sibling" leg of the
 * redirect + ticket + resume failover story.  A no-op (returns 0) when
 * there is no stored ticket or either address is unusable. */
int
ike_msg_resume_store_migrate(const struct sockaddr *oldgw,
			     const struct sockaddr *newgw)
{
	struct r2ticket_state st;
	rc_vchar_t *ticket_lt = NULL;
	char *oldkey, *newkey;
	int rc = 0;

	if (!oldgw || !newgw)
		return 0;
	oldkey = ike_msg_resume_store_key(oldgw);
	newkey = ike_msg_resume_store_key(newgw);
	if (!oldkey || !newkey) {
		if (oldkey) racoon_free(oldkey);
		if (newkey) racoon_free(newkey);
		return 0;
	}
	if (strcmp(oldkey, newkey) != 0 &&
	    r2ticket_store_load(ike_msg_resume_store_dir(), oldkey,
				&ticket_lt, &st) == 0) {
		if (ticket_lt && ticket_lt->l > 4 &&
		    r2ticket_store_save(ike_msg_resume_store_dir(), newkey,
					ticket_lt, &st) == 0) {
			r2ticket_store_clear(ike_msg_resume_store_dir(),
					     oldkey);
			rc = 1;
		}
		if (ticket_lt)
			rc_vfree(ticket_lt);
		r2ticket_state_free(&st);
	}
	racoon_free(oldkey);
	racoon_free(newkey);
	return rc;
}

/* Read the 8-octet IKE SA SPI (a cookie) as a big-endian u64, matching the
 * r2tick_pack() layout (spi >> 56 .. spi). */
static uint64_t
ike_msg_cookie_to_u64(const isakmp_cookie_t ck)
{
	uint64_t v = 0;
	unsigned i;
	for (i = 0; i < 8; i++)
		v = (v << 8) | ck[i];
	return v;
}

/* Persist the ticket + "from the ticket" state after a successful initial
 * IKE_AUTH, so a later establish can resume.  Called from
 * initiator_ike_sa_auth_cont() once the IKE_AUTH response proves the SA. */
void
ike_msg_resume_store_save_from_sa(struct ikev2_sa *ike_sa)
{
	struct r2ticket_state st;
	char *key;
	rc_vchar_t *sa_bytes = NULL;

	if (!ike_sa->resume_ticket || ike_sa->resume_ticket->l < 4)
		return;		/* no ticket from peer */
	if (ikev2_use_session_resumption(ike_sa->rmconf) != RCT_BOOL_ON)
		return;
	if (!ike_sa->remote)
		return;
	if (!(key = ike_msg_resume_store_key(ike_sa->remote)))
		return;
	memset(&st, 0, sizeof(st));
	{
		const uint8_t *q = (const uint8_t *)ike_sa->resume_ticket->v;
		uint32_t lt = ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16)
		    | ((uint32_t)q[2] << 8) | (uint32_t)q[3];
		st.expires_at = (uint32_t)time(NULL) + lt;
	}
	st.auth_method = (uint8_t)ikev2_auth_method(ike_sa);
	st.spi_i = ike_msg_cookie_to_u64(ike_sa->index.i_ck);
	st.spi_r = ike_msg_cookie_to_u64(ike_sa->index.r_ck);
	sa_bytes = ikev2_ikesa_to_proposal(ike_sa->negotiated_sa, 0);
	if (!sa_bytes)
		goto out;
	st.sa = sa_bytes;	sa_bytes = NULL;
	st.idi = rc_vdup(ike_sa->id_i);
	st.idr = rc_vdup(ike_sa->id_r);
	st.sk_d = rc_vdup(ike_sa->sk_d);
	st.cert_due = (ike_sa->due_time.tv_sec > 0) ?
	    (uint32_t)ike_sa->due_time.tv_sec : 0;
	if (!st.idi || !st.idr || !st.sk_d)
		goto out;
	if (r2ticket_store_save(ike_msg_resume_store_dir(), key,
	    ike_sa->resume_ticket, &st) == 0)
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
		    "RFC 5723: persisted session-resumption ticket for peer\n");
out:
	if (sa_bytes)
		rc_vfree(sa_bytes);
	racoon_free(key);
	r2ticket_state_free(&st);
}

/* If a valid stored resumption ticket exists for this peer (and session
 * resumption is on), initiate exchange 38 and return 1 (the SA is owned by
 * that path).  Otherwise 0 so the caller proceeds with a fresh IKE_SA_INIT.
 * Fails closed: expired/missing ticket never resumes. */
int
ike_msg_session_resume_available(struct ikev2_sa *ike_sa)
{
	struct r2ticket_state st;
	rc_vchar_t *ticket_lt = NULL;
	char *key;
	int have = 0;

	if (ikev2_use_session_resumption(ike_sa->rmconf) != RCT_BOOL_ON)
		return 0;
	if (ike_sa->resume_declined)
		return 0;	/* NACKed / unanswered: full exchange only */
	if (!ike_sa->remote) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
		    "RFC 5723: no peer address yet, cannot resume\n");
		return 0;
	}
	if (!(key = ike_msg_resume_store_key(ike_sa->remote)))
		return 0;
	{
		int lrc;
		lrc = r2ticket_store_load(ike_msg_resume_store_dir(), key,
		    &ticket_lt, &st);
		if (lrc == 0) {
			if (!r2ticket_expired(st.expires_at,
			    (uint32_t)time(NULL)) && ticket_lt &&
			    ticket_lt->l > 4 &&
			    (st.cert_due == 0 ||
			     (uint32_t)time(NULL) < st.cert_due))
				have = 1;
			else {
				/* expired or empty: remove it from the store
				 * too, it can never resume */
				r2ticket_state_free(&st);
				r2ticket_store_clear(
				    ike_msg_resume_store_dir(), key);
				isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
				    "RFC 5723: stored ticket for %s expired; "
				    "removed, fresh IKE_SA_INIT\n", key);
			}
		} else {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
			    "RFC 5723: no stored ticket for %s (load rc=%d), "
			    "fresh IKE_SA_INIT\n", key, lrc);
		}
	}
	if (ticket_lt)
		rc_vfree(ticket_lt);
	racoon_free(key);
	if (have) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
		    "RFC 5723: resuming via IKE_SESSION_RESUME\n");
		/* hand the loaded ticket to the sender, which re-loads its own
		 * copy from the store; this intermediate state is no longer
		 * owned and must not linger (review deleg_ddc1e0d6) */
		r2ticket_state_free(&st);
		initiator_ike_session_resume_send(ike_sa);
		return 1;
	}
	return 0;
}

/* RFC 5723 s4.3.2: the responder refused our ticket (N(TICKET_NACK)) or
 * never answered the IKE_SESSION_RESUME request.  Drop the stored ticket
 * and run a regular IKE_SA_INIT on this same half-open SA, so the pending
 * children ride the full exchange instead of being aborted.  Mirrors the
 * INVALID_KE_PAYLOAD restart (ikev2_notify.c): same SPIi, SPIr reset,
 * fresh nonce and first message.  resume_declined stops
 * ikev2_initiator_start() from presenting a ticket again. */
void
ike_msg_resume_store_drop(struct ikev2_sa *ike_sa)
{
	char *key;

	if (!ike_sa || !ike_sa->remote)
		return;
	if ((key = ike_msg_resume_store_key(ike_sa->remote)) == NULL)
		return;
	r2ticket_store_clear(ike_msg_resume_store_dir(), key);
	racoon_free(key);
}

void
ike_msg_session_resume_fallback(struct ikev2_sa *ike_sa, const char *why)
{
	/* Do NOT delete the stored ticket. RFC 5723 s4.3.2 says the
	 * initiator SHOULD drop a refused ticket, but a drain NACK is how
	 * a concentrator ferries the client onto a sibling: the ticket
	 * must still be in the store for ike_msg_resume_store_migrate()
	 * when the fallback IKE_SA_INIT is answered with N(REDIRECT).
	 * resume_declined stops THIS sa from presenting the ticket again
	 * to the peer that just refused it. Redirect-follow clears that
	 * flag after the migrate. A genuine refusal (bad key, reuse) is
	 * overwritten when the full IKE_AUTH stores a new ticket, or
	 * dropped then if the peer issues none. */
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
	    "RFC 5723: %s; kept stored ticket for redirect ferry, "
	    "falling back to a full IKE_SA_INIT\n", why);
	ike_sa->resume_declined = 1;
	ike_sa->resumed = 0;
	ikev2_stop_retransmit(ike_sa);
	if (ike_sa->n_i) {
		rc_vfree(ike_sa->n_i);
		ike_sa->n_i = NULL;
	}
	if (ike_sa->n_r) {
		rc_vfree(ike_sa->n_r);
		ike_sa->n_r = NULL;
	}
	if (ike_sa->my_first_message) {
		rc_vfree(ike_sa->my_first_message);
		ike_sa->my_first_message = NULL;
	}
	if (ike_sa->peer_first_message) {
		rc_vfree(ike_sa->peer_first_message);
		ike_sa->peer_first_message = NULL;
	}
	memset(&ike_sa->index.r_ck, 0, sizeof(ike_sa->index.r_ck));
	ike_sa->crypto_pending = 0;
	ikev2_set_state(ike_sa, IKEV2_STATE_IDLING);
	ikev2_initiator_start(ike_sa);
}

/* Build + send IKE_SESSION_RESUME (exchange 38) as INITIATOR:
 * HDR(SPIi=new,SPIr=0), Ni, N(TICKET_OPAQUE).  Loads the stored ticket,
 * sets a fresh nonce, records my_first_message (RealMessage1, the base for
 * the eventual resumed AUTH), and parks in INI_..._SENT awaiting the
 * unprotected Nr response. */
static void
initiator_ike_session_resume_send(struct ikev2_sa *ike_sa)
{
	struct r2ticket_state st;
	rc_vchar_t *ticket_lt = NULL, *nonce = NULL, *pkt = NULL;
	struct ikev2_payloads payl;
	char *key;
	int payl_inited = 0;

	/* the done: tail always runs r2ticket_state_free(&st), and goto fail
	 * can reach it before r2ticket_store_load() has zeroed the struct
	 * (its parameter-check early -1 fires before its memset) — so clear
	 * it up front or a stray pointer gets free()'d (review deleg_ddc1e0d6) */
	memset(&st, 0, sizeof(st));

	if (!(key = ike_msg_resume_store_key(ike_sa->remote)))
		goto fail;
	if (r2ticket_store_load(ike_msg_resume_store_dir(), key,
	    &ticket_lt, &st) != 0)
		goto fail;
	if (ticket_lt->l <= 4 ||
	    r2ticket_expired(st.expires_at, (uint32_t)time(NULL)))
		goto fail;

	nonce = random_bytes(ikev2_nonce_size(ike_sa->rmconf));
	if (!nonce)
		goto fail;
	ike_sa->n_i = nonce;	nonce = NULL;

	ikev2_payloads_init(&payl);	payl_inited = 1;
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NONCE, ike_sa->n_i, FALSE);
	/* RFC 5723 s4.3.2: N(TICKET_OPAQUE) carries the ticket VERBATIM
	 * (the 4-octet lifetime prefix is not part of the opaque ticket). */
	{
		rc_vchar_t *opaque = rc_vnew(
		    (uint8_t *)ticket_lt->v + 4, ticket_lt->l - 4);
		if (!opaque)
			goto fail;
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
		    ikev2_notify_payload(0, 0, 0, IKEV2_TICKET_OPAQUE,
		    opaque->v, opaque->l), TRUE);
		rc_vfree(opaque);
	}

	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_SESSION_RESUME,
	    IKEV2FLAG_INITIATOR, 0, ike_sa, &payl);
	if (!pkt)
		goto fail;
	if (ike_sa->my_first_message)
		rc_vfree(ike_sa->my_first_message);
	ike_sa->my_first_message = rc_vdup(pkt);
	if (!ike_sa->my_first_message)
		goto fail;

	ikev2_set_state(ike_sa, IKEV2_STATE_INI_IKE_SESSION_RESUME_SENT);
	if (ikev2_transmit(ike_sa, pkt) != 0)
		goto fail;
	pkt = NULL;
	ike_sa->crypto_pending = 0;
	goto done;

 fail:
	if (nonce && ike_sa->n_i == nonce)
		ike_sa->n_i = NULL;
	if (nonce)
		rc_vfree(nonce);
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
	    "RFC 5723: failed sending IKE_SESSION_RESUME; "
	    "falling back to IKE_SA_INIT\n");
	++isakmpstat.fail_send_packet;
	/* Fail closed: drop the stored ticket (avoid a re-initiate loop),
	 * then abort so the caller can fall back to a fresh IKE_SA_INIT. */
	if (key)
		r2ticket_store_clear(ike_msg_resume_store_dir(), key);
	ike_sa->crypto_pending = 0;
	ikev2_abort(ike_sa, ECONNREFUSED);
 done:
	if (ticket_lt)
		rc_vfree(ticket_lt);
	if (pkt)
		rc_vfree(pkt);
	if (payl_inited)
		ikev2_payloads_destroy(&payl);
	if (key)
		racoon_free(key);
	r2ticket_state_free(&st);
}

/* Handle the IKE_SESSION_RESUME (exchange 38) RESPONSE as INITIATOR.
 * The response is HDR(38), Nr -- UNPROTECTED (RFC 5723 Figure 5), like an
 * IKE_SA_INIT response.  On success: rebuild the negotiated IKE SA from the
 * stored ticket SAr, derive the resumed SKEYSEED + keys (s5.1), mark the SA
 * resumed (ticket already authenticated the peer), record the peer response
 * window, and send the resumed IKE_AUTH via initiator_state1_send().  On
 * failure fall back to a fresh IKE_SA_INIT (NACK/expiry/corrupt) by aborting
 * this half-open SA. */
void
initiator_ike_session_resume_recv(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
    struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	unsigned int type;
	struct r2ticket_state st;
	rc_vchar_t *ticket_lt = NULL;
	rc_vchar_t *n_r = NULL;
	struct prop_pair **parsed = NULL;
	struct ikev2_isakmpsa *nsa = NULL;
	char *key = NULL;

	ikehdr = (struct ikev2_header *)packet->v;
	memset(&st, 0, sizeof(st));

	if (!(ikehdr->exchange_type == IKEV2EXCH_IKE_SESSION_RESUME
	      && !(ikehdr->flags & IKEV2FLAG_INITIATOR)
	      && (ikehdr->flags & IKEV2FLAG_RESPONSE))) {
		isakmp_log(ike_sa, local, remote, packet,
		    PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: unexpected resume response packet\n");
		++isakmpstat.unexpected_packet;
		goto drop;
	}
	/* RFC 5723 s4.3.2: a refusal is HDR(38), N(TICKET_NACK) with no
	 * Nr.  The client then "SHOULD initiate a regular IKE exchange":
	 * forget the ticket and restart this SA with IKE_SA_INIT. */
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	for (; type != IKEV2_NO_NEXT_PAYLOAD; POINT_NEXT_PAYLOAD(p, type)) {
		if (type == IKEV2_PAYLOAD_NOTIFY &&
		    get_notify_type((struct ikev2payl_notify *)p) ==
		    IKEV2_TICKET_NACK) {
			isakmp_log(ike_sa, local, remote, packet,
			    PLOG_INFO, PLOGLOC,
			    "RFC 5723: received N(TICKET_NACK) in "
			    "IKE_SESSION_RESUME response\n");
			ike_msg_session_resume_fallback(ike_sa,
			    "ticket refused (TICKET_NACK)");
			goto done;
		}
	}

	/* Capture the responder's SPI from this exchange. */
	memcpy(&ike_sa->index.r_ck, &ikehdr->responder_spi,
	    sizeof(isakmp_cookie_t));

	/* Walk payloads: must contain Nr. */
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	for (; type != IKEV2_NO_NEXT_PAYLOAD; POINT_NEXT_PAYLOAD(p, type)) {
		if (type == IKEV2_PAYLOAD_NONCE) {
			if (n_r)
				goto drop;	/* duplicate Nr */
			n_r = isakmp_p2v((struct isakmp_gen *)p);
		}
	}
	if (!n_r || n_r->l < 16) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: no or short Nr in resume response\n");
		goto drop;
	}
	ike_sa->n_r = n_r;	n_r = NULL;

	/* Reload the stored ticket + from-ticket state for this peer. */
	if (!(key = ike_msg_resume_store_key(ike_sa->remote)))
		goto fail;
	if (r2ticket_store_load(ike_msg_resume_store_dir(), key,
	    &ticket_lt, &st) != 0)
		goto fail;

	/* RFC 5723 s5 / s6: the resumed keys are derived from the OLD SK_d and
	 * the negotiated SA carried in the ticket.  A ticket whose serialized
	 * state is missing either (corrupt/truncated store record) cannot
	 * resume; fail closed rather than deref a NULL length below. */
	if (!st.sa || !st.idi || !st.sk_d)
		goto fail;

	/* Rebuild the negotiated IKE SA from the serialized SAr (the ticket
	 * stores the raw Proposal bytes; wrap them in an SA payload header
	 * like the responder does). */
	{
		rc_vchar_t *sap = NULL;
		struct ikev2_payload_header *sh;

		sap = rc_vmalloc(st.sa->l + sizeof(struct ikev2_payload_header));
		if (!sap)
			goto fail;
		sh = (struct ikev2_payload_header *)sap->v;
		sh->next_payload = IKEV2_NO_NEXT_PAYLOAD;
		sh->header_byte_2 = 0;
		put_uint16(&sh->payload_length,
		    st.sa->l + sizeof(struct ikev2_payload_header));
		memcpy((uint8_t *)sap->v + sizeof(struct ikev2_payload_header),
		    st.sa->v, st.sa->l);
		parsed = ikev2_parse_sa(&ikev2_doi, sh);
		rc_vfree(sap);
	}
	nsa = NULL;
	if (parsed) {
		int _i;
		for (_i = 1; _i < MAXPROPPAIRLEN; ++_i)
			if (parsed[_i]) {
				nsa = ikev2_proppair_to_isakmpsa(parsed[_i]);
				break;
			}
	}
	if (!nsa) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: cannot rebuild IKE SA from stored ticket SAr\n");
		goto fail;
	}
	if (ikev2_isakmpsa_deprecated_refused(ike_sa->rmconf, nsa,
	    "RFC 5723 resume (stored ticket SA)")) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: resumed IKE SA uses a disallowed deprecated "
		    "transform - not resuming\n");
		racoon_free(nsa);
		nsa = NULL;
		goto fail;
	}
	if (ikev2_set_negotiated_sa(ike_sa, nsa) != 0)
		goto fail;
	nsa = NULL;		/* owned by ike_sa now */

	ike_sa->skeyseed = r2ticket_skeyseed(ike_sa->negotiated_sa->prf,
	    st.sk_d, ike_sa->n_i, ike_sa->n_r);
	if (!ike_sa->skeyseed)
		goto fail;
	if (ikev2_compute_keys(ike_sa) != 0)
		goto fail;

	/* RFC 5723: the ticket authenticated the peer.  The INITIATOR does not
	 * install ticket-carried IDs here: its own IDi comes from config and
	 * the peer's IDr from the resumed IKE_AUTH response (the normal
	 * initiator IKE_AUTH-response path manages both and asserts id_r is
	 * unset on entry).  The responder side, in contrast, adopts the peer's
	 * IDs from the ticket because it receives no fresh ones. */
	ike_sa->resumed = 1;

	/* RealMessage1 = our resume request (my_first_message, set at send);
	 * RealMessage2 = this resume response.  The resumed IKE_AUTH AUTH
	 * (which initiator_state1_send computes over my_first_message with
	 * resumed SK_pi) and the responder's AUTH verification (over
	 * peer_first_message with resumed SK_pr) both key off these. */
	if (ike_sa->peer_first_message)
		rc_vfree(ike_sa->peer_first_message);
	ike_sa->peer_first_message = rc_vdup(packet);
	if (!ike_sa->peer_first_message)
		goto fail;
	if (!ike_sa->my_first_message)
		goto fail;

	/* The ticket already authenticated the peer: short-circuit the full
	 * auth verify on the resumed IKE_AUTH response. */
	ike_sa->verified_info.result = VERIFIED_SUCCESS;

	/* Advance the send Message ID past the IKE_SESSION_RESUME exchange
	 * (which used msgid 0) so the resumed IKE_AUTH uses msgid 1 -- exactly
	 * what initiator_state1_send() builds (auth_msgid=1) and what
	 * ikev2_request_id() hands to the IKE_AUTH child.  Without this the
	 * child is registered under msgid 0 and the IKE_AUTH response (echoing
	 * 1) finds no matching request. */
	ikev2_update_message_id(ike_sa, get_uint32(&ikehdr->message_id), TRUE);

	/* Send the resumed IKE_AUTH as initiator (CHILD + IDs + AUTH over
	 * the resume request).  It reuses the full initiator IKE_AUTH
	 * builder; sa->resumed stops TICKET_REQUEST re-request and selects
	 * the resumed AUTH arm in ikev2_auth. */
	ikev2_set_state(ike_sa, IKEV2_STATE_INI_IKE_AUTH_SENT);
	initiator_state1_send(ike_sa, 0, ike_sa->remote);
	ike_sa->crypto_pending = 0;
	isakmp_log(ike_sa, local, remote, packet, PLOG_INFO, PLOGLOC,
	    "RFC 5723: accepted resume response, resumed keys derived, "
	    "IKE_AUTH sent\n");
	goto done;

 fail:
	/* Fall back to a normal IKE_SA_INIT: discard the stored ticket (it
	 * was NACKed / expired / corrupt), abort this half-open SA so the
	 * caller starts fresh. */
	if (key)
		r2ticket_store_clear(ike_msg_resume_store_dir(), key);
	isakmp_log(ike_sa, local, remote, packet, PLOG_INTERR, PLOGLOC,
	    "RFC 5723: resume response rejected; falling back to "
	    "IKE_SA_INIT\n");
	ikev2_abort(ike_sa, ECONNREFUSED);
	goto done;
 drop:
 done:
	if (n_r)
		rc_vfree(n_r);
	if (ticket_lt)
		rc_vfree(ticket_lt);
	if (key)
		racoon_free(key);
	r2ticket_state_free(&st);
}

/* RFC 5723 s4.3.2 responder side: accept an IKE_SESSION_RESUME (exchange 38)
 * request.  The request is HDR(SPIi=new, SPIr=0), [N(COOKIE),] Ni,
 * N(TICKET_OPAQUE).  Validate the returned ticket against our configured
 * ticket key, recover the "from the ticket" IKE state (IDs, SPIs, serialized
 * SAr, OLD SK_d, auth method, expiry), rebuild the negotiated IKE SA, and
 * derive the resumed keys:
 *     SKEYSEED = prf(SK_d_old, "Resumption" | Ni | Nr)
 * On success answer HDR(38), Nr exactly like an IKE_SA_INIT response (RFC
 * Figure 5) and park in the IKE_AUTH-approved window so the peer's resumed
 * IKE_AUTH (msgid 1) continues the build.  On rejection answer an
 * unprotected N(TICKET_NACK) so the client falls back to a normal exchange
 * (RFC 5723 s4.3.2).  Fail-closed: no resumed SA without a parseable,
 * unexpired ticket and a usable negotiated SA. */
void
responder_ike_session_resume_recv(struct ikev2_sa *ike_sa, rc_vchar_t *packet,
    struct sockaddr *remote, struct sockaddr *local)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	unsigned int type;
	rc_vchar_t *tkey = NULL;
	rc_vchar_t *ticket = NULL;
	rc_vchar_t *n_i = NULL;
	struct r2ticket_state st;
	struct prop_pair **parsed = NULL;
	struct ikev2_isakmpsa *nsa = NULL;
	rc_vchar_t *n_r = NULL, *pkt = NULL;
	struct ikev2_payloads payl;
	int payl_inited = 0;
	const char *keypath;
	int rc = -1;

	ikehdr = (struct ikev2_header *)packet->v;
	memset(&st, 0, sizeof(st));

	/* RFC 5685 + RFC 5723 interplay (failover drain): restoring a
	 * ticketed session onto the node being drained would re-home the
	 * client BACK to the retiring gateway — defeating the drain.  When
	 * this peer is in the drain table, REFUSE the resume (N(TICKET_NACK))
	 * so the client falls back to a normal IKE_SA_INIT, which then hits
	 * the drain gate (ikev2_sa_init.c) and is REDIRECTed to the live
	 * sibling.  The ticket itself is unaffected (the sibling validates
	 * it under the shared session_resume_ticket_key); we simply decline
	 * to consume it here.  This is the honest drain semantics: a drained
	 * node never re-establishes a session, resumed or fresh. */
	if (ikev2_drain_lookup(remote)) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_INFO, PLOGLOC,
		    "RFC 5685: IKE_SESSION_RESUME from drained peer; "
		    "refusing (TICKET_NACK) so it redirects to a sibling\n");
		goto nack;
	}

	/* RFC 5723 s8: session_resumption must be enabled to accept tickets. */
	if (ikev2_use_session_resumption(ike_sa->rmconf) != RCT_BOOL_ON) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: IKE_SESSION_RESUME received but session "
		    "resumption is not enabled in config\n");
		goto nack;
	}
	if (!(keypath = rc_vmem2str(
	    ikev2_session_resume_ticket_key(ike_sa->rmconf)))) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: no session_resume_ticket_key configured; "
		    "refusing resume\n");
		goto nack;
	}
	if (r2ticket_key_load(keypath, &tkey) != 0) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_INTERR, PLOGLOC,
		    "RFC 5723: cannot load session_resume_ticket_key; "
		    "refusing resume\n");
		goto nack;
	}

	/* Walk payloads: Ni and N(TICKET_OPAQUE)(16413). */
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	for (; type != IKEV2_NO_NEXT_PAYLOAD; POINT_NEXT_PAYLOAD(p, type)) {
		switch (type) {
		case IKEV2_PAYLOAD_NONCE:
			if (n_i) {
				isakmp_log(ike_sa, local, remote, packet,
				    PLOG_PROTOERR, PLOGLOC,
				    "RFC 5723: duplicate Ni\n");
				goto nack;
			}
			n_i = isakmp_p2v((struct isakmp_gen *)p);
			if (n_i && n_i->l < 16) {
				isakmp_log(ike_sa, local, remote, packet,
				    PLOG_PROTOERR, PLOGLOC,
				    "RFC 5723: short Ni in IKE_SESSION_RESUME "
				    "request\n");
				goto nack;
			}
			break;
		case IKEV2_PAYLOAD_NOTIFY: {
			struct ikev2payl_notify *n =
			    (struct ikev2payl_notify *)p;
			size_t ndlen;
			if (get_notify_type(n) != IKEV2_TICKET_OPAQUE)
				break;
			if (n->nh.spi_size != 0) {
				isakmp_log(ike_sa, local, remote, packet,
				    PLOG_PROTOERR, PLOGLOC,
				    "RFC 5723: TICKET_OPAQUE with nonzero "
				    "spi_size\n");
				goto nack;
			}
			if (ticket) {
				isakmp_log(ike_sa, local, remote, packet,
				    PLOG_PROTOERR, PLOGLOC,
				    "RFC 5723: duplicate TICKET_OPAQUE\n");
				goto nack;
			}
			ndlen = get_payload_length(&n->header)
			    - sizeof(struct ikev2payl_notify) - n->nh.spi_size;
			ticket = rc_vnew(get_notify_data(n), ndlen);
			if (!ticket)
				goto fail;
			break;
		}
		default:
			break;
		}
	}
	if (!n_i) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: no Ni in IKE_SESSION_RESUME request\n");
		goto nack;
	}
	if (!ticket || ticket->l == 0) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: no N(TICKET_OPAQUE) in IKE_SESSION_RESUME "
		    "request\n");
		goto nack;
	}

	/* Validate the ticket and recover the SA state. */
	if (r2ticket_parse(tkey, ticket, &st) != 0) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: ticket validation failed (len=%zu) -> "
		    "TICKET_NACK\n", ticket ? ticket->l : 0);
		goto nack;
	}
	/* Cert notAfter carried in the ticket.  RFC 5723 resume has no
	 * CERT payload, so cert_validate cannot re-check the chain here.
	 * 0 means the mint had no certificate expiry (PSK/EAP). */
	if (st.cert_due != 0 && (uint32_t)time(NULL) >= st.cert_due) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR,
		    PLOGLOC, "RFC 5723: ticket cert notAfter passed -> "
		    "TICKET_NACK\n");
		goto nack;
	}

	/* RFC 5723 s6: the resumed keys and negotiated SA come from the ticket.
	 * A validly-MAC'd ticket missing SA or OLD SK_d state (defensive: a
	 * crafted ticket that passes AEAD can't exist, but a zero-length
	 * packed field is possible) cannot resume; fail closed. */
	if (!st.sa || !st.sk_d)
		goto nack;

	/* RFC 5723 s4.3.1: "A reused ticket SHOULD be rejected by a gateway".
	 * Each ticket resumes at most once; the client must then run a full
	 * exchange (and may obtain a fresh ticket there). */
	/* RFC 5723 s4.3.1: a reused ticket SHOULD be rejected.  The cache
	 * is on disk beside the ticket key so a restart, and any other
	 * iked that loads the same key file, sees the same single-use
	 * set.  Bind before mark. */
	r2ticket_replay_bind_key(keypath);
	switch (r2ticket_replay_mark(ticket, st.expires_at,
	    (uint32_t)time(NULL))) {
	case 0:
		break;
	case 1:
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR,
		    PLOGLOC, "RFC 5723: ticket was already used (s4.3.1) -> "
		    "TICKET_NACK\n");
		goto nack;
	default:
		isakmp_log(ike_sa, local, remote, packet, PLOG_INTWARN,
		    PLOGLOC, "RFC 5723: used-ticket cache full (%d unexpired "
		    "tickets) -> TICKET_NACK\n", R2TICK_REPLAY_SLOTS);
		goto nack;
	}

	/* Rebuild the negotiated IKE SA from the serialized SAr.  The ticket
	 * stores the output of ikev2_ikesa_to_proposal() -- the raw Proposal
	 * bytes without the 4-octet SA payload header.  Wrap them back in an
	 * SA payload header so ikev2_parse_sa() can consume them. */
	{
		rc_vchar_t *sap = NULL;
		struct ikev2_payload_header *sh;

		sap = rc_vmalloc(st.sa->l + sizeof(struct ikev2_payload_header));
		if (!sap)
			goto fail;
		sh = (struct ikev2_payload_header *)sap->v;
		sh->next_payload = IKEV2_NO_NEXT_PAYLOAD;
		sh->header_byte_2 = 0;
		put_uint16(&sh->payload_length,
		    st.sa->l + sizeof(struct ikev2_payload_header));
		memcpy((uint8_t *)sap->v + sizeof(struct ikev2_payload_header),
		    st.sa->v, st.sa->l);
		parsed = ikev2_parse_sa(&ikev2_doi, sh);
		rc_vfree(sap);
	}
	nsa = NULL;
	if (parsed) {
		/* isakmp_parse_proposal returns an array indexed by p_no
		 * (1-based, slot 0 is the NULL sentinel); take the first
		 * non-NULL proposal. */
		int _i;
		for (_i = 1; _i < MAXPROPPAIRLEN; ++_i) {
			if (parsed[_i]) { nsa = ikev2_proppair_to_isakmpsa(parsed[_i]); break; }
		}
	}
	if (!nsa) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_PROTOERR, PLOGLOC,
		    "RFC 5723: cannot rebuild IKE SA from ticket SAr\n");
		goto fail;
	}
	/* allow_*_deprecated off: a ticket minted for a now-disallowed suite
	 * (config changed since) is rejected; TICKET_NACK makes the
	 * initiator fall back to a full exchange (RFC 5723 s4.3.2). */
	if (ikev2_isakmpsa_deprecated_refused(ike_sa->rmconf, nsa,
	    "RFC 5723 resume (ticket SA)")) {
		racoon_free(nsa);
		nsa = NULL;
		goto nack;
	}

	/* Resumed exchange: fresh Nr keeps the exchange fresh; the SPIs from
	 * this exchange (request SPIi already in index.i_ck, SPIr in
	 * index.r_ck set at SA create) drive the prf+ below. */
	n_r = random_bytes(ikev2_nonce_size(ike_sa->rmconf));
	if (!n_r)
		goto fail;
	ike_sa->n_i = n_i;	n_i = NULL;
	ike_sa->n_r = n_r;	n_r = NULL;

	/* RFC 5723 Figure 5: the response to IKE_SESSION_RESUME is an
	 * UNPROTECTED HDR, Nr (like IKE_SA_INIT) -- the SA and keys do not
	 * exist yet to encrypt with.  Send it BEFORE installing the
	 * negotiated SA (ikev2_set_negotiated_sa arms the encryptor), so
	 * ikev2_packet_construct emits plaintext. */
	ikev2_update_message_id(ike_sa, get_uint32(&ikehdr->message_id), FALSE);
	ikev2_payloads_init(&payl);	payl_inited = 1;
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NONCE, ike_sa->n_r, FALSE);
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_SESSION_RESUME,
	    IKEV2FLAG_RESPONSE, 0, ike_sa, &payl);
	if (!pkt) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_INTERR, PLOGLOC,
		    "RFC 5723: failed building resume response\n");
		goto fail;
	}

	/* RFC 5723 s4.3.3: the resumed IKE_AUTH's AUTH payloads are
	 * computed as prf(SK_px,<message octets>) per RFC 7296 s2.15, but
	 * over the IKE_SESSION_RESUME messages instead of IKE_SA_INIT.
	 * Record both windows on the resumed SA so ikev2_auth_input() can
	 * verify the initiator's AUTH (RealMessage1 = this request) and
	 * compute the responder's own AUTH (RealMessage2 = this response)
	 * without tripping its my_first_message/peer_first_message
	 * asserts. */
	ike_sa->peer_first_message = rc_vdup(packet);
	if (!ike_sa->peer_first_message)
		goto fail;
	ike_sa->my_first_message = rc_vdup(pkt);
	if (!ike_sa->my_first_message)
		goto fail;

	if (ikev2_transmit_response(ike_sa, pkt, local, remote) != 0)
		goto fail;
	pkt = NULL;

	/* Now install the resumed SA and derive the resumed SKEYSEED + keys
	 * (RFC 5723 s5.1), used by the peer's encrypted resumed IKE_AUTH. */
	if (ikev2_set_negotiated_sa(ike_sa, nsa) != 0) {
		isakmp_log(ike_sa, local, remote, packet, PLOG_INTERR, PLOGLOC,
		    "RFC 5723: failed instantiating resumed IKE SA\n");
		goto fail;
	}
	nsa = NULL;			/* owned by ike_sa now */
	ike_sa->skeyseed = r2ticket_skeyseed(ike_sa->negotiated_sa->prf,
	    st.sk_d, ike_sa->n_i, ike_sa->n_r);
	if (!ike_sa->skeyseed)
		goto fail;
	if (ikev2_compute_keys(ike_sa) != 0)
		goto fail;

	/* IDs from the ticket become this resumed SA's identities.
	 *
	 * Trust boundary (RFC 5723 s4): the ticket is MAC'd (AEAD) with the
	 * responder's own ticket key and bound to the original SPIs, so the
	 * embedded IDi/IDr are cryptographically trustworthy — the ticket
	 * cannot be forged by the peer.  POLICY: the ticket-carried IDi is
	 * still re-checked against this remote's configured peers_id in
	 * the resumed IKE_AUTH accept (ikev2_peer_id_ok, the same routine
	 * the fresh path uses), so a ticket minted under an older/looser
	 * identity policy, or replayed onto a gateway whose peers_id
	 * changed since mint, is refused just as a fresh IKE_AUTH would
	 * be.  If ticket keys are shared across gateways, a ticket minted
	 * for peer A could otherwise be replayed to a second gateway that
	 * trusts the same key; keep ticket keys per responder (default: a
	 * single local key file per iked) so a ticket only ever binds to
	 * the gateway that minted it. */
	ike_sa->id_i = st.idi;	st.idi = NULL;
	ike_sa->id_r = st.idr;	st.idr = NULL;
	ike_sa->resumed = 1;	/* established by ticket, not full IKE_AUTH */
	/* Do not pre-set verified_info.result. The resumed IKE_AUTH
	 * still has to pass ikev2_auth_verify; VERIFIED_WAITING (0) until
	 * that call returns is the honest state. */

	/* RFC 5723 s4.3.4: remember the OLD SA the client resumed from, so
	 * once the resumed IKE_AUTH succeeds we can silently delete it and
	 * its children (no DELETE informational).  st.spi_i/spi_r are in the
	 * same u64 form ike_msg_cookie_to_u64() produces, so the match in
	 * ikev2_silently_delete_old_resumed_sa() uses that conversion. */
	ike_sa->resume_old_spi_i = st.spi_i;
	ike_sa->resume_old_spi_r = st.spi_r;

	/* The peer is already identified by the ticket.  The resumed
	 * IKE_AUTH still verifies AUTH (ikev2_auth_verify); do not mark
	 * VERIFIED_SUCCESS here. */

	/* Resumed IKE_AUTH arrives with msgid 1, encrypted under these keys;
	 * the normal responder IKE_AUTH path takes over from here. */
	ikev2_set_state(ike_sa, IKEV2_STATE_RES_IKE_AUTH_RCVD);
	isakmp_log(ike_sa, local, remote, packet, PLOG_INFO, PLOGLOC,
	    "RFC 5723: accepted IKE_SESSION_RESUME ticket, resumed keys "
	    "derived, Nr sent\n");
	rc = 0;
	goto done;

 nack:
	/* RFC 5723 s4.3.2: reject with an unprotected N(TICKET_NACK); the
	 * client then falls back to a normal IKE exchange.  Abort this
	 * half-open SA (no resumed state was established). */
	ikev2_respond_with_notify_exch(packet, remote, local,
	    IKEV2EXCH_IKE_SESSION_RESUME, IKEV2_TICKET_NACK, 0, 0);
	isakmp_log(ike_sa, local, remote, packet, PLOG_INFO, PLOGLOC,
	    "RFC 5723: sent N(TICKET_NACK) in IKE_SESSION_RESUME (38) "
	    "response\n");
	ikev2_update_message_id(ike_sa, get_uint32(&ikehdr->message_id), FALSE);
	ikev2_abort(ike_sa, ECONNREFUSED);
	rc = 0;
	goto done;

 fail:
	rc = -1;
 done:
	if (tkey) { OPENSSL_cleanse(tkey->v, tkey->l); rc_vfreez(tkey); }
	if (ticket) rc_vfree(ticket);
	if (n_i) rc_vfree(n_i);
	if (n_r) rc_vfree(n_r);
	if (nsa) racoon_free(nsa);
	if (parsed) proplist_discard(parsed);
	r2ticket_state_free(&st);
	if (payl_inited) ikev2_payloads_destroy(&payl);
	if (pkt) rc_vfree(pkt);
	if (rc != 0)
		ikev2_abort(ike_sa, ECONNREFUSED);
}

/*
 * RFC 5723 s4.1/7.1: if the peer requested a session-resumption ticket
 * (N(TICKET_REQUEST) seen) and this remote has session_resumption enabled,
 * mint a ticket by value from the just-authenticated IKE SA and return the
 * TICKET_LT_OPAQUE notify DATA (4-octet lifetime || ticket).  Returns NULL
 * when no ticket should be issued (not requested, not enabled, key missing)
 * or on marshalling error.  The caller frees the returned rc_vchar_t.
 *
 * The ticket stores the RFC 5723 s5 "from the ticket" state: the negotiated
 * IKE SA proposal (SAr), the IDi/IDr of the established SA, the original
 * SPIs, the AUTH method, and the OLD SK_d (so a resumed IKE_AUTH can derive
 * SKEYSEED per s5.1 without re-running EAP).  It is bound to the responder's
 * ticket key (session_resume_ticket_key) with a fresh key_id derived from
 * this SA's SPIs so concurrent SAs don't collapse onto one ticket key id.
 */
static rc_vchar_t *
ikev2_ticket_lt_opaque(struct ikev2_sa *ike_sa)
{
	struct rcf_remote *rmconf = ike_sa->rmconf;
	const char *keypath;
	rc_vchar_t *tkey = NULL, *lt = NULL;
	struct r2ticket_state st;
	uint8_t key_id[R2TICK_KEY_ID_LEN];
	int lifetime;
	rc_vchar_t *sarl = NULL;
	int r;

	/* Zero the state up front so a later assignment (e.g. auth_method in
	 * the validation block below) is not clobbered by a second memset. */
	memset(&st, 0, sizeof(st));

	if (!ike_sa->ticket_requested)
		return NULL;
	if (rmconf && ikev2_use_session_resumption(rmconf) == RCT_BOOL_OFF)
		return NULL;
	if (!rmconf)
		return NULL;
	if (!(keypath = rc_vmem2str(ikev2_session_resume_ticket_key(rmconf))))
		return NULL;				/* not configured */
	if (ikev2_session_resume_ticket_lifetime(rmconf) <= 0)
		return NULL;
	{
		int auth_method = ikev2_auth_method(ike_sa);
		/* ikev2_auth_method() returns 0 (not -1) on every error path
		 * (no kmp_auth_method, EAP without a 64-octet MSK, missing
		 * private key).  `<= 0` is the fail-closed gate: an invalid or
		 * unresolved method must not be stamped into a ticket. */
		if (auth_method <= 0) {
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			    "RFC 5723: unresolved auth method %d, not issuing "
			    "ticket\n", auth_method);
			return NULL;
		}
		st.auth_method = (uint8_t)auth_method;
	}

	if (r2ticket_key_load(keypath, &tkey) != 0) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		    "RFC 5723: cannot load session_resume_ticket_key '%s' - "
		    "not issuing a ticket\n", keypath);
		return NULL;
	}

	st.expires_at = (uint32_t)time(NULL) +
	    (uint32_t)ikev2_session_resume_ticket_lifetime(rmconf);
	/* 0 = no certificate expiry to enforce (PSK/EAP).  A cert mint
	 * carries notAfter so a resume after expiry is NACKed even though
	 * RFC 5723 sends no CERT. */
	st.cert_due = (ike_sa->due_time.tv_sec > 0) ?
	    (uint32_t)ike_sa->due_time.tv_sec : 0;
	/* Store the SPIs in the same big-endian u64 form the codec packs and
	 * ikev2_silently_delete_old_resumed_sa() matches — NOT via a raw
	 * memcpy into the uint64, which on a little-endian host reverses the
	 * cookie byte order so the silent-delete never finds the old SA.
	 * (Same form ike_msg_resume_store_save_from_sa uses below.) */
	st.spi_i = ike_msg_cookie_to_u64(ike_sa->index.i_ck);
	st.spi_r = ike_msg_cookie_to_u64(ike_sa->index.r_ck);

	/* SAr: serialize the negotiated IKE SA proposal. */
	sarl = ikev2_ikesa_to_proposal(ike_sa->negotiated_sa, 0);
	if (!sarl)
		goto done;
	st.sa = sarl;

	/* IDi/IDr: the payload data of the established SA. */
	st.idi = ike_sa->id_i;
	st.idr = ike_sa->id_r;
	st.sk_d = ike_sa->sk_d;			/* OLD SK_d */

	memcpy(key_id, &ike_sa->index.i_ck, 4);
	memcpy(key_id + 4, &ike_sa->index.r_ck, 4);
	lifetime = ikev2_session_resume_ticket_lifetime(rmconf);

	lt = r2ticket_lt_opaque(tkey, key_id, &st, (uint32_t)lifetime);
 done:
	if (tkey) {
		OPENSSL_cleanse(tkey->v, tkey->l);
		rc_vfreez(tkey);
	}
	if (sarl)
		rc_vfree(sarl);
	return lt;
}

/*
 * Push N(TICKET_LT_OPAQUE) into a response payload list if a ticket should
 * be issued.  Used by every responder IKE_AUTH response builder after the
 * authentication completes, so a client that requested a ticket receives it
 * exactly once (RFC 5723 s4.2: only in the final IKE_AUTH response).
 */
void
ikev2_maybe_issue_ticket(struct ikev2_sa *ike_sa, struct ikev2_payloads *payl)
{
	rc_vchar_t *lt;

	lt = ikev2_ticket_lt_opaque(ike_sa);
	if (!lt) {
		/* RFC 5723 s4.1: when a peer N(TICKET_REQUEST)s and we
		 * support resumption but cannot (or choose not to) grant
		 * one, we MUST answer with N(TICKET_NACK) — not silence.
		 * A NULL here is ambiguous (also returned when no request
		 * was received), so only NACK when ticket_requested is
		 * actually set. */
		if (ike_sa->ticket_requested)
			ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
					    ikev2_notify_payload(
						IKEV2_NOTIFY_PROTO_NONE, 0, 0,
						IKEV2_TICKET_NACK, 0, 0),
					    TRUE);
		return;
	}
	isakmp_log(ike_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
	    "RFC 5723: issuing session-resumption ticket\n");
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(IKEV2_NOTIFY_PROTO_NONE,
						 0, 0, IKEV2_TICKET_LT_OPAQUE,
						 lt->v, lt->l),
			    TRUE);
	rc_vfree(lt);
}
