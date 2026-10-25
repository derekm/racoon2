/* $Id: ikev2_mobike.c	$ */

/*
 * Copyright (C) 2004-2026 WIDE Project.
 * All rights reserved.
 *
 * RFC 4555 MOBIKE address-mobility handling, consolidated from ikev2.c and
 * ikev2_child.c:
 *
 *   ikev2_mobike_apply        apply an implicit/triggered address update to
 *                             an ESTABLISHED SA (RFC 4555 s3.1 implicit,
 *                             or an explicit UPDATE_SA_ADDRESSES) and migrate
 *                             the Child SAs' kernel bindings
 *   ikev2_mobike_migrate_dir  migrate one XFRM direction to new endpoints
 *   ikev2_mobike_probe_next   probe the next same-family alternate address
 *                             with COOKIE2 when the current path's
 *                             retransmits are exhausted
 *
 * ikev2_mobike_apply is exported (called by the informational responder and
 * the established/DPD path); probe_next is exported (called by the
 * retransmit/timeout machinery in ikev2.c); migrate_dir is file-static.
 */
#include <config.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "racoon.h"
#include "isakmp.h"
#include "dhgroup.h"
#include "oakley.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "crypto_impl.h"
#include "sockmisc.h"
#include "debug.h"
#include "rc_net.h"
#include "ike_pfkey.h"

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

static void
ikev2_mobike_natt(struct ikev2_sa *ike_sa, struct rcpfk_msg *rc,
    struct sockaddr *n_src, struct sockaddr *n_dst)
{
	in_port_t *sp, *dp;

	/* RFC 9329: over TCP the child's ESP always rides UDP-encap 4500/4500
	 * (see ikev2_sadb_natt_tcp_pin); a MOBIKE address update must not
	 * re-derive natt_dport from the (TCP stream) peer port, or it would
	 * un-pin ESP from 4500. */
	if (ike_sa->rmconf != NULL &&
	    ikev2_tcp_encap(ike_sa->rmconf) == RCT_BOOL_ON) {
		rc->natt_type = UDP_ENCAP_ESPINUDP;
		rc->natt_sport = htons(IKEV2_UDP_PORT_NATT);
		rc->natt_dport = htons(IKEV2_UDP_PORT_NATT);
		return;
	}
	sp = rcs_getsaport(n_src);
	dp = rcs_getsaport(n_dst);
	if (!sp || !dp)
		return;
	if (*sp == htons(500) && *dp == htons(500))
		return;
	rc->natt_type = UDP_ENCAP_ESPINUDP;
	rc->natt_sport = *sp;
	rc->natt_dport = *dp;
}
static int
ikev2_mobike_migrate_dir(struct ikev2_sa *ike_sa, rc_type dir,
    struct sockaddr *old_s, struct sockaddr *old_d,
    struct sockaddr *new_s, struct sockaddr *new_d,
    struct sockaddr *sp_src, struct sockaddr *sp_dst,
    uint8_t pref_src, uint8_t pref_dst, rc_type samode, uint32_t reqid)
{
	struct rcpfk_msg rc;

	memset(&rc, 0, sizeof(rc));
	rc.sa_src = old_s;
	rc.sa_dst = old_d;
	rc.sa2_src = new_s;
	rc.sa2_dst = new_d;
	rc.sp_src = sp_src;
	rc.sp_dst = sp_dst;
	rc.pref_src = pref_src;
	rc.pref_dst = pref_dst;
	rc.satype = RCT_SATYPE_ESP;
	rc.samode = samode;
	rc.reqid = reqid;
	rc.dir = dir;
	rc.ul_proto = RC_PROTO_ANY;
	ikev2_mobike_natt(ike_sa, &rc, new_s, new_d);
	if (sadb_migrate(&rc) != 0) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "MOBIKE migrate failed: %s\n", rc.estr);
		return -1;
	}
	return 0;
}

/*
 * Move an ESTABLISHED IKE SA and its Child SAs to new endpoints.
 * migrate_kernel == 0 when the kernel already moved the SAs (an
 * XFRM_MSG_MIGRATE / SADB_X_MIGRATE from another KM): only the in-memory
 * endpoints, armed retransmit caches and NAT-D pins are updated.
 * Returns 0 when the endpoints were committed.
 */
static int ikev2_move_sa(struct ikev2_sa *, struct sockaddr *,
    struct sockaddr *, int, const char *);

void
ikev2_mobike_apply(struct ikev2_sa *ike_sa, struct sockaddr *remote,
    struct sockaddr *local)
{
	if (!ike_sa || !ike_sa->mobike_supported || !remote || !local)
		return;
	(void)ikev2_move_sa(ike_sa, remote, local, 1,
	    "MOBIKE UPDATE_SA_ADDRESSES");
}

/*
 * The kernel reported (XFRM_MSG_MAPPING) that authenticated ESP-in-UDP
 * for one of this IKE SA's Child SAs now arrives from new_remote.  With
 * natt_follow_mapping on and the peer behind a NAT, follow it the same
 * way an implicit MOBIKE update does (RFC 7296 s2.23).
 */
int
ikev2_natt_follow_mapping_event(struct ikev2_sa *ike_sa,
    struct sockaddr *new_remote)
{
	if (!ike_sa || !new_remote || !ike_sa->remote || !ike_sa->local)
		return -1;
	if (ike_sa->state != IKEV2_STATE_ESTABLISHED)
		return -1;
	if (ikev2_natt_follow_mapping(ike_sa->rmconf) != RCT_BOOL_ON) {
		isakmp_log(ike_sa, ike_sa->local, new_remote, 0, PLOG_INFO,
			   PLOGLOC,
			   "NAT-T mapping change %s -> %s ignored "
			   "(natt_follow_mapping off)\n",
			   rcs_sa2str(ike_sa->remote), rcs_sa2str(new_remote));
		return -1;
	}
	if (!ike_sa->peer_behind_nat) {
		isakmp_log(ike_sa, ike_sa->local, new_remote, 0, PLOG_PROTOWARN,
			   PLOGLOC,
			   "NAT-T mapping change %s -> %s ignored: NAT-D did "
			   "not place the peer behind a NAT\n",
			   rcs_sa2str(ike_sa->remote), rcs_sa2str(new_remote));
		return -1;
	}
	return ikev2_move_sa(ike_sa, new_remote, ike_sa->local, 1,
	    "NAT-T mapping change");
}

/* Another KM already migrated the kernel SAs; follow in memory. */
int
ikev2_kernel_migrated(struct ikev2_sa *ike_sa, struct sockaddr *remote,
    struct sockaddr *local)
{
	if (!ike_sa || !remote || !local || !ike_sa->remote || !ike_sa->local)
		return -1;
	return ikev2_move_sa(ike_sa, remote, local, 0, "kernel MIGRATE");
}

static int ikev2_move_sa_impl(struct ikev2_sa *, struct sockaddr *,
    struct sockaddr *, int, const char *);

/*
 * Callers may pass the IKE SA's own endpoint (the NAT mapping path passes
 * ike_sa->local as "local"), which ikev2_move_sa_impl frees when it
 * commits the move and then copies again for the retransmit caches: a
 * use-after-free that ASan caught on the live i2inatt-rebind row (and
 * that silently read freed memory everywhere else).  Work on private
 * copies of both endpoints.
 */
static int
ikev2_move_sa(struct ikev2_sa *ike_sa, struct sockaddr *remote,
    struct sockaddr *local, int migrate_kernel, const char *why)
{
	struct sockaddr *r, *l;
	int ret;

	r = rcs_sadup(remote);
	l = rcs_sadup(local);
	if (r == NULL || l == NULL) {
		if (r)
			rc_free(r);
		if (l)
			rc_free(l);
		return -1;
	}
	ret = ikev2_move_sa_impl(ike_sa, r, l, migrate_kernel, why);
	rc_free(r);
	rc_free(l);
	return ret;
}

static int
ikev2_move_sa_impl(struct ikev2_sa *ike_sa, struct sockaddr *remote,
    struct sockaddr *local, int migrate_kernel, const char *why)
{
	struct ikev2_child_sa *c;
	struct sockaddr *old_r, *old_l;
	struct rcf_selector *sl = NULL;
	struct sockaddr *lan = NULL, *inner = NULL;
	uint8_t lan_pref = 0, inner_pref = 0;
	struct sockaddr_storage lease_ss;
	rc_type samode = RCT_IPSM_TUNNEL;
	uint32_t reqid = 0;

	if (ike_sa->remote && ike_sa->local &&
	    rcs_cmpsa(ike_sa->remote, remote) == 0 &&
	    rcs_cmpsa(ike_sa->local, local) == 0)
		return 0;

	old_r = ike_sa->remote;
	old_l = ike_sa->local;
	isakmp_log(ike_sa, local, remote, 0, PLOG_INFO, PLOGLOC,
		   "%s %s -> %s\n", why,
		   rcs_sa2str(old_r), rcs_sa2str(remote));

	/*
	 * Collect the new endpoints / selectors first.  The kernel
	 * migrations below must ALL succeed before any in-memory
	 * endpoint is committed — a partial move strands the SAD and
	 * the returned (new) ike_sa pair would describe a broken
	 * data path (M3).
	 */
	for (c = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(c);
	     c = IKEV2_CHILD_LIST_NEXT(c)) {
		if (!sl && c->selector && c->selector->pl &&
		    c->selector->src && c->selector->dst &&
		    c->selector->src->type == RCT_ADDR_INET &&
		    c->selector->dst->type == RCT_ADDR_INET)
			sl = c->selector;
		if (inner == NULL && !LIST_EMPTY(&c->lease_list)) {
			struct rcf_address *a;
			int plen = 0;

			a = LIST_FIRST(&c->lease_list);
			ikev2_cfg_addr2sockaddr((struct sockaddr *)&lease_ss,
			    a, &plen);
			inner = (struct sockaddr *)&lease_ss;
			inner_pref = (uint8_t)plen;
		}
	}

	if (sl) {
		samode = ike_ipsec_mode(sl->pl);
		reqid = sl->reqid;
		if (sl->direction == RCT_DIR_INBOUND) {
			lan = sl->dst->a.ipaddr;
			lan_pref = sl->dst->prefixlen;
			if (!inner) {
				inner = sl->src->a.ipaddr;
				inner_pref = sl->src->prefixlen;
			}
		} else {
			lan = sl->src->a.ipaddr;
			lan_pref = sl->src->prefixlen;
			if (!inner) {
				inner = sl->dst->a.ipaddr;
				inner_pref = sl->dst->prefixlen;
			}
		}
	}

	if (migrate_kernel && old_l && old_r && lan && inner) {
		if (ikev2_mobike_migrate_dir(ike_sa, RCT_DIR_OUTBOUND,
		    old_l, old_r, local, remote,
		    lan, inner, lan_pref, inner_pref, samode, reqid) != 0 ||
		    ikev2_mobike_migrate_dir(ike_sa, RCT_DIR_INBOUND,
		    old_r, old_l, remote, local,
		    inner, lan, inner_pref, lan_pref, samode, reqid) != 0 ||
		    (samode == RCT_IPSM_TUNNEL &&
		     ikev2_mobike_migrate_dir(ike_sa, RCT_DIR_FWD,
		     old_r, old_l, remote, local,
		     inner, lan, inner_pref, lan_pref, samode, reqid) != 0)) {
			/* each failing direction already logged its error */
			isakmp_log(ike_sa, local, remote, 0, PLOG_INTERR,
				   PLOGLOC,
				   "MOBIKE migrate incomplete; keeping %s\n",
				   rcs_sa2str(old_r));
			return -1;
		}
	}

	/*
	 * All migrations succeeded (or there was nothing to move —
	 * no selector / lease).  Commit the endpoints now.
	 */
	for (c = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(c);
	     c = IKEV2_CHILD_LIST_NEXT(c)) {
		if (c->remote)
			rc_free(c->remote);
		if (c->local)
			rc_free(c->local);
		c->remote = rcs_sadup(remote);
		c->local = rcs_sadup(local);
	}

	ike_sa->remote = rcs_sadup(remote);
	ike_sa->local = rcs_sadup(local);
	/* Migrate before freeing old_r: the ticket store key is the peer
	 * address bytes. */
	if (old_r && ike_sa->is_initiator)
		(void)ike_msg_resume_store_migrate(old_r, remote);
	if (old_r)
		rc_free(old_r);
	if (old_l)
		rc_free(old_l);

	/* Armed transmit/response caches hold endpoint copies minted when
	 * the retransmit was scheduled.  On a roam the peer that will send
	 * the retransmit lives at the NEW addresses: retarget armed infos
	 * or a replay goes to the dead mapping and the exchange is lost
	 * (review).  Silent when idle -- packet==NULL means nothing armed. */
	if ((ike_sa->transmit_info.packet || ike_sa->transmit_info.frags) &&
	    ike_sa->transmit_info.src && ike_sa->transmit_info.dest) {
		rc_free(ike_sa->transmit_info.src);
		rc_free(ike_sa->transmit_info.dest);
		ike_sa->transmit_info.src = rcs_sadup(local);
		ike_sa->transmit_info.dest = rcs_sadup(remote);
	}
	if ((ike_sa->response_info.packet || ike_sa->response_info.frags) &&
	    ike_sa->response_info.src && ike_sa->response_info.dest) {
		rc_free(ike_sa->response_info.src);
		rc_free(ike_sa->response_info.dest);
		ike_sa->response_info.src = rcs_sadup(local);
		ike_sa->response_info.dest = rcs_sadup(remote);
	}
	/* RFC 4555 §3.8: the next binding report must describe the
	 * address we just moved to, not the INIT pins. */
	ikev2_sa_repin_natd(ike_sa);
	/* Crash dump of the new endpoints otherwise waits for the next
	 * message-id advance. */
	ike_sa->resume_dirty = 1;
	isakmp_log(ike_sa, local, remote, 0, PLOG_INFO, PLOGLOC,
		   "MOBIKE binding report re-pinned\n");
	return 0;
}

int
ikev2_mobike_probe_next(struct ikev2_sa *ike_sa)
{
	int n, idx;
	struct sockaddr *alt;
	struct ikev2_payloads *payl;
	rc_vchar_t *cookie;

	if (!ike_sa || ike_sa->state != IKEV2_STATE_ESTABLISHED ||
	    !ike_sa->mobike_supported || !ike_sa->remote || !ike_sa->local)
		return 0;
	if (ike_sa->remote->sa_family == AF_INET)
		n = ike_sa->n_extra_addr4;
#ifdef INET6
	else if (ike_sa->remote->sa_family == AF_INET6)
		n = ike_sa->n_extra_addr6;
#endif
	else
		return 0;
	idx = ike_sa->mobike_alt_idx;
	if (idx < 0 || idx >= n)
		return 0;
	alt = rcs_sadup(ike_sa->remote);
	if (!alt)
		return 0;
	if (alt->sa_family == AF_INET)
		memcpy(&((struct sockaddr_in *)alt)->sin_addr,
		       ike_sa->extra_addr4[idx], 4);
#ifdef INET6
	else
		memcpy(&((struct sockaddr_in6 *)alt)->sin6_addr,
		       ike_sa->extra_addr6[idx], 16);
#endif
	ike_sa->mobike_alt_idx = idx + 1;
	if (ike_sa->mobike_rr_prev)
		rc_free(ike_sa->mobike_rr_prev);
	ike_sa->mobike_rr_prev = ike_sa->remote;
	ike_sa->remote = alt;
	ike_sa->mobike_rr_pending = 1;
	cookie = eay_set_random(16);
	if (!cookie)
		goto restore;
	if (ike_sa->cookie2_sent)
		rc_vfree(ike_sa->cookie2_sent);
	ike_sa->cookie2_sent = cookie;
	ike_sa->cookie2_matched = 0;
	payl = racoon_malloc(sizeof(*payl));
	if (!payl)
		goto restore;
	ikev2_payloads_init(payl);
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(0, 0, 0, IKEV2_COOKIE2,
						 cookie->v, cookie->l),
			    TRUE);
	isakmp_log(ike_sa, ike_sa->local, alt, 0, PLOG_INFO, PLOGLOC,
		   "MOBIKE responder-follow COOKIE2 probe %s\n",
		   rcs_sa2str(alt));
	ikev2_informational_initiator_notify(ike_sa, payl);
	return 1;

restore:
	ike_sa->remote = ike_sa->mobike_rr_prev;
	ike_sa->mobike_rr_prev = NULL;
	ike_sa->mobike_rr_pending = 0;
	rc_free(alt);
	return 0;
}
