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
#include "nattraversal.h"
#include "ikev2_tcp.h"
#include <unistd.h>
#include <sys/socket.h>

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
	/* RFC 4555 3.3 floats IKE to 4500 whether or not a NAT is present,
	 * but ESP is UDP-encapsulated only when a NAT was detected (RFC 3948,
	 * RFC 7296 2.23).  Keying encap off the IKE ports alone installed
	 * espinudp SAs against a NAT-free peer that keeps sending plain ESP
	 * (strongSwan), and the kernel dropped every inbound frame as
	 * XfrmInStateMismatch after the move.  Mirror the child-install rule
	 * in ikev2_child.c. */
	if (!ike_sa->behind_nat && !ike_sa->peer_behind_nat &&
	    (ike_sa->rmconf == NULL ||
	     ikev2_nat_traversal(ike_sa->rmconf) != RCT_NATT_FORCE)) {
		/* a move OUT of a NAT must also drop the old encap */
		rc->flags |= PFK_FLAG_NOENCAP;
		return;
	}
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
 * UPDATE_SA_ADDRESSES whose NAT_DETECTION changed behind_nat or
 * peer_behind_nat (RFC 4555 3.5).  The SA may already sit on the new
 * endpoints (an earlier message from them moved it implicitly), so a
 * plain apply would be a no-op and leave the old encapsulation; force
 * the kernel migration so ikev2_mobike_natt() re-derives it.
 */
void
ikev2_mobike_apply_nat(struct ikev2_sa *ike_sa, struct sockaddr *remote,
    struct sockaddr *local, int nat_changed)
{
	if (!ike_sa || !ike_sa->mobike_supported || !remote || !local)
		return;
	(void)ikev2_move_sa(ike_sa, remote, local, nat_changed ? 2 : 1,
	    nat_changed ? "MOBIKE UPDATE_SA_ADDRESSES (NAT changed)" :
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

	/* migrate_kernel == 2: re-migrate even onto the same endpoints,
	 * because the encapsulation changed (ikev2_mobike_apply_nat). */
	if (migrate_kernel != 2 && ike_sa->remote && ike_sa->local &&
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

/*
 * ---- RFC 4555 s3.5 on the original initiator (mobike_initiate on) ----
 *
 * An rtnetlink address event calls ikev2_mobike_local_changed(), which
 * (once the burst has settled, see below) asks the kernel which source
 * address it now uses toward each MOBIKE peer.  When that differs from
 * the IKE SA's local address, ikev2_mobike_local_update() points the IKE
 * SA at the new address (port kept) and sends an INFORMATIONAL with
 * UPDATE_SA_ADDRESSES plus NAT_DETECTION_{SOURCE,DESTINATION}_IP computed
 * over the new pair.  The kernel SAs stay on the old pair until the reply
 * (ikev2_mobike_local_reply): then the NAT state the reply reports is
 * committed and the SAs migrate, encapsulation included.  A timeout puts
 * the old address back (ikev2_mobike_local_abandon).
 */

/* the source address the kernel picks toward dst (no packet is sent) */
static int
mobike_route_source(const struct sockaddr *dst, struct sockaddr_storage *out)
{
	struct sockaddr_storage d;
	socklen_t l;
	int s, ok = -1;

	memset(&d, 0, sizeof(d));
	memcpy(&d, dst, SA_LEN(dst));
	if (d.ss_family == AF_INET)
		((struct sockaddr_in *)&d)->sin_port = htons(IKEV2_UDP_PORT_NATT);
#ifdef INET6
	else if (d.ss_family == AF_INET6)
		((struct sockaddr_in6 *)&d)->sin6_port = htons(IKEV2_UDP_PORT_NATT);
#endif
	else
		return -1;
	s = socket(d.ss_family, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	l = sizeof(*out);
	if (connect(s, (struct sockaddr *)&d, SA_LEN(dst)) == 0 &&
	    getsockname(s, (struct sockaddr *)out, &l) == 0)
		ok = 0;
	close(s);
	return ok;
}

static struct sched *mobike_local_timer;

static int
mobike_initiator_eligible(struct ikev2_sa *sa)
{
	return sa->state == IKEV2_STATE_ESTABLISHED && sa->is_initiator &&
	    sa->mobike_supported && sa->rmconf != NULL &&
	    ikev2_mobike_initiate(sa->rmconf) == RCT_BOOL_ON &&
	    !sa->mobike_li_pending && !sa->mobike_rr_pending &&
	    sa->local != NULL && sa->remote != NULL;
}

static void
mobike_local_scan(void *unused)
{
	struct ikev2_sa *sa, *next;

	int any = 0;

	(void)unused;
	SCHED_INIT(mobike_local_timer);
	for (sa = IKEV2_SA_LIST_FIRST(&ikev2_sa_list); sa;
	    sa = IKEV2_SA_LIST_NEXT(sa)) {
		if (mobike_initiator_eligible(sa))
			any = 1;
		else if (sa->state == IKEV2_STATE_ESTABLISHED &&
		    sa->is_initiator && !sa->mobike_supported &&
		    sa->rmconf != NULL &&
		    ikev2_mobike_initiate(sa->rmconf) == RCT_BOOL_ON)
			/* RFC 4555 s3.1: no UPDATE_SA_ADDRESSES to a peer
			 * that did not send MOBIKE_SUPPORTED */
			isakmp_log(sa, sa->local, sa->remote, 0, PLOG_INFO,
			    PLOGLOC, "MOBIKE initiator: local address change "
			    "ignored, the peer does not support MOBIKE\n");
	}
	if (!any)
		return;
	/* sockets for the new address set (interface ike { MY_IP; }) */
	isakmp_reopen();
	for (sa = IKEV2_SA_LIST_FIRST(&ikev2_sa_list); sa; sa = next) {
		struct sockaddr_storage src;

		next = IKEV2_SA_LIST_NEXT(sa);
		if (!mobike_initiator_eligible(sa))
			continue;
		if (mobike_route_source(sa->remote, &src) != 0) {
			/* no usable address: keep the SA, a later event
			 * (an address or route coming back) retries */
			isakmp_log(sa, sa->local, sa->remote, 0, PLOG_INFO,
			    PLOGLOC, "MOBIKE initiator: no route to the peer, "
			    "waiting for an address\n");
			continue;
		}
		if (rcs_cmpsa_wop((struct sockaddr *)&src, sa->local) == 0)
			continue;
		(void)ikev2_mobike_local_update(sa, (struct sockaddr *)&src);
	}
}

/*
 * Debounce.  rtnetlink delivers an address change as a burst (NEWADDR,
 * routes, DELADDR...) and a flapping link delivers many: scan once the
 * events have been quiet for MOBIKE_SETTLE seconds (trailing edge), but
 * never later than MOBIKE_SETTLE_MAX after the first event of a burst, so
 * a link that never stops flapping still gets an update.  One update is
 * in flight per SA at a time; ikev2_mobike_local_reply/_abandon rescan,
 * so a change during that exchange is not lost.
 */
#define MOBIKE_SETTLE		1
#define MOBIKE_SETTLE_MAX	3
static time_t mobike_burst_start;

void
ikev2_mobike_local_changed(void)
{
	time_t now = time(NULL);

	if (mobike_local_timer != NULL) {
		if (now - mobike_burst_start >= MOBIKE_SETTLE_MAX)
			return;		/* due soon: let it fire */
		SCHED_KILL(mobike_local_timer);
	} else
		mobike_burst_start = now;
	mobike_local_timer = sched_new(MOBIKE_SETTLE, mobike_local_scan, NULL);
}

static void
mobike_push_natd(struct ikev2_payloads *payl, struct ikev2_sa *sa,
    struct sockaddr *addr, int type)
{
	rc_vchar_t *h = natt_create_hash(sa, addr, 1);

	if (h == NULL)
		return;
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
	    ikev2_notify_payload(0, 0, 0, type, (uint8_t *)h->v, h->l), TRUE);
	rc_vfree(h);
}

int
ikev2_mobike_local_update(struct ikev2_sa *sa, const struct sockaddr *newaddr)
{
	struct sockaddr *nl;
	struct ikev2_payloads *payl;
	in_port_t *np, *op;

	if (sa == NULL || newaddr == NULL || !mobike_initiator_eligible(sa))
		return 0;
	nl = rcs_sadup(newaddr);
	if (nl == NULL)
		return 0;
	np = rcs_getsaport(nl);
	op = rcs_getsaport(sa->local);
	if (np && op)
		*np = *op;	/* same IKE port, new address */
#ifdef ENABLE_NATT
	/*
	 * RFC 4555 s3.5 / RFC 7296 s2.23: the new path may sit behind a
	 * NAT this update is about to detect, and ESP-in-UDP and the NAT
	 * binding both live on port 4500, so a NAT-T-enabled IKE SA moves
	 * to 4500 (both ends) before the update leaves.  A peer with NAT-T
	 * on listens there; switching early is always allowed.
	 */
	if (ikev2_tcp_encap(sa->rmconf) != RCT_BOOL_ON &&
	    (ikev2_nat_traversal(sa->rmconf) == RCT_BOOL_ON ||
	    ikev2_nat_traversal(sa->rmconf) == RCT_NATT_FORCE) &&
	    np && rcs_getsaport(sa->remote) &&
	    ntohs(*np) != IKEV2_UDP_PORT_NATT) {
		*np = htons(IKEV2_UDP_PORT_NATT);
		*rcs_getsaport(sa->remote) = htons(IKEV2_UDP_PORT_NATT);
	}
#endif
	if (ikev2_tcp_encap(sa->rmconf) == RCT_BOOL_ON) {
		/* RFC 9329: the old stream is bound to the old address; the
		 * update must leave over a stream from the new one. */
		struct sockaddr_storage td, ts;

		memcpy(&td, sa->remote, SA_LEN(sa->remote));
		memcpy(&ts, nl, SA_LEN(nl));
		*rcs_getsaport((struct sockaddr *)&td) = htons(IKEV2_TCP_PORT);
		*rcs_getsaport((struct sockaddr *)&ts) = 0;
		if (isakmp_tcp_open((struct sockaddr *)&td,
		    (struct sockaddr *)&ts) == NULL) {
			isakmp_log(sa, nl, sa->remote, 0, PLOG_INTERR, PLOGLOC,
			    "MOBIKE: no TCP stream from the new address: %s\n",
			    strerror(errno));
			rc_free(nl);
			return 0;
		}
	}
	payl = racoon_malloc(sizeof(*payl));
	if (payl == NULL) {
		rc_free(nl);
		return 0;
	}
	sa->mobike_li_prev = sa->local;
	sa->local = nl;
	sa->mobike_li_pending = 1;
	ikev2_payloads_init(payl);
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
	    ikev2_notify_payload(0, 0, 0, IKEV2_UPDATE_SA_ADDRESSES, 0, 0),
	    TRUE);
	mobike_push_natd(payl, sa, sa->local, IKEV2_NAT_DETECTION_SOURCE_IP);
	mobike_push_natd(payl, sa, sa->remote,
	    IKEV2_NAT_DETECTION_DESTINATION_IP);
	isakmp_log(sa, sa->local, sa->remote, 0, PLOG_INFO, PLOGLOC,
	    "MOBIKE initiator: local address %s -> %s, sending "
	    "UPDATE_SA_ADDRESSES\n", rcs_sa2str(sa->mobike_li_prev),
	    rcs_sa2str(sa->local));
	ikev2_informational_initiator_notify(sa, payl);
	return 1;
}

/* the peer answered the UPDATE_SA_ADDRESSES: commit the move */
void
ikev2_mobike_local_reply(struct ikev2_sa *sa, int src_seen, int src_match,
    int dst_seen, int dst_match)
{
	struct sockaddr *nl;
	int natchg;

	if (sa == NULL || !sa->mobike_li_pending || sa->mobike_li_prev == NULL)
		return;
	nl = sa->local;
	sa->local = sa->mobike_li_prev;	/* what the kernel SAs still use */
	sa->mobike_li_prev = NULL;
	sa->mobike_li_pending = 0;
	natchg = natt_mobike_renat(sa, src_seen, src_match, dst_seen,
	    dst_match);
	ikev2_mobike_apply_nat(sa, sa->remote, nl, natchg);
	rc_free(nl);
	ikev2_mobike_local_changed();	/* moved again meanwhile? */
}

/* the update went unanswered: the kernel SAs never left the old address */
void
ikev2_mobike_local_abandon(struct ikev2_sa *sa)
{
	if (sa == NULL || !sa->mobike_li_pending || sa->mobike_li_prev == NULL)
		return;
	rc_free(sa->local);
	sa->local = sa->mobike_li_prev;
	sa->mobike_li_prev = NULL;
	sa->mobike_li_pending = 0;
	ikev2_mobike_local_changed();	/* retry from the current address */
}
