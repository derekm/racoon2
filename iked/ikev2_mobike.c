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
#include <net/if.h>
#include <ifaddrs.h>
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
#include <errno.h>
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
	/* RFC 4555 s3.5 enables NAT Traversal when a NAT is likely; RFC 3948
	 * and RFC 7296 s2.23 encapsulate ESP only when a NAT was detected.
	 * Keying encap off the IKE ports alone installed
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
	/* PF_KEY's SADB_X_MIGRATE carries the policy: without an action
	 * the pfkey backend refused every MOBIKE move (invalid pltype=0) */
	rc.pltype = RCT_ACT_AUTO_IPSEC;
	/* ... and a level (the pfkey backend aborted on seclevel=0) */
	rc.ipsec_level = reqid != 0 ? RCT_IPSL_UNIQUE : RCT_IPSL_REQUIRE;
	rc.samode = samode;
	rc.reqid = reqid;
	rc.dir = dir;
	rc.ul_proto = RC_PROTO_ANY;
	ikev2_mobike_natt(ike_sa, &rc, new_s, new_d);
	/*
	 * A rekey overlap leaves two SAs on the old addresses.  One
	 * MIGRATE moves one of them; repeat until the kernel reports
	 * none left, or the second SA stays on the old address and the
	 * peer keeps a target the move was supposed to clear.
	 */
	{
		int moved = 0;

		for (;;) {
			if (sadb_migrate(&rc) != 0) {
				/* none left is not a failure: a later Child with
				 * the same reqid, or a direction with no SA */
				if (rc.eno == ENOENT || rc.eno == ESRCH ||
				    (rc.estr[0] &&
				     strstr(rc.estr, "No data") != NULL))
					return moved;
				isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR,
				    PLOGLOC, "MOBIKE migrate failed: %s\n",
				    rc.estr);
				return -1;
			}
			if (++moved >= 8)
				return moved;
			}
		return moved;
	}
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

int ikev2_move_sa_impl(struct ikev2_sa *, struct sockaddr *,
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
	/* Confirmed NAT: kernel SAs are still on 500. New endpoints go to
	 * 4500 so ESP-in-UDP has a port. A clear path (flags still off)
	 * must not float — that is what broke a NAT-free move. */
	if (ike_sa->behind_nat || ike_sa->peer_behind_nat) {
		in_port_t *rp = rcs_getsaport(r);
		in_port_t *lp = rcs_getsaport(l);

		/* Only 500 floats.  Any other port is the one the NAT
		 * mapped (an XFRM MAPPING moves the peer to it); forcing
		 * that to 4500 made the move a no-op. */
		if (rp && *rp == htons(IKEV2_UDP_PORT))
			*rp = htons(IKEV2_UDP_PORT_NATT);
		if (lp && *lp == htons(IKEV2_UDP_PORT))
			*lp = htons(IKEV2_UDP_PORT_NATT);
	}
	ret = ikev2_move_sa_impl(ike_sa, r, l, migrate_kernel, why);
	rc_free(r);
	rc_free(l);
	return ret;
}

/*
 * One successfully-migrated (reqid, direction), enough to walk it back
 * to the old endpoint if a later direction hard-fails.  The kernel SA
 * now lives at cur_s/cur_d (the forward target); reversing it calls
 * ikev2_mobike_migrate_dir again with the forward source (old_s/old_d)
 * as the target, which exercises whatever reversal the backend supports
 * (the umig / no-SADB_X_MIGRATE fallback in if_pfkeyv2.c already has a
 * per-SA delete+re-add path).  A reqid is deduped once across children
 * and moved in at most three directions, so (seen[16] * 3) bounds it.
 */
#define	MAX_MOBIKE_MIGRATES	(16 * 3)
struct mobike_mig_trace {
	rc_type dir;
	struct sockaddr *cur_s, *cur_d;	/* current kernel location (fwd target) */
	struct sockaddr *old_s, *old_d;	/* reverse target (fwd source) */
	/* selector addresses are COPIED: the caller's inner address may be
	 * a per-child stack lease buffer that is gone (or reused by the
	 * next child) by the time a later failure rolls this entry back */
	struct sockaddr_storage sp_src, sp_dst;
	uint8_t pref_src, pref_dst;
	rc_type samode;
	uint32_t reqid;
};

/*
 * Reverse every migrated direction back to its old endpoint after a
 * hard failure.  Rely on ikev2_mobike_migrate_dir + the backend's
 * per-SA reversal: at minimum keep the kernel and the in-memory
 * endpoint from disagreeing (no "lying endpoint pair").  A reversal
 * that itself fails is logged loudly but still returns -1 from the
 * caller -- never a silent contradiction.
 */
static void
mobike_migrate_rollback(struct ikev2_sa *ike_sa,
    struct mobike_mig_trace *tr, int n)
{
	int i;

	for (i = n - 1; i >= 0; i--) {
		int m;

		m = ikev2_mobike_migrate_dir(ike_sa, tr[i].dir,
		    tr[i].cur_s, tr[i].cur_d,
		    tr[i].old_s, tr[i].old_d,
		    (struct sockaddr *)&tr[i].sp_src,
		    (struct sockaddr *)&tr[i].sp_dst, tr[i].pref_src,
		    tr[i].pref_dst, tr[i].samode, tr[i].reqid);
		if (m < 0)
			isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			    "MOBIKE rollback of reqid %u dir %s failed: "
			    "kernel SA may still sit on the new endpoint\n",
			    tr[i].reqid, rct2str(tr[i].dir));
	}
}

/*
 * One migrate_dir with rollback bookkeeping: on a hard failure (< 0)
 * walk back every direction already migrated in the kernel and re-raise
 * the failure.  Real moves (m > 0) are traced; m == 0 is a drained /
 * nothing-to-move and needs no reversal.
 */
static int
mobike_migrate_dir_track(struct ikev2_sa *ike_sa,
    struct mobike_mig_trace *tr, int *nt,
    rc_type dir, struct sockaddr *old_s, struct sockaddr *old_d,
    struct sockaddr *new_s, struct sockaddr *new_d,
    struct sockaddr *sp_src, struct sockaddr *sp_dst,
    uint8_t pref_src, uint8_t pref_dst, rc_type samode, uint32_t reqid)
{
	int m;
	size_t ls, ld;

	/* A move that could not be traced could not be rolled back either:
	 * refuse it (and undo what already moved) before touching the
	 * kernel, instead of silently migrating untracked SAs. */
	ls = sp_src ? (size_t)SA_LEN(sp_src) : 0;
	ld = sp_dst ? (size_t)SA_LEN(sp_dst) : 0;
	if (*nt >= MAX_MOBIKE_MIGRATES || ls == 0 || ld == 0 ||
	    ls > sizeof(tr[0].sp_src) || ld > sizeof(tr[0].sp_dst)) {
		isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		    "MOBIKE migrate of reqid %u dir %s cannot be tracked "
		    "for rollback (%d entries); refusing the move\n",
		    reqid, rct2str(dir), *nt);
		mobike_migrate_rollback(ike_sa, tr, *nt);
		return -1;
	}
	m = ikev2_mobike_migrate_dir(ike_sa, dir, old_s, old_d, new_s, new_d,
	    sp_src, sp_dst, pref_src, pref_dst, samode, reqid);
	if (m < 0) {
		mobike_migrate_rollback(ike_sa, tr, *nt);
		return -1;
	}
	if (m > 0) {
		tr[*nt].dir = dir;
		tr[*nt].cur_s = new_s;
		tr[*nt].cur_d = new_d;
		tr[*nt].old_s = old_s;
		tr[*nt].old_d = old_d;
		memset(&tr[*nt].sp_src, 0, sizeof(tr[*nt].sp_src));
		memset(&tr[*nt].sp_dst, 0, sizeof(tr[*nt].sp_dst));
		memcpy(&tr[*nt].sp_src, sp_src, ls);
		memcpy(&tr[*nt].sp_dst, sp_dst, ld);
		tr[*nt].pref_src = pref_src;
		tr[*nt].pref_dst = pref_dst;
		tr[*nt].samode = samode;
		tr[*nt].reqid = reqid;
		(*nt)++;
	}
	return m;
}

/*
 * RFC 4555 s3.5: update every IPsec SA associated with this IKE SA.
 * One MIGRATE moves one kernel SA of one reqid.  Walk every Child
 * selector (and its address-family twin).  A reqid already drained
 * returns 0 from ikev2_mobike_migrate_dir, not an error.
 * Returns 0 when every associated SA was migrated, or there was
 * nothing to move.  -1 if a migrate failed, or a selector was seen
 * and nothing moved.
 */
static int
mobike_migrate_children(struct ikev2_sa *ike_sa,
    struct sockaddr *old_l, struct sockaddr *old_r,
    struct sockaddr *local, struct sockaddr *remote)
{
	struct ikev2_child_sa *c;
	struct mobike_mig_trace tr[MAX_MOBIKE_MIGRATES];
	int nt = 0;
	uint32_t seen[MAX_MOBIKE_MIGRATES];
	int nseen = 0, moved = 0, saw = 0;

	for (c = IKEV2_CHILD_LIST_FIRST(&ike_sa->children);
	     !IKEV2_CHILD_LIST_END(c);
	     c = IKEV2_CHILD_LIST_NEXT(c)) {
		struct rcf_selector *cs;
		struct sockaddr *lease_inner = NULL;
		uint8_t lease_pref = 0;
		struct sockaddr_storage lease_ss;

		if (!LIST_EMPTY(&c->lease_list)) {
			struct rcf_address *a;
			int plen = 0;

			a = LIST_FIRST(&c->lease_list);
			ikev2_cfg_addr2sockaddr(
			    (struct sockaddr *)&lease_ss, a, &plen);
			lease_inner = (struct sockaddr *)&lease_ss;
			lease_pref = (uint8_t)plen;
		}
		for (cs = c->selector; cs; cs = cs->next) {
			int i, m;
			struct sockaddr *lan, *inner;
			uint8_t lan_pref, inner_pref;
			rc_type samode;
			uint32_t reqid;

			if (!cs->pl || !cs->src || !cs->dst ||
			    cs->src->type != RCT_ADDR_INET ||
			    cs->dst->type != RCT_ADDR_INET ||
			    !cs->src->a.ipaddr || !cs->dst->a.ipaddr)
				continue;
			reqid = cs->reqid;
			for (i = 0; i < nseen; i++)
				if (seen[i] == reqid)
					break;
			if (i < nseen)
				continue;
			if (nseen >= (int)(sizeof(seen) / sizeof(seen[0]))) {
				/* cannot dedupe further: fail closed */
				isakmp_log(ike_sa, 0, 0, 0, PLOG_INTERR,
				    PLOGLOC, "MOBIKE: too many reqids to "
				    "migrate (%d); refusing the move\n", nseen);
				mobike_migrate_rollback(ike_sa, tr, nt);
				return -1;
			}
			seen[nseen++] = reqid;
			saw = 1;
			samode = ike_ipsec_mode(cs->pl);
			if (cs->direction == RCT_DIR_INBOUND) {
				lan = cs->dst->a.ipaddr;
				lan_pref = cs->dst->prefixlen;
				inner = lease_inner ? lease_inner :
				    cs->src->a.ipaddr;
				inner_pref = lease_inner ? lease_pref :
				    cs->src->prefixlen;
			} else {
				lan = cs->src->a.ipaddr;
				lan_pref = cs->src->prefixlen;
				inner = lease_inner ? lease_inner :
				    cs->dst->a.ipaddr;
				inner_pref = lease_inner ? lease_pref :
				    cs->dst->prefixlen;
			}
			m = mobike_migrate_dir_track(ike_sa, tr, &nt,
			    RCT_DIR_OUTBOUND, old_l, old_r, local, remote,
			    lan, inner, lan_pref, inner_pref, samode, reqid);
			if (m < 0)
				return -1;
			moved += m;
			m = mobike_migrate_dir_track(ike_sa, tr, &nt,
			    RCT_DIR_INBOUND, old_r, old_l, remote, local,
			    inner, lan, inner_pref, lan_pref, samode, reqid);
			if (m < 0)
				return -1;
			moved += m;
			if (samode == RCT_IPSM_TUNNEL) {
				m = mobike_migrate_dir_track(ike_sa, tr, &nt,
				    RCT_DIR_FWD, old_r, old_l, remote, local,
				    inner, lan, inner_pref, lan_pref,
				    samode, reqid);
				if (m < 0)
					return -1;
				moved += m;
			}
		}
	}
	if (saw && moved == 0)
		return -1;
	return 0;
}

int
ikev2_move_sa_impl(struct ikev2_sa *ike_sa, struct sockaddr *remote,
    struct sockaddr *local, int migrate_kernel, const char *why)
{
	struct ikev2_child_sa *c;
	struct sockaddr *old_r, *old_l;

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
	 * RFC 4555 s3.5: every associated IPsec SA, not the first
	 * selector's reqid.  All of those migrates must succeed
	 * before any in-memory endpoint is committed.
	 */
	if (migrate_kernel && old_l && old_r &&
	    mobike_migrate_children(ike_sa, old_l, old_r,
	    local, remote) != 0) {
		isakmp_log(ike_sa, local, remote, 0, PLOG_INTERR,
			   PLOGLOC,
			   "MOBIKE migrate incomplete; keeping %s\n",
			   rcs_sa2str(old_r));
		return -1;
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
/* scans run so far (mobiketest checks the debounce with it) */
unsigned long ikev2_mobike_scan_count;

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
	ikev2_mobike_scan_count++;
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
 * events have been quiet for 1-2 seconds (trailing edge), but stop
 * re-arming MOBIKE_SETTLE_MAX seconds after the first event of a burst, so
 * a link that never stops flapping still gets an update.  One update is
 * in flight per SA at a time; ikev2_mobike_local_reply/_abandon rescan,
 * so a change during that exchange is not lost.
 */
/*
 * The scheduler clock has 1-second resolution: sched_new(n) fires at the
 * n-th second boundary from now, i.e. after (n-1, n] seconds, so a quiet
 * time of at least one second needs n = 2 (mobiketest found 1 firing on
 * nearly every event of a 100 ms flap).
 */
#define MOBIKE_SETTLE		2
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
	 * Float to 4500 only when a NAT is already known (or forced).
	 * Doing it on a clear port-500 SA makes the in-memory endpoints
	 * disagree with the kernel SAs, so XFRM_MSG_MIGRATE returns
	 * ENOENT ("No data available") and a NAT-D hash over the floated
	 * port looks like a NAT that is not there (espinudp on a
	 * NAT-free path).  A real NAT is detected from the UPDATE reply
	 * and applied by ikev2_mobike_apply_nat.
	 */
	if (ikev2_tcp_encap(sa->rmconf) != RCT_BOOL_ON &&
	    np && rcs_getsaport(sa->remote) &&
	    ntohs(*np) != IKEV2_UDP_PORT_NATT &&
	    (sa->behind_nat || sa->peer_behind_nat ||
	     ikev2_nat_traversal(sa->rmconf) == RCT_NATT_FORCE)) {
		*np = htons(IKEV2_UDP_PORT_NATT);
		*rcs_getsaport(sa->remote) = htons(IKEV2_UDP_PORT_NATT);
	}
#endif
	/*
	 * interface ike pins the listening addresses (no MY_IP): there is no
	 * socket on the new address to send from or to answer on, so a
	 * pinned config does not move (it keeps its SAs, as it did before
	 * initiator MOBIKE existed) instead of retransmitting into nowhere.
	 */
	if (ikev2_tcp_encap(sa->rmconf) != RCT_BOOL_ON &&
	    isakmp_find_socket(nl) == -1) {
		isakmp_log(sa, sa->local, sa->remote, 0, PLOG_INFO, PLOGLOC,
		    "MOBIKE initiator: no IKE socket on %s (interface ike "
		    "does not listen there), not moving\n", rcs_sa2str(nl));
		rc_free(nl);
		return 0;
	}
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
	/*
	 * RFC 4555 s3.5: if a request is still outstanding, retransmit it
	 * from the new address now.  The peer answers that copy (the
	 * window cannot take the UPDATE until the reply arrives), and the
	 * address the first copy was sent to may already be gone.
	 */
	if (sa->transmit_info.packet || sa->transmit_info.nfrags > 0) {
		struct sockaddr *ns = rcs_sadup(sa->local);
		in_port_t *oldp = sa->transmit_info.src ?
		    rcs_getsaport(sa->transmit_info.src) : NULL;
		in_port_t *np = ns ? rcs_getsaport(ns) : NULL;

		/*
		 * Keep the port the outstanding request was sent on.
		 * Floating it to 4500 makes the peer replay a port-500
		 * response (no non-ESP marker) at a UDP_ENCAP socket,
		 * and the kernel consumes it as ESP.  The UPDATE that
		 * follows is a new exchange and may use 4500.
		 */
		if (ns && oldp && np)
			*np = *oldp;
		isakmp_log(sa, ns ? ns : sa->local, sa->remote, 0,
		    PLOG_INFO, PLOGLOC,
		    "MOBIKE initiator: retransmitting outstanding request "
		    "from %s\n", rcs_sa2str(ns ? ns : sa->local));
		if (ns)
			isakmp_retarget_src(&sa->transmit_info, ns);
		if (ns)
			rc_free(ns);
	}
	ikev2_payloads_init(payl);
	ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
	    ikev2_notify_payload(0, 0, 0, IKEV2_UPDATE_SA_ADDRESSES, 0, 0),
	    TRUE);
	/*
	 * RFC 4555 s3.5 / s5.2: COOKIE2 on the update, which the responder
	 * MUST echo; the move is committed only if the echo matches, so a
	 * reply that did not come back over the new path (or an off-path
	 * forgery) cannot move the SAs.
	 */
	{
		rc_vchar_t *c2 = eay_set_random(16);

		if (c2 != NULL) {
			if (sa->cookie2_sent)
				rc_vfree(sa->cookie2_sent);
			sa->cookie2_sent = c2;
			sa->cookie2_matched = 0;
			ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(0, 0, 0, IKEV2_COOKIE2,
			    (uint8_t *)c2->v, c2->l), TRUE);
		}
	}
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
	if (sa->cookie2_sent != NULL) {
		int ok = sa->cookie2_matched;

		rc_vfree(sa->cookie2_sent);
		sa->cookie2_sent = NULL;
		sa->cookie2_matched = 0;
		if (!ok) {
			/* RFC 4555 s5.2: no (or a wrong) COOKIE2 echo */
			isakmp_log(sa, nl, sa->remote, 0, PLOG_PROTOERR,
			    PLOGLOC, "MOBIKE initiator: the update reply did "
			    "not echo our COOKIE2, not moving\n");
			rc_free(nl);
			return;
		}
		isakmp_log(sa, nl, sa->remote, 0, PLOG_INFO, PLOGLOC,
		    "MOBIKE initiator: COOKIE2 echoed, return routability "
		    "confirmed\n");
	}
	/*
	 * RFC 4555 s3.5: if the address changed again while this
	 * update was outstanding, do no MOBIKE processing on the
	 * reply.  The rescan sends a new update from the address
	 * the kernel SAs still use.
	 */
	{
		struct sockaddr_storage cur;

		if (sa->remote &&
		    mobike_route_source(sa->remote, &cur) == 0 &&
		    rcs_cmpsa_wop((struct sockaddr *)&cur, nl) != 0) {
			isakmp_log(sa, nl, sa->remote, 0, PLOG_INFO,
			    PLOGLOC, "MOBIKE initiator: address changed "
			    "again while UPDATE_SA_ADDRESSES was "
			    "outstanding; ignoring this reply\n");
			rc_free(nl);
			ikev2_mobike_local_changed();
			return;
		}
	}
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
	if (sa->cookie2_sent != NULL) {
		rc_vfree(sa->cookie2_sent);
		sa->cookie2_sent = NULL;
	}
	ikev2_mobike_local_changed();	/* retry from the current address */
}

/*
 * RFC 4555 s3.4: the initiator that will move lists its other addresses
 * (same family as the IKE SA, up to IKEV2_MAX_EXTRA_ADDR, no loopback or
 * IPv6 link-local) as ADDITIONAL_IP4/IP6_ADDRESS in IKE_AUTH, so the
 * responder can probe them (COOKIE2, s3.6) when the current path dies.
 * strongSwan's charon advertises its addresses the same way.  None
 * found: N(NO_ADDITIONAL_ADDRESSES).
 */
void
ikev2_mobike_push_additional(struct ikev2_sa *sa, struct ikev2_payloads *payl)
{
	struct ifaddrs *ifa0, *ifa;
	int n = 0;

	if (sa == NULL || sa->local == NULL || payl == NULL)
		return;
	if (getifaddrs(&ifa0) == 0) {
		for (ifa = ifa0; ifa && n < IKEV2_MAX_EXTRA_ADDR;
		    ifa = ifa->ifa_next) {
			const struct sockaddr *a = ifa->ifa_addr;
			const uint8_t *p = NULL;
			int type = 0;
			size_t l = 0;

			if (a == NULL || a->sa_family != sa->local->sa_family ||
			    (ifa->ifa_flags & IFF_LOOPBACK) ||
			    !(ifa->ifa_flags & IFF_UP))
				continue;
			if (a->sa_family == AF_INET) {
				const struct in_addr *x =
				    &((const struct sockaddr_in *)a)->sin_addr;

				if (x->s_addr == ((struct sockaddr_in *)
				    sa->local)->sin_addr.s_addr)
					continue;
				p = (const uint8_t *)x;
				l = 4;
				type = IKEV2_ADDITIONAL_IP4_ADDRESS;
			}
#ifdef INET6
			else if (a->sa_family == AF_INET6) {
				const struct in6_addr *x =
				    &((const struct sockaddr_in6 *)a)->sin6_addr;

				if (IN6_IS_ADDR_LINKLOCAL(x) ||
				    IN6_ARE_ADDR_EQUAL(x, &((struct sockaddr_in6 *)
				    sa->local)->sin6_addr))
					continue;
				p = (const uint8_t *)x;
				l = 16;
				type = IKEV2_ADDITIONAL_IP6_ADDRESS;
			}
#endif
			if (p == NULL)
				continue;
			ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
			    ikev2_notify_payload(0, 0, 0, type, (uint8_t *)p, l), TRUE);
			n++;
		}
		freeifaddrs(ifa0);
	}
	if (n == 0)
		ikev2_payloads_push(payl, IKEV2_PAYLOAD_NOTIFY,
		    ikev2_notify_payload(0, 0, 0, IKEV2_NO_ADDITIONAL_ADDRESSES,
		    0, 0), TRUE);
	TRACE((PLOGLOC, "MOBIKE: %d additional address(es) advertised\n", n));
}
