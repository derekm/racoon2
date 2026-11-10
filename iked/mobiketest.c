/*
 * mobiketest.c -- the RFC 4555 initiator's address-event handler
 * (ikev2_mobike_local_changed / mobike_local_scan in ikev2_mobike.c), run
 * under the unit suite (and its ASan/UBSan builds):
 *
 *  - a burst of events arms ONE timer, not one per event (debounce);
 *  - the scan runs once the events are quiet (1-2 s) and the timer is gone;
 *  - a link that never stops flapping is still scanned: the burst is
 *    capped (re-arming stops 3 s after its first event), so continuous
 *    events every 100 ms for 8 s produce one or two scans (each capped
 *    burst lasts at least 4 s and at most ~5 s), not one per second;
 *  - the reply / abandon hooks tolerate NULL and an SA with no update
 *    pending (no crash, no state change);
 *  - a reply without our COOKIE2 echo (RFC 4555 s5.2) moves nothing.
 *
 * Linked with the full iked object set like notifytest.
 */
#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>

#include "racoon.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "ike_pfkey.h"
#include <errno.h>

#include "test_util.h"

TEST_MAIN_STUBS()

extern unsigned long ikev2_mobike_scan_count;
void ikev2_mobike_local_changed(void);
void ikev2_mobike_local_reply(struct ikev2_sa *, int, int, int, int);
void ikev2_mobike_local_abandon(struct ikev2_sa *);

static int fails;

static void
ck(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails++;
}

/* live (not killed) scheduler entries; scheduler() reaps the dead ones */
static int
sched_live(void)
{
	caddr_t buf;
	int len;

	(void)scheduler();
	if (sched_dump(&buf, &len) != 0)
		return 0;
	racoon_free(buf);
	return len / (int)sizeof(struct scheddump);
}

static void
msleep(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

/* ================================================================= *
 * Transactional MOBIKE kernel migration (G07): a multi-child hard
 * failure must walk back every direction already migrated in the
 * kernel, so the kernel SAD and the in-memory endpoint never disagree
 * ("lying endpoint pair").  We drive ikev2_move_sa_impl through the
 * real mobike_migrate_children and override the migrate callback
 * (sadb_migrate, weak in ike_pfkey.c) with a mock kernel.
 * ================================================================= */

extern int ikev2_move_sa_impl(struct ikev2_sa *, struct sockaddr *,
    struct sockaddr *, int, const char *);

/* mock kernel SAD.  NSLOT leaves headroom for the reqids/dirs used
 * here; slot = 1 when that (reqid, dir) SA sits on the NEW endpoint. */
#define	M_NSLOT(reqid, dir)	((reqid) * 8 + (dir))
static int m_slots[64];
static int m_new_installs;	/* net SAs currently on the NEW endpoint */
static int m_migrate_calls;	/* total migrate attempts (diagnostic) */
static int m_fail_req2_out;	/* script: hard-fail child 2's OUT */
static struct sockaddr *m_new_l, *m_new_r;

int
sadb_migrate(struct rcpfk_msg *rc)
{
	int target_new, idx;

	m_migrate_calls++;
	target_new = (rcs_cmpsa(rc->sa2_src, m_new_l) == 0) ||
	    (rcs_cmpsa(rc->sa2_src, m_new_r) == 0);
	idx = M_NSLOT(rc->reqid, rc->dir);

	/* scripted hard failure: the second child's first (OUT) direction
	 * fails with a real errno, so grab it: nothing moves. */
	if (m_fail_req2_out && rc->reqid == 2 &&
	    rc->dir == RCT_DIR_OUTBOUND) {
		m_fail_req2_out = 0;
		rc->eno = ECONNREFUSED;
		snprintf(rc->estr, sizeof(rc->estr),
		    "scripted hard MOBIKE failure");
		return -1;
	}
	/* the SA already sits where requested: the migration loop's
	 * "none left" stop (migrate_dir returns `moved` on ENOENT). */
	if ((target_new && m_slots[idx]) || (!target_new && !m_slots[idx])) {
		rc->eno = ENOENT;
		return -1;
	}
	/* perform the move (target_new: onto the new endpoint; else back
	 * onto the old one -- the rollback path exercises this reversal). */
	m_slots[idx] = target_new ? 1 : 0;
	m_new_installs += target_new ? 1 : -1;
	return 0;
}

static void
m_free_selector(struct rcf_selector *s)
{
	if (s == NULL)
		return;
	if (s->src) {
		rc_free(s->src->a.ipaddr);
		free(s->src);
	}
	if (s->dst) {
		rc_free(s->dst->a.ipaddr);
		free(s->dst);
	}
	free(s->pl);
	free(s);
}

static struct rcf_selector *
m_mk_selector(int reqid, const char *sip, const char *dip)
{
	struct rcf_selector *s = calloc(1, sizeof(*s));
	struct rcf_policy *pl = calloc(1, sizeof(*pl));
	struct sockaddr_storage ss;

	s->direction = RCT_DIR_OUTBOUND;
	s->reqid = reqid;
	s->src = calloc(1, sizeof(*s->src));
	s->dst = calloc(1, sizeof(*s->dst));

	test_make_addr4(&ss, sip, 0);
	s->src->type = RCT_ADDR_INET;
	s->src->prefixlen = 24;
	s->src->a.ipaddr = rcs_sadup((struct sockaddr *)&ss);

	test_make_addr4(&ss, dip, 0);
	s->dst->type = RCT_ADDR_INET;
	s->dst->prefixlen = 32;
	s->dst->a.ipaddr = rcs_sadup((struct sockaddr *)&ss);

	pl->ipsec_mode = RCT_IPSM_TRANSPORT;	/* OUT + IN, no FWD */
	s->pl = pl;
	return s;
}

static void
test_migrate_rollback(void)
{
	struct ikev2_sa sa;
	struct ikev2_child_sa *c1, *c2;
	struct sockaddr_storage oldl, oldr, newl, newr;
	struct sockaddr *_oldl, *_oldr, *_newl, *_newr;
	int ret;

	/* old and new endpoints, all on the clear path (500/500) */
	test_make_addr4(&oldl, "192.0.2.2", 500);
	test_make_addr4(&oldr, "192.0.2.1", 500);
	test_make_addr4(&newl, "198.51.100.2", 500);
	test_make_addr4(&newr, "198.51.100.1", 500);
	_oldl = rcs_sadup((struct sockaddr *)&oldl);
	_oldr = rcs_sadup((struct sockaddr *)&oldr);
	_newl = rcs_sadup((struct sockaddr *)&newl);
	_newr = rcs_sadup((struct sockaddr *)&newr);
	m_new_l = _newl;
	m_new_r = _newr;
	m_new_installs = 0;
	m_migrate_calls = 0;
	m_fail_req2_out = 1;
	memset(m_slots, 0, sizeof(m_slots));

	memset(&sa, 0, sizeof(sa));
	IKEV2_CHILD_LIST_INIT(&sa.children);
	sa.local = rcs_sadup((struct sockaddr *)&oldl);
	sa.remote = rcs_sadup((struct sockaddr *)&oldr);
	sa.mobike_supported = 1;

	/* two children, two distinct reqids */
	c1 = calloc(1, sizeof(*c1));
	c1->selector = m_mk_selector(1, "10.1.1.1", "10.1.1.2");
	IKEV2_CHILD_LIST_LINK(&sa.children, c1);
	c2 = calloc(1, sizeof(*c2));
	c2->selector = m_mk_selector(2, "10.2.2.1", "10.2.2.2");
	IKEV2_CHILD_LIST_LINK(&sa.children, c2);

	/* The SA sits on the OLD endpoints; migrate to NEW.  Child 1's
	 * OUT + IN succeed in the kernel, child 2's OUT hard-fails. */
	ret = ikev2_move_sa_impl(&sa, _newr, _newl, 1,
	    "unit: transactional migrate");

	ck(ret == -1, "move_sa_impl returns -1 on a multi-child hard failure");
	ck(rcs_cmpsa(sa.remote, _oldr) == 0 && rcs_cmpsa(sa.local, _oldl) == 0,
	    "in-memory endpoints stay OLD after the failure (no partial commit)");
	ck(c1->remote == NULL && c1->local == NULL &&
	    c2->remote == NULL && c2->local == NULL,
	    "no child endpoint was committed");
	printf("migrate attempts=%d net new-endpoint installs=%d\n",
	    m_migrate_calls, m_new_installs);
	ck(m_new_installs == 0,
	    "kernel SAD is rolled back: net zero SAS left on the new endpoint");
	ck(m_slots[M_NSLOT(1, RCT_DIR_OUTBOUND)] == 0 &&
	    m_slots[M_NSLOT(1, RCT_DIR_INBOUND)] == 0,
	    "child-1 OUT and IN were reversed back to the old endpoint");

	/* cleanup */
	m_free_selector(c1->selector);
	m_free_selector(c2->selector);
	free(c1);
	free(c2);
	rc_free(sa.remote);
	rc_free(sa.local);
	rc_free(_oldl);
	rc_free(_oldr);
	rc_free(_newl);
	rc_free(_newr);
}

int
main(int argc, char *argv[])
{
	unsigned long s0;
	struct ikev2_sa sa;
	int i;

	(void)argc;
	test_init(argv[0]);
	sched_init();

	/* debounce: 100 events -> one timer */
	s0 = ikev2_mobike_scan_count;
	for (i = 0; i < 100; i++)
		ikev2_mobike_local_changed();
	ck(sched_live() == 1, "a burst of 100 events arms exactly one timer");
	ck(ikev2_mobike_scan_count == s0, "no scan while the burst is fresh");

	/* quiet for > 1 s: the scan runs once, the timer is gone */
	for (i = 0; i < 30 && ikev2_mobike_scan_count == s0; i++) {
		msleep(100);
		(void)scheduler();
	}
	ck(ikev2_mobike_scan_count == s0 + 1, "one scan after the burst settles");
	ck(sched_live() == 0, "no timer left after the scan");

	/* never-quiet link: events every 100 ms for 5 s still get scanned,
	 * but at most once per capped burst (~4-5 s) */
	s0 = ikev2_mobike_scan_count;
	for (i = 0; i < 80; i++) {
		ikev2_mobike_local_changed();
		msleep(100);
		(void)scheduler();
	}
	printf("continuous flapping: %lu scan(s) in 8 s\n",
	    ikev2_mobike_scan_count - s0);
	ck(ikev2_mobike_scan_count - s0 >= 1,
	    "a link that never settles is still scanned (burst cap)");
	ck(ikev2_mobike_scan_count - s0 <= 2,
	    "continuous events do not become a scan storm");
	for (i = 0; i < 40 && sched_live() > 0; i++)
		msleep(100);
	ck(sched_live() == 0, "the timer drains after the flapping stops");

	/* completion hooks: NULL and a non-pending SA are no-ops */
	ikev2_mobike_local_reply(NULL, 1, 1, 1, 1);
	ikev2_mobike_local_abandon(NULL);
	memset(&sa, 0, sizeof(sa));
	ikev2_mobike_local_reply(&sa, 1, 1, 1, 1);
	ikev2_mobike_local_abandon(&sa);
	ck(sa.local == NULL && sa.mobike_li_pending == 0,
	    "reply/abandon without a pending update change nothing");
	ck(sched_live() == 0, "and arm no rescan");

	/*
	 * RFC 4555 s5.2: an update reply without our COOKIE2 echo must not
	 * move anything: local goes back to the address the kernel SAs use,
	 * the pending state and the cookie are cleared.
	 */
	{
		struct sockaddr_in o4, n4;
		struct sockaddr *oldl;

		memset(&o4, 0, sizeof(o4));
		o4.sin_family = AF_INET;
		o4.sin_port = htons(500);
		inet_pton(AF_INET, "192.0.2.2", &o4.sin_addr);
		n4 = o4;
		inet_pton(AF_INET, "192.0.2.4", &n4.sin_addr);
		memset(&sa, 0, sizeof(sa));
		oldl = rcs_sadup((struct sockaddr *)&o4);
		sa.mobike_li_prev = oldl;
		sa.local = rcs_sadup((struct sockaddr *)&n4);
		sa.remote = rcs_sadup((struct sockaddr *)&o4);
		sa.mobike_li_pending = 1;
		sa.cookie2_sent = rc_vnew((const void *)"0123456789abcdef", 16);
		sa.cookie2_matched = 0;
		ikev2_mobike_local_reply(&sa, 1, 1, 1, 1);
		ck(sa.local == oldl && sa.mobike_li_prev == NULL &&
		    sa.mobike_li_pending == 0,
		    "no COOKIE2 echo: the move is refused, local restored");
		ck(sa.cookie2_sent == NULL && sa.cookie2_matched == 0,
		    "and the COOKIE2 state is cleared");
		ck(sched_live() == 0, "and no rescan is armed for a refusal");
		rc_free(sa.local);
		rc_free(sa.remote);
	}

	/* G07 transactional kernel migration on a multi-child hard failure */
	test_migrate_rollback();

	if (fails) {
		printf("mobiketest: %d failure(s)\n", fails);
		return 1;
	}
	printf("mobiketest: all checks passed\n");
	return 0;
}
