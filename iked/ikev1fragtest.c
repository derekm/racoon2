/*
 * ikev1fragtest.c -- IKEv1 fragment state-machine regressions.
 *
 * Drives the real isakmp_frag_recv() (the size gate) and the half-open
 * counter machinery (cap restore, live-SA survival) through the full iked
 * object set (addtest_ikedsrc); isakmp_frag_recv and the counter accessors
 * are exposed for exactly this.
 *
 * Rows:
 *  - size gate: a single large fragment (data_len ~60000, last) reassembles
 *    under the fixed `held > ISAKMP_MAX_REASM` gate.  red if `held + data_len`
 *    comes back (that double-count rejects it -> NULL).
 *  - cap restore: disarming 5 half-open temps returns the half-open counter
 *    to its baseline.  red if the disarm decrement is removed.
 *  - live SA survives: disarming a frag_halfopen == 0 (live) handle is a
 *    no-op -- it stays live and must not steal a cap slot.  red if the
 *    `!iph1->frag_halfopen` guard is removed.
 *  - handler dispatch: a first fragment for an unknown SA is rejected by
 *    the unconfigured-peer guard (newph1 -> getrmconf -> delph1), reaching
 *    ikev1_frag_dispatch() -- the lifecycle isakmp_frag_recv() alone cannot.
 *    red if the `rmconf == NULL` reject is removed.
 */
#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "racoon.h"
#include "oakley.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_impl.h"
#include "ikev1/handler.h"

#include <getopt.h>
#include "test_util.h"
TEST_MAIN_STUBS()

/* A single complete (last) fragment of `data_len` payload bytes. */
static void
test_size_gate(void)
{
	struct ph1handle ph1;
	rc_vchar_t *pkt = NULL, *out;
	struct isakmp *ih;
	struct isakmp_frag_hdr *frag;
	size_t data_len = 60000;

	memset(&ph1, 0, sizeof(ph1));
	pkt = rc_vmalloc(sizeof(struct isakmp) +
	    sizeof(struct isakmp_frag_hdr) + data_len);
	if (pkt == NULL) {
		TEST_CHECK(0);
		return;
	}
	memset(pkt->v, 0x21, pkt->l);
	ih = (struct isakmp *)pkt->v;
	ih->len = htonl((uint32_t)pkt->l);	/* len field is byte-swapped here */
	ih->msgid = htonl(0x11223344u);
	frag = (struct isakmp_frag_hdr *)(pkt->v + sizeof(struct isakmp));
	frag->frag_id = 0xbe;
	frag->h.len = htons(sizeof(struct isakmp_frag_hdr) + data_len);
	frag->frag_no = htons(1);
	frag->flags = 0;	/* MORE clear: this is the last fragment */

	/* 60000 payload bytes reassemble under `held > MAX_REASM`.  The old
	 * `held + data_len` double-counted (this frag is the whole held), so
	 * a single 60000-byte fragment was rejected; the fix accepts it. */
	out = isakmp_frag_recv(&ph1, pkt);
	TEST_CHECK(out != NULL);
	if (out != NULL) {
		TEST_CHECK(out->l == sizeof(struct isakmp) + data_len);
		/* the reassembled payload must be the received bytes */
		TEST_CHECK(((unsigned char *)out->v)[sizeof(struct isakmp)]
		    == 0x21);
		rc_vfree(out);
	}
	rc_vfree(pkt);
	isakmp_frag_purge(&ph1);
}

/* The reassembly cap itself: two fragments totalling more than
 * ISAKMP_MAX_REASM must be rejected (NULL) and the context freed.  Without
 * the `held > ISAKMP_MAX_REASM` check the second fragment has all parts and
 * reassembles (non-NULL) -> red.  This is distinct from the size-gate *brace*
 * row above (which guards the fit under the cap, not the cap itself). */
static void
test_reject_cap(void)
{
	struct ph1handle ph1;
	rc_vchar_t *f1 = NULL, *f2 = NULL, *out;
	struct isakmp *ih;
	struct isakmp_frag_hdr *frag;
	size_t d1 = 40000, d2 = 40000;
	uint32_t msgid = htonl(0x90abcdefu);

	memset(&ph1, 0, sizeof(ph1));

	f1 = rc_vmalloc(sizeof(struct isakmp) +
	    sizeof(struct isakmp_frag_hdr) + d1);
	if (f1 == NULL) {
		TEST_CHECK(0);
		return;
	}
	memset(f1->v, 0x11, f1->l);
	ih = (struct isakmp *)f1->v;
	ih->len = htonl((uint32_t)f1->l);
	ih->msgid = msgid;
	frag = (struct isakmp_frag_hdr *)(f1->v + sizeof(struct isakmp));
	frag->frag_id = 0xcd;
	frag->h.len = htons(sizeof(struct isakmp_frag_hdr) + d1);
	frag->frag_no = htons(1);
	frag->flags = ISAKMP_FRAG_MORE;	/* not the last */
	out = isakmp_frag_recv(&ph1, f1);
	TEST_CHECK(out == NULL);		/* incomplete: still assembling */
	if (out)
		rc_vfree(out);

	f2 = rc_vmalloc(sizeof(struct isakmp) +
	    sizeof(struct isakmp_frag_hdr) + d2);
	if (f2 == NULL) {
		TEST_CHECK(0);
		rc_vfree(f1);
		return;
	}
	memset(f2->v, 0x22, f2->l);
	ih = (struct isakmp *)f2->v;
	ih->len = htonl((uint32_t)f2->l);
	ih->msgid = msgid;
	frag = (struct isakmp_frag_hdr *)(f2->v + sizeof(struct isakmp));
	frag->frag_id = 0xcd;
	frag->h.len = htons(sizeof(struct isakmp_frag_hdr) + d2);
	frag->frag_no = htons(2);
	frag->flags = 0;			/* last */
	out = isakmp_frag_recv(&ph1, f2);
	/* held is now 80000 > 65535: rejected, context freed.  Dropping the
	 * cap check would reassemble this into a non-NULL buffer -> red. */
	TEST_CHECK(out == NULL);
	TEST_CHECK(ph1.frag_chain == NULL);	/* reject frees the context */
	if (out)
		rc_vfree(out);
	rc_vfree(f1);
	rc_vfree(f2);
}

/* Disarming half-open temps must return the 20-slot cap, not leak it. */
static void
test_cap_restore(void)
{
	struct ph1handle phs[5];
	int i, base, mid;

	memset(phs, 0, sizeof(phs));
	base = isakmp_frag_half_open_count();
	for (i = 0; i < 5; i++)
		isakmp_frag_half_open_take();
	mid = isakmp_frag_half_open_count();
	TEST_CHECK(mid == base + 5);
	for (i = 0; i < 5; i++) {
		phs[i].frag_halfopen = 1;
		isakmp_frag_halfopen_disarm(&phs[i]);
	}
	TEST_CHECK(isakmp_frag_half_open_count() == base);
}

/* A live Phase 1 (frag_halfopen == 0) must not be disarmed: it is not a
 * half-open slot, so disarm is a no-op and must not decrement the cap. */
static void
test_live_survives(void)
{
	struct ph1handle ph1;
	int base;

	base = isakmp_frag_half_open_count();
	isakmp_frag_half_open_take();	/* a real half-open exists elsewhere */
	memset(&ph1, 0, sizeof(ph1));
	ph1.frag_halfopen = 0;	/* live, in-progress exchange */
	isakmp_frag_halfopen_disarm(&ph1);
	/* disarming a live handle must not steal a cap slot (the guard
	 * `!iph1->frag_halfopen` makes this a no-op); removing it decrements
	 * the counter -> red below. */
	TEST_CHECK(isakmp_frag_half_open_count() == base + 1);
}

/* Reach the handler-side lifecycle: a first fragment for an unknown SA and
 * a free half-open slot goes through newph1()/getrmconf() and is rejected
 * because no peer is configured (delph1 tears the temp down; the counter is
 * untouched).  Removing the unconfigured-peer reject builds the temp and
 * returns 0 (consumed) instead of -1 -> red. */
static void
test_frag_dispatch_unconfigured(void)
{
	/* The red arm reaches sched_new(); the scheduler tree must exist
	 * (sched_init is what the daemon does at startup). */
	sched_init();
	rc_vchar_t *pkt = NULL;
	struct isakmp *ih;
	struct isakmp_frag_hdr *frag;
	struct sockaddr_storage remote, local;
	struct isakmp isakmp;
	int rc, base = isakmp_frag_half_open_count();

	memset(&remote, 0, sizeof(remote));
	memset(&local, 0, sizeof(local));
	((struct sockaddr_in *)&remote)->sin_family = AF_INET;
	((struct sockaddr_in *)&remote)->sin_port = htons(1500);
	((struct sockaddr_in *)&remote)->sin_addr.s_addr = htonl(0x7f000001u);
	((struct sockaddr_in *)&local)->sin_family = AF_INET;
	((struct sockaddr_in *)&local)->sin_port = htons(1500);

	pkt = rc_vmalloc(sizeof(struct isakmp) +
	    sizeof(struct isakmp_frag_hdr) + 128);
	TEST_CHECK(pkt != NULL);
	if (pkt == NULL)
		return;
	memset(pkt->v, 0x21, pkt->l);
	ih = (struct isakmp *)pkt->v;
	ih->np = ISAKMP_NPTYPE_FRAG;
	ih->len = htonl((uint32_t)pkt->l);
	ih->msgid = htonl(0x55667788u);
	frag = (struct isakmp_frag_hdr *)(pkt->v + sizeof(struct isakmp));
	frag->frag_no = htons(1);
	frag->frag_id = 0xab;
	frag->h.len = htons(sizeof(struct isakmp_frag_hdr) + 128);
	frag->flags = ISAKMP_FRAG_MORE;	/* not the last; incomplete */

	memcpy(&isakmp, pkt->v, sizeof(isakmp));
	rc = ikev1_frag_dispatch(&isakmp, &pkt,
	    (struct sockaddr *)&remote, (struct sockaddr *)&local,
	    sizeof(remote), sizeof(local));
	TEST_CHECK(rc < 0);
		/* unconfigured peer -> reject */
	TEST_CHECK(isakmp_frag_half_open_count() == base);
		/* no cap slot taken by the rejected temp */

	rc_vfree(pkt);
}

/* A helper that restores the half-open counter by `n` after a test sized it
 * up, so later rows observe their own pristine baseline. */
static void
restore_half_open(int base)
{
	struct ph1handle phs[IKED_MAX_HALF_OPEN_SA];
	int i, n = isakmp_frag_half_open_count() - base;

	if (n <= 0 || n > IKED_MAX_HALF_OPEN_SA)
		return;
	memset(phs, 0, sizeof(phs));
	for (i = 0; i < n; i++) {
		phs[i].frag_halfopen = 1;
		isakmp_frag_halfopen_disarm(&phs[i]);
	}
}

/*
 * Handler-side cap-admission reject: when the half-open table is already full
 * (counter == IKED_MAX_HALF_OPEN_SA), a NEW first-fragment for an unknown SA
 * must be rejected by ikev1_frag_dispatch() returning -1 at the cap check --
 * NOT a new slot claimed, NOT success, NOT a crash.  A configured default
 * peer is installed first (rcf_default_head->remote), so getrmconf() would
 * succeed: the -1 is provably the cap admit gate (isakmp.c: "IKE fragment
 * half-open cap"), not the unconfigured-peer reject.  Red if the cap check
 * is dropped (the same fragment would then consume a slot and return 0).
 */
static void
test_frag_dispatch_cap_admission(void)
{
	struct rcf_default dflt;
	struct rcf_remote rm;
	struct rcf_default *saved_default = rcf_default_head;
	rc_vchar_t *pkt = NULL;
	struct isakmp *ih;
	struct isakmp_frag_hdr *frag;
	struct sockaddr_storage remote, local;
	struct isakmp isakmp;
	int rc, base, i;

	/* configured default peer -> getrmconf() succeeds (deepcopy). */
	memset(&dflt, 0, sizeof(dflt));
	memset(&rm, 0, sizeof(rm));
	dflt.remote = &rm;
	rcf_default_head = &dflt;

	sched_init();
	base = isakmp_frag_half_open_count();
	for (i = 0; i < IKED_MAX_HALF_OPEN_SA; i++)
		isakmp_frag_half_open_take();	/* table full: 20 live temps */
	TEST_CHECK(isakmp_frag_half_open_count() == base + IKED_MAX_HALF_OPEN_SA);

	memset(&remote, 0, sizeof(remote));
	memset(&local, 0, sizeof(local));
	((struct sockaddr_in *)&remote)->sin_family = AF_INET;
	((struct sockaddr_in *)&remote)->sin_port = htons(1501);
	((struct sockaddr_in *)&remote)->sin_addr.s_addr = htonl(0x7f000002u);
	((struct sockaddr_in *)&local)->sin_family = AF_INET;
	((struct sockaddr_in *)&local)->sin_port = htons(1501);

	pkt = rc_vmalloc(sizeof(struct isakmp) +
	    sizeof(struct isakmp_frag_hdr) + 128);
	TEST_CHECK(pkt != NULL);
	if (pkt == NULL) {
		rcf_default_head = saved_default;
		restore_half_open(base);
		return;
	}
	memset(pkt->v, 0x31, pkt->l);
	ih = (struct isakmp *)pkt->v;
	ih->np = ISAKMP_NPTYPE_FRAG;
	ih->len = htonl((uint32_t)pkt->l);
	ih->msgid = htonl(0x10203040u);
	frag = (struct isakmp_frag_hdr *)(pkt->v + sizeof(struct isakmp));
	frag->frag_no = htons(1);
	frag->frag_id = 0xcd;
	frag->h.len = htons(sizeof(struct isakmp_frag_hdr) + 128);
	frag->flags = ISAKMP_FRAG_MORE;

	memcpy(&isakmp, pkt->v, sizeof(isakmp));
	rc = ikev1_frag_dispatch(&isakmp, &pkt,
	    (struct sockaddr *)&remote, (struct sockaddr *)&local,
	    sizeof(remote), sizeof(local));
	TEST_CHECK(rc < 0);		/* cap-admission reject (peer IS configured) */
	TEST_CHECK(isakmp_frag_half_open_count() == base + IKED_MAX_HALF_OPEN_SA);
		/* no extra slot claimed by the rejected fresh fragment */

	rc_vfree(pkt);
	rcf_default_head = saved_default;
	restore_half_open(base);
}

/*
 * Handler-side live-SA survival: an ESTABLISHED phase-1 in the tree
 * (frag_halfopen == 0) reached via getph1byindex() must survive fragment
 * dispatch -- a fragment carrying that SA's cookies is fed to the live
 * handle's reassembly, and the live SA is NOT freed (the teardown only
 * applies to half-open temps, `if (frag_iph1->frag_halfopen)`).  Red if the
 * dispatch drops the getph1byindex() carve-out and treats the fragment as a
 * fresh half-open (would claim a slot / free the live SA).
 */
static void
test_frag_dispatch_live_sa_survives(void)
{
	struct ph1handle *live = NULL;
	struct sockaddr_in *r4, *l4;
	rc_vchar_t *pkt = NULL;
	struct isakmp *ih;
	struct isakmp_frag_hdr *frag;
	struct sockaddr_storage remote, local;
	struct isakmp isakmp;
	int rc, base;

	sched_init();
	initph1tree();
	base = isakmp_frag_half_open_count();

	live = newph1();
	TEST_CHECK(live != NULL);
	if (live == NULL)
		return;
	memset(live->index.i_ck, 0x5a, sizeof(live->index.i_ck));
	memset(live->index.r_ck, 0x3c, sizeof(live->index.r_ck));
	live->status = PHASE1ST_ESTABLISHED;	/* live, in-progress */
	live->frag_halfopen = 0;		/* NOT a half-open temp */
	r4 = racoon_calloc(1, sizeof(*r4));
	l4 = racoon_calloc(1, sizeof(*l4));
	TEST_CHECK(r4 != NULL && l4 != NULL);
	if (r4 == NULL || l4 == NULL) {
		racoon_free(r4);
		racoon_free(l4);
		delph1(live);
		return;
	}
	r4->sin_family = AF_INET;
	r4->sin_port = htons(1502);
	r4->sin_addr.s_addr = htonl(0x7f000003u);
	l4->sin_family = AF_INET;
	l4->sin_port = htons(1502);
	l4->sin_addr.s_addr = htonl(0x7f000003u);
	live->remote = (struct sockaddr *)r4;
	live->local = (struct sockaddr *)l4;
	TEST_CHECK(insph1(live) == 0);
	TEST_CHECK(getph1byindex(&live->index) == live);	/* in tree */

	memset(&remote, 0, sizeof(remote));
	memset(&local, 0, sizeof(local));
	((struct sockaddr_in *)&remote)->sin_family = AF_INET;
	((struct sockaddr_in *)&remote)->sin_port = htons(1502);
	((struct sockaddr_in *)&remote)->sin_addr.s_addr = htonl(0x7f000003u);
	((struct sockaddr_in *)&local)->sin_family = AF_INET;
	((struct sockaddr_in *)&local)->sin_port = htons(1502);

	pkt = rc_vmalloc(sizeof(struct isakmp) +
	    sizeof(struct isakmp_frag_hdr) + 128);
	TEST_CHECK(pkt != NULL);
	if (pkt == NULL) {
		remph1(live);
		delph1(live);
		return;
	}
	memset(pkt->v, 0x41, pkt->l);
	ih = (struct isakmp *)pkt->v;
	memcpy(ih->i_ck, live->index.i_ck, sizeof(ih->i_ck));
	memcpy(ih->r_ck, live->index.r_ck, sizeof(ih->r_ck));
	ih->np = ISAKMP_NPTYPE_FRAG;
	ih->len = htonl((uint32_t)pkt->l);
	ih->msgid = htonl(0x50607080u);
	frag = (struct isakmp_frag_hdr *)(pkt->v + sizeof(struct isakmp));
	frag->frag_no = htons(1);
	frag->frag_id = 0xef;
	frag->h.len = htons(sizeof(struct isakmp_frag_hdr) + 128);
	frag->flags = 0;	/* not MORE: a single complete (last) fragment */

	memcpy(&isakmp, pkt->v, sizeof(isakmp));
	rc = ikev1_frag_dispatch(&isakmp, &pkt,
	    (struct sockaddr *)&remote, (struct sockaddr *)&local,
	    sizeof(remote), sizeof(local));
	TEST_CHECK(rc == 1);		/* reassembled, exchange continues */
	TEST_CHECK(getph1byindex(&live->index) == live);
		/* live SA NOT freed/removed by dispatch */
	if (getph1byindex(&live->index) != live) {
		/* live SA was torn down (the regression under test): the
		 * handle is already delph1()'d -- do not dereference it. */
		rc_vfree(pkt);
		return;
	}
	TEST_CHECK(live->frag_halfopen == 0);
		/* live SA still not a half-open slot */
	TEST_CHECK(isakmp_frag_half_open_count() == base);
		/* no cap slot taken for the live-SA fragment */

	rc_vfree(pkt);
	remph1(live);
	delph1(live);
}

int
main(int argc, char **argv)
{
	(void)argc;
	test_init(argv[0]);
	RUN_TEST(test_size_gate);
	RUN_TEST(test_reject_cap);
	RUN_TEST(test_cap_restore);
	RUN_TEST(test_live_survives);
	RUN_TEST(test_frag_dispatch_unconfigured);
	RUN_TEST(test_frag_dispatch_cap_admission);
	RUN_TEST(test_frag_dispatch_live_sa_survives);
	return test_exit_status();
}
