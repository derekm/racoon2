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
		rc_vfree(out);
	}
	rc_vfree(pkt);
	isakmp_frag_purge(&ph1);
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
	TEST_CHECK(ph1.frag_halfopen == 0);	/* still live */
	TEST_CHECK(isakmp_frag_half_open_count() == base + 1);
}

int
main(int argc, char **argv)
{
	(void)argc;
	test_init(argv[0]);
	RUN_TEST(test_size_gate);
	RUN_TEST(test_cap_restore);
	RUN_TEST(test_live_survives);
	return test_exit_status();
}
