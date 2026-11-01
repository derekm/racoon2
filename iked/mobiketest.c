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
 *    pending (no crash, no state change).
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
#include <time.h>

#include "racoon.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "ike_conf.h"

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

	if (fails) {
		printf("mobiketest: %d failure(s)\n", fails);
		return 1;
	}
	printf("mobiketest: all checks passed\n");
	return 0;
}
