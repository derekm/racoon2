/*
 * schedtest.c -- SCH-01 / SCH-03 / S7: iked timer deadlines follow
 * ELAPSED time, not the wall clock.
 *
 * time() and clock_gettime() are replaced at link time (--wrap) by an
 * injected clock with independent wall and monotonic readings, so a wall
 * step can be simulated deterministically:
 *   1. wall steps BACK one hour while 10 s elapse: a 10 s timer fires on
 *      time (the SCH-03 clamp alone stalled it for the hour);
 *   2. wall steps FORWARD one hour while 1 s elapses: a 10 s timer does
 *      NOT fire early, and sched_remaining() still reports 9 s;
 *   3. the returned select() timeout tracks the monotonic deadline;
 *   4. with no monotonic clock at sched_init the wall-clock base is used
 *      (fallback still schedules correctly).
 */
#include "config.h"
#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "racoon.h"
#include "schedule.h"

static time_t fake_wall = 1700000000;
static time_t fake_mono = 5000;
static int mono_broken;

time_t
__wrap_time(time_t *t)
{
	if (t)
		*t = fake_wall;
	return fake_wall;
}

int
__wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
	if (id != CLOCK_MONOTONIC) {
		ts->tv_sec = fake_wall;
		ts->tv_nsec = 0;
		return 0;
	}
	if (mono_broken) {
		errno = EINVAL;
		return -1;
	}
	ts->tv_sec = fake_mono;
	ts->tv_nsec = 0;
	return 0;
}

static int fails;
static int fired;

static void
ck(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails++;
}

static void
cb(void *p)
{
	(void)p;
	fired++;
}

static void
tick(time_t dwall, time_t dmono)
{
	fake_wall += dwall;
	fake_mono += dmono;
}

int
main(void)
{
	struct sched *sc;
	struct timeval *tv;

	plog_setmode(RCT_LOGMODE_DEBUG, NULL, "schedtest", 1, 1);

	/* 1: wall steps back 1 h while 10 s elapse */
	sched_init();
	fired = 0;
	sc = sched_new(10, cb, NULL);
	tick(-3600 + 10, 10);
	(void)scheduler();
	ck(fired == 1, "1: 10 s timer fires after 10 s elapsed although the "
	   "wall clock stepped back 1 h");
	(void)sc;

	/* 2: wall steps forward 1 h while 1 s elapses */
	sched_init();
	fired = 0;
	sc = sched_new(10, cb, NULL);
	tick(3600, 1);
	tv = scheduler();
	ck(fired == 0, "2: 10 s timer does not fire early on a +1 h wall step");
	ck(sched_remaining(sc) == 9, "2: sched_remaining() is 9 s");
	/* 3: select() timeout follows the monotonic deadline */
	ck(tv != NULL && tv->tv_sec == 9, "3: scheduler timeout is 9 s");
	tick(-7200, 9);
	(void)scheduler();
	ck(fired == 1, "3: fires once 10 s have elapsed in total");

	/* 4: no monotonic clock -> wall-clock base still works */
	mono_broken = 1;
	sched_init();
	fired = 0;
	sc = sched_new(5, cb, NULL);
	tick(4, 0);
	(void)scheduler();
	ck(fired == 0 && sched_remaining(sc) == 1,
	   "4: fallback: not due after 4 s of wall time");
	tick(1, 0);
	(void)scheduler();
	ck(fired == 1, "4: fallback: fires after 5 s of wall time");

	printf("schedtest: %s\n", fails ? "FAILED" : "OK");
	return fails ? 1 : 0;
}
