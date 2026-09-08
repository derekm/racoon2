/* $Id$ */
/*
 * Same shape as eaytest: check_PROGRAM, printf + exit status.
 * Inline submit always; 1-thread pool when HAVE_PTHREAD.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <err.h>

#include "racoon.h"
#include "debug.h"
#include "plog.h"
#include "crypto_workers.h"

static int ran;
static int donef;

static void
work(void *arg)
{
	int *p = arg;

	/* workers run in parallel — plain ++ loses updates */
	(void)__sync_fetch_and_add(p, 1);
	(void)__sync_fetch_and_add(&ran, 1);
}

static void
done_cb(void *arg)
{
	(void)arg;
	(void)__sync_fetch_and_add(&donef, 1);
}

static void
barrier(void)
{
#if defined(__GNUC__) || defined(__clang__)
	__sync_synchronize();
#else
	/* no-op on compilers without sync builtins */
#endif
}

static int
wait_drain(int timeout_ms)
{
	int fd = crypto_workers_fd();
	fd_set rfds;
	struct timeval tv;
	int n;

	if (fd < 0)
		return -1;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	n = select(fd + 1, &rfds, NULL, NULL, &tv);
	if (n > 0 && FD_ISSET(fd, &rfds))
		crypto_workers_drain();
	return n;
}

int
main(void)
{
	int arg = 40;

	if (rbuf_init(8, 80, 8, 1000, 5))
		errx(EXIT_FAILURE, "rbuf init failed");
	plog_setmode(RCT_LOGMODE_NORMAL, NULL, "workerstest", TRUE, TRUE);

	printf("**Test for crypto workers (inline).**\n");
	if (crypto_workers_init(0) != 0) {
		printf("init(0) failed\n");
		return 1;
	}
	ran = donef = 0;
	if (crypto_job_submit(work, done_cb, &arg) != 0) {
		printf("inline submit failed\n");
		return 1;
	}
	if (barrier(), ran != 1 || donef != 1 || arg != 41) {
		printf("inline: ran=%d done=%d arg=%d\n", ran, donef, arg);
		return 1;
	}
	if (crypto_workers_enabled()) {
		printf("inline pool should be disabled\n");
		return 1;
	}
	crypto_workers_fini();

#ifdef HAVE_PTHREAD
	printf("**Test for crypto workers (1 thread).**\n");
	arg = 40;
	ran = donef = 0;
	if (crypto_workers_init(1) != 0) {
		printf("init(1) failed\n");
		return 1;
	}
	if (!crypto_workers_enabled()) {
		printf("workers not enabled after init(1)\n");
		crypto_workers_fini();
		return 1;
	}
	if (crypto_job_submit(work, done_cb, &arg) != 0) {
		printf("pool submit failed\n");
		crypto_workers_fini();
		return 1;
	}
	{
		int i;

		for (i = 0; i < 50 && donef == 0; i++)
			wait_drain(100);
	}
	if (barrier(), ran != 1 || donef != 1 || arg != 41) {
		printf("pool: ran=%d done=%d arg=%d\n", ran, donef, arg);
		crypto_workers_fini();
		return 1;
	}
	crypto_workers_fini();

	printf("**Test for crypto workers (10 threads).**\n");
	{
		int args[10];
		int i;

		ran = donef = 0;
		if (crypto_workers_init(10) != 0) {
			printf("init(10) failed\n");
			return 1;
		}
		if (!crypto_workers_enabled()) {
			printf("workers not enabled after init(10)\n");
			crypto_workers_fini();
			return 1;
		}
		for (i = 0; i < 10; i++) {
			args[i] = i;
			if (crypto_job_submit(work, done_cb, &args[i]) != 0) {
				printf("pool10 submit %d failed\n", i);
				crypto_workers_fini();
				return 1;
			}
		}
		for (i = 0; i < 100 && donef < 10; i++)
			wait_drain(100);
		barrier();
		if (ran != 10 || donef != 10) {
			printf("pool10: ran=%d done=%d\n", ran, donef);
			crypto_workers_fini();
			return 1;
		}
		for (i = 0; i < 10; i++) {
			if (args[i] != i + 1) {
				printf("pool10 arg[%d]=%d\n", i, args[i]);
				crypto_workers_fini();
				return 1;
			}
		}
		crypto_workers_fini();
	}
#endif
	printf("\n===== worker tests passed =====\n\n");
	return 0;
}
