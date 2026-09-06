/* $Id$ */
/*
 * Same shape as eaytest: a small check_PROGRAM, printf + exit status.
 * Exercises evloop_wait (select or epoll via @EVLOOP@) with a pipe.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "evloop.h"

int
main(void)
{
	int p[2];
	fd_set rfds;
	struct timeval tv;
	char c = 'x';
	int n;

	if (evloop_init() != 0) {
		printf("evloop_init failed: %s\n", strerror(errno));
		return 1;
	}
	if (pipe(p) != 0) {
		printf("pipe failed: %s\n", strerror(errno));
		return 1;
	}

	printf("**Test for evloop_wait timeout.**\n");
	FD_ZERO(&rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	n = evloop_wait(1, &rfds, &tv);
	if (n < 0) {
		printf("evloop_wait timeout failed: %s\n", strerror(errno));
		return 1;
	}
	if (n != 0) {
		printf("expected 0 ready fds, got %d\n", n);
		return 1;
	}

	printf("**Test for evloop_wait pipe.**\n");
	if (write(p[1], &c, 1) != 1) {
		printf("write failed\n");
		return 1;
	}
	FD_ZERO(&rfds);
	FD_SET(p[0], &rfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	n = evloop_wait(p[0] + 1, &rfds, &tv);
	if (n < 1 || !FD_ISSET(p[0], &rfds)) {
		printf("pipe not ready n=%d\n", n);
		return 1;
	}
	if (read(p[0], &c, 1) != 1) {
		printf("read failed\n");
		return 1;
	}

	printf("**Test for evloop_wait unregister.**\n");
	FD_ZERO(&rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	n = evloop_wait(p[0] + 1, &rfds, &tv);
	if (n < 0) {
		printf("unregister wait failed: %s\n", strerror(errno));
		return 1;
	}

	close(p[0]);
	close(p[1]);
	if (pipe(p) != 0) {
		printf("pipe reuse failed: %s\n", strerror(errno));
		return 1;
	}
	printf("**Test for evloop_wait close/reuse.**\n");
	c = 'y';
	if (write(p[1], &c, 1) != 1) {
		printf("reuse write failed\n");
		return 1;
	}
	FD_ZERO(&rfds);
	FD_SET(p[0], &rfds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	n = evloop_wait(p[0] + 1, &rfds, &tv);
	if (n < 1 || !FD_ISSET(p[0], &rfds)) {
		printf("reused pipe not ready n=%d\n", n);
		return 1;
	}
	if (read(p[0], &c, 1) != 1) {
		printf("reuse read failed\n");
		return 1;
	}

	close(p[0]);
	close(p[1]);
	evloop_fini();
	printf("\n===== evloop tests passed =====\n\n");
	return 0;
}
