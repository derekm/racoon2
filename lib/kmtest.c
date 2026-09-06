/* $Id$ */
/*
 * Same shape as eaytest / lib/sample: check_PROGRAM, printf + exit status.
 * Exercises the userspace KM backend loopback (no kernel, no DPDK).
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "if_pfkeyv2.h"

static int n_getspi;
static int n_update;
static int n_add;

static int
cb_getspi(struct rcpfk_msg *rc)
{
	if (rc->spi == 0)
		return -1;
	n_getspi++;
	return 0;
}

static int
cb_update(struct rcpfk_msg *rc)
{
	(void)rc;
	n_update++;
	return 0;
}

static int
cb_add(struct rcpfk_msg *rc)
{
	(void)rc;
	n_add++;
	return 0;
}

int
main(void)
{
	struct rcpfk_msg rc;
	struct rcpfk_cb cb;
	struct sockaddr_in src, dst;
	unsigned char key[16];

	memset(&rc, 0, sizeof(rc));
	memset(&cb, 0, sizeof(cb));
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	memset(key, 0xab, sizeof(key));
	cb.cb_getspi = cb_getspi;
	cb.cb_update = cb_update;
	cb.cb_add = cb_add;
	src.sin_family = AF_INET;
	src.sin_port = htons(500);
	src.sin_addr.s_addr = htonl(0xc0000201);	/* 192.0.2.1 */
	dst.sin_family = AF_INET;
	dst.sin_port = htons(500);
	dst.sin_addr.s_addr = htonl(0xc0000202);	/* 192.0.2.2 */

	printf("**Test for userspace rcpfk_init.**\n");
	if (rcpfk_init(&rc, &cb) != 0) {
		printf("init failed: %s\n", rc.estr);
		return 1;
	}
	if (rc.so < 0) {
		printf("no loopback fd\n");
		return 1;
	}

	printf("**Test for GETSPI.**\n");
	rc.seq = 0x4000001;
	rc.sa_src = (struct sockaddr *)&src;
	rc.sa_dst = (struct sockaddr *)&dst;
	rc.satype = 3;	/* SADB_SATYPE_ESP */
	rc.samode = 1;
	rc.spi = 0;
	if (rcpfk_send_getspi(&rc) != 0) {
		printf("getspi send failed: %s\n", rc.estr);
		return 1;
	}
	if (rcpfk_handler(&rc) != 0) {
		printf("getspi handler failed: %s\n", rc.estr);
		return 1;
	}
	if (n_getspi != 1 || rc.spi == 0 || rc.seq != 0x4000001) {
		printf("getspi: n=%d spi=%u seq=%u\n", n_getspi, rc.spi,
		    rc.seq);
		return 1;
	}

	printf("**Test for UPDATE.**\n");
	rc.enckey = (caddr_t)key;
	rc.enckeylen = sizeof(key);
	rc.authkey = (caddr_t)key;
	rc.authkeylen = sizeof(key);
	if (rcpfk_send_update(&rc) != 0) {
		printf("update send failed: %s\n", rc.estr);
		return 1;
	}
	if (rcpfk_handler(&rc) != 0) {
		printf("update handler failed: %s\n", rc.estr);
		return 1;
	}
	if (n_update != 1) {
		printf("update cb count %d\n", n_update);
		return 1;
	}

	printf("**Test for ADD.**\n");
	if (rcpfk_send_add(&rc) != 0) {
		printf("add send failed: %s\n", rc.estr);
		return 1;
	}
	if (rcpfk_handler(&rc) != 0) {
		printf("add handler failed: %s\n", rc.estr);
		return 1;
	}
	if (n_add != 1) {
		printf("add cb count %d\n", n_add);
		return 1;
	}

	if (rcpfk_clean(&rc) != 0) {
		printf("clean failed\n");
		return 1;
	}
	printf("\n===== userspace km tests passed =====\n\n");
	return 0;
}
