/* $Id$ */
/*
 * Same shape as eaytest / lib/sample: check_PROGRAM, printf + exit status.
 * Exercises the userspace KM backend loopback (no kernel, no DPDK).
 * Handler is called on a fresh rcpfk_msg like sadb_poll.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "if_pfkeyv2.h"

int kmtest_live_spis(void);	/* kmtest_backend.c */
extern uint32_t rc_spirange_min, rc_spirange_max;

static int n_getspi;
static int n_update;
static int n_add;

static int
cb_getspi(struct rcpfk_msg *rc)
{
	if (rc->spi == 0 || rc->sa_src == NULL || rc->sa_dst == NULL)
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

static int
poll_one(int so, struct rcpfk_msg *out)
{
	memset(out, 0, sizeof(*out));
	out->so = so;
	return rcpfk_handler(out);
}

int
main(void)
{
	struct rcpfk_msg rc, poll;
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

	printf("**Test for GETSPI (sadb_poll rc).**\n");
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
	if (poll_one(rc.so, &poll) != 0) {
		printf("getspi handler failed: %s\n", poll.estr);
		return 1;
	}
	if (n_getspi != 1 || ntohl(poll.spi) == 0 || poll.seq != 0x4000001 ||
	    poll.sa_src == NULL || poll.sa_dst == NULL) {
		printf("getspi: n=%d spi=%u seq=%u src=%p dst=%p\n",
		    n_getspi, ntohl(poll.spi), poll.seq,
		    (void *)poll.sa_src, (void *)poll.sa_dst);
		return 1;
	}

	printf("**Test for UPDATE.**\n");
	rc.spi = poll.spi;
	rc.enckey = (caddr_t)key;
	rc.enckeylen = sizeof(key);
	rc.authkey = (caddr_t)key;
	rc.authkeylen = sizeof(key);
	rc.enctype = 20;
	if (rcpfk_send_update(&rc) != 0) {
		printf("update send failed: %s\n", rc.estr);
		return 1;
	}
	if (poll_one(rc.so, &poll) != 0) {
		printf("update handler failed: %s\n", poll.estr);
		return 1;
	}
	if (n_update != 1 || poll.enctype != 20) {
		printf("update cb count %d enctype %u\n", n_update,
		    poll.enctype);
		return 1;
	}

	printf("**Test for ADD.**\n");
	if (rcpfk_send_add(&rc) != 0) {
		printf("add send failed: %s\n", rc.estr);
		return 1;
	}
	if (poll_one(rc.so, &poll) != 0) {
		printf("add handler failed: %s\n", poll.estr);
		return 1;
	}
	if (n_add != 1) {
		printf("add cb count %d\n", n_add);
		return 1;
	}

	printf("**Test for unimplemented ops failing loudly.**\n");
	{
		struct rcpfk_msg u;

		memset(&u, 0, sizeof(u));
		u.so = rc.so;
		if (rcpfk_send_acquire(&u) != -1 || u.eno != EOPNOTSUPP) {
			printf("acquire must fail EOPNOTSUPP (eno %d)\n", u.eno);
			return 1;
		}
		memset(&u, 0, sizeof(u));
		if (rcpfk_send_spdget(&u) != -1 || u.eno != EOPNOTSUPP) {
			printf("spdget must fail EOPNOTSUPP (eno %d)\n", u.eno);
			return 1;
		}
		memset(&u, 0, sizeof(u));
		if (rcpfk_send_spddump(&u) != -1 || u.eno != EOPNOTSUPP) {
			printf("spddump must fail EOPNOTSUPP (eno %d)\n", u.eno);
			return 1;
		}
		memset(&u, 0, sizeof(u));
		if (rcpfk_send_migrate(&u) != -1 || u.eno != EOPNOTSUPP) {
			printf("migrate must fail EOPNOTSUPP (eno %d)\n", u.eno);
			return 1;
		}
	}

	printf("**Test for key length errors keeping their cause.**\n");
	{
		static unsigned char big[70000];
		struct rcpfk_msg k = rc;

		k.enckey = (caddr_t)big;
		k.enckeylen = sizeof(big);	/* > 16-bit wire field */
		if (rcpfk_send_add(&k) != -1 || k.eno != EOVERFLOW) {
			printf("70000-byte key: want EOVERFLOW, eno %d (%s)\n",
			    k.eno, k.estr);
			return 1;
		}
		k = rc;
		k.eno = 0;
		k.enckey = (caddr_t)big;
		k.enckeylen = 3000;	/* fits the field, not the message */
		if (rcpfk_send_add(&k) != -1 || k.eno != EMSGSIZE) {
			printf("3000-byte key: want EMSGSIZE, eno %d (%s)\n",
			    k.eno, k.estr);
			return 1;
		}
	}

	printf("**Test for random, unique, in-range SPIs.**\n");
	{
		uint32_t spis[64];
		int i, j, seqpairs = 0, live0 = kmtest_live_spis();

		for (i = 0; i < 64; i++) {
			struct rcpfk_msg g = rc;

			g.spi = 0;
			if (rcpfk_send_getspi(&g) != 0) {
				printf("getspi %d: %s\n", i, g.estr);
				return 1;
			}
			(void)poll_one(rc.so, &poll);
			spis[i] = ntohl(g.spi);
			if (spis[i] < rc_spirange_min ||
			    spis[i] > rc_spirange_max) {
				printf("spi %08x out of range\n", spis[i]);
				return 1;
			}
			for (j = 0; j < i; j++)
				if (spis[j] == spis[i]) {
					printf("duplicate spi %08x\n", spis[i]);
					return 1;
				}
			if (i > 0 && spis[i] == spis[i - 1] + 1)
				seqpairs++;
		}
		if (seqpairs > 2) {
			printf("SPIs look sequential (%d +1 steps)\n", seqpairs);
			return 1;
		}
		if (kmtest_live_spis() != live0 + 64) {
			printf("live SPI table %d, want %d\n", kmtest_live_spis(),
			    live0 + 64);
			return 1;
		}
		for (i = 0; i < 64; i++) {
			struct rcpfk_msg dl = rc;

			dl.spi = htonl(spis[i]);
			if (rcpfk_send_delete(&dl) != 0) {
				printf("delete: %s\n", dl.estr);
				return 1;
			}
			(void)poll_one(rc.so, &poll);
		}
		if (kmtest_live_spis() != live0) {
			printf("delete did not release SPIs (%d)\n", kmtest_live_spis());
			return 1;
		}
	}

	if (rcpfk_clean(&rc) != 0) {
		printf("clean failed\n");
		return 1;
	}

	printf("**Test for the dataplane mirror socket trust check.**\n");
	{
		char d[] = "/tmp/kmtestXXXXXX", sp[128], f[128];
		struct sockaddr_un un;
		struct rcpfk_msg i2;
		int ls, fd;
		char got[2048];

		if (mkdtemp(d) == NULL) {
			printf("mkdtemp: %s\n", strerror(errno));
			return 1;
		}
		snprintf(sp, sizeof(sp), "%s/dp.sock", d);
		snprintf(f, sizeof(f), "%s/plain", d);
		/* absent socket: init must fail, not run without the mirror */
		setenv("RACOON2_DATAPLANE_SOCK", sp, 1);
		memset(&i2, 0, sizeof(i2));
		if (rcpfk_init(&i2, &cb) != -1 || i2.eno != ENOENT) {
			printf("absent socket: want ENOENT, eno %d\n", i2.eno);
			return 1;
		}
		/* a regular file is not a socket */
		fd = open(f, O_CREAT | O_WRONLY, 0600);
		close(fd);
		setenv("RACOON2_DATAPLANE_SOCK", f, 1);
		memset(&i2, 0, sizeof(i2));
		if (rcpfk_init(&i2, &cb) != -1 || i2.eno != EPERM) {
			printf("regular file: want EPERM, eno %d\n", i2.eno);
			return 1;
		}
		ls = socket(AF_UNIX, SOCK_DGRAM, 0);
		memset(&un, 0, sizeof(un));
		un.sun_family = AF_UNIX;
		strncpy(un.sun_path, sp, sizeof(un.sun_path) - 1);
		if (ls < 0 || bind(ls, (struct sockaddr *)&un, sizeof(un)) < 0) {
			printf("bind %s: %s\n", sp, strerror(errno));
			return 1;
		}
		/* a directory others can write to (not sticky): refused */
		chmod(d, 0777);
		setenv("RACOON2_DATAPLANE_SOCK", sp, 1);
		memset(&i2, 0, sizeof(i2));
		if (rcpfk_init(&i2, &cb) != -1 || i2.eno != EPERM) {
			printf("world-writable dir: want EPERM, eno %d\n",
			    i2.eno);
			return 1;
		}
		/* our own socket in a private directory: mirrored */
		chmod(d, 0700);
		memset(&i2, 0, sizeof(i2));
		if (rcpfk_init(&i2, &cb) != 0) {
			printf("trusted socket refused: %s\n", i2.estr);
			return 1;
		}
		i2.seq = 0x4000002;
		i2.sa_src = (struct sockaddr *)&src;
		i2.sa_dst = (struct sockaddr *)&dst;
		i2.satype = 3;
		if (rcpfk_send_getspi(&i2) != 0 ||
		    recv(ls, got, sizeof(got), MSG_DONTWAIT) <= 0) {
			printf("GETSPI not mirrored: %s\n", i2.estr);
			return 1;
		}
		rcpfk_clean(&i2);
		unsetenv("RACOON2_DATAPLANE_SOCK");
		close(ls);
		unlink(sp);
		unlink(f);
		rmdir(d);
	}
	printf("\n===== userspace km tests passed =====\n\n");
	return 0;
}
