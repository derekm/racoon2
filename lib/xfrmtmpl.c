/* Linux XFRM: mixed-family tmpl (v4 local + v6 unspecified) must coerce
 * to one family with proto esp — not c0a8:444f::. Skip 77 if not root.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "racoon.h"

#ifndef HAVE_XFRM
int
main(void)
{
	printf("SKIP: not built with --with-km-backend=xfrm\n");
	return 77;
}
#else

static const char k_src[] = "198.18.0.1";
static const char k_sel_s[] = "192.0.2.10";
static const char k_sel_d[] = "192.0.2.20";

static int
policy_dump_ok(void)
{
	FILE *fp;
	char line[512];
	int saw_sel = 0, saw_proto = 0, saw_garbled = 0;

	fp = popen("ip xfrm policy src 192.0.2.10/32 dst 192.0.2.20/32 dir out 2>/dev/null || ip xfrm policy", "r");
	if (fp == NULL)
		return -1;
	while (fgets(line, sizeof(line), fp) != NULL) {
		fputs(line, stdout);
		if (strstr(line, k_sel_s) != NULL)
			saw_sel = 1;
		if (saw_sel && strstr(line, "proto esp") != NULL)
			saw_proto = 1;
		if (strstr(line, "c0a8:") != NULL || strstr(line, "C0A8:") != NULL)
			saw_garbled = 1;
	}
	pclose(fp);
	if (!saw_sel)
		return 1;
	if (saw_garbled)
		return 2;
	if (!saw_proto)
		return 3;
	return 0;
}

int
main(int argc, char **argv)
{
	struct rcpfk_msg rc;
	struct rcpfk_cb cb;
	struct sockaddr_in src, sel_s, sel_d;
	struct sockaddr_in6 dst6;
	int st;

	(void)argc;
	(void)argv;

	if (geteuid() != 0) {
		printf("SKIP: need root for NETLINK_XFRM SPDADD\n");
		return 77;
	}

	memset(&rc, 0, sizeof(rc));
	memset(&cb, 0, sizeof(cb));
	memset(&src, 0, sizeof(src));
	memset(&dst6, 0, sizeof(dst6));
	memset(&sel_s, 0, sizeof(sel_s));
	memset(&sel_d, 0, sizeof(sel_d));

	src.sin_family = AF_INET;
	inet_pton(AF_INET, k_src, &src.sin_addr);
	dst6.sin6_family = AF_INET6; /* unspecified :: — the mangling case */
	sel_s.sin_family = AF_INET;
	inet_pton(AF_INET, k_sel_s, &sel_s.sin_addr);
	sel_d.sin_family = AF_INET;
	inet_pton(AF_INET, k_sel_d, &sel_d.sin_addr);

	printf("**Test for XFRM tmpl family coerce.**\n");
	if (rcpfk_init(&rc, &cb) != 0) {
		printf("SKIP: rcpfk_init: %s\n", rc.estr);
		return 77;
	}

	rc.sa_src = (struct sockaddr *)&src;
	rc.sa_dst = (struct sockaddr *)&dst6;
	rc.sp_src = (struct sockaddr *)&sel_s;
	rc.sp_dst = (struct sockaddr *)&sel_d;
	rc.pref_src = 32;
	rc.pref_dst = 32;
	rc.satype = RCT_SATYPE_ESP;
	rc.samode = RCT_IPSM_TUNNEL;
	rc.dir = RCT_DIR_OUTBOUND;
	rc.pltype = RCT_ACT_AUTO_IPSEC;
	rc.ipsec_level = RCT_IPSL_REQUIRE;
	rc.ul_proto = RC_PROTO_ANY;
	rc.reqid = 4243;

	if (rcpfk_send_spdadd(&rc) != 0) {
		printf("SPDADD failed: %s (errno=%d)\n", rc.estr, rc.eno);
		(void)rcpfk_clean(&rc);
		return rc.eno == EPERM ? 77 : 1;
	}

	st = policy_dump_ok();
	(void)rcpfk_send_spddelete(&rc);
	(void)rcpfk_clean(&rc);

	if (st == -1) {
		printf("SKIP: ip xfrm not available\n");
		return 77;
	}
	if (st == 1) {
		printf("FAIL: policy missing selector\n");
		return 1;
	}
	if (st == 2) {
		printf("FAIL: garbled v6 tmpl (c0a8:)\n");
		return 1;
	}
	if (st == 3) {
		printf("FAIL: tmpl missing proto esp\n");
		return 1;
	}
	printf("\n===== xfrm tmpl family tests passed =====\n\n");
	return 0;
}
#endif /* HAVE_XFRM */
