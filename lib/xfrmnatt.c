/* Linux XFRM NAT-OA (RFC 3947 §4): rcpfk ADD with encap_oa, read back
 * via `ip xfrm state`. Skip (77) when not root / no NETLINK_XFRM.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
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

#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

static const uint32_t k_spi = 0x0a0b0c0du;
static const char k_oa[] = "198.51.100.99";
static const char k_src[] = "198.18.0.1";
static const char k_dst[] = "198.18.0.2";

static int
xfrm_dump_has_oa(void)
{
	char cmd[256];
	FILE *fp;
	char line[512];
	int saw_spi = 0, saw_encap = 0, saw_oa = 0;
	char spi_long[20], spi_short[20];

	snprintf(spi_long, sizeof(spi_long), "spi 0x%08x", k_spi);
	snprintf(spi_short, sizeof(spi_short), "spi 0x%x", k_spi);
	snprintf(cmd, sizeof(cmd),
	    "ip xfrm state get src %s dst %s proto esp spi 0x%x 2>/dev/null || ip xfrm state",
	    k_src, k_dst, k_spi);
	fp = popen(cmd, "r");
	if (fp == NULL)
		return -1;
	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, spi_long) != NULL ||
		    strstr(line, spi_short) != NULL)
			saw_spi = 1;
		if (saw_spi && strstr(line, "encap type espinudp") != NULL)
			saw_encap = 1;
		if (saw_spi && strstr(line, k_oa) != NULL)
			saw_oa = 1;
		fputs(line, stdout);
	}
	pclose(fp);
	if (!saw_spi)
		return 1;
	if (!saw_encap)
		return 1;
	if (!saw_oa)
		return 2;
	return 0;
}

int
main(int argc, char **argv)
{
	struct rcpfk_msg rc;
	struct rcpfk_cb cb;
	struct sockaddr_in src, dst, oa;
	unsigned char key[20];
	int st;

	(void)argc;
	(void)argv;

	if (geteuid() != 0) {
		printf("SKIP: need root for NETLINK_XFRM ADD\n");
		return 77;
	}

	memset(&rc, 0, sizeof(rc));
	memset(&cb, 0, sizeof(cb));
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	memset(&oa, 0, sizeof(oa));
	memset(key, 0xcd, sizeof(key));

	src.sin_family = AF_INET;
	src.sin_port = htons(4500);
	inet_pton(AF_INET, k_src, &src.sin_addr);
	dst.sin_family = AF_INET;
	dst.sin_port = htons(4500);
	inet_pton(AF_INET, k_dst, &dst.sin_addr);
	oa.sin_family = AF_INET;
	oa.sin_port = 0;
	inet_pton(AF_INET, k_oa, &oa.sin_addr);

	printf("**Test for XFRM NAT-OA encap_oa.**\n");
	if (rcpfk_init(&rc, &cb) != 0) {
		printf("SKIP: rcpfk_init: %s\n", rc.estr);
		return 77;
	}

	rc.sa_src = (struct sockaddr *)&src;
	rc.sa_dst = (struct sockaddr *)&dst;
	rc.satype = RCT_SATYPE_ESP;
	rc.samode = RCT_IPSM_TRANSPORT;
	rc.spi = htonl(k_spi);
	rc.reqid = 4242;
	rc.wsize = 4;
	rc.enctype = RCT_ALG_AES_GCM;
	rc.authtype = RCT_ALG_NON_AUTH;
	rc.enckey = (caddr_t)key;
	rc.enckeylen = sizeof(key);
	rc.authkey = NULL;
	rc.authkeylen = 0;
	rc.natt_type = UDP_ENCAP_ESPINUDP;
	rc.natt_sport = htons(4500);
	rc.natt_dport = htons(4500);
	rc.sa_natoa_src = (struct sockaddr *)&oa;

	if (rcpfk_send_add(&rc) != 0) {
		printf("ADD failed: %s (errno=%d)\n", rc.estr, rc.eno);
		(void)rcpfk_clean(&rc);
		return rc.eno == EPERM ? 77 : 1;
	}

	st = xfrm_dump_has_oa();
	(void)rcpfk_send_delete(&rc);
	(void)rcpfk_clean(&rc);

	if (st == -1) {
		printf("SKIP: ip xfrm not available\n");
		return 77;
	}
	if (st == 1) {
		printf("FAIL: SAD missing encap type espinudp\n");
		return 1;
	}
	if (st == 2) {
		printf("FAIL: encap_oa missing %s\n", k_oa);
		return 1;
	}
	printf("\n===== xfrm NAT-OA tests passed =====\n\n");
	return 0;
}
#endif /* HAVE_XFRM */
