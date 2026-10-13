/*
 * splitcfgtest.c -- RFC 7296 §3.15.2 split-tunnel CP attributes test.
 *
 * Drives the REAL ikev2_create_config_reply() with a fabricated child_sa
 * whose selector carries an IPv4 and an IPv6 remote-side subnet, requests
 * INTERNAL_IP4_SUBNET(13)/INTERNAL_IP6_SUBNET(15) via the param flags, and
 * asserts the reply payload carries both attributes with the exact
 * address/prefix.  Deterministic: no live exchange, no rekey timing.
 */
#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include "isakmp.h"
#include "ikev2.h"
#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "sockmisc.h"
#include "ike_conf.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "vmbuf.h"
#include "test_util.h"

TEST_MAIN_STUBS();

static int checks = 0;
static int fails = 0;

#define	CK(c_, m_)							\
	do {								\
		++checks;						\
		if (!(c_)) {						\
			printf("FAIL: %s (line %d)\n", m_, __LINE__);	\
			++fails;					\
		} else {						\
			printf("ok: %s\n", m_);				\
		}							\
	} while (0)

/* build a single-entry RCT_ADDR_INET addrlist for the selector dst */
static struct rc_addrlist *
mk_addrlist(int fam, const char *addrstr, int prefixlen)
{
	struct rc_addrlist *al = calloc(1, sizeof(*al));
	struct sockaddr_storage ss;
	struct sockaddr *sa;

	memset(&ss, 0, sizeof(ss));
	if (fam == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
		sin->sin_family = AF_INET;
		inet_pton(AF_INET, addrstr, &sin->sin_addr);
		sa = (struct sockaddr *)sin;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
		sin6->sin6_family = AF_INET6;
		inet_pton(AF_INET6, addrstr, &sin6->sin6_addr);
		sa = (struct sockaddr *)sin6;
	}
	al->type = RCT_ADDR_INET;
	al->prefixlen = prefixlen;
	al->a.ipaddr = rcs_sadup(sa);
	return al;
}

int
main(void)
{
	/* Fabricated child_sa with an IPv4 /24 and an IPv6 /32 split subnet */
	struct ikev2_child_sa child;
	struct rcf_selector sel4, sel6;
	struct ikev2_sa ike_sa;
	struct ikev2_payloads *resp = NULL;
	int i;

	memset(&child, 0, sizeof(child));
	memset(&sel4, 0, sizeof(sel4));
	memset(&sel6, 0, sizeof(sel6));
	memset(&ike_sa, 0, sizeof(ike_sa));
	/* ikev2_create_config_reply reads only child_sa->selector and
	 * lease_list (empty here); no list linkage is required. */

	/* responder-side subnets the client may reach via the tunnel */
	sel4.dst = mk_addrlist(AF_INET, "10.20.0.0", 24);
	sel6.dst = mk_addrlist(AF_INET6, "2001:db8:cafe::", 32);
	sel4.next = &sel6;
	child.selector = &sel4;

	/* peer asked for both split-tunnel subnet attributes */
	ikev2_child_param_init(&child.child_param);
	child.child_param.cfg_ip4_subnet = 1;
	child.child_param.cfg_ip6_subnet = 1;

	/* ike_sa->rmconf is only read when DNS/DHCP/version/mip6 flags are
	 * set; here all are 0, so a zeroed rmconf is safe to deref-free. */
	CK(ikev2_create_config_reply(&ike_sa, &child, &child.child_param) == 0,
	   "ikev2_create_config_reply(split) rc==0");

	if (child.child_param.cfg_payload == NULL) {
		CK(0, "cfg_payload allocated");
		return 1;
	}

	/* walk the reply attributes, find 13/15, verify values */
	{
		uint8_t *p = (uint8_t *)child.child_param.cfg_payload->v;
		size_t plen = child.child_param.cfg_payload->l;
		struct ikev2payl_config_h *cfgh =
		    (struct ikev2payl_config_h *)p;
		uint8_t *body = p + sizeof(*cfgh);
		size_t blen = plen - sizeof(*cfgh);
		int found13 = 0, found15 = 0;

		CK(cfgh->cfg_type == IKEV2_CFG_REPLY,
		   "reply config payload type == CFG_REPLY");

		for (i = 0; blen > 0 && i < 32; ++i) {
			struct ikev2cfg_attrib *a =
			    (struct ikev2cfg_attrib *)body;
			unsigned int t, l;

			if (blen < sizeof(*a))
				break;
			t = IKEV2CFG_ATTR_TYPE(a);
			l = IKEV2CFG_ATTR_LENGTH(a);
			if (sizeof(*a) + l > blen) {
				printf("FAIL: attrib %u len %u overruns (line %d)\n",
				       t, l, __LINE__);
				++fails;
				break;
			}
			if (t == IKEV2_CFG_INTERNAL_IP4_SUBNET) {
				uint8_t *v = IKEV2CFG_ATTR_VALUE(a);
				struct in_addr addr, mask;
				memcpy(&addr, v, sizeof(addr));
				memcpy(&mask, v + sizeof(addr), sizeof(mask));
				CK(addr.s_addr == htonl(0x0a140000),
				   "13 INTERNAL_IP4_SUBNET addr == 10.20.0.0");
				CK(mask.s_addr == htonl(0xffffff00),
				   "13 INTERNAL_IP4_SUBNET mask == /24");
				found13 = 1;
			} else if (t == IKEV2_CFG_INTERNAL_IP6_SUBNET) {
				uint8_t *v = IKEV2CFG_ATTR_VALUE(a);
				struct ikev2cfg_ip6addr *d =
				    (struct ikev2cfg_ip6addr *)v;
				uint8_t expect[16] = { 0 };
				/* 2001:0db8:cafe:0000:...:0000 */
				expect[0] = 0x20; expect[1] = 0x01;
				expect[2] = 0x0d; expect[3] = 0xb8;
				expect[4] = 0xca; expect[5] = 0xfe;
				CK(d->prefixlen == 32,
				   "15 INTERNAL_IP6_SUBNET prefixlen == 32");
				CK(memcmp(d->addr, expect, 16) == 0,
				   "15 INTERNAL_IP6_SUBNET addr == 2001:db8:cafe::");
				found15 = 1;
			}
			body += sizeof(*a) + l;
			blen -= sizeof(*a) + l;
		}
		CK(found13, "reply contains INTERNAL_IP4_SUBNET (13)");
		CK(found15, "reply contains INTERNAL_IP6_SUBNET (15)");

		/* negative: with NO subnet request, neither attribute appears */
		{
			struct ikev2_child_param p2;
			struct ikev2_child_sa c2 = child;
			ikev2_child_param_init(&p2);
			c2.child_param = p2;
			CK(ikev2_create_config_reply(&ike_sa, &c2, &p2) == 0,
			   "reply rc==0 with no subnet request");
			if (p2.cfg_payload && p2.cfg_payload->l > sizeof(struct ikev2payl_config_h)) {
				uint8_t *bp = (uint8_t *)p2.cfg_payload->v +
				    sizeof(struct ikev2payl_config_h);
				size_t bb = p2.cfg_payload->l -
				    sizeof(struct ikev2payl_config_h);
				int n13 = 0, n15 = 0;
				for (; bb > 0; ) {
					struct ikev2cfg_attrib *a =
					    (struct ikev2cfg_attrib *)bp;
					unsigned int t, l;
					if (bb < sizeof(*a))
						break;
					t = IKEV2CFG_ATTR_TYPE(a);
					l = IKEV2CFG_ATTR_LENGTH(a);
					if (sizeof(*a) + l > bb)
						break;
					if (t == IKEV2_CFG_INTERNAL_IP4_SUBNET) n13++;
					if (t == IKEV2_CFG_INTERNAL_IP6_SUBNET) n15++;
					bp += sizeof(*a) + l;
					bb -= sizeof(*a) + l;
				}
				CK(n13 == 0 && n15 == 0,
				   "no 13/15 emitted without a subnet request");
			} else {
				CK(1, "no-request reply has no subnet attrs (empty)");
			}
		}
	}

	if (child.child_param.cfg_payload)
		rc_vfree(child.child_param.cfg_payload);
	rcs_free_addrlist(sel4.dst);
	rcs_free_addrlist(sel6.dst);

	printf("splitcfgtest: %d checks, %d failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
