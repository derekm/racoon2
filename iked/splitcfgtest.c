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
main(int argc, char *argv[])
{
	test_init(argv[0]);

	/* Fabricated child_sa with an IPv4 /24 and an IPv6 /32 split subnet */
	struct ikev2_child_sa child;
	struct rcf_selector sel4, sel6;
	struct ikev2_sa ike_sa;
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
		int found13 = 0, found15 = 0, found2 = 0;

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
			} else if (t == IKEV2_CFG_INTERNAL_IP4_NETMASK) {
				/* B.3: legacy-Windows NETMASK(2) rides beside 13,
				 * same /24 mask as a plain address. */
				uint8_t *v = IKEV2CFG_ATTR_VALUE(a);
				struct in_addr m2;
				memcpy(&m2, v, sizeof(m2));
				CK(m2.s_addr == htonl(0xffffff00),
				   "2 INTERNAL_IP4_NETMASK == /24 (legacy Windows)");
				found2 = 1;
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
		CK(found2, "reply contains INTERNAL_IP4_NETMASK (2) beside 13");

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
				int n13 = 0, n15 = 0, n2 = 0;
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
					if (t == IKEV2_CFG_INTERNAL_IP4_NETMASK) n2++;
					bp += sizeof(*a) + l;
					bb -= sizeof(*a) + l;
				}
				CK(n13 == 0 && n15 == 0 && n2 == 0,
				   "no 2/13/15 emitted without a subnet request");
			} else {
				CK(1, "no-request reply has no subnet attrs (empty)");
			}
			if (p2.cfg_payload)
				rc_vfree(p2.cfg_payload);
		}
	}

	if (child.child_param.cfg_payload)
		rc_vfree(child.child_param.cfg_payload);

	/* ================= B.2 mirror: INITIATOR parsing =================
	 * Drive the real ikev2_process_config_reply() with a fabricated
	 * CFG_REPLY carrying INTERNAL_IP4_SUBNET(13) + INTERNAL_IP6_SUBNET(15)
	 * and assert the subnets are COMMITTED to the child (addr + prefixlen)
	 * in internal_ip4_subnet / internal_ip6_subnet. */
	{
		/* build a synthetic CFG_REPLY: payload header + cfgh + attrs */
		uint8_t buf[1 + sizeof(struct ikev2payl_config) +
			    2 * sizeof(struct in_addr) +
			    sizeof(struct ikev2cfg_ip6addr) + 32];
		int off = 0;
		struct ikev2payl_config *cfg;
		struct ikev2_child_sa c;
		struct ikev2_sa isa;
		struct rcf_address *ra;

		memset(buf, 0, sizeof(buf));
		cfg = (struct ikev2payl_config *)buf;
		cfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
		off += sizeof(struct ikev2payl_config);

		/* 13: addr (10.20.0.0) + netmask (/24) */
		{
			struct ikev2cfg_attrib *a =
			    (struct ikev2cfg_attrib *)(buf + off);
			struct in_addr addr, mask;
			put_uint16(&a->type, IKEV2_CFG_INTERNAL_IP4_SUBNET);
			put_uint16(&a->length, 2 * sizeof(struct in_addr));
			inet_pton(AF_INET, "10.20.0.0", &addr);
			inet_pton(AF_INET, "255.255.255.0", &mask);
			memcpy(IKEV2CFG_ATTR_VALUE(a), &addr, sizeof(addr));
			memcpy(IKEV2CFG_ATTR_VALUE(a) + sizeof(addr),
			       &mask, sizeof(mask));
			off += sizeof(*a) + 2 * sizeof(struct in_addr);
		}
		/* 15: prefixlen(32) + addr (2001:db8:cafe::) */
		{
			struct ikev2cfg_attrib *a =
			    (struct ikev2cfg_attrib *)(buf + off);
			struct ikev2cfg_ip6addr d;
			memset(&d, 0, sizeof(d));
			d.prefixlen = 32;
			uint8_t expect[16] = { 0 };
			expect[0] = 0x20; expect[1] = 0x01;
			expect[2] = 0x0d; expect[3] = 0xb8;
			expect[4] = 0xca; expect[5] = 0xfe;
			memcpy(d.addr, expect, 16);
			put_uint16(&a->type, IKEV2_CFG_INTERNAL_IP6_SUBNET);
			put_uint16(&a->length, sizeof(struct ikev2cfg_ip6addr));
			memcpy(IKEV2CFG_ATTR_VALUE(a), &d, sizeof(d));
			off += sizeof(*a) + sizeof(struct ikev2cfg_ip6addr);
		}
		/* set the 2-byte payload_length (big-endian) = total cfg body */
		{
			uint8_t pl[2];
			pl[0] = (uint8_t)((off >> 8) & 0xff);
			pl[1] = (uint8_t)(off & 0xff);
			memcpy((uint8_t *)&cfg->header.payload_length, pl, 2);
		}
		cfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;

		/* fresh child_sa to receive into */
		memset(&c, 0, sizeof(c));
		memset(&isa, 0, sizeof(isa));
		ikev2_child_param_init(&c.child_param);

		CK(ikev2_process_config_reply(&isa, &c, &cfg->header) == 0,
		   "ikev2_process_config_reply(13/15) rc==0");

		ra = LIST_FIRST(&c.internal_ip4_subnet);
		CK(ra != NULL, "ip4 subnet committed to internal_ip4_subnet");
		if (ra) {
			struct in_addr got;
			memcpy(&got, ra->address, sizeof(got));
			CK(got.s_addr == htonl(0x0a140000),
			   "ip4 subnet addr == 10.20.0.0");
			CK(ra->prefixlen == 24,
			   "ip4 subnet prefixlen == /24");
		}

		ra = LIST_FIRST(&c.internal_ip6_subnet);
		CK(ra != NULL, "ip6 subnet committed to internal_ip6_subnet");
		if (ra) {
			uint8_t expect[16] = { 0 };
			expect[0] = 0x20; expect[1] = 0x01;
			expect[2] = 0x0d; expect[3] = 0xb8;
			expect[4] = 0xca; expect[5] = 0xfe;
			CK(memcmp(ra->address, expect, 16) == 0,
			   "ip6 subnet addr == 2001:db8:cafe::");
			CK(ra->prefixlen == 32,
			   "ip6 subnet prefixlen == /32");
		}

		/* teardown the receive-side child (release committed subnets) */
		while (!LIST_EMPTY(&c.internal_ip4_subnet))
			rc_addrpool_release_addr(
			    LIST_FIRST(&c.internal_ip4_subnet));
		while (!LIST_EMPTY(&c.internal_ip6_subnet))
			rc_addrpool_release_addr(
			    LIST_FIRST(&c.internal_ip6_subnet));
	}

	rcs_free_addrlist(sel4.dst);
	rcs_free_addrlist(sel6.dst);

	/* ================= B.4: INTERNAL_DNS_DOMAIN (25) =================
	 * 1. Emit: responder with a configured split-DNS suffix, peer asked
	 *    for 25 -> CFG_REPLY carries  25 = "corp.example".
	 * 2. Parse: initiator receiving 25 commits it to internal_dns_domain. */
	{
		struct rcf_kmp ikm;
		struct rcf_remote rm;
		struct ikev2_sa isa;
		struct ikev2_child_sa c;
		struct ikev2_child_param p;
		uint8_t buf[256];
		uint8_t off = 0;
		struct ikev2payl_config *cfg;
		int found = 0;

		memset(&ikm, 0, sizeof(ikm));
		memset(&rm, 0, sizeof(rm));
		rm.ikev2 = &ikm;
		ikm.dns_domain = rc_vmalloc(strlen("corp.example") + 1);
		memcpy(ikm.dns_domain->v, "corp.example", strlen("corp.example"));
		ikm.dns_domain->s[strlen("corp.example")] = '\0';
		ikm.dns_domain->l = strlen("corp.example") + 1;

		memset(&isa, 0, sizeof(isa));
		isa.rmconf = &rm;
		memset(&c, 0, sizeof(c));
		ikev2_child_param_init(&p);
		p.cfg_dns_domain = 1;

		CK(ikev2_create_config_reply(&isa, &c, &p) == 0,
		   "create_config_reply rc==0 (dns_domain)");
		CK(p.cfg_payload != NULL, "reply allocated (dns_domain)");
		if (p.cfg_payload) {
			struct ikev2payl_config_h *cfgh =
			    (struct ikev2payl_config_h *)p.cfg_payload->v;
			uint8_t *body = (uint8_t *)p.cfg_payload->v +
			    sizeof(*cfgh);
			size_t blen = p.cfg_payload->l - sizeof(*cfgh);
			int i;
			for (i = 0; blen > 0; ++i) {
				struct ikev2cfg_attrib *a =
				    (struct ikev2cfg_attrib *)body;
				unsigned int t, l;
				if (blen < sizeof(*a))
					break;
				t = IKEV2CFG_ATTR_TYPE(a);
				l = IKEV2CFG_ATTR_LENGTH(a);
				if (sizeof(*a) + l > blen)
					break;
				if (t == IKEV2_CFG_INTERNAL_DNS_DOMAIN) {
					CK(l == strlen("corp.example") &&
					   memcmp(IKEV2CFG_ATTR_VALUE(a),
						  "corp.example", l) == 0,
					   "25 INTERNAL_DNS_DOMAIN == corp.example");
					found = 1;
				}
				body += sizeof(*a) + l;
				blen -= sizeof(*a) + l;
			}
			CK(found, "reply contains INTERNAL_DNS_DOMAIN (25)");
			rc_vfree(p.cfg_payload);
		}
		rc_vfree(ikm.dns_domain);

		/* negative: no DNS_DOMAIN unless both requested AND configured */
		{
			struct ikev2_child_param p2;
			struct ikev2_sa isa2;
			memset(&isa2, 0, sizeof(isa2));
			isa2.rmconf = &rm;	/* configured */
			ikev2_child_param_init(&p2);	/* not requested */
			CK(ikev2_create_config_reply(&isa2, &c, &p2) == 0,
			   "reply rc==0 no dns_domain request");
			if (p2.cfg_payload) {
				uint8_t *body2 = (uint8_t *)p2.cfg_payload->v +
				    sizeof(struct ikev2payl_config_h);
				size_t bl2 = p2.cfg_payload->l -
				    sizeof(struct ikev2payl_config_h);
				int n25 = 0;
				for (; bl2 > 0; ) {
					struct ikev2cfg_attrib *a =
					    (struct ikev2cfg_attrib *)body2;
					unsigned int t, l;
					if (bl2 < sizeof(*a))
						break;
					t = IKEV2CFG_ATTR_TYPE(a);
					l = IKEV2CFG_ATTR_LENGTH(a);
					if (sizeof(*a) + l > bl2)
						break;
					if (t == IKEV2_CFG_INTERNAL_DNS_DOMAIN) n25++;
					body2 += sizeof(*a) + l;
					bl2 -= sizeof(*a) + l;
				}
				CK(n25 == 0, "no 25 without a dns_domain request");
				rc_vfree(p2.cfg_payload);
			} else {
				/* rmconf set so reply is non-empty; just be safe */
				CK(1, "no-request reply handles DNS (non-null)");
			}
		}

		/* parse: initiator receives 25 in a CFG_REPLY */
		memset(buf, 0, sizeof(buf));
		cfg = (struct ikev2payl_config *)buf;
		cfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
		off = sizeof(struct ikev2payl_config);
		{
			struct ikev2cfg_attrib *a =
			    (struct ikev2cfg_attrib *)(buf + off);
			const char *dd = "corp.example";
			put_uint16(&a->type, IKEV2_CFG_INTERNAL_DNS_DOMAIN);
			put_uint16(&a->length, (uint16_t)strlen(dd));
			memcpy(IKEV2CFG_ATTR_VALUE(a), dd, strlen(dd));
			off += sizeof(*a) + strlen(dd);
		}
		{
			uint8_t pl[2];
			pl[0] = (uint8_t)((off >> 8) & 0xff);
			pl[1] = (uint8_t)(off & 0xff);
			memcpy((uint8_t *)&cfg->header.payload_length, pl, 2);
		}
		cfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;

		memset(&c, 0, sizeof(c));
		memset(&isa, 0, sizeof(isa));
		ikev2_child_param_init(&c.child_param);
		CK(ikev2_process_config_reply(&isa, &c, &cfg->header) == 0,
		   "process_config_reply rc==0 (25)");
		CK(c.internal_dns_domain != NULL &&
		   strcmp(c.internal_dns_domain->s, "corp.example") == 0,
		   "25 committed to internal_dns_domain (corp.example)");
		if (c.internal_dns_domain)
			rc_vfree(c.internal_dns_domain);
	}

	printf("splitcfgtest: %d checks, %d failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}
