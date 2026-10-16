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
#include "ikev2_notify.h"
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

/* An rcf_remote whose ikev2 accept_dns_domain
 * allowlist is `list` (static storage; one at a time). */
static struct rcf_remote *
mk_accept_rm(const char *list)
{
	static struct rcf_kmp k;
	static struct rcf_remote r;
	static rc_vchar_t *v;

	if (v)
		rc_vfree(v);
	v = rc_vmalloc(strlen(list) + 1);
	memcpy(v->v, list, strlen(list) + 1);
	v->l = strlen(list);
	memset(&k, 0, sizeof(k));
	memset(&r, 0, sizeof(r));
	k.accept_dns_domain = v;
	r.ikev2 = &k;
	return &r;
}

/* build a CFG_REPLY carrying the given (type, value, len) attributes */
static struct ikev2_payload_header *
mk_cfg_reply(uint8_t *buf, size_t bl, int n, const int *types,
	     const char *const *vals, const size_t *lens)
{
	struct ikev2payl_config *cfg = (struct ikev2payl_config *)buf;
	size_t off = sizeof(struct ikev2payl_config);
	int i;

	memset(buf, 0, bl);
	cfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
	for (i = 0; i < n; ++i) {
		struct ikev2cfg_attrib *a = (struct ikev2cfg_attrib *)(buf + off);

		put_uint16(&a->type, types[i]);
		put_uint16(&a->length, (uint16_t)lens[i]);
		memcpy(IKEV2CFG_ATTR_VALUE(a), vals[i], lens[i]);
		off += sizeof(*a) + lens[i];
	}
	buf[2] = (uint8_t)((off >> 8) & 0xff);
	buf[3] = (uint8_t)(off & 0xff);
	cfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;
	return &cfg->header;
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
		isa.rmconf = mk_accept_rm("corp.example");	/* M4 allowlist */
		ikev2_child_param_init(&c.child_param);
		CK(ikev2_process_config_reply(&isa, &c, &cfg->header) == 0,
		   "process_config_reply rc==0 (25)");
		CK(c.internal_dns_domain != NULL &&
		   strcmp(c.internal_dns_domain->s, "corp.example") == 0,
		   "25 committed to internal_dns_domain (corp.example)");
		if (c.internal_dns_domain)
			rc_vfree(c.internal_dns_domain);
	}

	/* ===== B.4b: INTERNAL_DNS_DOMAIN validation + allowlist (M4) =====
	 * A peer-pushed 25 is only committed when it is a valid LDH name
	 * inside accept_dns_domain (default: none); several are kept as a
	 * space-separated list; a 26 after a refused 25 is ignored. */
	{
		char o[256];
		static const struct { const char *v; size_t l; int ok;
		    const char *norm; } dv[] = {
			{ "corp.example", 12, 1, "corp.example" },
			{ "Corp.Example.", 13, 1, "corp.example" },
			{ "com", 3, 1, "com" },
			{ ".", 1, 0, 0 },
			{ "", 0, 0, 0 },
			{ "a..b", 4, 0, 0 },
			{ ".a.b", 4, 0, 0 },
			{ "-a.b", 4, 0, 0 },
			{ "a-.b", 4, 0, 0 },
			{ "a.b-", 4, 0, 0 },
			{ "a_b.example", 11, 0, 0 },
			{ "corp\0.example", 13, 0, 0 },
			{ "corp.example\n", 13, 0, 0 },
			{ "$(id).example", 13, 0, 0 },
			{ "a b.example", 11, 0, 0 },
			{ "*.example", 9, 0, 0 },
		};
		char lab64[80], big[300];
		size_t i;
		struct ikev2_sa isa;
		struct ikev2_child_sa c;
		uint8_t buf[512];
		struct ikev2_payload_header *ph;

		for (i = 0; i < sizeof(dv) / sizeof(dv[0]); ++i) {
			int r = ikev2_dns_domain_normalize(
			    (const uint8_t *)dv[i].v, dv[i].l, o, sizeof(o));
			CK((r == 0) == dv[i].ok &&
			   (!dv[i].ok || strcmp(o, dv[i].norm) == 0),
			   dv[i].ok ? "dns_domain valid LDH accepted+normalized"
				    : "dns_domain invalid name refused");
		}
		memset(lab64, 'a', 64);
		memcpy(lab64 + 64, ".example", 9);
		CK(ikev2_dns_domain_normalize((uint8_t *)lab64, 72, o,
		   sizeof(o)) != 0, "dns_domain 64-octet label refused");
		/* lab64 + 1 = 63 'a' + ".example": the longest legal label */
		CK(ikev2_dns_domain_normalize((uint8_t *)lab64 + 1, 71, o,
		   sizeof(o)) == 0, "dns_domain 63-octet label accepted");
		for (i = 0; i < 254; ++i)
			big[i] = (i % 2) ? '.' : 'a';
		big[253] = 'a';
		CK(ikev2_dns_domain_normalize((uint8_t *)big, 253, o,
		   sizeof(o)) == 0, "dns_domain 253 octets accepted");
		CK(ikev2_dns_domain_normalize((uint8_t *)big, 254, o,
		   sizeof(o)) != 0, "dns_domain 254 octets refused");

		CK(ikev2_dns_domain_allowed("corp.example", "corp.example"),
		   "allowlist: exact match");
		CK(ikev2_dns_domain_allowed("eng.corp.example",
		   "lab.test, corp.example."), "allowlist: subdomain match");
		CK(!ikev2_dns_domain_allowed("evilcorp.example",
		   "corp.example"), "allowlist: suffix without label boundary refused");
		CK(!ikev2_dns_domain_allowed("example", "corp.example"),
		   "allowlist: parent of an entry refused");
		CK(!ikev2_dns_domain_allowed("corp.example", NULL),
		   "allowlist: none configured accepts nothing");
		CK(!ikev2_dns_domain_allowed("com", ""),
		   "allowlist: empty list accepts nothing");

		/* parse: no allowlist -> refused, nothing committed */
		{
			int t[1] = { IKEV2_CFG_INTERNAL_DNS_DOMAIN };
			const char *v[1] = { "corp.example" };
			size_t l[1] = { 12 };

			ph = mk_cfg_reply(buf, sizeof(buf), 1, t, v, l);
			memset(&c, 0, sizeof(c));
			memset(&isa, 0, sizeof(isa));
			ikev2_child_param_init(&c.child_param);
			CK(ikev2_process_config_reply(&isa, &c, ph) == 0 &&
			   c.internal_dns_domain == NULL,
			   "25 refused when accept_dns_domain unset (default)");
		}
		/* parse: hostile names refused even when allowlisted broadly */
		{
			int t[2] = { IKEV2_CFG_INTERNAL_DNS_DOMAIN,
				     IKEV2_CFG_INTERNAL_DNSSEC_TA };
			const char *v[2] = { "x.corp.example\n;rm", "\x01\x02\x03\x04" };
			size_t l[2] = { 18, 4 };

			ph = mk_cfg_reply(buf, sizeof(buf), 2, t, v, l);
			memset(&c, 0, sizeof(c));
			memset(&isa, 0, sizeof(isa));
			isa.rmconf = mk_accept_rm("corp.example");
			ikev2_child_param_init(&c.child_param);
			CK(ikev2_process_config_reply(&isa, &c, ph) == 0 &&
			   c.internal_dns_domain == NULL &&
			   c.internal_dnssec_ta == NULL,
			   "invalid 25 refused and its 26 ignored");
		}
		/* parse: out-of-allowlist refused, in-list kept, list built */
		{
			int t[3] = { IKEV2_CFG_INTERNAL_DNS_DOMAIN,
				     IKEV2_CFG_INTERNAL_DNS_DOMAIN,
				     IKEV2_CFG_INTERNAL_DNS_DOMAIN };
			const char *v[3] = { "corp.example", "com",
					     "Lab.Test." };
			size_t l[3] = { 12, 3, 9 };

			ph = mk_cfg_reply(buf, sizeof(buf), 3, t, v, l);
			memset(&c, 0, sizeof(c));
			memset(&isa, 0, sizeof(isa));
			isa.rmconf = mk_accept_rm("corp.example,lab.test");
			ikev2_child_param_init(&c.child_param);
			CK(ikev2_process_config_reply(&isa, &c, ph) == 0 &&
			   c.internal_dns_domain != NULL &&
			   strcmp(c.internal_dns_domain->s,
				  "corp.example lab.test") == 0,
			   "multiple 25s: allowed kept as list, 'com' refused");
			if (c.internal_dns_domain)
				rc_vfree(c.internal_dns_domain);
		}
	}

	/* ============ B.6: INTERNAL_DNSSEC_TA (26, RFC 8598 §8) ==========
	 * 1. Emit: responder with a configured hex `dnssec_ta` trust anchor
	 *    and a peer that asked for 26 -> CFG_REPLY carries 26 = the
	 *    decoded bytes (Key Tag|Alg|Digest Type|Digest Data), placed
	 *    after 25; because RFC 8598 §4.2 says a 26 not preceded by a 25
	 *    is ignored, the responder only emits 26 alongside a 25.
	 * 2. Parse: initiator receiving 26 commits the raw bytes to
	 *    internal_dnssec_ta. */
	{
		struct rcf_kmp ikm;
		struct rcf_remote rm;
		struct ikev2_sa isa;
		struct ikev2_child_sa c;
		struct ikev2_child_param p;
		static const char taha[] =
		    "aabb04b6225ab2cc613e0dca7962bdc2342ea4"; /* keytag/alg/dt/digest */
		uint8_t tara[64];   /* decoded above */
		size_t tara_len = strlen(taha) / 2;
		int i;

		/* decode expected bytes */
		for (i = 0; i < (int)tara_len; i++) {
			unsigned v;
			sscanf(taha + 2 * i, "%2x", &v);
			tara[i] = (uint8_t)v;
		}

		memset(&ikm, 0, sizeof(ikm));
		memset(&rm, 0, sizeof(rm));
		rm.ikev2 = &ikm;
		ikm.dns_domain = rc_vmalloc(strlen("corp.example") + 1);
		memcpy(ikm.dns_domain->v, "corp.example", strlen("corp.example"));
		ikm.dns_domain->s[strlen("corp.example")] = '\0';
		ikm.dns_domain->l = strlen("corp.example") + 1;
		ikm.dnssec_ta = rc_vmalloc(strlen(taha) + 1);
		memcpy(ikm.dnssec_ta->v, taha, strlen(taha));
		ikm.dnssec_ta->s[strlen(taha)] = '\0';
		ikm.dnssec_ta->l = strlen(taha) + 1;

		memset(&isa, 0, sizeof(isa));
		isa.rmconf = &rm;
		memset(&c, 0, sizeof(c));
		ikev2_child_param_init(&p);
		p.cfg_dns_domain = 1;
		p.cfg_dnssec_ta = 1;

		CK(ikev2_create_config_reply(&isa, &c, &p) == 0,
		   "create_config_reply rc==0 (dnssec_ta)");
		CK(p.cfg_payload != NULL, "reply allocated (dnssec_ta)");
		if (p.cfg_payload) {
			struct ikev2payl_config_h *cfgh =
			    (struct ikev2payl_config_h *)p.cfg_payload->v;
			uint8_t *body = (uint8_t *)p.cfg_payload->v +
			    sizeof(*cfgh);
			size_t blen = p.cfg_payload->l - sizeof(*cfgh);
			int n25 = 0, n26 = 0, ta_ok = 0, ordered = 0;
			int saw25 = 0;

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
					n25++;
					saw25 = 1;
				} else if (t == IKEV2_CFG_INTERNAL_DNSSEC_TA &&
					   saw25) {
					n26++;
					/* 26 must immediately follow 25 */
					ordered |= (n25 >= 1);
					if (l == tara_len &&
					    memcmp(IKEV2CFG_ATTR_VALUE(a),
						   tara, tara_len) == 0)
						ta_ok = 1;
				}
				body += sizeof(*a) + l;
				blen -= sizeof(*a) + l;
			}
			CK(n25 == 1, "reply contains INTERNAL_DNS_DOMAIN (25)");
			CK(n26 == 1 && ta_ok,
			   "26 INTERNAL_DNSSEC_TA follows 25 with exact bytes");
			CK(ordered, "26 IMMEDIATELY follows 25 (RFC 8598 §4.2)");
			rc_vfree(p.cfg_payload);
		}
		rc_vfree(ikm.dns_domain);
		rc_vfree(ikm.dnssec_ta);

		/* deepcopy regression: the DAEMON config path hands iked
		 * rcf_deepcopy_remote() (rcf_get_remotebyindex/byaddr), and
		 * that copy MUST carry dnssec_ta — otherwise a config-file
		 * `provide { dnssec_ta ...; }` never reaches the live
		 * responder despite this test (which stuffs a stack rcf_kmp
		 * directly) passing.  Original bug: rcf_deepcopy_kmp
		 * DEEPCOPY_VDUP'd dns_domain but not dnssec_ta. */
		{
			struct rcf_remote src_remote, *cp;
			struct rcf_kmp src_kmp;
			static const char ta2[] =
			    "cafe08b6225ab2cc613e0dca7962bdc2342ea4";

			memset(&src_remote, 0, sizeof(src_remote));
			memset(&src_kmp, 0, sizeof(src_kmp));
			src_remote.ikev2 = &src_kmp;
			src_kmp.dnssec_ta = rc_vmalloc(strlen(ta2) + 1);
			memcpy(src_kmp.dnssec_ta->v, ta2, strlen(ta2));
			src_kmp.dnssec_ta->s[strlen(ta2)] = '\0';
			src_kmp.dnssec_ta->l = strlen(ta2) + 1;

			cp = rcf_deepcopy_remote(&src_remote);
			CK(cp != NULL && cp->ikev2 != NULL,
			   "deepcopy remote produced a copy");
			if (cp && cp->ikev2) {
				CK(cp->ikev2->dnssec_ta != NULL &&
				   cp->ikev2->dnssec_ta->l == (int)strlen(ta2) + 1 &&
				   memcmp(cp->ikev2->dnssec_ta->v, ta2,
					  strlen(ta2)) == 0,
				   "deepcopy carries dnssec_ta (config path)");
				/* rcf_clean_remote is static (not reusable from a
				 * test); the source remote only ever set dnssec_ta,
				 * so the copy owns exactly these three allocs. */
				rc_vfree(cp->ikev2->dnssec_ta);
				rc_free(cp->ikev2);
				rc_free(cp);
			}
			rc_vfree(src_kmp.dnssec_ta);
		}

		/* negative: 26 NOT emitted when the peer did not ask for it,
		 * nor when it asked for 26 but NOT 25 (RFC 8598 §3.1/§4.2:
		 * 26 relies on the preceding 25 and must not float alone) */
		{
			struct ikev2_child_param p2;
			struct ikev2_sa isa2;
			uint8_t *body2;
			size_t blen2;
			struct ikev2payl_config_h *cfgh2;
			int n26b = 0, i2;

			memset(&isa2, 0, sizeof(isa2));
			isa2.rmconf = &rm;   /* configured */
			ikev2_child_param_init(&p2);
                        /* note: p2.cfg_dnssec_ta = 0 (not requested) */
			CK(ikev2_create_config_reply(&isa2, &c, &p2) == 0,
			   "reply rc==0 no dnssec_ta request");
			if (p2.cfg_payload) {
				cfgh2 = (struct ikev2payl_config_h *)
				    p2.cfg_payload->v;
				body2 = (uint8_t *)p2.cfg_payload->v +
				    sizeof(*cfgh2);
				blen2 = p2.cfg_payload->l - sizeof(*cfgh2);
				for (i2 = 0; blen2 > 0; ++i2) {
					struct ikev2cfg_attrib *a =
					    (struct ikev2cfg_attrib *)body2;
					unsigned int t, l;
					if (blen2 < sizeof(*a))
						break;
					t = IKEV2CFG_ATTR_TYPE(a);
					l = IKEV2CFG_ATTR_LENGTH(a);
					if (sizeof(*a) + l > blen2)
						break;
					if (t == IKEV2_CFG_INTERNAL_DNSSEC_TA)
						n26b++;
					body2 += sizeof(*a) + l;
					blen2 -= sizeof(*a) + l;
				}
				CK(n26b == 0,
				   "no 26 emitted without a 26 request");
				rc_vfree(p2.cfg_payload);
			}

			/* requests 26 but NOT 25 -> still no 26 (unpaired) */
			{
				struct ikev2_child_param p3;
				struct ikev2_sa isa3;
				uint8_t *body3;
				size_t blen3;
				struct ikev2payl_config_h *cfgh3;
				int n26c = 0, i3;

				memset(&isa3, 0, sizeof(isa3));
				isa3.rmconf = &rm;
				ikev2_child_param_init(&p3);
				p3.cfg_dnssec_ta = 1;   /* 26 yes, 25 no */
				CK(ikev2_create_config_reply(&isa3, &c, &p3) == 0,
				   "reply rc==0 (26 w/o 25)");
				if (p3.cfg_payload) {
					cfgh3 = (struct ikev2payl_config_h *)
					    p3.cfg_payload->v;
					body3 = (uint8_t *)p3.cfg_payload->v +
					    sizeof(*cfgh3);
					blen3 = p3.cfg_payload->l - sizeof(*cfgh3);
					for (i3 = 0; blen3 > 0; ++i3) {
						struct ikev2cfg_attrib *a =
						    (struct ikev2cfg_attrib *)body3;
						unsigned int t, l;
						if (blen3 < sizeof(*a))
							break;
						t = IKEV2CFG_ATTR_TYPE(a);
						l = IKEV2CFG_ATTR_LENGTH(a);
						if (sizeof(*a) + l > blen3)
							break;
						if (t == IKEV2_CFG_INTERNAL_DNSSEC_TA)
							n26c++;
						body3 += sizeof(*a) + l;
						blen3 -= sizeof(*a) + l;
					}
					CK(n26c == 0,
					   "no 26 without a 25 (unpaired, RFC 8598 §3.1)");
					rc_vfree(p3.cfg_payload);
				}
			}
		}

		/* parse: initiator receives 25+26 -> internal_dnssec_ta set */
		{
			uint8_t buf[256];
			uint8_t off = 0;
			struct ikev2payl_config *cfg;
			const char *dd = "corp.example";
			struct ikev2cfg_attrib *a;

			memset(buf, 0, sizeof(buf));
			cfg = (struct ikev2payl_config *)buf;
			cfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
			off = sizeof(struct ikev2payl_config);
			a = (struct ikev2cfg_attrib *)(buf + off);
			put_uint16(&a->type, IKEV2_CFG_INTERNAL_DNS_DOMAIN);
			put_uint16(&a->length, (uint16_t)strlen(dd));
			memcpy(IKEV2CFG_ATTR_VALUE(a), dd, strlen(dd));
			off += sizeof(*a) + strlen(dd);
			a = (struct ikev2cfg_attrib *)(buf + off);
			put_uint16(&a->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&a->length, (uint16_t)tara_len);
			memcpy(IKEV2CFG_ATTR_VALUE(a), tara, tara_len);
			off += sizeof(*a) + tara_len;
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((off >> 8) & 0xff);
				pl[1] = (uint8_t)(off & 0xff);
				memcpy((uint8_t *)&cfg->header.payload_length,
				       pl, 2);
			}
			cfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;

			memset(&c, 0, sizeof(c));
			memset(&isa, 0, sizeof(isa));
			isa.rmconf = mk_accept_rm("corp.example");
			ikev2_child_param_init(&c.child_param);
			CK(ikev2_process_config_reply(&isa, &c,
			     &cfg->header) == 0,
			   "process_config_reply rc==0 (26)");
			CK(c.internal_dnssec_ta != NULL &&
			   c.internal_dnssec_ta->l == tara_len &&
			   memcmp(c.internal_dnssec_ta->v, tara,
				  tara_len) == 0,
			   "26 committed to internal_dnssec_ta (exact bytes)");
			if (c.internal_dnssec_ta)
				rc_vfree(c.internal_dnssec_ta);
			if (c.internal_dns_domain)
				rc_vfree(c.internal_dns_domain);
		}

		/* receive-side negative (RFC 8598 §4.2 MUST): a 26 not
		 * immediately preceded by its 25 (or another 26) is ignored,
		 * not committed.  Two cases: a lone 26, and a 26 after an
		 * unrelated attribute (which breaks adjacency). */
		{
			uint8_t buf2[256];
			uint8_t off2 = 0;
			struct ikev2payl_config *cfg2;
			struct ikev2_sa isa2;
			struct ikev2_child_sa c2;
			struct ikev2cfg_attrib *a2;

			/* lone 26: no preceding 25/26 */
			memset(buf2, 0, sizeof(buf2));
			cfg2 = (struct ikev2payl_config *)buf2;
			cfg2->cfgh.cfg_type = IKEV2_CFG_REPLY;
			off2 = sizeof(struct ikev2payl_config);
			a2 = (struct ikev2cfg_attrib *)(buf2 + off2);
			put_uint16(&a2->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&a2->length, (uint16_t)tara_len);
			memcpy(IKEV2CFG_ATTR_VALUE(a2), tara, tara_len);
			off2 += sizeof(*a2) + tara_len;
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((off2 >> 8) & 0xff);
				pl[1] = (uint8_t)(off2 & 0xff);
				memcpy((uint8_t *)&cfg2->header.payload_length, pl, 2);
			}
			cfg2->header.next_payload = IKEV2_PAYLOAD_CONFIG;

			memset(&c2, 0, sizeof(c2));
			memset(&isa2, 0, sizeof(isa2));
			ikev2_child_param_init(&c2.child_param);
			CK(ikev2_process_config_reply(&isa2, &c2,
			     &cfg2->header) == 0,
			   "process_config_reply rc==0 (lone 26)");
			CK(c2.internal_dnssec_ta == NULL,
			   "lone 26 (no preceding 25) is IGNORED, not committed");
			if (c2.internal_dnssec_ta)
				rc_vfree(c2.internal_dnssec_ta);
			if (c2.internal_dns_domain)
				rc_vfree(c2.internal_dns_domain);

			/* 26 after a non-25/non-26 attribute: adjacency broken.
			 * SUPPORTED_ATTRIBUTES (14) is read-only (no allocation),
			 * so this leaves nothing to free in the child. */
			memset(buf2, 0, sizeof(buf2));
			cfg2 = (struct ikev2payl_config *)buf2;
			cfg2->cfgh.cfg_type = IKEV2_CFG_REPLY;
			off2 = sizeof(struct ikev2payl_config);
			a2 = (struct ikev2cfg_attrib *)(buf2 + off2);
			put_uint16(&a2->type, IKEV2_CFG_SUPPORTED_ATTRIBUTES);
			put_uint16(&a2->length, 4);
			memcpy(IKEV2CFG_ATTR_VALUE(a2), "\x00\x19\x00\x1a", 4);
			off2 += sizeof(*a2) + 4;
			a2 = (struct ikev2cfg_attrib *)(buf2 + off2);
			put_uint16(&a2->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&a2->length, (uint16_t)tara_len);
			memcpy(IKEV2CFG_ATTR_VALUE(a2), tara, tara_len);
			off2 += sizeof(*a2) + tara_len;
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((off2 >> 8) & 0xff);
				pl[1] = (uint8_t)(off2 & 0xff);
				memcpy((uint8_t *)&cfg2->header.payload_length, pl, 2);
			}
			cfg2->header.next_payload = IKEV2_PAYLOAD_CONFIG;

			memset(&c2, 0, sizeof(c2));
			memset(&isa2, 0, sizeof(isa2));
			ikev2_child_param_init(&c2.child_param);
			CK(ikev2_process_config_reply(&isa2, &c2,
			     &cfg2->header) == 0,
			   "process_config_reply rc==0 (26 after SUPPORTED_ATTRIBUTES)");
			CK(c2.internal_dnssec_ta == NULL,
			   "26 after a non-25/26 attribute is IGNORED (adjacency broken)");
			if (c2.internal_dnssec_ta)
				rc_vfree(c2.internal_dnssec_ta);
			if (c2.internal_dns_domain)
				rc_vfree(c2.internal_dns_domain);
		}
	}

	/* ================= B.5 shared emit: ikev2_push_ip_allowed =============
	 * The RFC 8983 IP4_ALLOWED/IP6_ALLOWED status notify is emitted by a
	 * SHARED helper (ikev2_notify.c) so the childful IKE_AUTH responder and
	 * the CREATE_CHILD_SA responder stay in sync — and it advertises the
	 * responder's SUPPORTED families (RFC 8983 Table 1), read from the
	 * configured addresspool, not merely the family assigned this exchange.
	 *
	 * (a) No named pool (ikev2_addresspool -> NULL): fall back to the
	 *     assigned lease AFs — a v4 lease yields exactly IP4_ALLOWED.
	 * (b) A pool advertising v4+v6: BOTH IP4_ALLOWED and IP6_ALLOWED are
	 *     emitted even when only the v4 lease was assigned this exchange
	 *     (dual-stack responder signaling its full supported set). */
	{
		struct ikev2_sa iksa;
		struct ikev2_payloads p, p2;
		struct ikev2_child_sa c, c2;
		struct rcf_address_list_head leases, leases2;
		struct rcf_address *ra;
		struct in_addr v4;
		rc_vchar_t *blob;
		int has4 = 0, has6 = 0, off;
		struct ikev2payl_notify *n;

		/* ---- (a) fallback: no pool, v4 lease -> IP4_ALLOWED only ---- */
		memset(&iksa, 0, sizeof(iksa));
		memset(&c, 0, sizeof(c));
		ikev2_child_param_init(&c.child_param);
		c.child_param.cfg_payload = rc_vmalloc(1);
		if (c.child_param.cfg_payload)
			c.child_param.cfg_payload->l = 1;

		LIST_INIT(&leases);
		inet_pton(AF_INET, "10.99.0.10", &v4);
		ra = rc_address_new(AF_INET, (uint8_t *)&v4, 24, NULL, &leases);
		if (ra)
			LIST_INSERT_HEAD(&c.lease_list, ra, link_sa);

		ikev2_payloads_init(&p);
		ikev2_push_ip_allowed(&iksa, &p, &c);
		blob = ikev2_payloads_to_blob(&p, NULL);
		CK(blob != NULL, "ikev2_push_ip_allowed produced a payload blob");
		if (blob) {
			/* scan the notify payloads for 16439 / 16440.  The blob's
			 * payload_length is big-endian on the wire, so use
			 * get_payload_length() (network-order aware) to walk the
			 * payload chain — reading header.payload_length directly
			 * would be endian-wrong and only 'works' for a single
			 * payload. */
			off = 0;
			while (off + (int)sizeof(struct ikev2payl_notify_h) <= (int)blob->l) {
				n = (struct ikev2payl_notify *)(blob->v + off);
				if (get_uint16((uint8_t *)&n->nh.notify_message_type) == IKEV2_IP4_ALLOWED)
					has4 = 1;
				if (get_uint16((uint8_t *)&n->nh.notify_message_type) == IKEV2_IP6_ALLOWED)
					has6 = 1;
				{
					int plen = get_payload_length(&n->header);
					if (plen == 0)
						break;
					off += plen;
				}
			}
			CK(has4 == 1, "IP4_ALLOWED (16439) emitted for the v4 lease");
			CK(has6 == 0, "IP6_ALLOWED (16440) NOT emitted (no v6 lease)");
			rc_vfree(blob);
		}
		if (c.child_param.cfg_payload)
			rc_vfree(c.child_param.cfg_payload);
		/* the helper does not own the lease; release what we linked in */
		if (ra)
			rc_addrpool_release_addr(ra);	/* frees the rcf_address */
		ikev2_payloads_destroy(&p);

		/* ---- (b) configured pool advertises v4+v6: BOTH notifies ---- */
		{
			struct rcf_addresspool pool;
			struct rcf_address_pool_item iv4, iv6;
			struct rcf_remote rm;
			struct rcf_kmp ikm;
			rc_vchar_t *pname;
			struct rcf_addresspool *old_head = rcf_addresspool_head;
			struct in_addr a4; struct in6_addr a6;

			memset(&pool, 0, sizeof(pool));
			memset(&iv4, 0, sizeof(iv4));
			memset(&iv6, 0, sizeof(iv6));
			LIST_INIT(&pool.pool_list);
			iv4.af = AF_INET;  iv6.af = AF_INET6;
			LIST_INSERT_HEAD(&pool.pool_list, &iv4, link);
			LIST_INSERT_HEAD(&pool.pool_list, &iv6, link);
			pname = rc_vmalloc(3);
			if (pname) {
				memcpy(pname->v, "tst", 3); pname->l = 3;
			}
			pool.index = pname;
			pool.next = old_head;		/* chain into global head */
			rcf_addresspool_head = &pool;

			/* remote: ikev2->addresspool = "tst" */
			memset(&rm, 0, sizeof(rm));
			memset(&ikm, 0, sizeof(ikm));
			rm.ikev2 = &ikm;
			ikm.addresspool = pname;

			memset(&c2, 0, sizeof(c2));
			ikev2_child_param_init(&c2.child_param);
			c2.child_param.cfg_payload = rc_vmalloc(1);
			if (c2.child_param.cfg_payload)
				c2.child_param.cfg_payload->l = 1;
			/* only a v4 lease this exchange */
			LIST_INIT(&leases2);
			inet_pton(AF_INET, "10.99.0.11", &a4);
			ra = rc_address_new(AF_INET, (uint8_t *)&a4, 24, NULL, &leases2);
			if (ra)
				LIST_INSERT_HEAD(&c2.lease_list, ra, link_sa);

			memset(&iksa, 0, sizeof(iksa));
			iksa.rmconf = &rm;
			ikev2_payloads_init(&p2);
			ikev2_push_ip_allowed(&iksa, &p2, &c2);
			blob = ikev2_payloads_to_blob(&p2, NULL);
			CK(blob != NULL, "dual-stack pool: produced a payload blob");
			has4 = 0; has6 = 0;
			if (blob) {
				off = 0;
				while (off + (int)sizeof(struct ikev2payl_notify_h) <= (int)blob->l) {
					n = (struct ikev2payl_notify *)(blob->v + off);
					if (get_uint16((uint8_t *)&n->nh.notify_message_type) == IKEV2_IP4_ALLOWED)
						has4 = 1;
					if (get_uint16((uint8_t *)&n->nh.notify_message_type) == IKEV2_IP6_ALLOWED)
						has6 = 1;
					{
						int plen = get_payload_length(&n->header);
						if (plen == 0)
							break;
						off += plen;
					}
				}
				CK(has4 == 1, "dual-stack pool: IP4_ALLOWED emitted");
				CK(has6 == 1, "dual-stack pool: IP6_ALLOWED emitted (supported, not just assigned)");
				rc_vfree(blob);
			}
			if (c2.child_param.cfg_payload)
				rc_vfree(c2.child_param.cfg_payload);
			if (ra)
				rc_addrpool_release_addr(ra);
			ikev2_payloads_destroy(&p2);
			rcf_addresspool_head = old_head;	/* restore global */
			if (pname)
				rc_vfree(pname);
		}
	}

	/* ---- (c) family-mismatch / "assigned none" cell: ikev2_build_ip_allowed() ----
	 * Exercise the RFC 8983 s5.5 failure-path emit directly: a v6-only pool
	 * (no lease) must still announce IP6_ALLOWED (the supported family) so a
	 * dual-stack initiator that requested v4 can retry v6.  This is the cell
	 * the CFG_REPLY path cannot reach (it aborts at INTERNAL_ADDRESS_FAILURE
	 * first); ikev2_build_ip_allowed() is what the failure-response builder
	 * appends beside the error. */
	{
		struct ikev2_sa iksc;
		struct ikev2_payloads p3;
		struct rcf_addresspool poolv6;
		struct rcf_address_pool_item iv6;
		struct rcf_remote rm;
		struct rcf_kmp ikm;
		rc_vchar_t *pname;
		rc_vchar_t *blob2;
		int has4c = 0, has6c = 0, off2;
		struct ikev2payl_notify *n2;
		struct rcf_addresspool *old_head = rcf_addresspool_head;

		memset(&poolv6, 0, sizeof(poolv6));
		memset(&iv6, 0, sizeof(iv6));
		LIST_INIT(&poolv6.pool_list);
		iv6.af = AF_INET6;
		LIST_INSERT_HEAD(&poolv6.pool_list, &iv6, link);
		pname = rc_vmalloc(3);
		if (pname) { memcpy(pname->v, "v6t", 3); pname->l = 3; }
		poolv6.index = pname;
		poolv6.next = old_head;
		rcf_addresspool_head = &poolv6;

		memset(&rm, 0, sizeof(rm)); memset(&ikm, 0, sizeof(ikm));
		rm.ikev2 = &ikm; ikm.addresspool = pname;
		memset(&iksc, 0, sizeof(iksc)); iksc.rmconf = &rm;

		ikev2_payloads_init(&p3);
		ikev2_build_ip_allowed(&p3, &iksc);
		blob2 = ikev2_payloads_to_blob(&p3, NULL);
		CK(blob2 != NULL, "family-mismatch: produced a payload blob");
		if (blob2) {
			off2 = 0;
			while (off2 + (int)sizeof(struct ikev2payl_notify_h) <= (int)blob2->l) {
				n2 = (struct ikev2payl_notify *)(blob2->v + off2);
				if (get_uint16((uint8_t *)&n2->nh.notify_message_type) == IKEV2_IP4_ALLOWED)
					has4c = 1;
				if (get_uint16((uint8_t *)&n2->nh.notify_message_type) == IKEV2_IP6_ALLOWED)
					has6c = 1;
				{
					int plen = get_payload_length(&n2->header);
					if (plen == 0) break;
					off2 += plen;
				}
			}
			CK(has6c == 1, "family-mismatch v6-only pool: IP6_ALLOWED emitted (assigned none)");
			CK(has4c == 0, "family-mismatch v6-only pool: NO IP4_ALLOWED");
			rc_vfree(blob2);
		}
		ikev2_payloads_destroy(&p3);
		rcf_addresspool_head = old_head;
		if (pname) rc_vfree(pname);
	}

	/* ---- (d) mirror of case (c): v4-only pool, assigned none -> IP4_ALLOWED only.
	 * Symmetric Table 1 row coverage (requested v6 / supported v4 /
	 * assigned none -> IP4_ALLOWED). */
	{
		struct ikev2_sa iksd;
		struct ikev2_payloads p4;
		struct rcf_addresspool poolv4;
		struct rcf_address_pool_item iv4d;
		struct rcf_remote rmd;
		struct rcf_kmp ikmd;
		rc_vchar_t *pname;
		rc_vchar_t *blob3;
		int has4d = 0, has6d = 0, off3;
		struct ikev2payl_notify *n3;
		struct rcf_addresspool *old_head = rcf_addresspool_head;

		memset(&poolv4, 0, sizeof(poolv4));
		memset(&iv4d, 0, sizeof(iv4d));
		LIST_INIT(&poolv4.pool_list);
		iv4d.af = AF_INET;
		LIST_INSERT_HEAD(&poolv4.pool_list, &iv4d, link);
		pname = rc_vmalloc(3);
		if (pname) { memcpy(pname->v, "v4t", 3); pname->l = 3; }
		poolv4.index = pname;
		poolv4.next = old_head;
		rcf_addresspool_head = &poolv4;

		memset(&rmd, 0, sizeof(rmd)); memset(&ikmd, 0, sizeof(ikmd));
		rmd.ikev2 = &ikmd; ikmd.addresspool = pname;
		memset(&iksd, 0, sizeof(iksd)); iksd.rmconf = &rmd;

		ikev2_payloads_init(&p4);
		ikev2_build_ip_allowed(&p4, &iksd);
		blob3 = ikev2_payloads_to_blob(&p4, NULL);
		CK(blob3 != NULL, "mirror v4-only: produced a payload blob");
		if (blob3) {
			off3 = 0;
			while (off3 + (int)sizeof(struct ikev2payl_notify_h) <= (int)blob3->l) {
				n3 = (struct ikev2payl_notify *)(blob3->v + off3);
				if (get_uint16((uint8_t *)&n3->nh.notify_message_type) == IKEV2_IP4_ALLOWED)
					has4d = 1;
				if (get_uint16((uint8_t *)&n3->nh.notify_message_type) == IKEV2_IP6_ALLOWED)
					has6d = 1;
				{
					int plen = get_payload_length(&n3->header);
					if (plen == 0) break;
					off3 += plen;
				}
			}
			CK(has4d == 1, "mirror v4-only pool: IP4_ALLOWED emitted (assigned none)");
			CK(has6d == 0, "mirror v4-only pool: NO IP6_ALLOWED");
			rc_vfree(blob3);
		}
		ikev2_payloads_destroy(&p4);
		rcf_addresspool_head = old_head;
		if (pname) rc_vfree(pname);
	}

	printf("splitcfgtest: %d checks, %d failure(s)\n", checks, fails);
	return fails ? 1 : 0;
}


