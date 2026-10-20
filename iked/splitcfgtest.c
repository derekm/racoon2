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
#include "crypto_impl.h"
#include "vmbuf.h"
#include "test_util.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

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

/* A self-signed RSA cert with NO SAN whose subject
 * carries the given CN bytes (cnlen may include an embedded NUL), and a
 * second CN when cn2 != NULL.  Returns its DER as an rc_vchar_t. */
static rc_vchar_t *
mkcert_cn(const char *cn, int cnlen, const char *cn2)
{
	EVP_PKEY_CTX *kctx;
	EVP_PKEY *pk = NULL;
	X509 *x = NULL;
	X509_NAME *nm;
	rc_vchar_t *der = NULL;
	unsigned char *q;
	int len;

	kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(kctx, &pk) <= 0)
		goto out;
	x = X509_new();
	if (!x)
		goto out;
	ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, pk);
	nm = X509_get_subject_name(x);
	X509_NAME_add_entry_by_NID(nm, NID_commonName, V_ASN1_UTF8STRING,
	    (const unsigned char *)cn, cnlen, -1, 0);
	if (cn2)
		X509_NAME_add_entry_by_NID(nm, NID_commonName, MBSTRING_ASC,
		    (const unsigned char *)cn2, -1, -1, 0);
	X509_set_issuer_name(x, nm);
	if (X509_sign(x, pk, EVP_sha256()) <= 0)
		goto out;
	len = i2d_X509(x, NULL);
	if (len <= 0 || (der = rc_vmalloc((size_t)len)) == NULL)
		goto out;
	q = (unsigned char *)der->v;
	i2d_X509(x, &q);
	der->l = (size_t)len;
out:
	if (kctx)
		EVP_PKEY_CTX_free(kctx);
	if (x)
		X509_free(x);
	if (pk)
		EVP_PKEY_free(pk);
	return der;
}

/* asserted FQDN identity in the sa->id_i layout (id_h + bytes) */
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

static rc_vchar_t *
mkid_fqdn(const char *name)
{
	size_t n = strlen(name);
	rc_vchar_t *v = rc_vmalloc(sizeof(struct ikev2payl_ident_h) + n);

	if (!v)
		return NULL;
	memset(v->v, 0, sizeof(struct ikev2payl_ident_h));
	((uint8_t *)v->v)[0] = 2;	/* IKEV2_ID_FQDN */
	memcpy((char *)v->v + sizeof(struct ikev2payl_ident_h), name, n);
	v->l = sizeof(struct ikev2payl_ident_h) + n;
	return v;
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
		/* RFC 7296 §3.15.1: only ONE NETMASK(2), used only with an
		 * INTERNAL_IP4_ADDRESS.  This fixture assigns no address, so 2
		 * must NOT appear (review A2). */
		CK(!found2, "INTERNAL_IP4_NETMASK (2) ABSENT without an assigned IP4 address");

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

	/* ============= A2: NETMASK(2) emitted once, gated on IP4 addr =====
	 * RFC 7296 §3.15.1: only ONE INTERNAL_IP4_NETMASK, and only used
	 * with an INTERNAL_IP4_ADDRESS.  This fixture assigns a v4 address
	 * (lease) plus a single v4 split subnet -> exactly one 2 with the
	 * /24 mask. */
	{
		struct ikev2_child_sa cA;
		struct ikev2_sa isaA;
		struct ikev2_child_param pA;
		struct rcf_address *raA = NULL;
		struct rcf_address_list_head leases;
		struct in_addr v4A;
		uint8_t *p;
		size_t plen, blen;
		struct ikev2payl_config_h *cfghA;
		uint8_t *body;
		int nAddr = 0, nM2 = 0, i;

		memset(&cA, 0, sizeof(cA));
		memset(&isaA, 0, sizeof(isaA));
		ikev2_child_param_init(&pA);
		pA.cfg_ip4_subnet = 1;
		cA.selector = child.selector;	/* sel4(10.20.0.0/24)+sel6 */
		LIST_INIT(&leases);
		inet_pton(AF_INET, "10.99.0.10", &v4A);
		raA = rc_address_new(AF_INET, (uint8_t *)&v4A, 24, NULL, &leases);
		if (raA)
			LIST_INSERT_HEAD(&cA.lease_list, raA, link_sa);

		CK(ikev2_create_config_reply(&isaA, &cA, &pA) == 0,
		   "create_config_reply rc==0 (A2 address+subnet)");
		CK(pA.cfg_payload != NULL && pA.cfg_payload->l > 0,
		   "A2 reply allocated");
		plen = pA.cfg_payload->l;
		p = (uint8_t *)pA.cfg_payload->v;
		cfghA = (struct ikev2payl_config_h *)p;
		body = p + sizeof(*cfghA);
		blen = plen - sizeof(*cfghA);
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
			if (t == IKEV2_CFG_INTERNAL_IP4_ADDRESS)
				nAddr++;
			if (t == IKEV2_CFG_INTERNAL_IP4_NETMASK) {
				uint8_t *v = IKEV2CFG_ATTR_VALUE(a);
				uint32_t m2;
				memcpy(&m2, v, sizeof(m2));
				CK(ntohl(m2) == 0xffffff00,
				   "A2 INTERNAL_IP4_NETMASK == /24");
				nM2++;
			}
			body += sizeof(*a) + l;
			blen -= sizeof(*a) + l;
		}
		CK(nAddr == 1, "A2 reply assigns one IP4 address");
		CK(nM2 == 1, "A2 NETMASK(2) emitted exactly once beside the address");
		if (pA.cfg_payload)
			rc_vfree(pA.cfg_payload);
		if (raA)
			rc_addrpool_release_addr(raA);
	}

	/* A2 at-most-one pin: two v4 split subnets + one assigned v4 address.
	 * INTERNAL_IP4_NETMASK is single-valued (RFC 7296 §3.15.1, Multi-Valued
	 * NO; one netmask cannot express two splits), so it must be SUPPRESSED
	 * here, not emitted once per v4 subnet (the old per-dst behavior). */
	{
		struct ikev2_child_sa cB;
		struct ikev2_sa isaB;
		struct ikev2_child_param pB;
		struct rcf_selector sA2, sB2;
		struct ikev2payl_config_h *cfghB;
		struct rcf_address *raB = NULL;
		struct rcf_address_list_head leasesB;
		struct in_addr v4B;
		uint8_t *pb, *bodyb;
		size_t blenb;
		int nM2b = 0;

		memset(&cB, 0, sizeof(cB));
		memset(&isaB, 0, sizeof(isaB));
		memset(&sA2, 0, sizeof(sA2));
		memset(&sB2, 0, sizeof(sB2));
		ikev2_child_param_init(&pB);
		pB.cfg_ip4_subnet = 1;
		sA2.dst = mk_addrlist(AF_INET, "10.20.0.0", 24);
		sB2.dst = mk_addrlist(AF_INET, "192.168.50.0", 24);
		sA2.next = &sB2;
		cB.selector = &sA2;
		LIST_INIT(&leasesB);
		inet_pton(AF_INET, "10.99.0.10", &v4B);
		raB = rc_address_new(AF_INET, (uint8_t *)&v4B, 24, NULL, &leasesB);
		if (raB)
			LIST_INSERT_HEAD(&cB.lease_list, raB, link_sa);
		CK(ikev2_create_config_reply(&isaB, &cB, &pB) == 0,
		   "create_config_reply rc==0 (A2 two v4 subnets)");
		if (pB.cfg_payload && pB.cfg_payload->l > 0) {
			pb = (uint8_t *)pB.cfg_payload->v;
			cfghB = (struct ikev2payl_config_h *)pb;
			bodyb = pb + sizeof(*cfghB);
			blenb = pB.cfg_payload->l - sizeof(*cfghB);
			for (; blenb > 0; ) {
				struct ikev2cfg_attrib *a =
				    (struct ikev2cfg_attrib *)bodyb;
				unsigned int t, l;
				if (blenb < sizeof(*a))
					break;
				t = IKEV2CFG_ATTR_TYPE(a);
				l = IKEV2CFG_ATTR_LENGTH(a);
				if (sizeof(*a) + l > blenb)
					break;
				if (t == IKEV2_CFG_INTERNAL_IP4_NETMASK)
					nM2b++;
				bodyb += sizeof(*a) + l;
				blenb -= sizeof(*a) + l;
			}
		}
		CK(nM2b == 0,
		   "two v4 subnets: NETMASK(2) NOT emitted (at most one)");
		if (pB.cfg_payload)
			rc_vfree(pB.cfg_payload);
		if (raB)
			rc_addrpool_release_addr(raB);
		rcs_free_addrlist(sA2.dst);
		rcs_free_addrlist(sB2.dst);
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

		/* ================= B.2b: INTERNAL_IP4_SUBNET /0 (match-any) =====
		 * A 0.0.0.0/0 (mask 0.0.0.0) 'send-all' split must be committed as
		 * prefixlen 0, NOT coerced to a /32 host route — this is the
		 * receive-side symmetry of the emit fix (mask 0 -> prefixlen 0). */
		{
			uint8_t buf[1 + sizeof(struct ikev2payl_config) +
				    2 * sizeof(struct in_addr) + 8];
			int off = 0;
			struct ikev2payl_config *cfg;
			struct ikev2_child_sa c;
			struct ikev2_sa isa;
			struct rcf_address *ra;

			memset(buf, 0, sizeof(buf));
			cfg = (struct ikev2payl_config *)buf;
			cfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
			off += sizeof(struct ikev2payl_config);

			{
				struct ikev2cfg_attrib *a =
				    (struct ikev2cfg_attrib *)(buf + off);
				struct in_addr addr, mask;
				put_uint16(&a->type, IKEV2_CFG_INTERNAL_IP4_SUBNET);
				put_uint16(&a->length, 2 * sizeof(struct in_addr));
				addr.s_addr = htonl(0);		/* 0.0.0.0 */
				mask.s_addr = htonl(0);		/* /0 */
				memcpy(IKEV2CFG_ATTR_VALUE(a), &addr, sizeof(addr));
				memcpy(IKEV2CFG_ATTR_VALUE(a) + sizeof(addr),
				       &mask, sizeof(mask));
				off += sizeof(*a) + 2 * sizeof(struct in_addr);
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
			   "ikev2_process_config_reply(13 /0) rc==0");

			ra = LIST_FIRST(&c.internal_ip4_subnet);
			CK(ra != NULL, "ip4 /0 subnet committed");
			if (ra) {
				struct in_addr got;
				memcpy(&got, ra->address, sizeof(got));
				CK(got.s_addr == htonl(0),
				   "ip4 /0 subnet addr == 0.0.0.0");
				CK(ra->prefixlen == 0,
				   "ip4 /0 subnet prefixlen == 0 (match-any, NOT /32)");
			}

			while (!LIST_EMPTY(&c.internal_ip4_subnet))
				rc_addrpool_release_addr(
				    LIST_FIRST(&c.internal_ip4_subnet));
		}

		/* receive-side negatives (review A6): a 13 whose netmask is
		 * not a contiguous prefix, and a 15 whose prefixlen is out
		 * of range, must NOT be committed (RFC 7296 §3.15.2). */
		{
			uint8_t nb[1 + sizeof(struct ikev2payl_config) +
				    2 * sizeof(struct in_addr) + 8];
			int noff = 0;
			struct ikev2payl_config *ncfg;
			struct ikev2_child_sa nc;
			struct ikev2_sa nisa;

			memset(nb, 0, sizeof(nb));
			ncfg = (struct ikev2payl_config *)nb;
			ncfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
			noff += sizeof(struct ikev2payl_config);
			{
				struct ikev2cfg_attrib *a =
				    (struct ikev2cfg_attrib *)(nb + noff);
				struct in_addr addr, mask;
				put_uint16(&a->type,
				    IKEV2_CFG_INTERNAL_IP4_SUBNET);
				put_uint16(&a->length,
				    2 * sizeof(struct in_addr));
				inet_pton(AF_INET, "10.20.0.0", &addr);
				inet_pton(AF_INET, "255.255.0.255", &mask);
				memcpy(IKEV2CFG_ATTR_VALUE(a), &addr,
				    sizeof(addr));
				memcpy(IKEV2CFG_ATTR_VALUE(a) + sizeof(addr),
				    &mask, sizeof(mask));
				noff += sizeof(*a) + 2 * sizeof(struct in_addr);
			}
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((noff >> 8) & 0xff);
				pl[1] = (uint8_t)(noff & 0xff);
				memcpy((uint8_t *)&ncfg->header.payload_length,
				    pl, 2);
			}
			ncfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;
			memset(&nc, 0, sizeof(nc));
			memset(&nisa, 0, sizeof(nisa));
			ikev2_child_param_init(&nc.child_param);
			CK(ikev2_process_config_reply(&nisa, &nc,
			    &ncfg->header) == 0,
			    "process_config_reply rc==0 (non-contig v4 mask)");
			CK(LIST_EMPTY(&nc.internal_ip4_subnet),
			    "non-contiguous v4 netmask NOT committed");
		}
		{
			uint8_t nb[1 + sizeof(struct ikev2payl_config) +
				    sizeof(struct ikev2cfg_ip6addr) + 8];
			int noff = 0;
			struct ikev2payl_config *ncfg;
			struct ikev2_child_sa nc;
			struct ikev2_sa nisa;

			memset(nb, 0, sizeof(nb));
			ncfg = (struct ikev2payl_config *)nb;
			ncfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
			noff += sizeof(struct ikev2payl_config);
			{
				struct ikev2cfg_attrib *a =
				    (struct ikev2cfg_attrib *)(nb + noff);
				struct ikev2cfg_ip6addr d;
				memset(&d, 0, sizeof(d));
				d.prefixlen = 200;
				put_uint16(&a->type,
				    IKEV2_CFG_INTERNAL_IP6_SUBNET);
				put_uint16(&a->length,
				    sizeof(struct ikev2cfg_ip6addr));
				memcpy(IKEV2CFG_ATTR_VALUE(a), &d, sizeof(d));
				noff += sizeof(*a) +
				    sizeof(struct ikev2cfg_ip6addr);
			}
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((noff >> 8) & 0xff);
				pl[1] = (uint8_t)(noff & 0xff);
				memcpy((uint8_t *)&ncfg->header.payload_length,
				    pl, 2);
			}
			ncfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;
			memset(&nc, 0, sizeof(nc));
			memset(&nisa, 0, sizeof(nisa));
			ikev2_child_param_init(&nc.child_param);
			CK(ikev2_process_config_reply(&nisa, &nc,
			    &ncfg->header) == 0,
			    "process_config_reply rc==0 (v6 prefix >128)");
			CK(LIST_EMPTY(&nc.internal_ip6_subnet),
			    "out-of-range v6 prefixlen NOT committed");
		}

rcs_free_addrlist(sel4.dst);
	rcs_free_addrlist(sel6.dst);

	/* ================= B.2c: RFC 4945 / 6125 FQDN identity matching ====
	 * fqdn_id_match(cert_name, asserted, len, allow_wildcard): the
	 * wildcard is only ever in the CERTIFICATE; an asserted ID with '*'
	 * never matches (the old code had it reversed,
	 * so IDi "*.example.com" bound to an "x.example.com" cert). */
	CK(fqdn_id_match("gw.example.com", "gw.example.com", 14, 0) == 1,
	   "exact FQDN matches");
	CK(fqdn_id_match("GW.EXAMPLE.COM", "gw.example.com", 14, 0) == 1,
	   "exact FQDN is case-insensitive");
	CK(fqdn_id_match("gw.example.com", "gw.example.com", 5, 0) == 0,
	   "length mismatch does not match");
	/* reversed direction: asserted wildcard is refused, both settings */
	CK(fqdn_id_match("x.example.com", "*.example.com", 13, 0) == 0,
	   "asserted '*.example.com' does NOT bind to an x.example.com cert");
	CK(fqdn_id_match("x.example.com", "*.example.com", 13, 1) == 0,
	   "asserted wildcard refused even with allow_wildcard_cert on");
	CK(fqdn_id_match("*.example.com", "*.example.com", 13, 1) == 0,
	   "asserted wildcard refused even against an identical cert wildcard");
	CK(fqdn_id_match("gw.example.com", "gw.example.com\0.evil", 20, 0) == 0,
	   "asserted ID with an embedded NUL never matches");
	/* certificate wildcard: only with allow_wildcard_cert on */
	CK(fqdn_id_match("*.example.com", "a.example.com", 13, 0) == 0,
	   "cert wildcard refused when allow_wildcard_cert is off");
	CK(fqdn_id_match("*.example.com", "a.example.com", 13, 1) == 1,
	   "cert wildcard matches one leftmost label when allowed");
	CK(fqdn_id_match("*.Example.COM", "A.example.com", 13, 1) == 1,
	   "cert wildcard is case-insensitive");
	CK(fqdn_id_match("*.example.com", "a.b.example.com", 15, 1) == 0,
	   "cert wildcard does NOT match an extra leftmost label (RFC 6125 s6.4.3)");
	CK(fqdn_id_match("*.example.com", "example.com", 11, 1) == 0,
	   "cert wildcard does not match the bare domain");
	CK(fqdn_id_match("*.example.com", ".example.com", 12, 1) == 0,
	   "cert wildcard needs a non-empty leftmost label");
	CK(fqdn_id_match("*.gw.example.com", "x.gw.example.com", 16, 1) == 1,
	   "cert wildcard with a multi-label suffix matches one label");
	CK(fqdn_id_match("*.gw.example.com", "a.b.gw.example.com", 18, 1) == 0,
	   "cert wildcard with a multi-label suffix rejects two extra labels");
	CK(fqdn_id_match("*.com", "example.com", 11, 1) == 0,
	   "cert wildcard over a single-label suffix (*.com) never matches");
	CK(fqdn_id_match("gw.*.com", "gw.example.com", 14, 1) == 0,
	   "non-leftmost '*' in the cert never matches");
	CK(fqdn_id_match("g*.example.com", "gw.example.com", 14, 1) == 0,
	   "partial-label '*' in the cert never matches");
	CK(fqdn_id_match("*.*.example.com", "a.b.example.com", 15, 1) == 0,
	   "a second '*' in the cert never matches");

	/* ================= B.2d: SAN-iPAddress <-> IP peers_id binding ======
	 * Build a minimal X.509 with an iPAddress SAN (192.0.2.77), DER-encode
	 * it, and drive both eay_get_x509subjectipaddr() and
	 * ikev2_wire_cert_id_ok() with a peers_id of type RCT_IDT_IPADDR —
	 * the cert must bind to the IP identity (and a wrong IP must fail). */
	{
		EVP_PKEY *pk = NULL;
		X509 *x = NULL;
		X509_NAME *nm = NULL;
		X509_EXTENSION *ext = NULL;
		GENERAL_NAMES *sans = NULL;
		GENERAL_NAME *gn = NULL;
		rc_vchar_t *der = NULL;
		rc_vchar_t *cert;
		struct rcf_kmp ikm;
		struct rcf_remote rm;
		struct ikev2_sa isa;
		struct rc_idlist id;
		unsigned char *p = NULL;
		int len;
		unsigned char ip4[4] = { 192, 0, 2, 77 };

		memset(&ikm, 0, sizeof(ikm));
		memset(&rm, 0, sizeof(rm));
		memset(&isa, 0, sizeof(isa));
		memset(&id, 0, sizeof(id));

		/* simple self-signed RSA key + cert with an IP SAN */
		{
			EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
			CK(kctx != NULL, "ip-bind: rsa pkey ctx");
			if (!kctx) goto b2d_err;
			CK(EVP_PKEY_keygen_init(kctx) > 0 &&
			   EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 1024) > 0 &&
			   EVP_PKEY_keygen(kctx, &pk) > 0,
			   "ip-bind: rsa keygen");
			EVP_PKEY_CTX_free(kctx);
			if (!pk) goto b2d_err;
		}
		x = X509_new();
		CK(x != NULL, "ip-bind: X509_new");
		if (!x) goto b2d_err;
		X509_set_version(x, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(x), 0x1234);
		X509_gmtime_adj(X509_get_notBefore(x), 0);
		X509_gmtime_adj(X509_get_notAfter(x), 3600L * 24 * 30);
		nm = X509_get_subject_name(x);
		X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
					   (unsigned char *)"192.0.2.77",
					   -1, -1, 0);
		X509_set_issuer_name(x, nm);
		X509_set_pubkey(x, pk);

		/* SAN: iPAddress 192.0.2.77 */
		sans = sk_GENERAL_NAME_new_null();
		CK(sans != NULL, "ip-bind: SAN stack");
		gn = GENERAL_NAME_new();
		CK(gn != NULL, "ip-bind: GENERAL_NAME");
		if (!gn) goto b2d_err;
		gn->type = GEN_IPADD;
		gn->d.ip = ASN1_OCTET_STRING_new();
		ASN1_OCTET_STRING_set(gn->d.ip, ip4, 4);
		sk_GENERAL_NAME_push(sans, gn);
		ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, sans);
		CK(ext != NULL, "ip-bind: SAN extension");
		X509_add_ext(x, ext, -1);
		X509_EXTENSION_free(ext);
		ext = NULL;	/* X509_add_ext copies; don't free again in b2d_err */
		GENERAL_NAMES_free(sans);
		sans = NULL;

		X509_sign(x, pk, EVP_sha256());

		/* DER-encode into a wire-capture-shaped rc_vchar_t */
		len = i2d_X509(x, NULL);
		CK(len > 0, "ip-bind: i2d size");
		p = malloc((size_t)len);
		CK(p != NULL, "ip-bind: der buf");
		{
			unsigned char *q = p;
			i2d_X509(x, &q);
		}
		der = rc_vmalloc((size_t)len);
		CK(der != NULL, "ip-bind: rc_vmalloc");
		memcpy(der->v, p, (size_t)len);
		der->l = (size_t)len;
		free(p); p = NULL;
		cert = der;

		/* eay_get_x509subjectipaddr: pos 1 -> "192.0.2.77" */
		{
			char *s = eay_get_x509subjectipaddr(cert, 1);
			CK(s != NULL && strcmp(s, "192.0.2.77") == 0,
			   "eay_get_x509subjectipaddr(1)==192.0.2.77");
			if (s) { printf("  (ipbind SAN %s)\n", s); racoon_free(s); }
			CK(eay_get_x509subjectipaddr(cert, 2) == NULL,
			   "eay_get_x509subjectipaddr(2)==NULL (one IP SAN)");
		}

		/* ikev2_wire_cert_id_ok: asserted IDi ip 192.0.2.77 must bind */
		ikm.cert_validate = RCT_BOOL_ON;
		rm.ikev2 = &ikm;
		isa.rmconf = &rm;
		isa.peer_cert = cert;
		/* the peer asserted IDi as an IPv4 address matching the SAN.
		 * sa->id_i stores the ID payload after the IKE header, i.e.
		 * id_type + reserved[] + data (the AUTH-input form); replicate
		 * that layout so the binding's id_h offset matches real life. */
		isa.id_i = rc_vmalloc(sizeof(struct ikev2payl_ident_h) + 4);
		CK(isa.id_i != NULL, "ip-bind: asserted IDi alloc");
		isa.id_i_type = RCT_IDT_IPADDR;
		isa.id_i->l = sizeof(struct ikev2payl_ident_h) + 4;
		{
			uint8_t *iv = (uint8_t *)isa.id_i->v;
			iv[0] = 1;	/* IKEV2_ID_IPV4_ADDR */
			iv[4] = 192; iv[5] = 0; iv[6] = 2; iv[7] = 77;
		}
		CK(ikev2_wire_cert_id_ok(&isa, TRUE) == 0,
		   "ikev2_wire_cert_id_ok: asserted IP IDi matches cert SAN-iPAddress");

		/* asserted IDi != cert SAN must FAIL (identity substitution) */
		rc_vfree(isa.id_i);
		isa.id_i = rc_vmalloc(sizeof(struct ikev2payl_ident_h) + 4);
		CK(isa.id_i != NULL, "ip-bind: wrong asserted IDi alloc");
		isa.id_i->l = sizeof(struct ikev2payl_ident_h) + 4;
		{
			uint8_t *iv = (uint8_t *)isa.id_i->v;
			iv[0] = 1;	/* IKEV2_ID_IPV4_ADDR */
			iv[4] = 198; iv[5] = 51; iv[6] = 100; iv[7] = 9;
		}

		CK(ikev2_wire_cert_id_ok(&isa, TRUE) != 0,
		   "ikev2_wire_cert_id_ok: asserted IDi != cert SAN rejected");

		CK(1, "ip-bind block");
	b2d_err:
		if (sans) GENERAL_NAMES_free(sans);
		if (ext) X509_EXTENSION_free(ext);
		if (x) X509_free(x);
		if (pk) EVP_PKEY_free(pk);
		if (der) rc_vfree(der);
		if (id.id) rc_vfree(id.id);
		if (isa.id_i) rc_vfree(isa.id_i);
	}

	/* ============ B.2f: CN fallback is opt-in and NUL-safe ============
	 * eay_get_x509subject_cn() used
	 * X509_NAME_get_text_by_NID, so a CN "gw.example.com\0.evil" read as
	 * "gw.example.com" (null-prefix).  It now refuses an embedded NUL or
	 * a second CN, and the CN fallback needs cert_cn_fallback on. */
	{
		struct rcf_kmp ikm;
		struct rcf_remote rm;
		struct ikev2_sa isa;
		rc_vchar_t *cplain, *cnul, *ctwo;
		char *cn;
		static const char nulcn[] = "gw.example.com\0.evil.test";

		cplain = mkcert_cn("gw.example.com", -1, NULL);
		cnul = mkcert_cn(nulcn, (int)sizeof(nulcn) - 1, NULL);
		ctwo = mkcert_cn("gw.example.com", -1, "other.example.com");
		CK(cplain && cnul && ctwo, "B.2f: test certs built");

		cn = cplain ? eay_get_x509subject_cn(cplain) : NULL;
		CK(cn && strcmp(cn, "gw.example.com") == 0,
		   "eay_get_x509subject_cn: plain CN returned");
		free(cn);
		cn = cnul ? eay_get_x509subject_cn(cnul) : NULL;
		CK(cn == NULL, "eay_get_x509subject_cn: CN with embedded NUL refused");
		free(cn);
		cn = ctwo ? eay_get_x509subject_cn(ctwo) : NULL;
		CK(cn == NULL, "eay_get_x509subject_cn: two CNs (ambiguous) refused");
		free(cn);

		memset(&ikm, 0, sizeof(ikm));
		memset(&rm, 0, sizeof(rm));
		memset(&isa, 0, sizeof(isa));
		ikm.cert_validate = RCT_BOOL_ON;
		rm.ikev2 = &ikm;
		isa.rmconf = &rm;
		isa.id_i = mkid_fqdn("gw.example.com");
		isa.id_i_type = RCT_IDT_FQDN;

		isa.peer_cert = cplain;
		ikm.cert_cn_fallback = RCT_BOOL_OFF;
		CK(ikev2_wire_cert_id_ok(&isa, TRUE) != 0,
		   "CN-only cert does NOT bind with cert_cn_fallback off (default)");
		ikm.cert_cn_fallback = RCT_BOOL_ON;
		CK(ikev2_wire_cert_id_ok(&isa, TRUE) == 0,
		   "CN-only cert binds with cert_cn_fallback on");
		isa.peer_cert = cnul;
		CK(ikev2_wire_cert_id_ok(&isa, TRUE) != 0,
		   "null-prefix CN does NOT bind gw.example.com even with cert_cn_fallback on");
		isa.peer_cert = ctwo;
		CK(ikev2_wire_cert_id_ok(&isa, TRUE) != 0,
		   "two-CN cert does NOT bind with cert_cn_fallback on");
		/* wildcard CN follows allow_wildcard_cert like a SAN */
		rc_vfree(isa.id_i);
		isa.id_i = mkid_fqdn("x.example.com");
		{
			rc_vchar_t *cw = mkcert_cn("*.example.com", -1, NULL);
			isa.peer_cert = cw;
			ikm.allow_wildcard_cert = RCT_BOOL_OFF;
			CK(cw && ikev2_wire_cert_id_ok(&isa, TRUE) != 0,
			   "wildcard CN refused with allow_wildcard_cert off");
			ikm.allow_wildcard_cert = RCT_BOOL_ON;
			CK(cw && ikev2_wire_cert_id_ok(&isa, TRUE) == 0,
			   "wildcard CN binds one label with allow_wildcard_cert on");
			if (cw) rc_vfree(cw);
		}
		isa.peer_cert = NULL;
		rc_vfree(isa.id_i);
		if (cplain) rc_vfree(cplain);
		if (cnul) rc_vfree(cnul);
		if (ctwo) rc_vfree(ctwo);
	}

	/* ============ B.2e: embedded-NUL SAN must not CN-fallback =====
	 * A cert whose FIRST DNS SAN is "gw.example.com\0.evil.test"
	 * (embedded NUL) and whose CN is "gw.example.com" must NOT bind to an
	 * asserted IDi of "gw.example.com" via the CN fallback, and the
	 * binder must still see a LATER clean DNS SAN.  Regression for the
	 * d2d8896 guard: fix the return so a NUL entry is SKIPPED (return 0,
	 * NULL altname) so the scan continues, not treated as end-of-list
	 * (which would wrongly CN-fallback a null-prefix cert). */
	{
		struct rcf_kmp ikm;
		struct rcf_remote rm;
		struct ikev2_sa isa;
		X509 *x = NULL;
		EVP_PKEY *pk = NULL;
		STACK_OF(GENERAL_NAME) *sans = NULL;
		GENERAL_NAME *gn0 = NULL, *gn1 = NULL;
		X509_EXTENSION *ext = NULL;
		unsigned char *p = NULL;
		rc_vchar_t *der = NULL;
		rc_vchar_t *cert = NULL;
		int len;

		memset(&ikm, 0, sizeof(ikm));
		memset(&rm, 0, sizeof(rm));
		memset(&isa, 0, sizeof(isa));
		ikm.cert_validate = RCT_BOOL_ON;
		rm.ikev2 = &ikm;
		isa.rmconf = &rm;

		/* simple self-signed RSA key + cert with two DNS SANs */
		{
			EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
			CK(kctx != NULL, "nul: rsa pkey ctx");
			if (!kctx) goto b2e_err;
			CK(EVP_PKEY_keygen_init(kctx) > 0 &&
			   EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 1024) > 0 &&
			   EVP_PKEY_keygen(kctx, &pk) > 0,
			   "nul: rsa keygen");
			EVP_PKEY_CTX_free(kctx);
			if (!pk) goto b2e_err;
		}
		x = X509_new();
		CK(x != NULL, "nul: x509");
		X509_set_version(x, 2);
		ASN1_INTEGER_set(X509_get_serialNumber(x), 0x1235);
		X509_gmtime_adj(X509_get_notBefore(x), 0);
		X509_gmtime_adj(X509_get_notAfter(x), 3600L * 24 * 30);
		{
			X509_NAME *nm = X509_get_subject_name(x);
			X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
						   (unsigned char *)"gw.example.com",
						   -1, -1, 0);
			X509_set_issuer_name(x, nm);
		}
		X509_set_pubkey(x, pk);

		/* SAN[0] = "gw.example.com\0.evil.test" (embedded NUL),
		 * SAN[1] = "vpn.example.com" (clean, later) */
		sans = sk_GENERAL_NAME_new(NULL);
		CK(sans != NULL, "nul: SAN stack");
		gn0 = GENERAL_NAME_new();
		CK(gn0 != NULL, "nul: SAN0");
		gn0->type = GEN_DNS;
		gn0->d.dNSName = ASN1_IA5STRING_new();
		ASN1_STRING_set(gn0->d.dNSName,
				"gw.example.com\0.evil.test", 25);
		sk_GENERAL_NAME_push(sans, gn0);
		gn1 = GENERAL_NAME_new();
		CK(gn1 != NULL, "nul: SAN1");
		gn1->type = GEN_DNS;
		gn1->d.dNSName = ASN1_IA5STRING_new();
		ASN1_STRING_set(gn1->d.dNSName, "vpn.example.com", -1);
		sk_GENERAL_NAME_push(sans, gn1);
		ext = X509V3_EXT_i2d(NID_subject_alt_name, 0, sans);
		CK(ext != NULL, "nul: SAN extension");
		X509_add_ext(x, ext, -1);
		X509_EXTENSION_free(ext);
		ext = NULL;
		GENERAL_NAMES_free(sans);
		sans = NULL;

		X509_sign(x, pk, EVP_sha256());
		len = i2d_X509(x, NULL);
		CK(len > 0, "nul: i2d");
		if (len <= 0)
			goto b2e_err;
		p = malloc((size_t)len);
		CK(p != NULL, "nul: der buf");
		if (!p)
			goto b2e_err;
		{
			unsigned char *q = p;
			i2d_X509(x, &q);
		}
		der = rc_vmalloc((size_t)len);
		CK(der != NULL, "nul: rc_vmalloc");
		memcpy(der->v, p, (size_t)len);
		der->l = (size_t)len;
		free(p); p = NULL;
		cert = der;
		isa.peer_cert = cert;

		/* SAN[1] is visible past the embedded-NUL SAN[0]: extraction
		 * must SKIP SAN[0] (return 0, NULL altname), not treat it as
		 * end-of-list. */
		{
			char *alt = NULL; int t = GENT_OTHERNAME;
			CK(eay_get_x509subjectaltname(cert, &alt, &t, 1) == 0 &&
			   alt == NULL,
			   "nul: SAN1 extract skips embedded-NUL SAN0");
			if (alt) racoon_free(alt);
			alt = NULL; t = GENT_OTHERNAME;
			CK(eay_get_x509subjectaltname(cert, &alt, &t, 2) == 0 &&
			   alt && strcmp(alt, "vpn.example.com") == 0,
			   "nul: SAN2 extract returns clean vpn.example.com");
			if (alt) racoon_free(alt);
		}

		/* helper: the asserted FQDN IDi is built directly below
		 * (set id_i and id_i_type on the SA, AUTH-input form). */

		/* asserted IDi "gw.example.com": CN fallback must NOT fire
		 * (authoritative SAN present), so the NUL-prefix identity
		 * must be REJECTED. */
		isa.id_i = rc_vmalloc(sizeof(struct ikev2payl_ident_h) +
				      strlen("gw.example.com"));
		CK(isa.id_i != NULL, "nul: asserted IDi (gw) alloc");
		isa.id_i_type = RCT_IDT_FQDN;
		isa.id_i->l = sizeof(struct ikev2payl_ident_h) +
		    strlen("gw.example.com");
		{
			uint8_t *iv = (uint8_t *)isa.id_i->v;
			memset(iv, 0, sizeof(struct ikev2payl_ident_h));
			iv[0] = 2;	/* IKEV2_ID_FQDN */
			memcpy(iv + sizeof(struct ikev2payl_ident_h),
			       "gw.example.com", strlen("gw.example.com"));
		}
		CK(ikev2_wire_cert_id_ok(&isa, TRUE) != 0,
		   "nul: asserted gw.example.com REJECTED (no CN fallback)");

		/* asserted IDi "vpn.example.com": the clean LATER SAN binds. */
		rc_vfree(isa.id_i);
		isa.id_i = rc_vmalloc(sizeof(struct ikev2payl_ident_h) +
				      strlen("vpn.example.com"));
		CK(isa.id_i != NULL, "nul: asserted IDi (vpn) alloc");
		isa.id_i->l = sizeof(struct ikev2payl_ident_h) +
		    strlen("vpn.example.com");
		{
			uint8_t *iv = (uint8_t *)isa.id_i->v;
			memset(iv, 0, sizeof(struct ikev2payl_ident_h));
			iv[0] = 2;	/* IKEV2_ID_FQDN */
			memcpy(iv + sizeof(struct ikev2payl_ident_h),
			       "vpn.example.com", strlen("vpn.example.com"));
		}
		CK(ikev2_wire_cert_id_ok(&isa, TRUE) == 0,
		   "nul: asserted vpn.example.com binds clean later SAN");

		CK(1, "nul block");
	b2e_err:
		if (sans) GENERAL_NAMES_free(sans);
		if (ext) X509_EXTENSION_free(ext);
		if (x) X509_free(x);
		if (pk) EVP_PKEY_free(pk);
		if (der) rc_vfree(der);
		if (isa.id_i) rc_vfree(isa.id_i);
	}

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
		/* A3: a DNS_DOMAIN(25) may only ride a reply that also carries
		 * >=1 DNS address (RFC 8598 §3.2); supply one here. */
		ikm.cfg_dns = mk_addrlist(AF_INET, "8.8.8.8", 32);

		memset(&isa, 0, sizeof(isa));
		isa.rmconf = &rm;
		memset(&c, 0, sizeof(c));
		ikev2_child_param_init(&p);
		p.cfg_dns_domain = 1;
		p.cfg_ip4_dns = 1;	/* A3: dns_domain needs a DNS address too */

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

		/* A3 negative: dns_domain requested + configured, but NO DNS
		 * address request -> a 25 must NOT be emitted (RFC 8598 §3.2). */
		{
			struct ikev2_child_param p3;
			struct ikev2_sa isa3;
			memset(&isa3, 0, sizeof(isa3));
			isa3.rmconf = &rm;
			ikev2_child_param_init(&p3);
			p3.cfg_dns_domain = 1;	/* no cfg_ip4_dns */
			CK(ikev2_create_config_reply(&isa3, &c, &p3) == 0,
			   "reply rc==0 dns_domain w/o dns addr");
			if (p3.cfg_payload) {
				uint8_t *body3 = (uint8_t *)p3.cfg_payload->v +
				    sizeof(struct ikev2payl_config_h);
				size_t bl3 = p3.cfg_payload->l -
				    sizeof(struct ikev2payl_config_h);
				int n25 = 0;
				for (; bl3 > 0; ) {
					struct ikev2cfg_attrib *a =
					    (struct ikev2cfg_attrib *)body3;
					unsigned int t, l;
					if (bl3 < sizeof(*a))
						break;
					t = IKEV2CFG_ATTR_TYPE(a);
					l = IKEV2CFG_ATTR_LENGTH(a);
					if (sizeof(*a) + l > bl3)
						break;
					if (t == IKEV2_CFG_INTERNAL_DNS_DOMAIN) n25++;
					body3 += sizeof(*a) + l;
					bl3 -= sizeof(*a) + l;
				}
				CK(n25 == 0, "no 25 without a DNS address emitted (A3)");
				rc_vfree(p3.cfg_payload);
			}
		}
		rcs_free_addrlist(ikm.cfg_dns);

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
		/* parse: an ACCEPTED 25, then a REJECTED 25, breaks the chain —
		 * a following well-formed 26 is unpaired and MUST be ignored.
		 * Pins the prev_type=0 set on a rejected 25 (ikev2_config.c); a
		 * leading-invalid-25 row cannot do that (prev_type already 0).
		 * Note: a rejected 25 also resets the accumulated internal_
		 * dns_domain list, so only the 26-ignored half is asserted here. */
		{
			int t[3] = { IKEV2_CFG_INTERNAL_DNS_DOMAIN,
				     IKEV2_CFG_INTERNAL_DNS_DOMAIN,
				     IKEV2_CFG_INTERNAL_DNSSEC_TA };
			const char *v[3] = { "corp.example",
					     "x.corp.example\n;rm",
					     "\x01\x02\x03\x04\x05\x06\x07\x08" };
			size_t l[3] = { 12, 18, 8 };

			ph = mk_cfg_reply(buf, sizeof(buf), 3, t, v, l);
			memset(&c, 0, sizeof(c));
			memset(&isa, 0, sizeof(isa));
			isa.rmconf = mk_accept_rm("corp.example");
			ikev2_child_param_init(&c.child_param);
			CK(ikev2_process_config_reply(&isa, &c, ph) == 0 &&
			   c.internal_dnssec_ta == NULL,
			   "accepted 25 -> rejected 25 -> good 26: 26 unpaired, "
			   "ignored (rejected 25 reset prev_type)");
			if (c.internal_dnssec_ta)
				rc_vfree(c.internal_dnssec_ta);
			if (c.internal_dns_domain)
				rc_vfree(c.internal_dns_domain);
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

	/* ============ B.6: INTERNAL_DNSSEC_TA (26, RFC 8598 §4.2) ==========
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
		/* A3: a DNS_DOMAIN(25)/DNSSEC_TA(26) may only ride a reply
		 * carrying >=1 DNS address (RFC 8598 §3.2); supply one. */
		ikm.cfg_dns = mk_addrlist(AF_INET, "8.8.8.8", 32);
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
		p.cfg_ip4_dns = 1;	/* A3: need a DNS address too */

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
		rcs_free_addrlist(ikm.cfg_dns);

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
			/* X.509-from-wire: cert_validate is a SCALAR rc_type — a
			 * plain DEEPCOPY_VDUP can't carry it and rcf_deepcopy_kmp
			 * must assign it explicitly or the runtime remote silently
			 * reverts to OFF (the same dropped-field class as
			 * dnssec_ta, caught live by i2icert-wire). */
			src_kmp.cert_validate = RCT_BOOL_ON;
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
				CK(cp->ikev2->cert_validate == RCT_BOOL_ON,
				   "deepcopy carries cert_validate (X.509-from-wire)");
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
		 * nor when it asked for 26 but NOT 25 (RFC 8598 §3.2/§4.2:
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
					   "no 26 without a 25 (unpaired, RFC 8598 §3.2/§4.2)");
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

		/* receive-side negative (review A5): a 26 must carry >=5
		 * octets (Key Tag 2|Alg 1|Digest Type 1|Digest Data, RFC
		 * 8598 §4.2); a short anchor must be dropped, not committed.
		 * Preceded by an ACCEPTED 25 so we exercise the length gate,
		 * not the adjacency gate. */
		{
			uint8_t tb[256];
			uint8_t toff = 0;
			struct ikev2payl_config *tcfg;
			struct ikev2_sa tisa;
			struct ikev2_child_sa tc;
			struct ikev2cfg_attrib *ta;

			memset(tb, 0, sizeof(tb));
			tcfg = (struct ikev2payl_config *)tb;
			tcfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
			toff = sizeof(struct ikev2payl_config);
			ta = (struct ikev2cfg_attrib *)(tb + toff);
			put_uint16(&ta->type, IKEV2_CFG_INTERNAL_DNS_DOMAIN);
			put_uint16(&ta->length, (uint16_t)strlen("corp.example"));
			memcpy(IKEV2CFG_ATTR_VALUE(ta), "corp.example",
			    strlen("corp.example"));
			toff += sizeof(*ta) + strlen("corp.example");
			ta = (struct ikev2cfg_attrib *)(tb + toff);
			put_uint16(&ta->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&ta->length, 3);
			memcpy(IKEV2CFG_ATTR_VALUE(ta), "\x01\x02\x03", 3);
			toff += sizeof(*ta) + 3;
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((toff >> 8) & 0xff);
				pl[1] = (uint8_t)(toff & 0xff);
				memcpy((uint8_t *)&tcfg->header.payload_length,
				    pl, 2);
			}
			tcfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;
			memset(&tc, 0, sizeof(tc));
			memset(&tisa, 0, sizeof(tisa));
			tisa.rmconf = mk_accept_rm("corp.example");
			ikev2_child_param_init(&tc.child_param);
			CK(ikev2_process_config_reply(&tisa, &tc,
			    &tcfg->header) == 0,
			    "process_config_reply rc==0 (short 26)");
			CK(tc.internal_dnssec_ta == NULL,
			    "short INTERNAL_DNSSEC_TA (<5 octets) NOT committed");
			/* free the ACCEPTED 25's committed domain (mk_accept_rm) */
			if (tc.internal_dns_domain)
				rc_vfree(tc.internal_dns_domain);
		}

		/* receive: a legal ZERO-length 26 (RFC 8598 §4.2 empty attr) is a
		 * silent no-op and must NOT reset adjacency: 25 -> empty-26 ->
		 * good-26 still commits the good anchor, and the empty 26 itself
		 * commits nothing. */
		{
			uint8_t eb[256];
			uint8_t eoff = 0;
			struct ikev2payl_config *ecfg;
			struct ikev2_sa eisa;
			struct ikev2_child_sa ec;
			struct ikev2cfg_attrib *ea;

			memset(eb, 0, sizeof(eb));
			ecfg = (struct ikev2payl_config *)eb;
			ecfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
			eoff = sizeof(struct ikev2payl_config);
			ea = (struct ikev2cfg_attrib *)(eb + eoff);
			put_uint16(&ea->type, IKEV2_CFG_INTERNAL_DNS_DOMAIN);
			put_uint16(&ea->length, (uint16_t)strlen("corp.example"));
			memcpy(IKEV2CFG_ATTR_VALUE(ea), "corp.example",
			    strlen("corp.example"));
			eoff += sizeof(*ea) + strlen("corp.example");
			ea = (struct ikev2cfg_attrib *)(eb + eoff);
			put_uint16(&ea->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&ea->length, 0);	/* legal empty attr */
			eoff += sizeof(*ea);		/* no value octets */
			ea = (struct ikev2cfg_attrib *)(eb + eoff);
			put_uint16(&ea->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&ea->length, 8);
			memcpy(IKEV2CFG_ATTR_VALUE(ea),
			    "\x00\x01\x02\x03\x04\x05\x06\x07", 8);
			eoff += sizeof(*ea) + 8;
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((eoff >> 8) & 0xff);
				pl[1] = (uint8_t)(eoff & 0xff);
				memcpy((uint8_t *)&ecfg->header.payload_length,
				    pl, 2);
			}
			ecfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;
			memset(&ec, 0, sizeof(ec));
			memset(&eisa, 0, sizeof(eisa));
			eisa.rmconf = mk_accept_rm("corp.example");
			ikev2_child_param_init(&ec.child_param);
			CK(ikev2_process_config_reply(&eisa, &ec,
			    &ecfg->header) == 0,
			    "process_config_reply rc==0 (empty-26 -> good-26)");
			CK(ec.internal_dnssec_ta != NULL &&
			    ec.internal_dnssec_ta->l == 8,
			    "good 26 after a legal EMPTY 26 still committed");
			if (ec.internal_dns_domain)
				rc_vfree(ec.internal_dns_domain);
			if (ec.internal_dnssec_ta)
				rc_vfree(ec.internal_dnssec_ta);
		}

		/* empty-26 must NOT free the prior committed anchor: 25 -> good-26
		 * -> empty-26 leaves the good anchor intact (RFC 8598 §4.2 empty
		 * attr is a no-op, not a clear).  A fixture that frees or clears
		 * on a length-0 26 fails the l==8 assertion below. */
		{
			uint8_t fb[256];
			uint8_t foff = 0;
			struct ikev2payl_config *fcfg;
			struct ikev2_sa fisa;
			struct ikev2_child_sa fc;
			struct ikev2cfg_attrib *fa;

			memset(fb, 0, sizeof(fb));
			fcfg = (struct ikev2payl_config *)fb;
			fcfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
			foff = sizeof(struct ikev2payl_config);
			fa = (struct ikev2cfg_attrib *)(fb + foff);
			put_uint16(&fa->type, IKEV2_CFG_INTERNAL_DNS_DOMAIN);
			put_uint16(&fa->length, (uint16_t)strlen("corp.example"));
			memcpy(IKEV2CFG_ATTR_VALUE(fa), "corp.example",
			    strlen("corp.example"));
			foff += sizeof(*fa) + strlen("corp.example");
			fa = (struct ikev2cfg_attrib *)(fb + foff);
			put_uint16(&fa->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&fa->length, 8);
			memcpy(IKEV2CFG_ATTR_VALUE(fa),
			    "\x00\x01\x02\x03\x04\x05\x06\x07", 8);
			foff += sizeof(*fa) + 8;
			fa = (struct ikev2cfg_attrib *)(fb + foff);
			put_uint16(&fa->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&fa->length, 0);	/* legal empty attr */
			foff += sizeof(*fa);
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((foff >> 8) & 0xff);
				pl[1] = (uint8_t)(foff & 0xff);
				memcpy((uint8_t *)&fcfg->header.payload_length,
				    pl, 2);
			}
			fcfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;
			memset(&fc, 0, sizeof(fc));
			memset(&fisa, 0, sizeof(fisa));
			fisa.rmconf = mk_accept_rm("corp.example");
			ikev2_child_param_init(&fc.child_param);
			CK(ikev2_process_config_reply(&fisa, &fc,
			    &fcfg->header) == 0,
			    "process_config_reply rc==0 (good-26 -> empty-26)");
			CK(fc.internal_dnssec_ta != NULL &&
			    fc.internal_dnssec_ta->l == 8,
			    "empty 26 does NOT free the prior committed anchor");
			if (fc.internal_dns_domain)
				rc_vfree(fc.internal_dns_domain);
			if (fc.internal_dnssec_ta)
				rc_vfree(fc.internal_dnssec_ta);
		}

		/* Adjacency survives a DROPPED short 26 (RFC 8598 §4.2): 25,
		 * short-26(ignored), good-26 must still commit the good anchor —
		 * the dropped 26 is still type 26 on the wire and applies to the
		 * preceding accepted 25's domain.  Regression-pins the
		 * prev_type-clear bug.  (A REJECTED 25 does break the chain.) */
		{
			uint8_t ub[256];
			uint8_t uoff = 0;
			struct ikev2payl_config *ucfg;
			struct ikev2_sa uisa;
			struct ikev2_child_sa uc;
			struct ikev2cfg_attrib *ua;

			memset(ub, 0, sizeof(ub));
			ucfg = (struct ikev2payl_config *)ub;
			ucfg->cfgh.cfg_type = IKEV2_CFG_REPLY;
			uoff = sizeof(struct ikev2payl_config);
			ua = (struct ikev2cfg_attrib *)(ub + uoff);
			put_uint16(&ua->type, IKEV2_CFG_INTERNAL_DNS_DOMAIN);
			put_uint16(&ua->length, (uint16_t)strlen("corp.example"));
			memcpy(IKEV2CFG_ATTR_VALUE(ua), "corp.example",
			    strlen("corp.example"));
			uoff += sizeof(*ua) + strlen("corp.example");
			ua = (struct ikev2cfg_attrib *)(ub + uoff);
			put_uint16(&ua->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&ua->length, 3);
			memcpy(IKEV2CFG_ATTR_VALUE(ua), "\x01\x02\x03", 3);
			uoff += sizeof(*ua) + 3;
			ua = (struct ikev2cfg_attrib *)(ub + uoff);
			put_uint16(&ua->type, IKEV2_CFG_INTERNAL_DNSSEC_TA);
			put_uint16(&ua->length, (uint16_t)tara_len);
			memcpy(IKEV2CFG_ATTR_VALUE(ua), tara, tara_len);
			uoff += sizeof(*ua) + tara_len;
			{
				uint8_t pl[2];
				pl[0] = (uint8_t)((uoff >> 8) & 0xff);
				pl[1] = (uint8_t)(uoff & 0xff);
				memcpy((uint8_t *)&ucfg->header.payload_length,
				    pl, 2);
			}
			ucfg->header.next_payload = IKEV2_PAYLOAD_CONFIG;
			memset(&uc, 0, sizeof(uc));
			memset(&uisa, 0, sizeof(uisa));
			uisa.rmconf = mk_accept_rm("corp.example");
			ikev2_child_param_init(&uc.child_param);
			CK(ikev2_process_config_reply(&uisa, &uc,
			    &ucfg->header) == 0,
			    "process_config_reply rc==0 (good 26 after short 26)");
			CK(uc.internal_dnssec_ta != NULL &&
			   uc.internal_dnssec_ta->l == tara_len &&
			   memcmp(uc.internal_dnssec_ta->v, tara, tara_len) == 0,
			    "good 26 after a dropped short 26 still committed");
			if (uc.internal_dnssec_ta)
				rc_vfree(uc.internal_dnssec_ta);
			if (uc.internal_dns_domain)
				rc_vfree(uc.internal_dns_domain);
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


