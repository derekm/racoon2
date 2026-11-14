/* $Id$ */
/*
 * addresspool_test.c -- in-tree regression tests for lib/addresspool.c and
 * the addresspool config parsing in lib/cfsetup.c (AP-01..AP-05).
 *
 * AP-01  rc_addrpool_assign_ip6intf stores/returns/leases the FULL constructed
 *        candidate (pool prefix + interface-ID), not the raw peer bytes, and
 *        rejects constructed candidates below the configured start.
 * AP-02  rc_addrpool_item_new returns NULL (instead of SIGSEGV) when malloc
 *        fails.
 * AP-03  rc_addrpool_move relinks the SAME lease nodes (no allocation, no
 *        failure path), so a move never drops a reservation even under an
 *        injected allocator failure.
 * AP-04  exhaustion guards: a range ending at the address-space (or IPv6
 *        prefix) maximum must FAIL further allocation instead of wrapping
 *        below the configured start.
 * AP-05  the config parser rejects overlapping same-family ranges within one
 *        addresspool.
 *
 * Links the real addresspool.lo / cfsetup.lo objects and provides
 * -Wl,--wrap=malloc/--wrap=calloc/--wrap=free fault injection (same pattern
 * as vmbuf_test).  The exhaustion probes are bounded (tiny ranges) with an
 * alarm(5) time-out so an unbounded wrap on the old code cannot hang the
 * suite.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "racoon.h"
#include "addresspool.h"

/* -------- allocator fault injection (--wrap=malloc/--wrap=calloc/--wrap=free) */
static int g_fail_next = 0;	/* fail the next malloc/calloc, then clear */
static long g_allocs = 0;

extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void __real_free(void *);

void *__wrap_malloc(size_t sz)
{
	if (g_fail_next) { g_fail_next = 0; return NULL; }
	g_allocs++;
	return __real_malloc(sz);
}
void *__wrap_calloc(size_t n, size_t sz)
{
	if (g_fail_next) { g_fail_next = 0; return NULL; }
	g_allocs++;
	return __real_calloc(n, sz);
}
void __wrap_free(void *p)
{
	__real_free(p);
}

/* -------- harness */
static int g_failures = 0;
static const char *g_probe = "?";

#define CHECK(cond, name) \
	do { if (cond) printf("ok:   %s\n", name); \
	     else { printf("FAIL: %s\n", name); g_failures++; } } while (0)

static void on_alarm(int sig)
{
	static const char m[] = "\n[addresspool_test] TIMEOUT in probe: ";
	(void)sig;
	(void)write(2, m, sizeof(m) - 1);
	(void)write(2, g_probe, strlen(g_probe));
	(void)write(2, "\n", 1);
	_exit(1);
}

static int eq4(const uint8_t *a, const char *s)
{
	struct in_addr x;
	inet_pton(AF_INET, s, &x);
	return memcmp(a, &x, 4) == 0;
}

static int eq6(const uint8_t *a, const char *s)
{
	struct in6_addr x;
	inet_pton(AF_INET6, s, &x);
	return memcmp(a, &x, 16) == 0;
}

static struct rcf_addresspool *new_cfg(void)
{
	struct rcf_addresspool *c = malloc(sizeof(*c));
	if (!c) return NULL;
	memset(c, 0, sizeof(*c));
	LIST_INIT(&c->pool_list);
	return c;
}

static struct rcf_address_pool_item *
add_range(struct rcf_addresspool *c, int af, const char *start, const char *end)
{
	struct rcf_address_pool_item *p = rc_addrpool_item_new();
	if (!p) return NULL;
	p->af = af;
	if (inet_pton(af, start, p->start) != 1 ||
	    inet_pton(af, end, p->end) != 1) {
		free(p);
		return NULL;
	}
	LIST_INSERT_HEAD(&c->pool_list, p, link);
	return p;
}

/* release every lease held by a pool item, then the item. */
static void free_pool_item(struct rcf_address_pool_item *p)
{
	struct rcf_address *a, *n;
	if (!p) return;
	for (a = LIST_FIRST(&p->lease_list); a; a = n) {
		n = LIST_NEXT(a, link_pool);
		rc_addrpool_release_addr(a);
	}
	free(p);
}

static void free_list(struct rcf_addresspool *c)
{
	struct rcf_address_pool_item *p, *n;
	if (!c) return;
	for (p = LIST_FIRST(&c->pool_list); p; p = n) {
		n = LIST_NEXT(p, link);
		free_pool_item(p);
	}
	free(c);
}

/* -------- AP-01: assign_ip6intf stores full prefix+intf, lower bound */
static void test_ap01(void)
{
	struct rcf_addresspool *c;
	uint8_t peer[16];
	struct rcf_address *a, *d;
	uint8_t a1[16], a2[16];
	struct rcf_address *pl, *b;

	printf("== AP-01 ==\n");

	/* (a) exact returned bytes = pool prefix + interface-ID, membership,
	 * duplicate rejection, pool prefix authoritative (peer high 64 is 0).
	 * Single /64 prefix so an occupied candidate cannot roll to another
	 * prefix -- duplicate rejection must yield NULL. */
	c = new_cfg(); CHECK(c != NULL, "AP-01 cfg alloc");
	add_range(c, AF_INET6, "2001:db8::10", "2001:db8::20");
	inet_pton(AF_INET6, "::15", peer);
	a = rc_addrpool_assign_ip6intf(c, peer);
	CHECK(a != NULL, "AP-01a assign_ip6intf non-NULL");
	if (a) {
		CHECK(eq6(a->address, "2001:db8::15"),
		      "AP-01a exact bytes = pool prefix + intf-id");
		/* the upper 64 bits must be the pool prefix, not the peer's 0 */
		{
			uint8_t hi[8];
			memcpy(hi, a->address, 8);
			CHECK(memcmp(hi,
			    "\x20\x01\x0d\xb8\x00\x00\x00\x00", 8) == 0,
			      "AP-01a stored high 64 = pool prefix");
		}
	}
	/* duplicate: same candidate must now be rejected (no other prefix) */
	d = rc_addrpool_assign_ip6intf(c, peer);
	CHECK(d == NULL, "AP-01a duplicate candidate rejected");
	free_list(c);

	/* (b) constructed candidate below the configured start is rejected */
	c = new_cfg();
	add_range(c, AF_INET6, "2001:db8:0:1::1", "2001:db8:0:1::ffff");
	memset(peer, 0, sizeof(peer));	/* interface-ID = 0 */
	a = rc_addrpool_assign_ip6intf(c, peer);
	CHECK(a == NULL, "AP-01b candidate below start rejected");
	free_list(c);

	/* (c) occupied candidate forces the next prefix to be tried, and the
	 * returned bytes carry that prefix. */
	c = new_cfg();
	add_range(c, AF_INET6, "2001:db8::", "2001:db8:0:1::ffff");
	inet_pton(AF_INET6, "2001:db8::1", a1);
	pl = rc_addrpool_assign(c, AF_INET6, a1);
	CHECK(pl != NULL, "AP-01c pre-lease first-prefix candidate");
	memset(peer, 0, sizeof(peer)); peer[15] = 1;	/* ::1 */
	b = rc_addrpool_assign_ip6intf(c, peer);
	CHECK(b != NULL, "AP-01c next prefix tried");
	if (b)
		CHECK(eq6(b->address, "2001:db8:0:1::1"),
		      "AP-01c exact bytes at next prefix");
	free_list(c);
}

/* -------- AP-02: ctor NULL on allocation failure */
static void test_ap02(void)
{
	struct rcf_address_pool_item *p;

	printf("== AP-02 ==\n");
	g_fail_next = 1;
	p = rc_addrpool_item_new();
	g_fail_next = 0;
	CHECK(p == NULL, "AP-02 rc_addrpool_item_new NULL on alloc failure");
	if (p) free(p);
}

/* -------- AP-03: move preserves reservations, no failure path */
static void test_ap03(void)
{
	struct rcf_addresspool *c;
	struct rcf_address_list_head src, dst;
	struct rcf_address *x1, *x2, *it, *again1, *again2;
	uint8_t x1b[16], x2b[16];
	int n;

	printf("== AP-03 ==\n");
	c = new_cfg();
	add_range(c, AF_INET, "192.168.1.1", "192.168.1.5");
	LIST_INIT(&src); LIST_INIT(&dst);

	x1 = rc_addrpool_alloc_any(c, AF_INET);
	x2 = rc_addrpool_alloc_any(c, AF_INET);
	CHECK(x1 != NULL && x2 != NULL, "AP-03 alloc two leases");
	if (!x1 || !x2) return;
	LIST_INSERT_HEAD(&src, x1, link_sa);
	LIST_INSERT_HEAD(&src, x2, link_sa);
	memcpy(x1b, x1->address, 16);
	memcpy(x2b, x2->address, 16);

	/* inject an allocator failure: the new relink move has no allocation,
	 * so it must NOT drop either reservation.  Check BOTH leases, since the
	 * pre-fix loop's injected-failure victim is whichever node is at the
	 * head of src. */
	g_fail_next = 1;
	rc_addrpool_move(&dst, &src);
	g_fail_next = 0;

	again1 = rc_addrpool_assign(c, AF_INET, x1b);
	again2 = rc_addrpool_assign(c, AF_INET, x2b);
	CHECK((again1 == NULL) && (again2 == NULL),
	      "AP-03 both reservations preserved (not reassignable)");
	CHECK(LIST_FIRST(&src) == NULL, "AP-03 src list emptied");
	n = 0;
	for (it = LIST_FIRST(&dst); it; it = LIST_NEXT(it, link_sa))
		n++;
	CHECK(n == 2, "AP-03 destination holds both leases");
	free_list(c);
}

/* -------- AP-04: exhaustion / no wrap below start */
static void test_ap04(void)
{
	struct rcf_addresspool *c;
	struct rcf_address *s1, *s2, *t1, *t2, *t3, *pv, *pv2;
	uint8_t maxad[16], peer[16];

	printf("== AP-04 ==\n");

	/* IPv4 singleton at the max address: next alloc must be NULL, not 0.0.0.0 */
	c = new_cfg();
	add_range(c, AF_INET, "255.255.255.255", "255.255.255.255");
	s1 = rc_addrpool_alloc_any(c, AF_INET);
	CHECK(s1 != NULL && eq4(s1->address, "255.255.255.255"),
	      "AP-04 v4 singleton-at-max leased");
	s2 = rc_addrpool_alloc_any(c, AF_INET);
	CHECK(s2 == NULL, "AP-04 v4 no wrap below start (NULL on 2nd alloc)");
	free_list(c);

	/* IPv4 range ending at max, fully leased: 3rd alloc must be NULL. */
	c = new_cfg();
	add_range(c, AF_INET, "255.255.255.254", "255.255.255.255");
	t1 = rc_addrpool_alloc_any(c, AF_INET);
	t2 = rc_addrpool_alloc_any(c, AF_INET);
	CHECK(t1 != NULL && t2 != NULL, "AP-04 v4 two max-ending leases");
	t3 = rc_addrpool_alloc_any(c, AF_INET);
	CHECK(t3 == NULL, "AP-04 v4 exhausted-at-max returns NULL");
	free_list(c);

	/* IPv6 prefix path: singleton at the prefix maximum, occupied; a
	 * further ip6intf assignment must fail, not wrap below start.
	 * (bounded with alarm so the old unbounded prefix loop cannot hang.) */
	alarm(5); g_probe = "AP-04 ip6intf exhaustion";
	c = new_cfg();
	add_range(c, AF_INET6, "ffff:ffff:ffff:ffff:0:0:0:1",
	                    "ffff:ffff:ffff:ffff:0:0:0:1");
	inet_pton(AF_INET6, "ffff:ffff:ffff:ffff:0:0:0:1", maxad);
	pv = rc_addrpool_assign(c, AF_INET6, maxad);
	CHECK(pv != NULL, "AP-04 ip6 max pre-leased");
	memset(peer, 0, sizeof(peer)); peer[15] = 1;	/* interface-ID 1 */
	pv2 = rc_addrpool_assign_ip6intf(c, peer);
	CHECK(pv2 == NULL, "AP-04 ip6intf exhausted (no wrap below start)");
	alarm(0);
	free_list(c);
}

/* -------- AP-05: config parser rejects overlapping ranges */
static int write_cfg(const char *path, const char *body)
{
	FILE *f = fopen(path, "w");
	if (!f) return -1;
	if (fputs(body, f) == EOF) { fclose(f); return -1; }
	return fclose(f);
}

static void test_ap05(void)
{
	static const char *olap =
	    "addresspool ap_olap {\n"
	    "  \"192.168.5.1\" - \"192.168.5.20\";\n"
	    "  \"192.168.5.15\" - \"192.168.5.30\";\n"
	    "};\n";
	static const char *nolap =
	    "addresspool ap_nolap {\n"
	    "  \"192.168.6.1\" - \"192.168.6.20\";\n"
	    "  \"192.168.7.1\" - \"192.168.7.20\";\n"
	    "};\n";
	int r1, r2;

	printf("== AP-05 ==\n");

	if (write_cfg("ap_olap.conf", olap) || write_cfg("ap_nolap.conf", nolap)) {
		CHECK(0, "AP-05 could not write config files");
		return;
	}
	r1 = rcf_read("ap_olap.conf", 0);
	CHECK(r1 != 0, "AP-05 overlapping ranges rejected by config parser");
	rcf_clean();

	r2 = rcf_read("ap_nolap.conf", 0);
	CHECK(r2 == 0, "AP-05 non-overlapping ranges still accepted");
	rcf_clean();

	unlink("ap_olap.conf");
	unlink("ap_nolap.conf");

	/* Every rcf_fix_addresspool rejection must release what it built so
	 * far (the unlinked item, the pool being filled and the pools
	 * already chained).  These are LeakSanitizer-gated in the ASan
	 * lanes: a leak on any of these paths fails the test binary. */
	{
		static const struct {
			const char *label, *cfg;
		} bad[] = {
		    { "overlap after a valid earlier pool",
		      "addresspool ap_ok {\n"
		      "  \"10.9.0.1\" - \"10.9.0.9\";\n"
		      "};\n"
		      "addresspool ap_bad {\n"
		      "  \"10.9.1.1\" - \"10.9.1.9\";\n"
		      "  \"10.9.2.1\" - \"10.9.2.9\";\n"
		      "  \"10.9.2.5\" - \"10.9.2.20\";\n"
		      "};\n" },
		    { "reversed range",
		      "addresspool ap_rev {\n"
		      "  \"10.8.0.1\" - \"10.8.0.9\";\n"
		      "  \"10.8.1.9\" - \"10.8.1.1\";\n"
		      "};\n" },
		    { "start/end family mismatch",
		      "addresspool ap_fam {\n"
		      "  \"10.7.0.1\" - \"10.7.0.9\";\n"
		      "  \"10.7.1.1\" - \"2001:db8::9\";\n"
		      "};\n" },
		    { "unparsable address",
		      "addresspool ap_junk {\n"
		      "  \"10.6.0.1\" - \"10.6.0.9\";\n"
		      "  \"not-an-address\" - \"10.6.1.9\";\n"
		      "};\n" },
		};
		size_t i;
		int rr;

		for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			if (write_cfg("ap_bad.conf", bad[i].cfg)) {
				CHECK(0, "AP-05 could not write config file");
				continue;
			}
			rr = rcf_read("ap_bad.conf", 0);
			printf("   (reject: %s)\n", bad[i].label);
			CHECK(rr != 0, "AP-05 invalid addresspool rejected");
			rcf_clean();
		}
		unlink("ap_bad.conf");
	}
}

int
main(int argc, char **argv)
{
	struct sigaction sa;

	(void)argc; (void)argv;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_alarm;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGALRM, &sa, NULL);

	/* rcf_read() (AP-05) uses the rbuf scratch ring; initialize it like
	 * sample/icketest do before parsing any config. */
	if (rbuf_init(8, 80, 4, 160, 4))
		return 1;

	test_ap01();
	test_ap03();
	test_ap05();
	test_ap04();
	test_ap02();

	printf("addresspool_test: %s (%d failures)\n",
	    g_failures ? "FAIL" : "PASS", g_failures);
	return g_failures ? 1 : 0;
}
