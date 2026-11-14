/*
 * rc_net_test - in-tree regression pin for lib/rc_net.c:
 *   CM-01 rcs_addrlist_cmp is a distinct-consumption multiset compare
 *        (symmetry, duplicate reuse, multiplicity, permutation, empties);
 *   CM-03 rcs_in_prefixlen2mask builds all 33 IPv4 masks correctly;
 *   CM-04 invalid prefixes leave the output zeroed (both v4 and v6).
 *
 * The invalid-mask path logs via plog() before zeroing; plog needs a live
 * logging context, so plog is wrapped (--wrap=plog) to a no-op here, which
 * also keeps test output deterministic.  No kernel/policy state is touched.
 * Extensionless test: the sample-wrapper LOG_COMPILER passes an (ignored)
 * sample config; main() runs its own probes.
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "racoon.h"
#include "rc_net.h"

/* plog/plog_location no-ops so the invalid-prefix path (which logs via the
 * PLOGLOC macro before zeroing) can run without a logging context / rbuf. */
struct rc_log;
char *__wrap_plog(int tag, const char *location, struct rc_log *plg,
    const char *fmt, ...)
{
	(void)tag; (void)location; (void)plg; (void)fmt;
	return NULL;
}
const char *__wrap_plog_location(const char *file, int line, const char *func)
{
	(void)file; (void)line; (void)func;
	return "rc_net_test";
}

static int fails = 0;

static void
chk(const char *name, int got, int want)
{
	printf("%-40s rc=%d want=%d %s\n", name, got, want,
	    got == want ? "ok" : "FAIL");
	if (got != want)
		fails++;
}

/* Build an RCT_ADDR_INET list from dotted-quad strings. */
static struct rc_addrlist *
mkv4(const char *const *ips, int n)
{
	struct rc_addrlist *head = NULL, **lp = &head;
	int i;

	for (i = 0; i < n; i++) {
		struct sockaddr_in sin;
		struct rc_addrlist *ne;
		struct sockaddr *sa;

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
#ifdef HAVE_SA_LEN
		sin.sin_len = sizeof(sin);	/* BSD: SA_LEN uses sa_len */
#endif
		if (inet_pton(AF_INET, ips[i], &sin.sin_addr) != 1) {
			printf("mkv4: bad ip %s\n", ips[i]);
			exit(2);
		}
		sa = rcs_sadup((struct sockaddr *)&sin);
		if (sa == NULL) {
			rcs_free_addrlist(head);
			exit(2);
		}
		ne = rc_calloc(1, sizeof(*ne));
		if (ne == NULL) {
			rc_free(sa);
			rcs_free_addrlist(head);
			exit(2);
		}
		ne->type = RCT_ADDR_INET;
		ne->port = 0;
		ne->prefixlen = 32;
		ne->a.ipaddr = sa;
		*lp = ne;
		lp = &ne->next;
	}
	return head;
}

/* Build a single RCT_ADDR_MACRO node (not matched by rcs_addrlist_cmp). */
static struct rc_addrlist *
mkmacro(void)
{
	struct rc_addrlist *ne = rc_calloc(1, sizeof(*ne));

	if (ne == NULL)
		exit(2);
	ne->type = RCT_ADDR_MACRO;
	ne->port = 0;
	ne->prefixlen = 32;
	ne->a.vstr = rc_vnew("MYIP", 4);
	return ne;
}

int
main(void)
{
	static const char *a[] = { "10.0.0.1" };
	static const char *b[] = { "10.0.0.2" };
	static const char *aa[] = { "10.0.0.1", "10.0.0.1" };
	static const char *ab[] = { "10.0.0.1", "10.0.0.2" };
	static const char *aab[] = { "10.0.0.1", "10.0.0.1", "10.0.0.2" };
	static const char *abb[] = { "10.0.0.1", "10.0.0.2", "10.0.0.2" };
	struct rc_addrlist *x, *y;
	uint32_t m;
	struct in6_addr m6;
	int i;

	/* ---- CM-01: multiset compare ---- */
	x = mkv4(aa, 2); y = mkv4(aa, 2);
	chk("[A,A] vs [A,A]", rcs_addrlist_cmp(x, y), 0);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(aa, 2); y = mkv4(ab, 2);
	chk("[A,A] vs [A,B] (fwd)", rcs_addrlist_cmp(x, y), 1);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(ab, 2); y = mkv4(aa, 2);
	chk("[A,B] vs [A,A] (rev)", rcs_addrlist_cmp(x, y), 1);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(ab, 2); y = mkv4(ab, 2);
	chk("[A,B] vs [A,B]", rcs_addrlist_cmp(x, y), 0);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(a, 1); y = mkv4(aa, 2);
	chk("[A] vs [A,A]", rcs_addrlist_cmp(x, y), 1);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(aa, 2); y = mkv4(a, 1);
	chk("[A,A] vs [A]", rcs_addrlist_cmp(x, y), 1);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(NULL, 0); y = mkv4(NULL, 0);
	chk("[] vs []", rcs_addrlist_cmp(x, y), 0);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(NULL, 0); y = mkv4(a, 1);
	chk("[] vs [A]", rcs_addrlist_cmp(x, y), 1);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(aab, 3); y = mkv4(abb, 3);
	chk("[A,A,B] vs [A,B,B] (multiset)", rcs_addrlist_cmp(x, y), 1);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	x = mkv4(abb, 3); y = mkv4(abb, 3);
	chk("[A,B,B] vs [A,B,B]", rcs_addrlist_cmp(x, y), 0);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	/* permutation: [A,B] vs [B,A] is equal (order-insensitive) */
	{ static const char *ba[] = { "10.0.0.2", "10.0.0.1" };
	  x = mkv4(ab, 2); y = mkv4(ba, 2);
	  chk("[A,B] vs [B,A] (permutation)", rcs_addrlist_cmp(x, y), 0);
	  rcs_free_addrlist(x); rcs_free_addrlist(y); }

	/* RCT_ADDR_MACRO is not matched (default case): two identical
	 * single-macro lists compare unequal. */
	x = mkmacro(); y = mkmacro();
	chk("[M] vs [M] (MACRO unmatched)", rcs_addrlist_cmp(x, y), 1);
	rcs_free_addrlist(x); rcs_free_addrlist(y);

	/* ---- CM-03: all 33 IPv4 prefix masks ---- */
	{
		int masked_fail = 0;

		for (i = 0; i <= 32; i++) {
			uint32_t want = (i == 0) ? 0
			    : (i == 32) ? 0xFFFFFFFFu
			    : (((uint32_t)0xFFFFFFFFu) << (32 - i));
			rcs_in_prefixlen2mask(&m, i);
			if (m != want) {
				printf("mask /%d = 0x%08x want 0x%08x FAIL\n", i,
				    (unsigned)m, (unsigned)want);
				fails++;
				masked_fail = 1;
			}
		}
		printf("v4 masks 0..32 %s\n", masked_fail ? "FAILED" : "passed");
	}

	/* ---- CM-04: invalid -> zeroed output (plog is wrapped) ---- */
	m = 0xDEADBEEFu;
	rcs_in_prefixlen2mask(&m, -1);
	chk("v4 invalid -1", m == 0, 1);
	m = 0xDEADBEEFu;
	rcs_in_prefixlen2mask(&m, 33);
	chk("v4 invalid 33", m == 0, 1);

	memset(&m6, 0xEE, sizeof(m6));
	rcs_in6_prefixlen2mask(&m6, 129);
	for (i = 0; i < 16; i++)
		if (m6.s6_addr[i] != 0)
			break;
	chk("v6 invalid 129 zeroed", i == 16, 1);

	rcs_in6_prefixlen2mask(&m6, 64);
	for (i = 0; i < 16; i++) {
		int want = (i < 8) ? 0xff : 0;
		if (m6.s6_addr[i] != want)
			break;
	}
	chk("v6 /64 correct", i == 16, 1);

	printf("RC_NET_TEST_FAILS=%d\n", fails);
	return fails ? 1 : 0;
}
