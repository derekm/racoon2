/*
 * rc_net_test - in-tree regression pin for lib/rc_net.c:
 *   CM-01 rcs_addrlist_cmp is a distinct-consumption multiset compare
 *        (symmetry, duplicate reuse, multiplicity, permutation, empties);
 *   CM-03 rcs_in_prefixlen2mask builds all 33 IPv4 masks correctly;
 *   CM-04 invalid prefixes leave the output zeroed (both v4 and v6) and
 *         (N9) are reported with -1, valid ones with 0;
 *   AS-02 rcs_getport rejects out-of-range/truncating/malformed ports;
 *   AS-01 rcs_prefixlen_ok / rcs_getaddrlist bound a prefix by family;
 *   N1    rcs_ifreq_name_eq never over-reads an unterminated ifr_name;
 *   N7    rcs_if_inet6_tentative parses /proc/net/if_inet6 fixtures.
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
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
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

	/* ---- N1/IE-04: ifname vs unterminated IFNAMSIZ ifr_name ---- */
	{
		char full[IFNAMSIZ], term[IFNAMSIZ];
		char longreq[IFNAMSIZ + 4];

		memset(full, 'e', sizeof(full));	/* no NUL anywhere */
		memset(term, 0, sizeof(term));
		memcpy(term, "eth0", 4);
		memset(longreq, 'e', sizeof(longreq) - 1);
		longreq[sizeof(longreq) - 1] = '\0';
		chk("ifreq eq terminated", rcs_ifreq_name_eq("eth0", term), 1);
		chk("ifreq ne terminated", rcs_ifreq_name_eq("eth1", term), 0);
		chk("ifreq prefix ne", rcs_ifreq_name_eq("eth", term), 0);
		/* full-width unterminated name: never read past IFNAMSIZ, and
		 * a request that cannot fit never matches */
		chk("ifreq unterminated vs long req",
		    rcs_ifreq_name_eq(longreq, full), 0);
		longreq[IFNAMSIZ - 1] = '\0';	/* 15 chars: fits */
		chk("ifreq unterminated vs 15-char req",
		    rcs_ifreq_name_eq(longreq, full), 0);
		chk("ifreq NULL", rcs_ifreq_name_eq(NULL, term), 0);
	}

	/* ---- N7/IE-02: /proc/net/if_inet6 parser on fixtures ---- */
	{
		char path[] = "/tmp/r2ifinet6XXXXXX";
		int fd = mkstemp(path);
		FILE *f;
		struct in6_addr a1, a2, a3, a4, a5;

		if (fd < 0 || (f = fdopen(fd, "w")) == NULL)
			exit(2);
		/* addr ifindex prefix scope flags dev  (flags hex: 0x80
		 * PERMANENT, 0x40 TENTATIVE, 0x08 DADFAILED, 0x20 DEPRECATED) */
		fprintf(f,
		    "20010db8000000000000000000000001 02 40 00 80     eth0\n"
		    "20010db8000000000000000000000002 02 40 00 c0     eth0\n"
		    "20010db8000000000000000000000003 02 40 00 88     eth0\n"
		    "20010db8000000000000000000000004 03 40 00 a0     eth1\n"
		    "20010db8000000000000000000000004 02 40 00 40     eth0\n"
		    "20010db8000000000000000000000005 02 40 00 zz     eth0\n"
		    "20010db8000000000000000000000005 02 40\n");
		fclose(f);
		inet_pton(AF_INET6, "2001:db8::1", &a1);
		inet_pton(AF_INET6, "2001:db8::2", &a2);
		inet_pton(AF_INET6, "2001:db8::3", &a3);
		inet_pton(AF_INET6, "2001:db8::4", &a4);
		inet_pton(AF_INET6, "2001:db8::5", &a5);
		chk("if_inet6 permanent usable",
		    rcs_if_inet6_tentative(path, "eth0", &a1), 0);
		chk("if_inet6 tentative",
		    rcs_if_inet6_tentative(path, "eth0", &a2), 1);
		chk("if_inet6 dadfailed",
		    rcs_if_inet6_tentative(path, "eth0", &a3), 1);
		chk("if_inet6 deprecated (not tentative) on eth1",
		    rcs_if_inet6_tentative(path, "eth1", &a4), 0);
		chk("if_inet6 same addr tentative on eth0",
		    rcs_if_inet6_tentative(path, "eth0", &a4), 1);
		chk("if_inet6 any-if first match",
		    rcs_if_inet6_tentative(path, NULL, &a4), 0);
		chk("if_inet6 malformed/short lines skipped",
		    rcs_if_inet6_tentative(path, "eth0", &a5), 0);
		chk("if_inet6 unlisted",
		    rcs_if_inet6_tentative(path, "eth9", &a1), 0);
		unlink(path);
		chk("if_inet6 missing file -> -1",
		    rcs_if_inet6_tentative(path, "eth0", &a1), -1);
	}

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
			if (rcs_in_prefixlen2mask(&m, i) != 0 || m != want) {
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
	chk("v4 invalid -1 reports", rcs_in_prefixlen2mask(&m, -1), -1);
	chk("v4 invalid -1", m == 0, 1);
	m = 0xDEADBEEFu;
	chk("v4 invalid 33 reports", rcs_in_prefixlen2mask(&m, 33), -1);
	chk("v4 invalid 33", m == 0, 1);

	memset(&m6, 0xEE, sizeof(m6));
	chk("v6 invalid 129 reports", rcs_in6_prefixlen2mask(&m6, 129), -1);
	for (i = 0; i < 16; i++)
		if (m6.s6_addr[i] != 0)
			break;
	chk("v6 invalid 129 zeroed", i == 16, 1);

	chk("v6 /64 ok", rcs_in6_prefixlen2mask(&m6, 64), 0);
	chk("v6 invalid -1 reports", rcs_in6_prefixlen2mask(&m6, -1), -1);
	chk("v6 /128 reports 0", rcs_in6_prefixlen2mask(&m6, 128), 0);
	rcs_in6_prefixlen2mask(&m6, 64);
	for (i = 0; i < 16; i++) {
		int want = (i < 8) ? 0xff : 0;
		if (m6.s6_addr[i] != want)
			break;
	}
	chk("v6 /64 correct", i == 16, 1);

	/* ---- AS-02: rcs_getport range/format ---- */
	chk("port 0 (any)", rcs_getport("0"), 0);
	chk("port 500", rcs_getport("500"), 500);
	chk("port 65535", rcs_getport("65535"), 65535);
	chk("port 65536 rejected", rcs_getport("65536"), -1);
	chk("port -1 rejected", rcs_getport("-1"), -1);
	chk("port empty rejected", rcs_getport(""), -1);
	chk("port 80x rejected", rcs_getport("80x"), -1);
	chk("port ' 80' rejected", rcs_getport(" 80"), -1);
	chk("port +80 rejected", rcs_getport("+80"), -1);
	/* 2^32 + 1: fits a 64-bit long, (int) truncation would give 1 */
	chk("port 4294967297 rejected", rcs_getport("4294967297"), -1);
	chk("port 4294967296 rejected", rcs_getport("4294967296"), -1);
	chk("port 2^64+80 rejected (ERANGE)",
	    rcs_getport("18446744073709551696"), -1);
	chk("port any", rcs_getport("any"), 0);

	/* ---- AS-01: prefix length bounded by the address family ---- */
	{
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
		struct sockaddr sx;
		struct rc_addrlist *al = NULL;
		int e;

		memset(&s4, 0, sizeof(s4)); s4.sin_family = AF_INET;
		memset(&s6, 0, sizeof(s6)); s6.sin6_family = AF_INET6;
		memset(&sx, 0, sizeof(sx)); sx.sa_family = AF_UNIX;
		chk("v4 /0 ok", rcs_prefixlen_ok((void *)&s4, 0), 1);
		chk("v4 /32 ok", rcs_prefixlen_ok((void *)&s4, 32), 1);
		chk("v4 /33 rejected", rcs_prefixlen_ok((void *)&s4, 33), 0);
		chk("v4 /64 rejected (family mismatch)",
		    rcs_prefixlen_ok((void *)&s4, 64), 0);
		chk("v4 /-1 rejected", rcs_prefixlen_ok((void *)&s4, -1), 0);
		/* 288 & 0xff == 32: must be rejected before uint8_t narrowing */
		chk("v4 /288 rejected", rcs_prefixlen_ok((void *)&s4, 288), 0);
		chk("v6 /128 ok", rcs_prefixlen_ok((void *)&s6, 128), 1);
		chk("v6 /129 rejected", rcs_prefixlen_ok((void *)&s6, 129), 0);
		chk("unknown family rejected", rcs_prefixlen_ok(&sx, 8), 0);
		chk("NULL address rejected", rcs_prefixlen_ok(NULL, 8), 0);

		e = rcs_getaddrlist("192.0.2.0/24", NULL, RCT_ADDR_INET, &al);
		chk("getaddrlist 192.0.2.0/24 ok", e == 0 && al != NULL &&
		    al->prefixlen == 24, 1);
		rcs_free_addrlist(al); al = NULL;
		e = rcs_getaddrlist("192.0.2.0/33", NULL, RCT_ADDR_INET, &al);
		chk("getaddrlist 192.0.2.0/33 rejected", e != 0 && al == NULL, 1);
		rcs_free_addrlist(al); al = NULL;
		e = rcs_getaddrlist("2001:db8::/129", NULL, RCT_ADDR_INET, &al);
		chk("getaddrlist 2001:db8::/129 rejected", e != 0 && al == NULL, 1);
		rcs_free_addrlist(al); al = NULL;
	}

	printf("RC_NET_TEST_FAILS=%d\n", fails);
	return fails ? 1 : 0;
}
