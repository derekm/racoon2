/*
 * rc_pcap_test.c -- lib/rc_pcap.c synthetic capture records (PC-01..05).
 *
 *   PC-01  the synthetic IPv6 header carries version 6 in the HIGH nibble
 *          (first byte 0x60), on every platform (Linux wrote 0x06).
 *   PC-02  a payload that cannot fit the 16-bit IP/UDP length fields is
 *          rejected without writing a record; lengths of a normal record
 *          are internally consistent (caplen == len == eth+ip+udp+payload,
 *          ip6_plen / ip_len / uh_ulen agree).
 *   PC-03  the file-scope stream is not left dangling after init/push,
 *          so a second rc_pcap_init succeeds.
 *   PC-05  the file header snaplen is 0xFFFF (>= every caplen written).
 *
 * plog/plog_location are wrapped to no-ops (no logging context).  The
 * on-disk record header is the 16-byte pcap one (32-bit ts_sec, ts_usec,
 * caplen, len) in host byte order.
 */
#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "racoon.h"

char *__wrap_plog(int tag, const char *location, struct rc_log *plg,
    const char *fmt, ...)
{
	(void)tag; (void)location; (void)plg; (void)fmt;
	return NULL;
}
const char *__wrap_plog_location(const char *file, int line, const char *func)
{
	(void)file; (void)line; (void)func;
	return "rc_pcap_test";
}

static int fails;

static void
ck(int ok, const char *what)
{
	printf("%s: %s\n", ok ? "ok" : "FAIL", what);
	if (!ok)
		fails++;
}

static uint32_t
rd32(const unsigned char *p)
{
	uint32_t v;

	memcpy(&v, p, 4);
	return v;
}

static uint16_t
rd16be(const unsigned char *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static void
mk4(struct sockaddr_storage *ss, const char *a, int port)
{
	struct sockaddr_in *s = (struct sockaddr_in *)ss;

	memset(ss, 0, sizeof(*ss));
	s->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	s->sin_len = sizeof(*s);
#endif
	s->sin_port = htons(port);
	inet_pton(AF_INET, a, &s->sin_addr);
}

static void
mk6(struct sockaddr_storage *ss, const char *a, int port)
{
	struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;

	memset(ss, 0, sizeof(*ss));
	s->sin6_family = AF_INET6;
#ifdef HAVE_SA_LEN
	s->sin6_len = sizeof(*s);
#endif
	s->sin6_port = htons(port);
	inet_pton(AF_INET6, a, &s->sin6_addr);
}

int
main(void)
{
	char path[] = "/tmp/rc_pcap_test.XXXXXX";
	struct sockaddr_storage s4, d4, s6, d6;
	rc_vchar_t *pl, *big;
	unsigned char buf[4096];
	const unsigned char *r, *ip;
	FILE *f;
	size_t n, off;
	int fd;
	const size_t PL = 20, ETH = 14, IP4 = 20, IP6 = 40, UDP = 8;

	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		return 1;
	}
	close(fd);
	unlink(path);		/* rc_pcap_init writes the header on create */

	mk4(&s4, "192.0.2.1", 500);
	mk4(&d4, "192.0.2.2", 500);
	mk6(&s6, "2001:db8::1", 500);
	mk6(&d6, "2001:db8::2", 500);
	pl = rc_vmalloc(PL);
	big = rc_vmalloc(0xFFFF);
	if (!pl || !big)
		return 1;
	memset(pl->v, 0xab, PL);

	ck(rc_pcap_init(path, "a") == 0, "init creates the capture file");
	rc_pcap_push((struct sockaddr *)&s6, (struct sockaddr *)&d6, pl);
	rc_pcap_push((struct sockaddr *)&s6, (struct sockaddr *)&d6, big);
	rc_pcap_push((struct sockaddr *)&s4, (struct sockaddr *)&d4, pl);
	rc_pcap_push((struct sockaddr *)&s4, (struct sockaddr *)&d4, big);
	ck(rc_pcap_init(path, "a") == 0,
	   "PC-03: re-init succeeds (no dangling stream)");

	f = fopen(path, "rb");
	if (!f) {
		perror("fopen");
		return 1;
	}
	n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	unlink(path);

	ck(n == 24 + (16 + ETH + IP6 + UDP + PL) + (16 + ETH + IP4 + UDP + PL),
	   "PC-02: exactly the two in-range records were written");
	if (n < 24 + 16 + ETH + IP6 + UDP + PL + 16 + ETH + IP4 + UDP + PL) {
		ck(0, "capture too short to inspect");
		goto out;
	}
	ck(rd32(buf + 16) == 0xFFFF, "PC-05: file header snaplen 0xFFFF");

	/* record 1: IPv6 */
	off = 24;
	r = buf + off;
	ck(rd32(r + 8) == ETH + IP6 + UDP + PL && rd32(r + 12) == rd32(r + 8),
	   "PC-02: v6 caplen == len == eth+ip6+udp+payload");
	ck(rd16be(r + 16 + 12) == 0x86dd, "v6 ethertype 0x86dd");
	ip = r + 16 + ETH;
	ck(ip[0] == 0x60, "PC-01: v6 first byte 0x60 (version 6 high nibble)");
	ck(rd16be(ip + 4) == UDP + PL, "PC-02: ip6_plen == udp+payload");
	ck(ip[6] == IPPROTO_UDP, "v6 next header UDP");
	ck(rd16be(ip + IP6 + 4) == UDP + PL, "PC-02: v6 uh_ulen == udp+payload");

	/* record 2: IPv4 */
	off += 16 + ETH + IP6 + UDP + PL;
	r = buf + off;
	ck(rd32(r + 8) == ETH + IP4 + UDP + PL && rd32(r + 12) == rd32(r + 8),
	   "PC-02: v4 caplen == len == eth+ip+udp+payload");
	ip = r + 16 + ETH;
	ck(ip[0] == 0x45, "v4 first byte 0x45");
	ck(rd16be(ip + 2) == IP4 + UDP + PL, "PC-02: ip_len == ip+udp+payload");
	ck(rd16be(ip + IP4 + 4) == UDP + PL, "PC-02: v4 uh_ulen == udp+payload");
out:
	rc_vfree(pl);
	rc_vfree(big);
	printf("rc_pcap_test: %s\n", fails ? "FAILED" : "OK");
	return fails ? 1 : 0;
}
