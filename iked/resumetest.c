/* $Id$ */
/*
 * Resume-dump record-layer unit test (same shape as eaytest/workerstest:
 * check_PROGRAM, printf + exit status).
 *
 * Exercises ikev2_resume_rec.c standalone: key and sockaddr round-trips,
 * filename layout, and r2rs_validate() against a clean record plus each
 * corruption class a resume load can hit on disk (bad magic/version,
 * child-count overrun, oversized key lengths, zero SPIs, bogus lease
 * family).  This is the reviewer's finding #3 gate: save/load
 * serialization was only ever checked with "file exists + magic".
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmbuf.h"
#include "ikev2_resume_rec.h"

static int failures;

#define CHECK(cond, name)						\
	do {								\
		if (cond)						\
			printf("ok %s\n", (name));			\
		else {							\
			printf("not ok %s\n", (name));			\
			failures++;					\
		}							\
	} while (/*CONSTCOND*/0)

static void
fill_rec(struct r2rs_sa *rec)
{
	rc_vchar_t *k;
	int i;

	memset(rec, 0, sizeof(*rec));
	rec->magic = R2RS_MAGIC;
	rec->version = R2RS_VERSION;
	memset(rec->i_ck, 0xaa, 8);
	memset(rec->r_ck, 0xbb, 8);
	rec->is_initiator = 1;
	rec->mobike = 1;
	rec->send_message_id = 7;
	rec->recv_message_id = 6;
	rec->ike_expire_at = 2000000000u;

	k = rc_vnew((const uint8_t *)"\x01\x02\x03\x04", 4);
	r2rs_key_from_vchar(&rec->sk_d, k);
	rc_vfree(k);
	k = rc_vnew((const uint8_t *)"abcdefghijklmnop", 16);
	r2rs_key_from_vchar(&rec->n_i, k);
	rc_vfree(k);

	rec->nchild = 2;
	for (i = 0; i < 2; i++) {
		rec->child[i].in_spi = 0x11111111u + i;
		rec->child[i].out_spi = 0x22222222u + i;
		rec->child[i].expire_at = 2000000100u;
		rec->child[i].satype = 3;	/* ESP */
		strcpy(rec->child[i].sl_index, "sl1");
	}
	rec->child[0].lease_af = AF_INET;
	memcpy(rec->child[0].lease_addr, "\xc0\xa8\x01\x02", 4);
	rec->child[1].lease_af = 0;
}

static void
test_keys(void)
{
	rc_vchar_t *v, *back;
	struct r2rs_key k;
	uint8_t longish[R2RS_MAXKEY + 32];
	int ok;

	/* exact round-trip */
	v = rc_vnew((const uint8_t *)"0123456789abcdef", 16);
	r2rs_key_from_vchar(&k, v);
	back = r2rs_key_to_vchar(&k);
	ok = back && back->l == 16 && memcmp(back->v, v->v, 16) == 0;
	CHECK(ok, "key round-trip 16B");
	rc_vfree(v);
	rc_vfree(back);

	/* NULL/empty in -> zeroed slot -> NULL out */
	r2rs_key_from_vchar(&k, NULL);
	CHECK(k.len == 0 && r2rs_key_to_vchar(&k) == NULL, "key NULL in");
	v = rc_vnew((const uint8_t *)"", 0);
	r2rs_key_from_vchar(&k, v);
	rc_vfree(v);
	CHECK(k.len == 0 && r2rs_key_to_vchar(&k) == NULL, "key empty in");

	/* oversize input truncates to R2RS_MAXKEY, never beyond */
	memset(longish, 0x5a, sizeof(longish));
	v = rc_vnew(longish, sizeof(longish));
	r2rs_key_from_vchar(&k, v);
	rc_vfree(v);
	ok = k.len == R2RS_MAXKEY;
	back = r2rs_key_to_vchar(&k);
	ok = ok && back && back->l == R2RS_MAXKEY;
	rc_vfree(back);
	CHECK(ok, "key oversize truncates to MAXKEY");

	/* boundary: exactly MAXKEY survives untouched */
	v = rc_vnew(longish, R2RS_MAXKEY);
	r2rs_key_from_vchar(&k, v);
	rc_vfree(v);
	back = r2rs_key_to_vchar(&k);
	ok = back && back->l == R2RS_MAXKEY;
	rc_vfree(back);
	CHECK(ok, "key boundary MAXKEY");

	/* hand-corrupted len above MAXKEY is refused, not read past */
	k.len = R2RS_MAXKEY + 1;
	CHECK(r2rs_key_to_vchar(&k) == NULL, "key corrupt len refused");
}

static void
test_sockaddrs(void)
{
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
	struct sockaddr *out;
	uint16_t fam, port;
	uint8_t addr[16];
	int ok;

	memset(&in, 0, sizeof(in));
	in.sin_family = AF_INET;
	in.sin_port = htons(500);
	inet_pton(AF_INET, "203.0.113.7", &in.sin_addr);
	r2rs_sa_to_wire((struct sockaddr *)&in, &fam, &port, addr);
	out = r2rs_wire_to_sa(fam, port, addr);
	ok = out && out->sa_family == AF_INET && port == 500 &&
	    memcmp(&((struct sockaddr_in *)out)->sin_addr,
		&in.sin_addr, 4) == 0;
	CHECK(ok, "sockaddr v4 round-trip");
	free(out);

	memset(&in6, 0, sizeof(in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_port = htons(4500);
	inet_pton(AF_INET6, "2001:db8::1", &in6.sin6_addr);
	r2rs_sa_to_wire((struct sockaddr *)&in6, &fam, &port, addr);
	out = r2rs_wire_to_sa(fam, port, addr);
	ok = out && out->sa_family == AF_INET6 && port == 4500 &&
	    memcmp(&((struct sockaddr_in6 *)out)->sin6_addr,
		&in6.sin6_addr, 16) == 0;
	CHECK(ok, "sockaddr v6 round-trip");
	free(out);

	/* NULL and unknown family degrade to zeroed / refused */
	r2rs_sa_to_wire(NULL, &fam, &port, addr);
	ok = fam == 0 && port == 0;
	ok = ok && r2rs_wire_to_sa(999, 500, addr) == NULL;
	CHECK(ok, "sockaddr NULL/unknown family");
}

static void
test_filename(void)
{
	char buf[192];
	uint8_t ic[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t rc[8] = {0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1};
	int ok;

	r2rs_filename_in(buf, sizeof(buf), "/d", ic, rc);
	ok = strcmp(buf, "/d/0102030405060708-deadbeef00000001") == 0;
	CHECK(ok, "filename layout cookies-hex");
}

static void
test_validate(void)
{
	struct r2rs_sa rec;

	/* clean record passes */
	fill_rec(&rec);
	CHECK(r2rs_validate(&rec) == 0, "validate clean");

	/* magic / version */
	rec.magic = R2RS_MAGIC ^ 1;
	CHECK(r2rs_validate(&rec) != 0, "validate bad magic");
	fill_rec(&rec);
	rec.version = R2RS_VERSION + 1;
	CHECK(r2rs_validate(&rec) != 0, "validate bad version");

	/* child count overrun */
	fill_rec(&rec);
	rec.nchild = R2RS_MAXCHILD + 1;
	CHECK(r2rs_validate(&rec) != 0, "validate nchild overrun");

	/* every key slot catches a corrupt length */
	fill_rec(&rec);
	rec.sk_pr.len = R2RS_MAXKEY + 1;
	CHECK(r2rs_validate(&rec) != 0, "validate key len corrupt");

	/* child sanity: zero SPI, bogus lease family */
	fill_rec(&rec);
	rec.child[1].in_spi = 0;
	CHECK(r2rs_validate(&rec) != 0, "validate child zero SPI");
	fill_rec(&rec);
	rec.child[0].lease_af = 99;
	CHECK(r2rs_validate(&rec) != 0, "validate child bogus lease_af");

	/* zero children is legal (IKE SA without matures) */
	fill_rec(&rec);
	rec.nchild = 0;
	CHECK(r2rs_validate(&rec) == 0, "validate zero children");

	CHECK(r2rs_validate(NULL) != 0, "validate NULL refused");
}

int
main(void)
{
	test_keys();
	test_sockaddrs();
	test_filename();
	test_validate();

	if (failures) {
		printf("1..%d FAILED %d\n", 0, failures);
		return 1;
	}
	printf("resumetest: all checks passed\n");
	return 0;
}
