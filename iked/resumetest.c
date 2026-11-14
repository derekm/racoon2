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
#include <stddef.h>
#include <string.h>

#include "vmbuf.h"
#include "ikev2_resume_rec.h"

static int checks;
static int failures;

#define CHECK(cond, name)						\
	do {								\
		checks++;						\
		if (cond)						\
			printf("ok %d - %s\n", checks, (name));		\
		else {							\
			printf("not ok %d - %s\n", checks, (name));	\
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

	/* oversize input is refused, never truncated into a slot that
	 * restore would treat as complete */
	memset(longish, 0x5a, sizeof(longish));
	v = rc_vnew(longish, sizeof(longish));
	ok = r2rs_key_from_vchar(&k, v) != 0 && k.len == 0;
	rc_vfree(v);
	CHECK(ok, "key oversize refused");

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
	{
		struct r2rs_key *slots[] = {
		    &rec.sk_d, &rec.sk_ai, &rec.sk_ar, &rec.sk_ei,
		    &rec.sk_er, &rec.sk_pi, &rec.sk_pr,
		    &rec.n_i, &rec.n_r, &rec.id_i, &rec.id_r,
		};
		size_t ns = sizeof(slots) / sizeof(slots[0]);
		size_t s;
		int all = 1;
		for (s = 0; s < ns; s++) {
			uint16_t save = slots[s]->len;
			slots[s]->len = R2RS_MAXKEY + 1;
			if (r2rs_validate(&rec) == 0)
				all = 0;
			slots[s]->len = save;
		}
		CHECK(all, "validate key len corrupt (all 11 slots)");
	}

	/* child sanity: zero SPI, bogus lease family */
	fill_rec(&rec);
	rec.child[1].in_spi = 0;
	CHECK(r2rs_validate(&rec) != 0, "validate child zero SPI");
	fill_rec(&rec);
	rec.child[0].lease_af = 99;
	CHECK(r2rs_validate(&rec) != 0, "validate child bogus lease_af");

	/* unterminated fixed-size strings: strlen consumers must
	 * never see an index that fills the array with no NUL */
	fill_rec(&rec);
	memset(rec.rm_index, 'x', R2RS_MAXSTR);
	CHECK(r2rs_validate(&rec) != 0, "validate rm_index unterminated");
	fill_rec(&rec);
	memset(rec.child[0].sl_index, 'y', R2RS_MAXSTR);
	CHECK(r2rs_validate(&rec) != 0, "validate sl_index unterminated");

	/* RFC 9370 ADDKE (v3): pending flag with sane link passes;
	 * pending with zero method / oversized link is rejected. */
	fill_rec(&rec);
	rec.child[0].addke_pending = 1;
	rec.child[0].addke_method = 36;
	rec.child[0].addke_link_len = 16;
	memcpy(rec.child[0].addke_link, "0123456789abcdef", 16);
	CHECK(r2rs_validate(&rec) == 0, "validate pending ADDKE child");
	fill_rec(&rec);
	rec.child[0].addke_pending = 1;
	rec.child[0].addke_method = 0;
	rec.child[0].addke_link_len = 16;
	memcpy(rec.child[0].addke_link, "0123456789abcdef", 16);
	CHECK(r2rs_validate(&rec) != 0, "validate pending ADDKE no method");
	fill_rec(&rec);
	rec.child[0].addke_pending = 1;
	rec.child[0].addke_method = 36;
	rec.child[0].addke_link_len = R2RS_MAXSTR + 1;
	CHECK(r2rs_validate(&rec) != 0, "validate pending ADDKE bad link len");

	/* v5: fragment form binds nfrags and per-frag lengths */
	fill_rec(&rec);
	rec.resp_nfrags = 1;
	rec.resp_frag_len[0] = R2RS_MAXFRAG;
	CHECK(r2rs_validate(&rec) == 0, "validate single frag ok");
	fill_rec(&rec);
	rec.resp_nfrags = R2RS_MAXFRAGS + 1;
	CHECK(r2rs_validate(&rec) != 0, "validate nfrags overrun");
	fill_rec(&rec);
	rec.resp_nfrags = 1;
	rec.resp_frag_len[0] = R2RS_MAXFRAG + 1;
	CHECK(r2rs_validate(&rec) != 0, "validate frag len overrun");
	fill_rec(&rec);
	rec.resp_nfrags = R2RS_MAXFRAGS;
	for (int fi = 0; fi < R2RS_MAXFRAGS; fi++)
		rec.resp_frag_len[fi] = R2RS_MAXFRAG;
	/* MAXFRAGS*MAXFRAG == MAXRESP: boundary is legal */
	CHECK(r2rs_validate(&rec) == 0, "validate frag total boundary ok");
	fill_rec(&rec);
	rec.resp_len = 100;
	rec.resp_nfrags = 1;
	rec.resp_frag_len[0] = R2RS_MAXFRAG;
	CHECK(r2rs_validate(&rec) != 0, "validate whole+frag both set");

	/* zero children is legal (IKE SA without matures) */
	fill_rec(&rec);
	rec.nchild = 0;
	CHECK(r2rs_validate(&rec) == 0, "validate zero children");

	/* child role is a boolean: 0 (peer-created) or 1 (locally created)
	 * both pass; any other byte is a corrupt dump. */
	fill_rec(&rec);
	rec.child[0].is_initiator = 0;
	rec.child[1].is_initiator = 1;
	CHECK(r2rs_validate(&rec) == 0, "validate child roles 0/1 ok");
	fill_rec(&rec);
	rec.child[0].is_initiator = 2;
	CHECK(r2rs_validate(&rec) != 0, "validate child role corrupt");

	CHECK(r2rs_validate(NULL) != 0, "validate NULL refused");
}

/*
 * Legacy-record loader.  The mirror structs below are the v3..v6
 * on-disk layouts copied from the headers that wrote them (child record
 * without the v7 dh_id, v4 resp_buf[2048], v5 frag table, v6 cert_due),
 * written independently of r2rs_parse()'s offset arithmetic.  The
 * literal sizes are what those builds wrote to disk.
 */
struct leg_child {
	uint32_t in_spi, out_spi, expire_at;
	uint8_t satype, lease_af, lease_addr[16];
	char sl_index[R2RS_MAXSTR];
	uint16_t encr_id, integr_id, encr_klen;
	uint8_t esn;
	uint8_t is_initiator;
	uint8_t addke_pending, addke_link_len;
	uint16_t addke_method;
	char addke_link[R2RS_MAXSTR];
} __attribute__((packed));

#define LEG_HEAD_FIELDS							\
	uint8_t head[offsetof(struct r2rs_sa, child)];			\
	struct leg_child child[R2RS_MAXCHILD];

struct leg_v3 { LEG_HEAD_FIELDS } __attribute__((packed));
struct leg_v4 { LEG_HEAD_FIELDS
	uint32_t resp_msgid; uint16_t resp_len; uint8_t resp_buf[2048];
} __attribute__((packed));
struct leg_v6 { LEG_HEAD_FIELDS
	uint32_t resp_msgid; uint16_t resp_len; uint16_t resp_nfrags;
	uint16_t resp_frag_len[R2RS_MAXFRAGS]; uint8_t resp_buf[R2RS_MAXRESP];
	uint32_t cert_due;
} __attribute__((packed));

static void
leg_fill(uint8_t *head, struct leg_child *ch, uint32_t version,
    struct r2rs_sa *ref)
{
	int i;

	fill_rec(ref);
	ref->version = version;
	ref->nchild = 2;
	for (i = 0; i < 2; i++) {
		struct r2rs_child *c = &ref->child[i];

		c->in_spi = 0x1000 + i;
		c->out_spi = 0x2000 + i;
		c->expire_at = 1900000000u + i;
		c->satype = 3;
		c->lease_af = AF_INET;
		c->lease_addr[3] = 10 + i;
		snprintf(c->sl_index, sizeof(c->sl_index), "sl%d", i);
		c->encr_id = 12;
		c->integr_id = 12 + i;
		c->encr_klen = 256;
		c->esn = 1;
		c->dh_id = 0;	/* not on disk before v7 */
		c->is_initiator = (uint8_t)i;
		c->addke_pending = (uint8_t)i;
		c->addke_link_len = i ? 5 : 0;
		c->addke_method = i ? 36 : 0;
		if (i)
			memcpy(c->addke_link, "LINK!", 5);

		ch[i].in_spi = c->in_spi;
		ch[i].out_spi = c->out_spi;
		ch[i].expire_at = c->expire_at;
		ch[i].satype = c->satype;
		ch[i].lease_af = c->lease_af;
		memcpy(ch[i].lease_addr, c->lease_addr, 16);
		memcpy(ch[i].sl_index, c->sl_index, R2RS_MAXSTR);
		ch[i].encr_id = c->encr_id;
		ch[i].integr_id = c->integr_id;
		ch[i].encr_klen = c->encr_klen;
		ch[i].esn = c->esn;
		ch[i].is_initiator = c->is_initiator;
		ch[i].addke_pending = c->addke_pending;
		ch[i].addke_link_len = c->addke_link_len;
		ch[i].addke_method = c->addke_method;
		memcpy(ch[i].addke_link, c->addke_link, R2RS_MAXSTR);
	}
	memcpy(head, ref, offsetof(struct r2rs_sa, child));
}

static void
test_legacy(void)
{
	static struct leg_v3 v3;
	static struct leg_v4 v4;
	static struct leg_v6 v6;
	static struct r2rs_sa ref, got;
	static uint8_t big[sizeof(struct r2rs_sa) + 1];
	int ok;

	/* sizes those builds actually wrote */
	CHECK(sizeof(v3) == 2258 && r2rs_wire_size(3) == 2258, "v3 size 2258");
	CHECK(sizeof(v4) == 4312 && r2rs_wire_size(4) == 4312, "v4 size 4312");
	CHECK(r2rs_wire_size(5) == 6890, "v5 size 6890");
	CHECK(sizeof(v6) == 6894 && r2rs_wire_size(6) == 6894, "v6 size 6894");
	CHECK(r2rs_wire_size(R2RS_VERSION) == sizeof(struct r2rs_sa),
	    "current size");
	CHECK(r2rs_wire_size(2) == 0 && r2rs_wire_size(R2RS_VERSION + 1) == 0,
	    "unknown versions sized 0");

	/* v6: whole record carried over, child dh_id = 0 */
	memset(&v6, 0, sizeof(v6));
	leg_fill(v6.head, v6.child, 6, &ref);
	ref.resp_msgid = v6.resp_msgid = 9;
	ref.resp_nfrags = v6.resp_nfrags = 2;
	ref.resp_frag_len[0] = v6.resp_frag_len[0] = 500;
	ref.resp_frag_len[1] = v6.resp_frag_len[1] = 300;
	memset(ref.resp_buf, 0x5c, 800);
	memset(v6.resp_buf, 0x5c, 800);
	ref.cert_due = v6.cert_due = 1999999999u;
	ok = r2rs_parse(&got, &v6, sizeof(v6)) == 0;
	CHECK(ok, "v6 parses");
	CHECK(ok && memcmp(&got, &ref, sizeof(got)) == 0,
	    "v6 re-expanded field-for-field (child dh_id 0)");
	CHECK(ok && r2rs_validate(&got) == 0, "v6 validates");
	/* v6 frag table is still bounds-checked (gate is v5, not current) */
	got.resp_frag_len[0] = R2RS_MAXFRAG + 1;
	CHECK(r2rs_validate(&got) != 0, "v6 frag overrun refused");

	/* v5 == v6 minus cert_due */
	{
		uint32_t five = 5;

		memcpy(v6.head + 4, &five, 4);
		ref.version = 5;
		ref.cert_due = 0;
		ok = r2rs_parse(&got, &v6, 6890) == 0;
		CHECK(ok && memcmp(&got, &ref, sizeof(got)) == 0,
		    "v5 re-expanded (cert_due 0)");
		CHECK(r2rs_parse(&got, &v6, sizeof(v6)) != 0,
		    "v5 header with v6 size refused");
	}

	/* v4: 2048-byte resp_buf */
	memset(&v4, 0, sizeof(v4));
	leg_fill(v4.head, v4.child, 4, &ref);
	ref.resp_msgid = v4.resp_msgid = 4;
	ref.resp_len = v4.resp_len = 2048;
	memset(ref.resp_buf, 0x77, 2048);
	memset(v4.resp_buf, 0x77, 2048);
	ok = r2rs_parse(&got, &v4, sizeof(v4)) == 0;
	CHECK(ok && memcmp(&got, &ref, sizeof(got)) == 0, "v4 re-expanded");
	v4.resp_len = 2049;
	CHECK(r2rs_parse(&got, &v4, sizeof(v4)) != 0,
	    "v4 resp_len beyond its 2048 buffer refused");

	/* v3: no tail */
	memset(&v3, 0, sizeof(v3));
	leg_fill(v3.head, v3.child, 3, &ref);
	ok = r2rs_parse(&got, &v3, sizeof(v3)) == 0;
	CHECK(ok && memcmp(&got, &ref, sizeof(got)) == 0, "v3 re-expanded");

	/* current version round-trips byte for byte */
	fill_rec(&ref);
	ref.child[0].dh_id = 19;
	ok = r2rs_parse(&got, &ref, sizeof(ref)) == 0;
	CHECK(ok && memcmp(&got, &ref, sizeof(got)) == 0 &&
	    got.child[0].dh_id == 19, "current record verbatim");

	/* size/version disagreement and junk */
	CHECK(r2rs_parse(&got, &ref, sizeof(ref) - 1) != 0,
	    "current version truncated refused");
	memcpy(big, &ref, sizeof(ref));
	CHECK(r2rs_parse(&got, big, sizeof(big)) != 0,
	    "current version oversized refused");
	CHECK(r2rs_parse(&got, &ref, 6894) != 0,
	    "current header at v6 size refused");
	ref.magic ^= 1;
	CHECK(r2rs_parse(&got, &ref, sizeof(ref)) != 0, "bad magic refused");
	CHECK(r2rs_parse(&got, &ref, 4) != 0, "short header refused");
	CHECK(r2rs_parse(NULL, &ref, sizeof(ref)) != 0 &&
	    r2rs_parse(&got, NULL, sizeof(ref)) != 0, "NULL refused");
}

int
main(void)
{
	test_keys();
	test_sockaddrs();
	test_filename();
	test_validate();
	test_legacy();

	printf("1..%d\n", checks);
	if (failures) {
		printf("# FAILED %d of %d checks\n", failures, checks);
		return 1;
	}
	return 0;
}
