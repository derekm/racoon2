/*
 * Q8 / G05: pack/parse round-trip of a resume-restored child proposal.
 *
 * restore_one() rebuilds a child's my_proposal[1] from the dump with
 * ikev2_resume_prop_new() + ikev2_resume_prop_add_trns(), and the dump
 * side snapshots it with ikev2_resume_suite_from_prop().  This drives
 * those helpers through the real packer (ikev2_pack_proposal), the real
 * wire parser (ikev2_get_transforms) and the real matcher
 * (ikev2_match_transforms):
 *   RP-01  wire form: num_t, transform order ENCR/INTEGR/DH/ESN, the
 *          `more` bit MORE on every transform but the last (the packer
 *          derives it from the ->next/->tnext topology), keylen attr,
 *          proposal length.
 *   RP-02  the parsed proposal snapshots back to the same suite.
 *   RP-03  the restored proposal matches its own parsed echo (what the
 *          peer's response carries), i.e. no "does not match my
 *          proposal" on the recovery rekey.
 *   RP-04  AEAD-shaped suite (no INTEGR, no DH) round-trips with 2
 *          transforms.
 */
#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <arpa/inet.h>
#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "ikev2_resume_rec.h"
#include "test_util.h"

TEST_MAIN_STUBS()

static int checks, failures;
#define CHECK(c, n) do { checks++; if (c) printf("ok %d - %s\n", checks, n); \
	else { printf("not ok %d - %s\n", checks, n); failures++; } } while (0)

static struct prop_pair **
build(const struct r2rs_child *c)
{
	struct prop_pair **pl = proplist_new();
	struct prop_pair *p;

	if (!pl)
		return NULL;
	p = pl[1] = ikev2_resume_prop_new(IKEV2PROPOSAL_ESP, c->in_spi);
	if (!p)
		return NULL;
	if (ikev2_resume_prop_add_trns(p, IKEV2TRANSFORM_TYPE_ENCR,
	    c->encr_id, c->encr_klen) != 0)
		return NULL;
	if (c->integr_id && ikev2_resume_prop_add_trns(p,
	    IKEV2TRANSFORM_TYPE_INTEGR, c->integr_id, 0) != 0)
		return NULL;
	if (c->dh_id && ikev2_resume_prop_add_trns(p, IKEV2TRANSFORM_TYPE_DH,
	    c->dh_id, 0) != 0)
		return NULL;
	if (ikev2_resume_prop_add_trns(p, IKEV2TRANSFORM_TYPE_ESN,
	    c->esn ? 1 : 0, 0) != 0)
		return NULL;
	return pl;
}

static void
roundtrip(const char *tag, const struct r2rs_child *c, int ntrns,
    const uint8_t *types)
{
	struct prop_pair **pl = build(c);
	rc_vchar_t *buf;
	struct isakmp_pl_p *ph;
	uint8_t *q, *end;
	struct prop_pair *parsed;
	struct r2rs_child back;
	char name[128];
	int i, ok;
	uint32_t spi;

	snprintf(name, sizeof(name), "%s: built", tag);
	CHECK(pl != NULL, name);
	if (!pl)
		return;
	/* RP-00 in-memory topology: one node per distinct type on ->next,
	 * no alternatives on ->tnext (what the matcher/packer expect) */
	{
		struct prop_pair *t;

		ok = 1;
		i = 0;
		for (t = pl[1]->tnext; t; t = t->next, i++) {
			struct ikev2transform *tr =
			    (struct ikev2transform *)t->trns;
			if (i >= ntrns || t->tnext ||
			    tr->transform_type != types[i])
				ok = 0;
		}
		ok = ok && i == ntrns;
		snprintf(name, sizeof(name), "%s: RP-00 types on ->next", tag);
		CHECK(ok, name);
	}
	buf = ikev2_pack_proposal(pl);
	snprintf(name, sizeof(name), "%s: packed", tag);
	CHECK(buf != NULL, name);
	if (!buf)
		return;

	/* RP-01 wire form */
	ph = (struct isakmp_pl_p *)buf->v;
	memcpy(&spi, ph + 1, 4);
	ok = ph->num_t == ntrns && ph->proto_id == IKEV2PROPOSAL_ESP &&
	    ph->spi_size == 4 && ntohl(spi) == c->in_spi &&
	    get_uint16(&ph->h.len) == buf->l &&
	    ph->h.np == ISAKMP_NPTYPE_NONE;
	snprintf(name, sizeof(name), "%s: RP-01 proposal header", tag);
	CHECK(ok, name);
	q = (uint8_t *)(ph + 1) + 4;
	end = (uint8_t *)buf->v + buf->l;
	ok = 1;
	for (i = 0; i < ntrns; i++) {
		struct ikev2transform *t = (struct ikev2transform *)q;
		uint16_t tl;

		if (q + sizeof(*t) > end) {
			ok = 0;
			break;
		}
		tl = get_uint16(&t->transform_length);
		if (t->transform_type != types[i] ||
		    t->more != (i == ntrns - 1 ? IKEV2TRANSFORM_LAST :
		    IKEV2TRANSFORM_MORE))
			ok = 0;
		if (types[i] == IKEV2TRANSFORM_TYPE_ENCR && c->encr_klen) {
			uint8_t *a = (uint8_t *)(t + 1);
			if (tl != sizeof(*t) + 4 ||
			    get_uint16(a) != (0x8000 | 14) ||
			    get_uint16(a + 2) != c->encr_klen)
				ok = 0;
		}
		q += tl;
	}
	ok = ok && q == end;
	snprintf(name, sizeof(name),
	    "%s: RP-01 transform order, more bits, keylen, length", tag);
	CHECK(ok, name);

	/* RP-02 parse back + snapshot */
	parsed = ikev2_get_transforms(&ikev2_doi,
	    (caddr_t)((uint8_t *)(ph + 1) + 4), ph);
	snprintf(name, sizeof(name), "%s: RP-02 parsed", tag);
	CHECK(parsed != NULL, name);
	if (!parsed)
		return;
	memset(&back, 0xee, sizeof(back));
	ikev2_resume_suite_from_prop(parsed, &back);
	ok = back.encr_id == c->encr_id && back.encr_klen == c->encr_klen &&
	    back.integr_id == c->integr_id && back.dh_id == c->dh_id &&
	    back.esn == c->esn;
	snprintf(name, sizeof(name), "%s: RP-02 suite survives the wire", tag);
	CHECK(ok, name);
	memset(&back, 0xee, sizeof(back));
	ikev2_resume_suite_from_prop(pl[1], &back);
	ok = back.encr_id == c->encr_id && back.encr_klen == c->encr_klen &&
	    back.integr_id == c->integr_id && back.dh_id == c->dh_id &&
	    back.esn == c->esn;
	snprintf(name, sizeof(name), "%s: RP-02 snapshot of rebuilt prop", tag);
	CHECK(ok, name);

	/* RP-03 matcher accepts the echo and keeps EVERY type (a proposal
	 * whose distinct types sit on ->tnext matches on ENCR alone and
	 * silently drops INTEGR) */
	{
		struct prop_pair *m = ikev2_match_transforms(&ikev2_doi,
		    pl[1], parsed), *t;

		ok = m != NULL;
		i = 0;
		for (t = m; ok && t; t = t->next, i++) {
			struct ikev2transform *tr =
			    (struct ikev2transform *)t->trns;
			if (i >= ntrns || !tr || tr->transform_type != types[i])
				ok = 0;
		}
		ok = ok && i == ntrns;
		snprintf(name, sizeof(name),
		    "%s: RP-03 matches parsed echo with all %d types", tag,
		    ntrns);
		CHECK(ok, name);
		proppair_discard(m);
	}
	proppair_discard(parsed);
	proplist_discard(pl);
	rc_vfree(buf);
}

int
main(int argc, char **argv)
{
	struct r2rs_child c;
	static const uint8_t full[] = {IKEV2TRANSFORM_TYPE_ENCR,
	    IKEV2TRANSFORM_TYPE_INTEGR, IKEV2TRANSFORM_TYPE_DH,
	    IKEV2TRANSFORM_TYPE_ESN};
	static const uint8_t aead[] = {IKEV2TRANSFORM_TYPE_ENCR,
	    IKEV2TRANSFORM_TYPE_ESN};

	(void)argc;
	test_init(argv[0]);

	memset(&c, 0, sizeof(c));
	c.in_spi = 0xc0ffee01;
	c.encr_id = 12;		/* AES-CBC */
	c.encr_klen = 256;
	c.integr_id = 12;	/* HMAC-SHA2-256-128 */
	c.dh_id = 19;		/* ECP-256 PFS */
	c.esn = 1;
	roundtrip("cbc+sha256+ecp256+esn", &c, 4, full);

	memset(&c, 0, sizeof(c));
	c.in_spi = 0xc0ffee02;
	c.encr_id = 20;		/* AES-GCM-16 */
	c.encr_klen = 128;
	roundtrip("RP-04 gcm no-integ no-pfs", &c, 2, aead);

	printf("1..%d\n", checks);
	return failures ? 1 : 0;
}
