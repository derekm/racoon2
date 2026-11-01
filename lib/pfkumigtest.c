/*
 * Unit test for the PF_KEY no-SADB_X_MIGRATE path (lib/if_pfkeyv2.c,
 * pfk_migrate_userspace): the SADB_ADD built from a dumped SA carries the
 * new endpoints and everything else unchanged, minus LIFETIME_CURRENT; the
 * SADB_DELETE names the old SA; a dumped policy has only the templates on
 * the old endpoints (and our reqid) rewritten.  Kernel-free, so it runs on
 * every PF_KEY build: FreeBSD, NetBSD and Linux --with-kernel-pfkey.
 *
 * Copyright (C) 2026 racoon2 contributors.  BSD-3-Clause (see COPYRIGHT).
 */
#include "if_pfkeyv2.c"

#include <arpa/inet.h>

static int fails;

#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %s:%d: ", \
	__func__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void
mksin(struct sockaddr_in *s, const char *a)
{
	memset(s, 0, sizeof(*s));
	s->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
	s->sin_len = sizeof(*s);
#endif
	inet_pton(AF_INET, a, &s->sin_addr);
}

static const char *
ntoa(const struct sockaddr *sa)
{
	static char b[4][INET_ADDRSTRLEN];
	static int i;

	i = (i + 1) & 3;
	inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr,
	    b[i], sizeof(b[i]));
	return b[i];
}

static uint8_t *
put(uint8_t *p, int type, const void *body, size_t blen)
{
	struct sadb_ext *x = (struct sadb_ext *)p;
	size_t l = PFKEY_ALIGN8(sizeof(*x) + blen);

	memset(p, 0, l);
	x->sadb_ext_len = PFKEY_UNIT64(l);
	x->sadb_ext_type = type;
	memcpy(p + sizeof(*x), body, blen);
	return p + l;
}

static uint8_t *
putaddr(uint8_t *p, int type, const char *a)
{
	struct sadb_address *ad = (struct sadb_address *)p;
	struct sockaddr_in s;
	size_t l = PFKEY_ALIGN8(sizeof(*ad) + sizeof(s));

	memset(p, 0, l);
	mksin(&s, a);
	ad->sadb_address_len = PFKEY_UNIT64(l);
	ad->sadb_address_exttype = type;
	ad->sadb_address_proto = IPSEC_ULPROTO_ANY;
	ad->sadb_address_prefixlen = 32;
	memcpy(ad + 1, &s, sizeof(s));
	return p + l;
}

/* a dumped ESP SA 192.0.2.1 -> 192.0.2.2, with a key and lifetimes */
static size_t
mksa(uint8_t *buf)
{
	struct sadb_msg *m = (struct sadb_msg *)buf;
	uint8_t *p = buf + sizeof(*m);
	struct sadb_sa sa;
	uint8_t key[sizeof(struct sadb_key) - sizeof(struct sadb_ext) + 32];
	uint8_t lt[sizeof(struct sadb_lifetime) - sizeof(struct sadb_ext)];

	memset(m, 0, sizeof(*m));
	m->sadb_msg_version = PF_KEY_V2;
	m->sadb_msg_type = SADB_DUMP;
	m->sadb_msg_satype = SADB_SATYPE_ESP;
	m->sadb_msg_errno = 3;
	m->sadb_msg_reserved = 2;	/* Linux: refcount */
	m->sadb_msg_seq = 0;
	m->sadb_msg_pid = 77;
	memset(&sa, 0, sizeof(sa));
	sa.sadb_sa_spi = htonl(0x1234);
	sa.sadb_sa_replay = 32;
	sa.sadb_sa_state = SADB_SASTATE_MATURE;
	p = put(p, SADB_EXT_SA, (uint8_t *)&sa + sizeof(struct sadb_ext),
	    sizeof(sa) - sizeof(struct sadb_ext));
	memset(lt, 0x11, sizeof(lt));
	p = put(p, SADB_EXT_LIFETIME_CURRENT, lt, sizeof(lt));
	p = put(p, SADB_EXT_LIFETIME_HARD, lt, sizeof(lt));
	p = putaddr(p, SADB_EXT_ADDRESS_SRC, "192.0.2.1");
	p = putaddr(p, SADB_EXT_ADDRESS_DST, "192.0.2.2");
	memset(key, 0x5a, sizeof(key));
	((struct sadb_key *)(key - sizeof(struct sadb_ext)))->sadb_key_bits = 256;
	p = put(p, SADB_EXT_KEY_ENCRYPT, key, sizeof(key));
	m->sadb_msg_len = PFKEY_UNIT64(p - buf);
	return p - buf;
}

static void
t_mkadd_mkdel(void)
{
	uint8_t buf[1024];
	struct sockaddr_in o_s, o_d, n_s, n_d;
	struct rcpfk_msg rc;
	rc_vchar_t *a, *d;
	struct sadb_msg *m;
	struct sadb_address *ad;
	struct sadb_sa *sa;

	mksa(buf);
	mksin(&o_s, "192.0.2.1"); mksin(&o_d, "192.0.2.2");
	mksin(&n_s, "192.0.2.1"); mksin(&n_d, "192.0.2.9");
	memset(&rc, 0, sizeof(rc));
	rc.sa_src = (struct sockaddr *)&o_s; rc.sa_dst = (struct sockaddr *)&o_d;
	rc.sa2_src = (struct sockaddr *)&n_s; rc.sa2_dst = (struct sockaddr *)&n_d;
	a = pfk_umig_mkadd((struct sadb_msg *)buf, &rc, 41);
	CHECK(a != NULL, "mkadd failed");
	if (a == NULL)
		return;
	m = (struct sadb_msg *)a->v;
	CHECK(m->sadb_msg_type == SADB_ADD, "type %d", m->sadb_msg_type);
	CHECK(m->sadb_msg_errno == 0 && m->sadb_msg_reserved == 0,
	    "errno %d reserved %d", m->sadb_msg_errno, m->sadb_msg_reserved);
	CHECK(m->sadb_msg_seq == 41, "seq %u", m->sadb_msg_seq);
	CHECK(PFKEY_UNUNIT64(m->sadb_msg_len) == a->l, "len %u vs %zu",
	    m->sadb_msg_len, a->l);
	CHECK(pfk_umig_ext(m, SADB_EXT_LIFETIME_CURRENT) == NULL,
	    "LIFETIME_CURRENT kept");
	CHECK(pfk_umig_ext(m, SADB_EXT_LIFETIME_HARD) != NULL,
	    "LIFETIME_HARD dropped");
	CHECK(pfk_umig_ext(m, SADB_EXT_KEY_ENCRYPT) != NULL, "key dropped");
	sa = (struct sadb_sa *)pfk_umig_ext(m, SADB_EXT_SA);
	CHECK(sa != NULL && sa->sadb_sa_spi == htonl(0x1234), "SPI lost");
	ad = (struct sadb_address *)pfk_umig_ext(m, SADB_EXT_ADDRESS_DST);
	CHECK(ad && strcmp(ntoa((struct sockaddr *)(ad + 1)), "192.0.2.9") == 0,
	    "dst %s", ad ? ntoa((struct sockaddr *)(ad + 1)) : "-");
	ad = (struct sadb_address *)pfk_umig_ext(m, SADB_EXT_ADDRESS_SRC);
	CHECK(ad && strcmp(ntoa((struct sockaddr *)(ad + 1)), "192.0.2.1") == 0,
	    "src %s", ad ? ntoa((struct sockaddr *)(ad + 1)) : "-");
	rc_vfree(a);

	d = pfk_umig_mkdel((struct sadb_msg *)buf, 42);
	CHECK(d != NULL, "mkdel failed");
	if (d == NULL)
		return;
	m = (struct sadb_msg *)d->v;
	CHECK(m->sadb_msg_type == SADB_DELETE, "type %d", m->sadb_msg_type);
	CHECK(m->sadb_msg_reserved == 0, "reserved %d", m->sadb_msg_reserved);
	CHECK(pfk_umig_ext(m, SADB_EXT_KEY_ENCRYPT) == NULL, "key in DELETE");
	ad = (struct sadb_address *)pfk_umig_ext(m, SADB_EXT_ADDRESS_DST);
	CHECK(ad && strcmp(ntoa((struct sockaddr *)(ad + 1)), "192.0.2.2") == 0,
	    "DELETE must name the old dst");
	rc_vfree(d);
}

/* policy with two tunnel templates: (old endpoints, reqid 7), (other, 7) */
static void
t_pol_rewrite(void)
{
	uint8_t buf[1024];
	struct sadb_msg *m = (struct sadb_msg *)buf;
	struct sadb_x_policy *xp;
	struct sadb_x_ipsecrequest *r;
	struct sockaddr_in s4[4], o_s, o_d, n_s, n_d;
	struct rcpfk_msg rc;
	uint8_t *p;
	size_t rl = sizeof(*r) + 2 * sizeof(struct sockaddr_in);
	int k;

	memset(buf, 0, sizeof(buf));
	p = putaddr(buf + sizeof(*m), SADB_EXT_ADDRESS_SRC, "10.0.0.1");
	p = putaddr(p, SADB_EXT_ADDRESS_DST, "10.0.0.2");
	xp = (struct sadb_x_policy *)p;
	xp->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	xp->sadb_x_policy_type = IPSEC_POLICY_IPSEC;
	xp->sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	mksin(&s4[0], "192.0.2.1"); mksin(&s4[1], "192.0.2.2");
	mksin(&s4[2], "198.51.100.1"); mksin(&s4[3], "198.51.100.2");
	r = (struct sadb_x_ipsecrequest *)(xp + 1);
	for (k = 0; k < 2; k++) {
		r->sadb_x_ipsecrequest_len = rl;
		r->sadb_x_ipsecrequest_proto = IPPROTO_ESP;
		r->sadb_x_ipsecrequest_mode = IPSEC_MODE_TUNNEL;
		r->sadb_x_ipsecrequest_level = IPSEC_LEVEL_UNIQUE;
		r->sadb_x_ipsecrequest_reqid = 7;
		memcpy(r + 1, &s4[2 * k], sizeof(s4[0]));
		memcpy((uint8_t *)(r + 1) + sizeof(s4[0]), &s4[2 * k + 1],
		    sizeof(s4[0]));
		r = (struct sadb_x_ipsecrequest *)((uint8_t *)r + rl);
	}
	xp->sadb_x_policy_len = PFKEY_UNIT64((uint8_t *)r - (uint8_t *)xp);
	m->sadb_msg_len = PFKEY_UNIT64((uint8_t *)r - buf);

	mksin(&o_s, "192.0.2.1"); mksin(&o_d, "192.0.2.2");
	mksin(&n_s, "192.0.2.5"); mksin(&n_d, "192.0.2.2");
	memset(&rc, 0, sizeof(rc));
	rc.sa_src = (struct sockaddr *)&o_s; rc.sa_dst = (struct sockaddr *)&o_d;
	rc.sa2_src = (struct sockaddr *)&n_s; rc.sa2_dst = (struct sockaddr *)&n_d;
	rc.reqid = 9;	/* another SA's policy: nothing to touch */
	CHECK(pfk_umig_pol_rewrite(m, &rc) == 0, "rewrote a foreign reqid");
	rc.reqid = 7;
	CHECK(pfk_umig_pol_rewrite(m, &rc) == 1, "no template matched");
	r = (struct sadb_x_ipsecrequest *)(xp + 1);
	CHECK(strcmp(ntoa((struct sockaddr *)(r + 1)), "192.0.2.5") == 0,
	    "template 1 src %s", ntoa((struct sockaddr *)(r + 1)));
	r = (struct sadb_x_ipsecrequest *)((uint8_t *)r + rl);
	CHECK(strcmp(ntoa((struct sockaddr *)(r + 1)), "198.51.100.1") == 0,
	    "template 2 touched: %s", ntoa((struct sockaddr *)(r + 1)));
	CHECK(pfk_umig_pol_rewrite(m, &rc) == 0, "rewrote twice");
}

int
main(void)
{
	t_mkadd_mkdel();
	t_pol_rewrite();
	if (fails) {
		printf("pfkumigtest: %d failure(s)\n", fails);
		return 1;
	}
	printf("pfkumigtest: OK\n");
	return 0;
}
