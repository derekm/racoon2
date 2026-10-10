/* $Id$ */
/* RFC 5723 ticket-layer KAT (same shape as resumetest/ndcppkats:
 * check_PROGRAM, printf + exit).  Pin the s5.1 SKEYSEED derivation and the
 * ticket-by-value codec round-trip + tamper rejection. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "vmbuf.h"
#include "ikev2_resume_ticket.h"

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

/* fixed 32-octet AES-256 ticket key for the determinism of the codec
 * round-trip (it is a cipher key, but a test fixture — never a real
 * session secret). */
static const uint8_t TKEY[32] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};
/* test key ids */
static const uint8_t KID1[R2TICK_KEY_ID_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8 };
static const uint8_t KID2[R2TICK_KEY_ID_LEN] = { 9, 8, 7, 6, 5, 4, 3, 2 };

static uint8_t skd[32];

static struct r2ticket_state
make_state(uint32_t expires)
{
	struct r2ticket_state st;

	memset(&st, 0, sizeof(st));
	st.expires_at = expires;
	st.auth_method = 7;			/* IKEV2_AUTHMETHOD_ECDSA_SHA1 */
	st.spi_i = 0x0123456789abcdefULL;
	st.spi_r = 0xfedcba9876543210ULL;
	/* static fixture vchar_t data (not heap-owned: freed below) */
	static uint8_t sa[3] = { 0x01, 0x6e, 0x19 };
	static uint8_t idi[4] = { 'I','D','I','_' };
	static uint8_t idr[4] = { 'I','D','R','_' };
	for (int i = 0; i < 32; i++) skd[i] = (uint8_t)i;
	st.sa = rc_vnew(sa, 3);
	st.idi = rc_vnew(idi, 4);
	st.idr = rc_vnew(idr, 4);
	st.sk_d = rc_vnew(skd, 32);
	return st;
}

static void
free_state(struct r2ticket_state *st)
{
	if (st->sa) rc_vfree(st->sa);
	if (st->idi) rc_vfree(st->idi);
	if (st->idr) rc_vfree(st->idr);
	if (st->sk_d) rc_vfree(st->sk_d);
	memset(st, 0, sizeof(*st));
}

int
main(void)
{
	rc_vchar_t *tkey, *ticket;
	struct r2ticket_state st, back;
	uint8_t *p;
	size_t i;

	/* ---- s5.1 SKEYSEED (pinned against python hmac/sha256) ---- */
	static const uint8_t kd[32] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
		16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31 };
	static const uint8_t ni[16] = { [0 ... 15] = 0xaa };
	static const uint8_t nr[16] = { [0 ... 15] = 0xbb };
	rc_vchar_t *kdv, *niv, *nrv, *seed;
	uint8_t expect[32] = {
		0xf1,0xca,0x21,0xed,0x6c,0x1c,0xc2,0x0e,
		0x96,0x77,0xce,0xff,0x6e,0x0c,0xd6,0xe3,
		0xd7,0x35,0x03,0xc3,0x66,0x3a,0xe4,0xa3,
		0x39,0x02,0xd5,0x72,0x0b,0x13,0xf3,0x86 };

	kdv = rc_vnew(kd, sizeof(kd));
	niv = rc_vnew(ni, sizeof(ni));
	nrv = rc_vnew(nr, sizeof(nr));
	seed = r2ticket_skeyseed(5 /* PRF_HMAC_SHA2_256 */, kdv, niv, nrv);
	CHECK(seed && seed->l == 32, "s5.1 SKEYSEED is 32 bytes (HMAC-SHA256)");
	CHECK(seed && memcmp(seed->v, expect, 32) == 0,
	    "s5.1 SKEYSEED = prf(SK_d_old, Resumption|Ni|Nr) matches python pin");
	free(seed);

	/* unsupported PRF (AES-XCBC/CMAC have no HMAC EVP_MD here) -> NULL */
	CHECK(r2ticket_skeyseed(4, kdv, niv, nrv) == NULL,
	    "s5.1 AES-XCBC PRF returns NULL (no HMAC md)");
	CHECK(r2ticket_skeyseed(5, NULL, niv, nrv) == NULL,
	    "s5.1 NULL SK_d_old returns NULL");

	/* ---- codec round trip ---- */
	tkey = rc_vnew(TKEY, sizeof(TKEY));
	st = make_state(0x7fffffffu);	/* far future (2038-01-19), not expired */
	ticket = r2ticket_create(tkey, KID1, &st);
	CHECK(ticket != NULL, "ticket create succeeds");
	CHECK(ticket == NULL || ticket->l > 4 + R2TICK_KEY_ID_LEN + 12 + 16,
	    "ticket is larger than the bare header+tag");
	if (ticket) {
		/* header: version byte 1, key_id at offset 4 */
		CHECK(((uint8_t *)ticket->v)[0] == 1, "ticket version byte == 1");
		CHECK(memcmp((uint8_t *)ticket->v + 4, KID1, R2TICK_KEY_ID_LEN) == 0,
		    "ticket carries key_id");
	}
	CHECK(r2ticket_parse(tkey, ticket, &back) == 0,
	    "ticket parses OK");
	if (ticket) {
		free_state(&back);
	}
	/* (free_state above freed back's members; re-parse for field checks) */
	CHECK(r2ticket_parse(tkey, ticket, &back) == 0, "ticket parses again");
	if (r2ticket_parse(tkey, ticket, &back) == 0) {
		CHECK(back.expires_at == 0x7fffffffu, "expires_at round-trips");
		CHECK(back.auth_method == 7, "auth_method round-trips");
		CHECK(back.spi_i == 0x0123456789abcdefULL, "spi_i round-trips");
		CHECK(back.spi_r == 0xfedcba9876543210ULL, "spi_r round-trips");
		CHECK(back.sa && back.sa->l == 3 &&
		      memcmp((uint8_t *)back.sa->v, "\x01\x6e\x19", 3) == 0,
		    "SAr round-trips");
		CHECK(back.idi && back.idi->l == 4 &&
		      memcmp((uint8_t *)back.idi->v, "IDI_", 4) == 0, "IDi round-trips");
		CHECK(back.idr && back.idr->l == 4 &&
		      memcmp((uint8_t *)back.idr->v, "IDR_", 4) == 0, "IDr round-trips");
		CHECK(back.sk_d && back.sk_d->l == 32, "sk_d_len round-trips");
		{
			int skdok = 1;
			for (i = 0; i < 32; i++)
				if (((uint8_t *)back.sk_d->v)[i] != (uint8_t)i)
					skdok = 0;
			CHECK(skdok, "SK_d round-trips byte-for-byte");
		}
		free_state(&back);
	}

	/* ---- tamper detection ---- */
	if (ticket) {
		rc_vchar_t *t2 = rc_vdup(ticket);
		/* flip one body byte (past header+iv, before tag) */
		if (t2 && t2->l > 4 + R2TICK_KEY_ID_LEN + 12 + 4) {
			p = (uint8_t *)t2->v;
			p[4 + R2TICK_KEY_ID_LEN + 12 + 2] ^= 0x01;
		}
		CHECK(t2 && r2ticket_parse(tkey, t2, &back) == -1,
		    "tampered ticket body rejected (GCM tag)");
		if (t2) rc_vfree(t2);
	}

	/* ---- wrong key rejected ---- */
	if (ticket) {
		rc_vchar_t *wk;
		static const uint8_t badk[32] = { [0 ... 31] = 0x77 };
		wk = rc_vnew(badk, sizeof(badk));
		CHECK(r2ticket_parse(wk, ticket, &back) == -1,
		    "wrong ticket key rejected");
		free_state(&back);	/* no-op, parse failed -> zeroed */
		rc_vfree(wk);
	}

	/* ---- expired rejected ---- */
	{
		rc_vchar_t *exp;
		struct r2ticket_state st2 = make_state(1u);	/* expired ~1970 */
		exp = r2ticket_create(tkey, KID1, &st2);
		CHECK(exp && r2ticket_parse(tkey, exp, &back) == -1,
		    "expired ticket rejected");
		if (exp) rc_vfree(exp);
	}

	/* ---- key_id round trip: KID2 also mints valid ---- */
	{
		rc_vchar_t *tk2;
		/* key_id is opaque to create/parse (caller picks key by id);
		 * KID2 with the same key still round-trips */
		tk2 = r2ticket_create(tkey, KID2, &st);
		CHECK(tk2 && r2ticket_parse(tkey, tk2, &back) == 0,
		    "alternate key_id mints + parses OK");
		if (tk2 && r2ticket_parse(tkey, tk2, &back) == 0)
			free_state(&back);
		if (tk2) rc_vfree(tk2);
	}

	rc_vfree(kdv);
	rc_vfree(niv);
	rc_vfree(nrv);
	if (tkey) rc_vfree(tkey);
	if (ticket) rc_vfree(ticket);

	printf("# ticketkat: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
