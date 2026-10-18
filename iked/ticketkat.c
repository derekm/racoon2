/* $Id$ */
/* RFC 5723 ticket-layer KAT (same shape as resumetest/ndcppkats:
 * check_PROGRAM, printf + exit).  Pin the s5.1 SKEYSEED derivation and the
 * ticket-by-value codec round-trip + tamper rejection. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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
	rc_vfree(seed);

	/* ---- s5.1 prf+ key expansion (pinned vs python hmac prf+) ---- */
	{
		static const uint8_t spii[8] = { [0 ... 7] = 0x11 };
		static const uint8_t spir[8] = { [0 ... 7] = 0x22 };
		static const uint8_t expout[160] = {
			0x52,0xc4,0x1a,0xa7,0x45,0xa0,0x09,0x0e,0x81,0xc9,0x24,0xf0,0x1f,0xcd,0xd7,0x27,
			0xc6,0x60,0x4a,0x59,0x3f,0x08,0x91,0x6d,0xfc,0x8f,0x17,0x6e,0x02,0x7b,0x27,0x9e,
			0x22,0x73,0xc4,0x19,0x8d,0x8e,0x80,0x1b,0xb3,0xe6,0x84,0x3b,0xd8,0x15,0xd3,0x69,
			0x6a,0xbe,0x3f,0x4a,0xb0,0x58,0x15,0xe9,0x3c,0xd9,0x3c,0x37,0xd8,0xd2,0x44,0x92,
			0x52,0x28,0x81,0xf0,0x82,0xb7,0x78,0xc8,0xb5,0x90,0x13,0xb3,0xd5,0x88,0x83,0x30,
			0x5a,0x65,0xbe,0x3d,0x4f,0x73,0x10,0x2f,0xfe,0x85,0x29,0x3e,0x75,0xe9,0xb1,0x7c,
			0xb1,0x9d,0x54,0x05,0x84,0x29,0xe2,0x19,0x2d,0xc6,0x87,0xa7,0x47,0x81,0x00,0x6e,
			0x55,0xfe,0x47,0xe7,0x06,0xda,0x29,0xe8,0xcd,0xc4,0x8f,0xf4,0xfc,0x0d,0xe6,0xec,
			0x97,0x0f,0x45,0x0a,0x1c,0x2a,0x95,0x85,0xf5,0xc3,0x7f,0x50,0xdf,0x1a,0xcc,0x44,
			0xe6,0xcf,0x2e,0x33,0x4c,0x55,0x83,0xac,0x68,0x78,0xe4,0xa1,0x17,0x8a,0x8f,0x31 };
		rc_vchar_t *keyseed, *expanded, *ni2 = niv, *nr2 = nrv;

		keyseed = r2ticket_skeyseed(5, kdv, ni2, nr2);
		CHECK(keyseed != NULL, "keyexp: recomputed SKEYSEED");
		expanded = r2ticket_keyexp(5, keyseed, ni2, nr2, spii, spir,
		    32, 16, 16, 32);
		CHECK(expanded && expanded->l == 160, "keyexp: output is 160 bytes");
		CHECK(expanded && memcmp(expanded->v, expout, 160) == 0,
		    "keyexp: prf+(SKEYSEED,Ni|Nr|SPIi|SPIr) matches python pin");
		if (keyseed) rc_vfree(keyseed);
		if (expanded) rc_vfree(expanded);
	}

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
	{
		int ok = (r2ticket_parse(tkey, ticket, &back) == 0);
		CHECK(ok, "ticket parses again");
		if (ok) {
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
		free_state(&st2);
	}

	/* ---- key_id round trip: KID2 also mints valid ---- */
	{
		rc_vchar_t *tk2;
		/* key_id is opaque to create/parse (caller picks key by id);
		 * KID2 with the same key still round-trips */
		int ok;
		tk2 = r2ticket_create(tkey, KID2, &st);
		ok = (tk2 && r2ticket_parse(tkey, tk2, &back) == 0);
		CHECK(ok, "alternate key_id mints + parses OK");
		if (ok)
			free_state(&back);
		if (tk2) rc_vfree(tk2);
	}

	/* ---- N(TICKET_LT_OPAQUE) layout: 4-octet BE lifetime || ticket ---- */
	{
		rc_vchar_t *lt;
		uint32_t lifetime = 0x4e1fb000u;	/* 1310000000 s */
		rc_vchar_t *tail;
		struct r2ticket_state back2;

		lt = r2ticket_lt_opaque(tkey, KID1, &st, lifetime);
		CHECK(lt != NULL, "N(TICKET_LT_OPAQUE) mints");
		if (lt && lt->l >= 4) {
			uint8_t *q = (uint8_t *)lt->v;
			CHECK(q[0] == 0x4e && q[1] == 0x1f && q[2] == 0xb0 &&
			      q[3] == 0x00,
			    "lifetime is a 4-octet big-endian value");
			/* the tail must be a stand-alone parseable ticket.  A
			 * fresh GCM IV per create means ciphertext differs
			 * run-to-run even for equal state, so the body is
			 * verified by parsing it back, not by byte compare. */
			tail = rc_vnew((uint8_t *)lt->v + 4, lt->l - 4);
			{
				int ok = (tail && r2ticket_parse(tkey, tail, &back2) == 0);
				CHECK(ok, "opaque ticket body parses back out of N()");
				if (ok) {
					CHECK(back2.expires_at == st.expires_at &&
					      back2.auth_method == st.auth_method &&
					      back2.spi_i == st.spi_i &&
					      back2.spi_r == st.spi_r,
					    "parsed ticket state equals the minted state");
					free_state(&back2);
				}
			}
			if (tail) rc_vfree(tail);
		}
		if (lt) rc_vfree(lt);
	}

	/* ---- initiator persistence store: save -> load -> clear ---- */
	{
		const char *sdir = "/tmp/r2tkt-kat";
		struct r2ticket_state got;
		rc_vchar_t *tload = NULL;
		rc_vchar_t *lt = NULL;
		int s, l, ok;

		mkdir(sdir, 0700);
		r2ticket_store_clear(sdir, "peer-a");
		lt = r2ticket_lt_opaque(tkey, KID1, &st, 0x4e1fb000u);
		CHECK(lt != NULL, "store: minted lifetime+opaque ticket");

		s = r2ticket_store_save(sdir, "peer-a", lt, &st);
		CHECK(s == 0, "store: save returns 0");
		memset(&got, 0, sizeof(got));
		l = r2ticket_store_load(sdir, "peer-a", &tload, &got);
		ok = (l == 0 && tload && tload->l == 4 + (lt ? lt->l - 4 : 0) &&
		      got.expires_at == st.expires_at &&
		      got.auth_method == st.auth_method &&
		      got.spi_i == st.spi_i && got.spi_r == st.spi_r);
		CHECK(ok, "store: load round-trips lifetime+ticket+state");
		/* loaded opaque ticket tail must parse back */
		if (ok && tload && tload->l >= 4) {
			rc_vchar_t *tail = rc_vnew((uint8_t *)tload->v + 4,
						     tload->l - 4);
			struct r2ticket_state b3;
			int p = (tail && r2ticket_parse(tkey, tail, &b3) == 0);
			CHECK(p, "store: persisted ticket is a valid parse ticket");
			if (p)
				free_state(&b3);
			if (tail) rc_vfree(tail);
		}
		if (tload) rc_vfree(tload);
		free_state(&got);
		/* missing key must fail, not confuse a later fresh load */
		CHECK(r2ticket_store_load(sdir, "no-such-peer", &tload, &got) == -1,
		      "store: load of unknown key fails closed");
		r2ticket_store_clear(sdir, "peer-a");
		CHECK(r2ticket_store_load(sdir, "peer-a", &tload, &got) == -1,
		      "store: clear removes the entry");
		if (lt) rc_vfree(lt);
	}

	/* ---- store record mode / symlink hardening (review L4) ---- */
	{
		const char *sdir = "/tmp/r2tkt-kat-l4";
		struct r2ticket_state sm = make_state(0x7fffffffu);
		struct r2ticket_state got;
		rc_vchar_t *lt, *tl = NULL;
		struct stat sb;
		char rec[256], target[256];
		FILE *pf;
		mode_t om;

		mkdir(sdir, 0700);
		snprintf(rec, sizeof(rec), "%s/%speer-l4", sdir,
			 R2TICK_STORE_PREFIX);
		snprintf(target, sizeof(target), "%s/elsewhere", sdir);
		unlink(rec); unlink(target);
		lt = r2ticket_lt_opaque(tkey, KID1, &sm, 3600);
		/* a pre-created 0644 file at the record name */
		om = umask(0);
		pf = fopen(rec, "wb");
		if (pf) fclose(pf);
		chmod(rec, 0644);
		umask(om);
		CHECK(lt && r2ticket_store_save(sdir, "peer-l4", lt, &sm) == 0 &&
		      stat(rec, &sb) == 0 && (sb.st_mode & 0777) == 0600,
		      "store: save forces 0600 over a pre-created 0644 file");
		/* a symlink at the record name is replaced, not followed */
		unlink(rec);
		pf = fopen(target, "wb");
		if (pf) fclose(pf);
		CHECK(symlink(target, rec) == 0 &&
		      r2ticket_store_save(sdir, "peer-l4", lt, &sm) == 0 &&
		      lstat(rec, &sb) == 0 && S_ISREG(sb.st_mode) &&
		      stat(target, &sb) == 0 && sb.st_size == 0,
		      "store: save replaces a symlink instead of writing through it");
		/* load refuses a group/other-readable record */
		chmod(rec, 0640);
		CHECK(r2ticket_store_load(sdir, "peer-l4", &tl, &got) == -1,
		      "store: load refuses a group-readable record");
		chmod(rec, 0600);
		CHECK(r2ticket_store_load(sdir, "peer-l4", &tl, &got) == 0,
		      "store: load accepts the owner-only record");
		if (tl) rc_vfree(tl);
		free_state(&got);
		tl = NULL;
		/* load refuses to follow a symlink */
		unlink(target);
		rename(rec, target);
		CHECK(symlink(target, rec) == 0 &&
		      r2ticket_store_load(sdir, "peer-l4", &tl, &got) == -1,
		      "store: load does not follow a symlink");
		if (tl) rc_vfree(tl);
		unlink(rec); unlink(target); rmdir(sdir);
		if (lt) rc_vfree(lt);
		free_state(&sm);
	}

	/* ---- one expiry rule everywhere (review L3) ---- */
	CHECK(!r2ticket_expired(1001, 1000), "expiry: usable before expires_at");
	CHECK(r2ticket_expired(1000, 1000), "expiry: expired at expires_at");
	CHECK(r2ticket_expired(999, 1000), "expiry: expired after expires_at");
	CHECK(r2ticket_expired(0, 1000), "expiry: expires_at 0 is expired, not never");
	{
		struct r2ticket_state z0 = make_state(0);
		rc_vchar_t *t0 = r2ticket_create(tkey, KID1, &z0);
		struct r2ticket_state b0;

		CHECK(t0 && r2ticket_parse(tkey, t0, &b0) == -1,
		      "expiry: parse refuses an expires_at 0 ticket");
		if (t0) rc_vfree(t0);
		free_state(&z0);
	}

	/* ---- key file must be exactly 32 octets (review L1) ---- */
	{
		const char *kp = "/tmp/r2tkt-kat-key";
		rc_vchar_t *k = NULL;
		uint8_t kb[33];
		FILE *kf;

		memset(kb, 0x42, sizeof(kb));
		kf = fopen(kp, "wb");
		if (kf) { fwrite(kb, 1, 32, kf); fclose(kf); }
		CHECK(r2ticket_key_load(kp, &k) == 0 && k && k->l == 32,
		      "key: 32-octet file loads");
		if (k) { rc_vfreez(k); k = NULL; }
		kf = fopen(kp, "wb");
		if (kf) { fwrite(kb, 1, 33, kf); fclose(kf); }
		CHECK(r2ticket_key_load(kp, &k) == -1 && k == NULL,
		      "key: 33-octet file is refused, not truncated");
		kf = fopen(kp, "wb");
		if (kf) { fwrite(kb, 1, 31, kf); fclose(kf); }
		CHECK(r2ticket_key_load(kp, &k) == -1 && k == NULL,
		      "key: 31-octet file is refused");
		unlink(kp);
	}

	/* ---- RFC 5723 s4.3.1 used-ticket cache (review M4) ---- */
	{
		rc_vchar_t *ta = rc_vnew("ticket-A", 8);
		rc_vchar_t *tb = rc_vnew("ticket-B", 8);
		uint8_t buf[8];
		int i, full_ok = 1;

		r2ticket_replay_reset();
		CHECK(r2ticket_replay_mark(ta, 2000, 1000) == 0,
		      "replay: first use of a ticket is accepted");
		CHECK(r2ticket_replay_mark(ta, 2000, 1001) == 1,
		      "replay: second use of the same ticket is rejected");
		CHECK(r2ticket_replay_mark(tb, 2000, 1001) == 0,
		      "replay: a different ticket is accepted");
		CHECK(r2ticket_replay_mark(ta, 2000, 1999) == 1,
		      "replay: still rejected up to its expiry");
		CHECK(r2ticket_replay_mark(ta, 3000, 2000) == 0,
		      "replay: entry ages out at the ticket's expiry");
		CHECK(r2ticket_replay_mark(ta, 900, 1000) == -1,
		      "replay: an already-expired ticket is never recorded");
		/* fill: every slot holds an unexpired ticket -> fail closed */
		r2ticket_replay_reset();
		for (i = 0; i < R2TICK_REPLAY_SLOTS; i++) {
			rc_vchar_t *t;

			memcpy(buf, &i, sizeof(i));
			memset(buf + sizeof(i), 0x5a, sizeof(buf) - sizeof(i));
			t = rc_vnew(buf, sizeof(buf));
			if (!t || r2ticket_replay_mark(t, 5000, 1000) != 0)
				full_ok = 0;
			rc_vfree(t);
		}
		CHECK(full_ok, "replay: cache holds R2TICK_REPLAY_SLOTS tickets");
		CHECK(r2ticket_replay_mark(ta, 5000, 1000) == -1,
		      "replay: full cache of live tickets fails closed");
		CHECK(r2ticket_replay_mark(ta, 9000, 5000) == 0,
		      "replay: slots free again once those tickets expire");
		r2ticket_replay_reset();
		{
			uint8_t ub[8];
			uint32_t u = (uint32_t)time(NULL);
			rc_vchar_t *tu;

			memcpy(ub, &u, 4);
			memset(ub + 4, 0x11, 4);
			tu = rc_vnew(ub, 8);
			r2ticket_replay_set_dir("/tmp/r2tick-replay-kat");
			CHECK(tu && r2ticket_replay_mark(tu, 2000, 1000) == 0,
			      "replay: first use recorded on disk");
			r2ticket_replay_reset();
			CHECK(r2ticket_replay_mark(tu, 2000, 1001) == 1,
			      "replay: disk cache rejects after memory reset");
			r2ticket_replay_set_dir(NULL);
			r2ticket_replay_reset();
			rc_vfree(tu);
		}
		rc_vfree(ta);
		rc_vfree(tb);
	}

	/* ---- zero-length-SA / corrupt-record hardening (deep-review) ----
	 * r2tick_unpack yields st.sa==NULL for a zero-length SA field; the
	 * resume rebuild paths MUST fail closed on that (they now NULL-guard
	 * st.sa/st.sk_d).  Verify the store round-trip preserves it so the
	 * guard is reachable, and that a trailing-byte record is rejected. */
	{
		const char *sdir = "/tmp/r2tkt-kat";
		struct r2ticket_state z = make_state(0x7fffffffu);
		struct r2ticket_state got;
		rc_vchar_t *tload = NULL, *lt = NULL;
		int ok;

		rc_vfree(z.sa); z.sa = NULL;	/* zero-length SA */
		rc_vfree(z.sk_d); z.sk_d = NULL;/* zero-length OLD SK_d */

		lt = r2ticket_lt_opaque(tkey, KID1, &z, 0x4e1fb000u);
		CHECK(lt != NULL, "zero-sa: mint lifetime+opaque ticket");
		r2ticket_store_clear(sdir, "peer-a");
		ok = (r2ticket_store_save(sdir, "peer-a", lt, &z) == 0);
		CHECK(ok, "zero-sa: store save succeeds");
		memset(&got, 0, sizeof(got));
		ok = (r2ticket_store_load(sdir, "peer-a", &tload, &got) == 0);
		CHECK(ok, "zero-sa: store load succeeds");
		if (ok)
			CHECK(got.sa == NULL && got.sk_d == NULL,
			      "zero-sa: load yields NULL sa/sk_d (caller guard fires)");
		/* trailing bytes past the record must be refused: the store file
		 * has no MAC, and r2tick_unpack is strict (o == len) so a
		 * mangled/truncated/extended record fails load, not misparse */
		if (ok) {
			char *path;
			FILE *fp;
			path = malloc(strlen(sdir) + 1
			    + strlen(R2TICK_STORE_PREFIX) + strlen("peer-a") + 1);
			if (path) {
				snprintf(path, strlen(sdir) + 1
				    + strlen(R2TICK_STORE_PREFIX)
				    + strlen("peer-a") + 1, "%s/%s%s", sdir,
				    R2TICK_STORE_PREFIX, "peer-a");
				fp = fopen(path, "ab");
				if (fp) {
					size_t w = fwrite("XX", 1, 2, fp);
					CHECK(w == 2, "trailing-bytes: garbage appended");
					fclose(fp);
				}
				free(path);
			}
			/* the second load clears *ticket_lt (store_load) before
			 * reading, so hand back the first load's ticket and fields
			 * first -- the retry must not leak them (LeakSanitizer) */
			if (tload) rc_vfree(tload);
			tload = NULL;
			free_state(&got);
			CHECK(r2ticket_store_load(sdir, "peer-a", &tload, &got) == -1,
			      "trailing-bytes: record refused by strict length");
		}
		if (tload) rc_vfree(tload);
		free_state(&got);
		r2ticket_store_clear(sdir, "peer-a");
		if (lt) rc_vfree(lt);
		free_state(&z);
	}

	/* ---- cluster shared-trust: a ticket minted under a key FILE
	 * validates when a second "instance" loads the SAME key file
	 * (RFC 5723 cross-node migration).  Simulates two pool nodes: node A
	 * mints under tkey (as ikev2_ticket_lt_opaque would after
	 * r2ticket_key_load), then node B loads the same 32 bytes from a
	 * key file via r2ticket_key_load() and must parse the ticket back
	 * to the identical state.  This is the "migratable SA state via
	 * session tickets" property a shared-trust concentrator pool relies
	 * on — no node identity is embedded, only the shared secret. */
	{
		const char *kpath = "/tmp/r2tkt-kat-key";
		FILE *kf;
		rc_vchar_t *kloaded = NULL, *ktick = NULL;
		struct r2ticket_state kback;
		int nok;

		/* (re)write node A's key-file: exactly the 32 tkey bytes */
		kf = fopen(kpath, "wb");
		CHECK(kf != NULL, "cluster: open key file");
		if (kf) {
			size_t wrote = fwrite(tkey->v, 1, 32, kf);
			CHECK(wrote == 32, "cluster: wrote 32-octet key file");
			fclose(kf);
		}
		/* node B loads the shared key file -> must equal node A's key */
		nok = (r2ticket_key_load(kpath, &kloaded) == 0 &&
		       kloaded && kloaded->l == 32 &&
		       memcmp(kloaded->v, tkey->v, 32) == 0);
		CHECK(nok, "cluster: second instance loads identical key from file");

		/* node A mints the ticket (opaque DATA, state st) */
		ktick = r2ticket_lt_opaque(tkey, KID1, &st, st.expires_at);
		CHECK(ktick != NULL, "cluster: node A mints opaque ticket");

		/* node B parses node A's ticket under the key it loaded */
		memset(&kback, 0, sizeof(kback));
		if (ktick && kloaded) {
			rc_vchar_t *opq;
			int p;

			opq = rc_vnew((uint8_t *)ktick->v + 4, ktick->l - 4);
			p = (opq && r2ticket_parse(kloaded, opq, &kback) == 0);
			CHECK(p, "cluster: node B validates node A's ticket (shared key)");
			if (p) {
				CHECK(kback.expires_at == st.expires_at &&
				      kback.auth_method == st.auth_method &&
				      kback.spi_i == st.spi_i &&
				      kback.spi_r == st.spi_r &&
				      kback.sk_d && kback.sk_d->l == 32 &&
				      memcmp(kback.sk_d->v, st.sk_d->v, 32) == 0,
				      "cluster: recovered state equals minted state on node B");
			}
			if (opq) rc_vfree(opq);
			free_state(&kback);
		}
		/* a second instance with a DIFFERENT key file must NOT validate */
		if (ktick) {
			uint8_t other[32];
			rc_vchar_t *ok2 = NULL, *opq2;
			int p2;
			for (i = 0; i < 32; i++)
				other[i] = (uint8_t)(0xff - i);
			/* load a wrong key file */
			{
				FILE *wf = fopen("/tmp/r2tkt-kat-key2", "wb");
				size_t w2 = 0;
				if (wf) {
					w2 = fwrite(other, 1, 32, wf);
					fclose(wf);
				}
				CHECK(w2 == 32,
				      "cluster: wrote wrong-key file (negative control)");
			}
			nok = (r2ticket_key_load("/tmp/r2tkt-kat-key2",
						 &ok2) == 0);
			opq2 = rc_vnew((uint8_t *)ktick->v + 4, ktick->l - 4);
			/* The contrast is only real if the wrong-key file
			 * ACTUALLY LOADED (a 32-octet key, different from
			 * the fixture) and the ticket body was prepared; a
			 * silent load/alloc failure must not let the
			 * rejection check pass vacuously. */
			CHECK(nok && ok2 && ok2->l == 32 && opq2 != NULL,
			      "cluster: wrong key loaded, ticket prepared");
			memset(&kback, 0, sizeof(kback));
			p2 = (nok && ok2 && opq2 &&
			      r2ticket_parse(ok2, opq2, &kback) == 0);
			CHECK(!p2, "cluster: wrong shared key rejected on node B");
			if (p2)
				free_state(&kback);
			if (ok2) rc_vfree(ok2);
			if (opq2) rc_vfree(opq2);
		}
		if (ktick) rc_vfree(ktick);
		if (kloaded) rc_vfree(kloaded);
		remove("/tmp/r2tkt-kat-key");
		remove("/tmp/r2tkt-kat-key2");
	}

	rc_vfree(kdv);
	rc_vfree(niv);
	rc_vfree(nrv);
	if (tkey) rc_vfree(tkey);
	if (ticket) rc_vfree(ticket);
	free_state(&st);

	printf("# ticketkat: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
