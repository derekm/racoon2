/* $Id$ */
/*
 * RFC 5723 (IKEv2 Session Resumption) ticket core: the "ticket by value"
 * format (s6.1 / Appendix A.1) and the s5.1 resumed-IKE-SA key derivation.
 *
 * A ticket by value is an opaque blob created by the IKEv2 responder under a
 * key known only to that responder.  It must be encrypted and integrity
 * protected.  The resumed IKE SA's crypto material is refreshed from the old
 * SK_d carried in the ticket plus fresh nonces from the resumption exchange:
 *
 *      SKEYSEED = prf(SK_d_old, "Resumption" | Ni | Nr)
 *      {SK_d|SK_ai|SK_ar|SK_ei|SK_er|SK_pi|SK_pr} =
 *                                  prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
 *
 * where the literal "Resumption" is 10 ASCII octets with no NUL.
 *
 * This module is kept dependency-light (vmbuf + OpenSSL EVP only) so it can be
 * KATed standalone with the daemon linked in (like eaytest); it does NOT pull
 * in the SA/negotiation machinery.  The ticket body carried here is exactly
 * the RFC 5723 s5 "from the ticket" state: IDs, SPIs, the negotiated SA, the
 * old SK_d, the authentication method, and an absolute expiry.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include "gcmalloc.h"
#include "vmbuf.h"
#include "ikev2_resume_ticket.h"

/* IKEv2 PRF transform ids (IANA / RFC 8247) — kept local so this module
 * does not drag in the iked SA headers. */
#define R2TICK_PRF_HMAC_SHA1		2
#define R2TICK_PRF_HMAC_SHA2_256	5
#define R2TICK_PRF_HMAC_SHA2_384	6
#define R2TICK_PRF_HMAC_SHA2_512	7

#define R2TICK_VERSION		1
#define R2TICK_IV_LEN		12
#define R2TICK_TAG_LEN		16
#define R2TICK_HDR_LEN		(4 + R2TICK_KEY_ID_LEN + R2TICK_IV_LEN)

/*
 * Authenticated plaintext layout (network byte order):
 *   u32 expires_at   u8 auth_method   u64 spi_i   u64 spi_r
 *   u16 sa_len u8[] sa   u16 idi_len u8[] idi   u16 idr_len u8[] idr
 *   u8 sk_d_len u8[] sk_d
 */

static rc_vchar_t *
r2tick_pack(const struct r2ticket_state *st)
{
	size_t len, o = 0;
	rc_vchar_t *out;
	uint8_t *p;

	uint32_t sa_l = st->sa ? st->sa->l : 0;
	uint32_t idi_l = st->idi ? st->idi->l : 0;
	uint32_t idr_l = st->idr ? st->idr->l : 0;
	uint32_t skd_l = st->sk_d ? st->sk_d->l : 0;

	if (skd_l > 255 || st->expires_at > 0xffffffffu)
		return NULL;
	if (sa_l > 65535 || idi_l > 65535 || idr_l > 65535)
		return NULL;
	len = 4 + 1 + 8 + 8 + 2 + sa_l + 2 + idi_l + 2 + idr_l + 1 + skd_l;
	out = rc_vmalloc(len);
	if (!out)
		return NULL;
	p = (uint8_t *)out->v;

	p[o++] = (st->expires_at >> 24) & 0xff;
	p[o++] = (st->expires_at >> 16) & 0xff;
	p[o++] = (st->expires_at >> 8) & 0xff;
	p[o++] = st->expires_at & 0xff;
	p[o++] = st->auth_method;

	p[o++] = (uint8_t)(st->spi_i >> 56); p[o++] = (uint8_t)(st->spi_i >> 48);
	p[o++] = (uint8_t)(st->spi_i >> 40); p[o++] = (uint8_t)(st->spi_i >> 32);
	p[o++] = (uint8_t)(st->spi_i >> 24); p[o++] = (uint8_t)(st->spi_i >> 16);
	p[o++] = (uint8_t)(st->spi_i >> 8);  p[o++] = (uint8_t)(st->spi_i);
	p[o++] = (uint8_t)(st->spi_r >> 56); p[o++] = (uint8_t)(st->spi_r >> 48);
	p[o++] = (uint8_t)(st->spi_r >> 40); p[o++] = (uint8_t)(st->spi_r >> 32);
	p[o++] = (uint8_t)(st->spi_r >> 24); p[o++] = (uint8_t)(st->spi_r >> 16);
	p[o++] = (uint8_t)(st->spi_r >> 8);  p[o++] = (uint8_t)(st->spi_r);

	p[o++] = (sa_l >> 8) & 0xff; p[o++] = sa_l & 0xff;
	if (sa_l) { memcpy(p + o, st->sa->v, sa_l); o += sa_l; }

	p[o++] = (idi_l >> 8) & 0xff; p[o++] = idi_l & 0xff;
	if (idi_l) { memcpy(p + o, st->idi->v, idi_l); o += idi_l; }

	p[o++] = (idr_l >> 8) & 0xff; p[o++] = idr_l & 0xff;
	if (idr_l) { memcpy(p + o, st->idr->v, idr_l); o += idr_l; }

	p[o++] = (uint8_t)skd_l;
	if (skd_l) { memcpy(p + o, st->sk_d->v, skd_l); o += skd_l; }

	if (o != out->l) {
		rc_vfreez(out);
		return NULL;
	}
	return out;
}

void
r2ticket_state_free(struct r2ticket_state *st)
{
	if (st->sa) { rc_vfree(st->sa); st->sa = NULL; }
	if (st->idi) { rc_vfree(st->idi); st->idi = NULL; }
	if (st->idr) { rc_vfree(st->idr); st->idr = NULL; }
	if (st->sk_d) { rc_vfree(st->sk_d); st->sk_d = NULL; }
	memset(st, 0, sizeof(*st));
}

static int
r2tick_unpack(const uint8_t *p, size_t len, struct r2ticket_state *st)
{
	size_t o = 0;
	uint16_t v16;
	uint8_t v8;

	memset(st, 0, sizeof(*st));

	if (o + 4 > len) goto err;
	st->expires_at = ((uint32_t)p[o] << 24) | ((uint32_t)p[o+1] << 16) |
	    ((uint32_t)p[o+2] << 8) | p[o+3]; o += 4;
	if (o + 1 > len) goto err;
	st->auth_method = p[o++];

	if (o + 8 > len) goto err;
	for (int i = 0; i < 8; i++) st->spi_i = (st->spi_i << 8) | p[o++];
	if (o + 8 > len) goto err;
	for (int i = 0; i < 8; i++) st->spi_r = (st->spi_r << 8) | p[o++];

	if (o + 2 > len) goto err; v16 = ((uint16_t)p[o]<<8)|p[o+1]; o+=2;
	if (o + v16 > len) goto err;
	if (v16) {
		st->sa = rc_vnew(p + o, v16);
		if (!st->sa) goto err;
	}
	o += v16;

	if (o + 2 > len) goto err; v16 = ((uint16_t)p[o]<<8)|p[o+1]; o+=2;
	if (o + v16 > len) goto err;
	if (v16) {
		st->idi = rc_vnew(p + o, v16);
		if (!st->idi) goto err;
	}
	o += v16;

	if (o + 2 > len) goto err; v16 = ((uint16_t)p[o]<<8)|p[o+1]; o+=2;
	if (o + v16 > len) goto err;
	if (v16) {
		st->idr = rc_vnew(p + o, v16);
		if (!st->idr) goto err;
	}
	o += v16;

	if (o + 1 > len) goto err; v8 = p[o++];
	if (o + v8 > len) goto err;
	if (v8) {
		st->sk_d = rc_vnew(p + o, v8);
		if (!st->sk_d) goto err;
	}
	o += v8;

	/* The store record has no MAC, so be strict: trailing bytes past the
	 * last field make the record self-delimiting and refuse a mangled
	 * offset/length (a corrupt record must fail here, not be misparsed). */
	if (o != len)
		goto err;

	return 0;
err:
	/* Keep the documented "-1 => *st cleared / nothing owned" contract no
	 * matter how far the parse got: mid-parse failure may have allocated
	 * sa/idi/idr/sk_d already, and not every caller cleans up on -1
	 * (r2ticket_parse does; r2ticket_store_load does not). */
	r2ticket_state_free(st);
	return -1;
}

/* Derive the per-SA GCM subkey for ticket encryption/decryption from the
 * static ticket key and the key_id (which is based on the SA SPIs).  The
 * subkey is deterministic and reproduced identically by both r2ticket_create
 * and r2ticket_parse, so binding here needs no wire-format change, while it
 * bounds random-IV reuse to a single SA's tickets instead of the whole
 * ticket-key lifetime (cf. NIST SP 800-38D §6 per-key IV limits). */
static int
r2tick_subkey(const rc_vchar_t *tkey, const uint8_t key_id[R2TICK_KEY_ID_LEN],
    uint8_t sub[32])
{
	unsigned int l = 0;

	if (!tkey || tkey->l != 32 || !key_id || !sub)
		return -1;
	if (HMAC(EVP_sha256(), tkey->v, (int)tkey->l, key_id,
	    R2TICK_KEY_ID_LEN, sub, &l) != sub || l != 32)
		return -1;
	return 0;
}

rc_vchar_t *
r2ticket_create(const rc_vchar_t *tkey, const uint8_t key_id[R2TICK_KEY_ID_LEN],
    const struct r2ticket_state *st)
{
	rc_vchar_t *pt = NULL, *out = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
	uint8_t subkey[32];
	uint8_t iv[R2TICK_IV_LEN];
	uint8_t tag[R2TICK_TAG_LEN];
	uint8_t *ct = NULL;
	uint8_t hdr[4 + R2TICK_KEY_ID_LEN];
	uint8_t *p;
	size_t o = 0;
	int outl, ct_len = 0;

	if (!tkey || tkey->l != 32 || !st)
		return NULL;
	if (!(pt = r2tick_pack(st)))
		return NULL;
	/* Per-SA GCM subkey from the static ticket key: bind the encryption
	 * key to key_id (which is derived from the SA's SPIs), so a fresh
	 * random IV is only ever reused within one SA's tickets rather than
	 * under a single key across the whole key lifetime (NIST SP 800-38D §6
	 * caps random-IV use per key well below unbounded).  Deterministic and
	 * header-derived, so r2ticket_parse() reproduces the same key. */
	if (r2tick_subkey(tkey, key_id, subkey) != 0)
		goto out;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		goto out;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, R2TICK_IV_LEN,
	    NULL) != 1)
		goto out;
	if (RAND_bytes(iv, R2TICK_IV_LEN) != 1)
		goto out;
	hdr[0] = R2TICK_VERSION; hdr[1] = 0; hdr[2] = 0; hdr[3] = 0;
	memcpy(hdr + 4, key_id, R2TICK_KEY_ID_LEN);

	if (EVP_EncryptInit_ex(ctx, NULL, NULL, subkey, iv) != 1)
		goto out;
	if (EVP_EncryptUpdate(ctx, NULL, &outl, hdr, sizeof(hdr)) != 1)
		goto out;	/* GCM AAD = cleartext header */
	ct = racoon_malloc(pt->l ? pt->l : 1);
	if (!ct)
		goto out;
	if (EVP_EncryptUpdate(ctx, ct, &outl, pt->v, (int)pt->l) != 1)
		goto out;
	ct_len = outl;
	if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &outl) != 1)
		goto out;
	ct_len += outl;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, R2TICK_TAG_LEN, tag)
	    != 1)
		goto out;

	out = rc_vmalloc(sizeof(hdr) + R2TICK_IV_LEN + ct_len +
	    R2TICK_TAG_LEN);
	if (!out)
		goto out;
	p = (uint8_t *)out->v;
	memcpy(p + o, hdr, sizeof(hdr)); o += sizeof(hdr);
	memcpy(p + o, iv, R2TICK_IV_LEN); o += R2TICK_IV_LEN;
	memcpy(p + o, ct, ct_len); o += ct_len;
	memcpy(p + o, tag, R2TICK_TAG_LEN); o += R2TICK_TAG_LEN;
	if (o != out->l) { rc_vfreez(out); out = NULL; }

 out:
	if (pt) rc_vfreez(pt);
	if (ctx) EVP_CIPHER_CTX_free(ctx);
	if (ct) racoon_free(ct);
	return out;
}

int
r2ticket_parse(const rc_vchar_t *tkey, const rc_vchar_t *ticket,
    struct r2ticket_state *st)
{
	const uint8_t *p;
	size_t len, bodylen;
	EVP_CIPHER_CTX *ctx = NULL;
	uint8_t subkey[32];
	uint8_t *plain = NULL;
	int outl, plen = 0;
	int rc = -1;

	memset(st, 0, sizeof(*st));
	if (!tkey || tkey->l != 32 || !ticket || !st)
		return -1;

	len = ticket->l;
	if (len < R2TICK_HDR_LEN + R2TICK_TAG_LEN)
		return -1;
	p = (const uint8_t *)ticket->v;
	if (p[0] != R2TICK_VERSION)
		return -1;

	/* Reconstruct the per-SA GCM subkey (same derivation as create). */
	if (r2tick_subkey(tkey, p + 4, subkey) != 0)
		return -1;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		goto out;
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, R2TICK_IV_LEN,
	    NULL) != 1)
		goto out;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, subkey,
	    p + 4 + R2TICK_KEY_ID_LEN) != 1)
		goto out;
	if (EVP_DecryptUpdate(ctx, NULL, &outl, p, 4 + R2TICK_KEY_ID_LEN) != 1)
		goto out;

	bodylen = len - R2TICK_HDR_LEN - R2TICK_TAG_LEN;
	plain = racoon_malloc(bodylen ? bodylen : 1);
	if (!plain)
		goto out;
	if (bodylen > 0) {
		if (EVP_DecryptUpdate(ctx, plain, &outl, p + R2TICK_HDR_LEN,
		    (int)bodylen) != 1)
			goto out;
		plen = outl;
	}
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, R2TICK_TAG_LEN,
	    (void *)(p + len - R2TICK_TAG_LEN)) != 1)
		goto out;
	if (EVP_DecryptFinal_ex(ctx, plain + plen, &outl) != 1)
		goto out;	/* tag mismatch -> tampered / wrong key */
	plen += outl;

	if (r2tick_unpack(plain, plen, st) != 0)
		goto out;

	/* Expired: strict, no grace window.  `expires_at < now` (rather
	 * than <=) keeps a ticket valid through the last instant of its
	 * lifetime, then rejects it — the conservative edge: a client
	 * boundary-skewed past expiry is refused and must do a fresh
	 * IKE_SA_INIT.  expires_at == 0 on a legacy record means "never",
	 * which is kept. */
	if (st->expires_at && st->expires_at < (uint32_t)time(NULL))
		goto out;	/* expired */

	rc = 0;
	goto out;

 out:
	if (rc != 0)
		r2ticket_state_free(st);
	if (plain)
		racoon_free(plain);
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return rc;
}

rc_vchar_t *
r2ticket_skeyseed(int prf_id, const rc_vchar_t *sk_d_old,
    const rc_vchar_t *ni, const rc_vchar_t *nr)
{
	const EVP_MD *md;
	const unsigned char lit[] = "Resumption";	/* 10, no NUL */
	unsigned char out[EVP_MAX_MD_SIZE];
	unsigned int outl = 0;
	HMAC_CTX *h = NULL;
	rc_vchar_t *r = NULL;

	md = r2ticket_prf_md(prf_id);
	if (!md || !sk_d_old || !ni || !nr)
		return NULL;
	h = HMAC_CTX_new();
	if (!h)
		return NULL;
	if (HMAC_Init_ex(h, sk_d_old->v, (int)sk_d_old->l, md, NULL) != 1)
		goto out;
	if (HMAC_Update(h, lit, sizeof(lit) - 1) != 1)
		goto out;
	if (HMAC_Update(h, ni->v, ni->l) != 1)
		goto out;
	if (HMAC_Update(h, nr->v, nr->l) != 1)
		goto out;
	if (HMAC_Final(h, out, &outl) != 1)
		goto out;
	r = rc_vnew(out, outl);

 out:
	if (h)
		HMAC_CTX_free(h);
	OPENSSL_cleanse(out, sizeof(out));
	return r;
}

/* RFC 7296 s2.14 prf+:  {T1|T2|...} where
 *   T1 = prf(K, S | 0x01)
 *   T2 = prf(K, T1 | S | 0x02)
 *   T3 = prf(K, T2 | S | 0x03) ...
 * K = SKEYSEED, S = Ni | Nr | SPIi | SPIr.  Returns the first
 * required_len octets.  Here required_len spans the whole
 * {SK_d|SK_ai|SK_ar|SK_ei|SK_er|SK_pi|SK_pr} output; the caller slices it. */
static rc_vchar_t *
r2ticket_prf_plus(int prf_id, const rc_vchar_t *key, const rc_vchar_t *seed,
    size_t required_len)
{
	const EVP_MD *md;
	HMAC_CTX *h = NULL;
	unsigned char t[EVP_MAX_MD_SIZE];
	unsigned int tlen;
	rc_vchar_t *out = NULL, *acc = NULL;
	size_t mdlen, produced = 0;
	uint8_t ctr = 1;

	md = r2ticket_prf_md(prf_id);
	if (!md || !key || !seed || required_len == 0)
		return NULL;
	mdlen = EVP_MD_size(md);
	if (mdlen == 0)
		return NULL;

	out = rc_vmalloc(required_len);
	acc = rc_vmalloc(mdlen);		/* previous T */
	if (!out || !acc)
		goto fail;
	h = HMAC_CTX_new();
	if (!h)
		goto fail;

	while (produced < required_len) {
		size_t take;

		if (HMAC_Init_ex(h, key->v, (int)key->l, md, NULL) != 1)
			goto fail;
		if (produced == 0) {
			/* T1 = prf(K, S | 0x01): feed S then ctr */
			if (HMAC_Update(h, seed->v, seed->l) != 1)
				goto fail;
		} else {
			/* Tn = prf(K, Tprev | S | ctr) */
			if (HMAC_Update(h, acc->v, acc->l) != 1)
				goto fail;
			if (HMAC_Update(h, seed->v, seed->l) != 1)
				goto fail;
		}
		if (HMAC_Update(h, &ctr, 1) != 1)
			goto fail;
		if (HMAC_Final(h, t, &tlen) != 1)
			goto fail;
		memcpy(acc->v, t, mdlen);
		take = required_len - produced;
		if (take > mdlen)
			take = mdlen;
		memcpy((uint8_t *)out->v + produced, t, take);
		produced += take;
		ctr++;
	}
	if (h)
		HMAC_CTX_free(h);
	OPENSSL_cleanse(t, sizeof(t));
	rc_vfree(acc);
	return out;

 fail:
	if (h)
		HMAC_CTX_free(h);
	OPENSSL_cleanse(t, sizeof(t));
	if (acc)
		rc_vfree(acc);
	if (out)
		rc_vfree(out);
	return NULL;
}

/* RFC 5723 s5.1: expand the resumed SKEYSEED into the full key set. */
rc_vchar_t *
r2ticket_keyexp(int prf_id, const rc_vchar_t *skeyseed,
    const rc_vchar_t *ni, const rc_vchar_t *nr,
    const uint8_t spi_i[8], const uint8_t spi_r[8],
    size_t sk_d_len, size_t sk_ai_len, size_t sk_ei_len, size_t sk_pi_len)
{
	rc_vchar_t *seed, *r;
	size_t seedlen;

	if (!skeyseed || !ni || !nr || !spi_i || !spi_r)
		return NULL;
	seedlen = ni->l + nr->l + 16;
	seed = rc_vmalloc(seedlen);
	if (!seed)
		return NULL;
	memcpy((uint8_t *)seed->v, ni->v, ni->l);
	memcpy((uint8_t *)seed->v + ni->l, nr->v, nr->l);
	memcpy((uint8_t *)seed->v + ni->l + nr->l, spi_i, 8);
	memcpy((uint8_t *)seed->v + ni->l + nr->l + 8, spi_r, 8);

	r = r2ticket_prf_plus(prf_id, skeyseed, seed,
	    sk_d_len + 2 * sk_ai_len + 2 * sk_ei_len + 2 * sk_pi_len);
	rc_vfree(seed);
	return r;
}


/*
 * Load the RFC 5723 ticket key from a configured file: the raw file content
 * must be exactly 32 bytes (AES-256).  Like ppk_id / radius_secret_file the
 * key never appears in a config; the path does.  Caller owns *key (cleanse
 * with OPENSSL_cleanse before rc_vfree).  Returns 0 ok, -1 on any error
 * (missing/unreadable/wrong-length path).  Fail-closed.
 */

rc_vchar_t *
r2ticket_lt_opaque(const rc_vchar_t *tkey,
    const uint8_t key_id[R2TICK_KEY_ID_LEN], const struct r2ticket_state *st,
    uint32_t lifetime_sec)
{
	rc_vchar_t *ticket, *out;
	size_t o = 0;
	uint8_t *p;

	ticket = r2ticket_create(tkey, key_id, st);
	if (!ticket)
		return NULL;
	out = rc_vmalloc(4 + ticket->l);
	if (!out) {
		rc_vfree(ticket);
		return NULL;
	}
	p = (uint8_t *)out->v;
	p[o++] = (lifetime_sec >> 24) & 0xff;
	p[o++] = (lifetime_sec >> 16) & 0xff;
	p[o++] = (lifetime_sec >> 8) & 0xff;
	p[o++] = lifetime_sec & 0xff;
	memcpy(p + o, ticket->v, ticket->l);
	rc_vfree(ticket);
	return out;
}

int
r2ticket_key_load(const char *path, rc_vchar_t **key)
{
	FILE *f;
	uint8_t buf[32];
	size_t n;

	/* Fail-closed on a missing/unreadable/wrong-length file (must be
	 * exactly 32 raw octets).  The file's mode is NOT enforced here:
	 * the deployable keys are root-owned 0600 (the matrix kchmods them),
	 * and enforcing a mode would break ad-hoc probe setups that rely on
	 * yescorp-readable scratch keys.  Owners should keep this file out
	 * of group/other read; the loader must never log its contents. */
	if (!path || !key)
		return -1;
	*key = NULL;
	f = fopen(path, "rb");
	if (!f)
		return -1;
	n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	if (n != sizeof(buf))		/* must be exactly 32 bytes */
		return -1;
	*key = rc_vnew(buf, sizeof(buf));
	OPENSSL_cleanse(buf, sizeof(buf));
	return *key ? 0 : -1;
}

const EVP_MD *
r2ticket_prf_md(int prf_id)
{
	switch (prf_id) {
	case R2TICK_PRF_HMAC_SHA1:
		return EVP_sha1();
	case R2TICK_PRF_HMAC_SHA2_256:
		return EVP_sha256();
	case R2TICK_PRF_HMAC_SHA2_384:
		return EVP_sha384();
	case R2TICK_PRF_HMAC_SHA2_512:
		return EVP_sha512();
	default:
		return NULL;
	}
}

/*
 * Initiator-side persistence store (see header).  Record layout on disk:
 *   [0]  version (R2TICK_STORE_VERSION)
 *   [1..4]  ticket_lt length (big-endian u32)
 *   [5..4+tlen]  ticket_lt bytes (4-octet BE lifetime || ticket)
 *   [...]  packed r2ticket_state (r2tick_pack format, self-delimiting)
 */
#define R2TICK_STORE_VERSION	1

static char *
r2tick_store_path(const char *dir, const char *key)
{
	char *path;
	size_t n;

	if (!dir || !key || *key == '\0')
		return NULL;
	n = strlen(dir) + 1 + strlen(R2TICK_STORE_PREFIX) + strlen(key) + 1;
	path = racoon_malloc(n);
	if (!path)
		return NULL;
	snprintf(path, n, "%s/%s%s", dir, R2TICK_STORE_PREFIX, key);
	return path;
}

int
r2ticket_store_save(const char *dir, const char *key,
    const rc_vchar_t *ticket_lt, const struct r2ticket_state *st)
{
	/* Store is keyed by peer socket-address (one ticket per peer); a
	 * roaming/multi-identity client that re-establishes from a new
	 * address overwrites the old address's ticket.  Acceptable for the
	 * first implementation (a fresh IAU/terminate re-mints anyway), and
	 * the address->ticket mapping keeps concurrent SAs to different
	 * peers from colliding. */
	rc_vchar_t *pack;
	char *path;
	FILE *fp;
	size_t tlen;
	uint8_t hdr[1 + 4];
	int rc = -1;

	if (!dir || !key || !ticket_lt || !ticket_lt->v || ticket_lt->l == 0
	    || !st)
		return -1;
	if (ticket_lt->l > 0xffffffffu)
		return -1;
	if (mkdir(dir, 0700) < 0 && errno != EEXIST)
		return -1;
	if (!(pack = r2tick_pack(st)))
		return -1;
	path = r2tick_store_path(dir, key);
	if (!path)
		goto out;

	/* Defend against umask: force 0600 (owner-only) regardless of the
	 * caller's umask, like the legacy resume-dump writer.  The ticket is
	 * keyed to us and lets the holder resume into this remote. */
	fp = fdopen(open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600), "wb");
	if (!fp)
		goto out;
	tlen = ticket_lt->l;
	hdr[0] = R2TICK_STORE_VERSION;
	hdr[1] = (uint8_t)(tlen >> 24); hdr[2] = (uint8_t)(tlen >> 16);
	hdr[3] = (uint8_t)(tlen >> 8);  hdr[4] = (uint8_t)tlen;
	if (fwrite(hdr, 1, sizeof(hdr), fp) != sizeof(hdr)
	    || fwrite(ticket_lt->v, 1, tlen, fp) != tlen
	    || fwrite(pack->v, 1, pack->l, fp) != pack->l) {
		fclose(fp);
		goto out;
	}
	if (fflush(fp) != 0 || fclose(fp) != 0)
		goto out;
	rc = 0;
out:
	if (path)
		racoon_free(path);
	rc_vfreez(pack);
	return rc;
}

int
r2ticket_store_load(const char *dir, const char *key,
    rc_vchar_t **ticket_lt, struct r2ticket_state *st)
{
	char *path;
	FILE *fp;
	uint8_t hdr[5];
	size_t tlen, rd;
	rc_vchar_t *tl = NULL, *pack = NULL;
	uint8_t *buf;
	long flen;
	int rc = -1;

	if (!dir || !key || !ticket_lt || !st)
		return -1;
	*ticket_lt = NULL;
	memset(st, 0, sizeof(*st));

	path = r2tick_store_path(dir, key);
	if (!path)
		return -1;
	fp = fopen(path, "rb");
	racoon_free(path);
	if (!fp)
		return -1;
	if (fread(hdr, 1, sizeof(hdr), fp) != sizeof(hdr))
		goto out;
	if (hdr[0] != R2TICK_STORE_VERSION)
		goto out;
	tlen = ((size_t)hdr[1] << 24) | ((size_t)hdr[2] << 16)
	    | ((size_t)hdr[3] << 8) | (size_t)hdr[4];
	/* bound the ticket size to a sane ceiling (e.g. 1 MiB) */
	if (tlen == 0 || tlen > (1u << 20))
		goto out;

	tl = rc_vmalloc(tlen);
	if (!tl)
		goto out;
	rd = fread(tl->v, 1, tlen, fp);
	if (rd != tlen)
		goto out;

	if (fseek(fp, 0L, SEEK_END) != 0)
		goto out;
	flen = ftell(fp);
	if (flen < (long)sizeof(hdr) + (long)tlen
	    || flen - (long)tlen - (long)sizeof(hdr) > (long)(1u << 20))
		goto out;
	if (fseek(fp, (long)sizeof(hdr) + (long)tlen, SEEK_SET) != 0)
		goto out;
	pack = rc_vmalloc((size_t)(flen - (long)tlen - (long)sizeof(hdr)));
	if (!pack)
		goto out;
	buf = (uint8_t *)pack->v;
	rd = fread(buf, 1, pack->l, fp);
	if (rd != pack->l)
		goto out;
	if (r2tick_unpack(buf, pack->l, st) != 0)
		goto out;

	*ticket_lt = tl;
	tl = NULL;
	rc = 0;
out:
	if (tl)
		rc_vfree(tl);
	if (pack)
		rc_vfree(pack);
	fclose(fp);
	return rc;
}

void
r2ticket_store_clear(const char *dir, const char *key)
{
	char *path;

	if (!dir || !key)
		return;
	path = r2tick_store_path(dir, key);
	if (!path)
		return;
	unlink(path);
	racoon_free(path);
}

/* ---- RFC 5723 s4.3.1 used-ticket cache (see header) ---- */
struct r2tick_seen {
	uint32_t expires_at;		/* 0 = free slot */
	uint8_t h[32];			/* SHA-256(opaque ticket) */
};
static struct r2tick_seen r2tick_seen[R2TICK_REPLAY_SLOTS];

int
r2ticket_replay_mark(const rc_vchar_t *ticket, uint32_t expires_at,
    uint32_t now)
{
	uint8_t h[32];
	unsigned int hl = 0;
	int i, slot = -1;

	if (!ticket || !ticket->l || expires_at <= now)
		return -1;
	if (EVP_Digest(ticket->v, ticket->l, h, &hl, EVP_sha256(), NULL) != 1
	    || hl != sizeof(h))
		return -1;
	for (i = 0; i < R2TICK_REPLAY_SLOTS; i++) {
		struct r2tick_seen *e = &r2tick_seen[i];

		if (e->expires_at && e->expires_at <= now)
			memset(e, 0, sizeof(*e));	/* ticket expired */
		if (!e->expires_at) {
			if (slot < 0)
				slot = i;
			continue;
		}
		if (memcmp(e->h, h, sizeof(h)) == 0)
			return 1;
	}
	if (slot < 0)
		return -1;
	r2tick_seen[slot].expires_at = expires_at;
	memcpy(r2tick_seen[slot].h, h, sizeof(h));
	return 0;
}

void
r2ticket_replay_reset(void)
{
	memset(r2tick_seen, 0, sizeof(r2tick_seen));
}
