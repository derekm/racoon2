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
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdio.h>

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

static void
r2tick_state_free(struct r2ticket_state *st)
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

	if (o + 4 > len) return -1;
	st->expires_at = ((uint32_t)p[o] << 24) | ((uint32_t)p[o+1] << 16) |
	    ((uint32_t)p[o+2] << 8) | p[o+3]; o += 4;
	if (o + 1 > len) return -1;
	st->auth_method = p[o++];

	if (o + 8 > len) return -1;
	for (int i = 0; i < 8; i++) st->spi_i = (st->spi_i << 8) | p[o++];
	if (o + 8 > len) return -1;
	for (int i = 0; i < 8; i++) st->spi_r = (st->spi_r << 8) | p[o++];

	if (o + 2 > len) return -1; v16 = ((uint16_t)p[o]<<8)|p[o+1]; o+=2;
	if (o + v16 > len) return -1;
	if (v16) {
		st->sa = rc_vnew(p + o, v16);
		if (!st->sa) return -1;
	}
	o += v16;

	if (o + 2 > len) return -1; v16 = ((uint16_t)p[o]<<8)|p[o+1]; o+=2;
	if (o + v16 > len) return -1;
	if (v16) {
		st->idi = rc_vnew(p + o, v16);
		if (!st->idi) return -1;
	}
	o += v16;

	if (o + 2 > len) return -1; v16 = ((uint16_t)p[o]<<8)|p[o+1]; o+=2;
	if (o + v16 > len) return -1;
	if (v16) {
		st->idr = rc_vnew(p + o, v16);
		if (!st->idr) return -1;
	}
	o += v16;

	if (o + 1 > len) return -1; v8 = p[o++];
	if (o + v8 > len) return -1;
	if (v8) {
		st->sk_d = rc_vnew(p + o, v8);
		if (!st->sk_d) return -1;
	}

	return 0;
}

rc_vchar_t *
r2ticket_create(const rc_vchar_t *tkey, const uint8_t key_id[R2TICK_KEY_ID_LEN],
    const struct r2ticket_state *st)
{
	rc_vchar_t *pt = NULL, *out = NULL;
	EVP_CIPHER_CTX *ctx = NULL;
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

	if (EVP_EncryptInit_ex(ctx, NULL, NULL, tkey->v, iv) != 1)
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

	if (!(ctx = EVP_CIPHER_CTX_new()))
		goto out;
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, R2TICK_IV_LEN,
	    NULL) != 1)
		goto out;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, tkey->v,
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

	if (st->expires_at && st->expires_at < (uint32_t)time(NULL))
		goto out;	/* expired */

	rc = 0;
	goto out;

 out:
	if (rc != 0)
		r2tick_state_free(st);
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
