/* $Id$ */
/*
 * RFC 5723 (IKEv2 Session Resumption): ticket-by-value codec and the
 * s5.1 resumed-IKE-SA key derivation (see ikev2_resume_ticket.c).
 *
 * A ticket is an opaque blob minted by the IKEv2 responder.  The responder
 * (and only the responder) can validate it and recover the original SA
 * state; the client treats it as opaque.  AES-256-GCM provides the mandatory
 * encryption + integrity protection (RFC 5723 s6.1).
 */

#ifndef IKEV2_RESUME_TICKET_H
#define IKEV2_RESUME_TICKET_H

#include <stdint.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include "vmbuf.h"

#define R2TICK_KEY_ID_LEN	8

/* The "from the ticket" IKE state (RFC 5723 s5).  All rc_vchar_t members
 * are read by create / owned-by-caller on a successful parse (free with
 * rc_vfree).  expires_at is absolute unix time. */
struct r2ticket_state {
	uint32_t	expires_at;
	uint8_t		auth_method;
	uint64_t	spi_i;
	uint64_t	spi_r;
	rc_vchar_t	*sa;		/* serialized IKE SA proposal (SAr) */
	rc_vchar_t	*idi;		/* IDi payload data */
	rc_vchar_t	*idr;		/* IDr payload data */
	rc_vchar_t	*sk_d;		/* OLD SK_d */
};

/* Create a ticket under tkey (32-octet AES-256).  Returns fresh opaque
 * rc_vchar_t (caller rc_vfree), or NULL on error. */
rc_vchar_t *r2ticket_create(const rc_vchar_t *tkey,
    const uint8_t key_id[R2TICK_KEY_ID_LEN],
    const struct r2ticket_state *st);

/* Validate a ticket and recover state.  0 + *st filled on success (caller
 * frees st->sa/idi/idr/sk_d); -1 on malformed/expired/tampered, *st zeroed. */
int r2ticket_parse(const rc_vchar_t *tkey, const rc_vchar_t *ticket,
    struct r2ticket_state *st);

/* RFC 5723 s5.1: SKEYSEED = prf(SK_d_old, "Resumption" | Ni | Nr). */
rc_vchar_t *r2ticket_skeyseed(int prf_id, const rc_vchar_t *sk_d_old,
    const rc_vchar_t *ni, const rc_vchar_t *nr);

/* map an IKEv2 PRF transform id to an HMAC EVP_MD (NULL if unsupported) */
const EVP_MD *r2ticket_prf_md(int prf_id);

/* Load a 32-octet AES-256 ticket key from a file path.  0 ok / -1 fail-closed
 * (missing, unreadable, or wrong length).  Caller owns *key; cleanse before
 * rc_vfree. */
int r2ticket_key_load(const char *path, rc_vchar_t **key);

#endif /* IKEV2_RESUME_TICKET_H */
