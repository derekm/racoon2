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

/* filename prefix for the initiator-side persistence store (see below) */
#define R2TICK_STORE_PREFIX	"r2tkt-"

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
	uint32_t	cert_due;	/* cert notAfter unix time, 0 if none */
};

/* Create a ticket under tkey (32-octet AES-256).  Returns fresh opaque
 * rc_vchar_t (caller rc_vfree), or NULL on error. */
rc_vchar_t *r2ticket_create(const rc_vchar_t *tkey,
    const uint8_t key_id[R2TICK_KEY_ID_LEN],
    const struct r2ticket_state *st);

/* Validate a ticket and recover state.  0 + *st filled on success (caller
 * frees with r2ticket_state_free); -1 on malformed/expired/tampered, *st
 * zeroed. */
int r2ticket_parse(const rc_vchar_t *tkey, const rc_vchar_t *ticket,
    struct r2ticket_state *st);

/* One expiry rule for every ticket check (responder parse, initiator
 * store, replay cache): a ticket is usable while now < expires_at, i.e.
 * for exactly its lifetime after minting.  expires_at == 0 is never
 * minted (both mint sites add a lifetime to the clock) and is treated as
 * expired, so a zeroed or corrupt record fails closed. */
int r2ticket_expired(uint32_t expires_at, uint32_t now);

/* Free the heap members of a state returned by r2ticket_parse and zero it. */
void r2ticket_state_free(struct r2ticket_state *st);

/* RFC 5723 s5.1: SKEYSEED = prf(SK_d_old, "Resumption" | Ni | Nr). */
rc_vchar_t *r2ticket_skeyseed(int prf_id, const rc_vchar_t *sk_d_old,
    const rc_vchar_t *ni, const rc_vchar_t *nr);

/* RFC 5723 s5.1 / RFC 7296 s2.14 key expansion.  From the resumed SKEYSEED
 * derive the full resumed IKE SA key set:
 *     {SK_d|SK_ai|SK_ar|SK_ei|SK_er|SK_pi|SK_pr} =
 *         prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
 * Returns a fresh rc_vchar_t holding sk_d_len + 2*sk_ai_len + 2*sk_ei_len +
 * 2*sk_pi_len octets, laid out in that order (SK_d then ai,ar,ei,er,pi,pr).
 * A single key of that length must be sliced by the caller.  NULL on any
 * error (unsupported prf, NULL seed/ni/nr). */
rc_vchar_t *r2ticket_keyexp(int prf_id, const rc_vchar_t *skeyseed,
    const rc_vchar_t *ni, const rc_vchar_t *nr,
    const uint8_t spi_i[8], const uint8_t spi_r[8],
    size_t sk_d_len, size_t sk_ai_len, size_t sk_ei_len, size_t sk_pi_len);

/* map an IKEv2 PRF transform id to an HMAC EVP_MD (NULL if unsupported) */
const EVP_MD *r2ticket_prf_md(int prf_id);

/* Load a 32-octet AES-256 ticket key from a file path.  0 ok / -1 fail-closed
 * (missing, unreadable, or wrong length).  Caller owns *key; cleanse before
 * rc_vfree. */
int r2ticket_key_load(const char *path, rc_vchar_t **key);

/* Build the RFC 5723 s7.1 TICKET_LT_OPAQUE notify DATA: a 4-octet big-endian
 * Lifetime (seconds) followed by the minted ticket.  Returns a fresh
 * rc_vchar_t (caller rc_vfree), or NULL on any error. */
rc_vchar_t *r2ticket_lt_opaque(const rc_vchar_t *tkey,
    const uint8_t key_id[R2TICK_KEY_ID_LEN], const struct r2ticket_state *st,
    uint32_t lifetime_sec);

/*
 * INITIATOR-side persistence store (RFC 5723 s4.2/s4.3): the client keeps the
 * responder-minted ticket plus the "from the ticket" IKE state so that, after
 * the original IKE SA dies, it can resume a NEW exchange 38 to the same peer.
 * This store is deliberately SEPARATE from the daemon's legacy crash-resume
 * dir (iked/ikev2_resume.c) and from the responder's live ticket key.
 *
 * A stored entry binds a filesystem-safe 'key' (the caller formats it, e.g. a
 * remote IP/ID string) to {lifetime||ticket} and the packed r2ticket_state.
 * The record is length-checked on load; bytes are cleansed before free.
 *
 *   r2ticket_store_save(dir, key, ticket_lt, st)  0 ok / -1 on any I/O or
 *                          (ticket_lt = 4-octet lifetime||ticket)
 *   r2ticket_store_load(dir, key, ticket_lt, st)  0 + owned *ticket_lt and
 *                          *st filled (caller frees) / -1 missing or corrupt
 *   r2ticket_store_clear(dir, key)
 */
int r2ticket_store_save(const char *dir, const char *key,
    const rc_vchar_t *ticket_lt, const struct r2ticket_state *st);
int r2ticket_store_load(const char *dir, const char *key,
    rc_vchar_t **ticket_lt, struct r2ticket_state *st);
void r2ticket_store_clear(const char *dir, const char *key);

/* RFC 5723 s4.3.1 "A reused ticket SHOULD be rejected by a gateway":
 * bounded in-memory cache of the tickets this responder has accepted,
 * each kept until the ticket's own expiry (after which r2ticket_parse()
 * refuses it anyway).  r2ticket_replay_mark() records the SHA-256 of the
 * opaque ticket and returns 0 on first use, 1 when the ticket was seen
 * before, -1 when every slot holds an unexpired ticket (fail closed: the
 * caller NACKs, the client falls back to a full exchange).  The cache does
 * does not survive an iked restart unless r2ticket_replay_bind_key() has
 * pointed the cache at a directory (beside the ticket key).  That
 * directory is the cluster single-use set: two ikeds that load the same
 * key file share it.  r2ticket_replay_reset() clears memory only. */
#define R2TICK_REPLAY_SLOTS	4096
int r2ticket_replay_mark(const rc_vchar_t *ticket, uint32_t expires_at,
    uint32_t now);
void r2ticket_replay_reset(void);
void r2ticket_replay_set_dir(const char *dir);
void r2ticket_replay_bind_key(const char *keypath);

#endif /* IKEV2_RESUME_TICKET_H */
