/* iked/ikev2_drain.h
 *
 * Runtime drain-redirect table (RFC 5685 failover integration, step 4).
 *
 * An operator may drain a concentrator for maintenance / failure without
 * editing + reloading config: a per-peer drain entry records a redirect
 * gateway to use for NEW IKE_SA_INITs from that peer, taking precedence
 * over the config redirect_to.  This is exactly the "regardless of
 * proposal but only to a peer that offered 16406" rule — the drain only
 * changes WHERE the responder redirects, not whether it may (the
 * peer-offered-16406 gate and the no-SA REDIRECT response are unchanged).
 *
 * The table is keyed by peer address (the same address the responder uses
 * in ikev2_sa_init.c to pick the config redirect target), so a CLI
 * management plane can drain one peer or the whole pool entry-by-entry.
 * Entries are small and bounded; the responder path is O(entries).
 *
 * All functions are exported for the admin (admin.c) and the responder
 * (ikev2_sa_init.c).  The same functions are exercised from a unit test.
 */

#ifndef _IKEV2_DRAIN_H
#define _IKEV2_DRAIN_H

#include <sys/socket.h>
#include <stdint.h>

/* Set (or clear, when gw==NULL) the drain-redirect target for `peer`.
 * `peer` must be a valid AF_INET/AF_INET6 sockaddr.  Returns 0 on
 * success, -1 on error (ENOMEM). */
int ikev2_drain_set(const struct sockaddr *peer, const char *gw);

/* Look up the drain target for `peer`, else NULL.  Borrowed (do not
 * free).  A caller that only needs the pool-select callback passes peer
 * and gets a stable pointer for the duration of the call. */
const char *ikev2_drain_lookup(const struct sockaddr *peer);

/* Reset the whole table (used by reload). */
void ikev2_drain_clear_all(void);

#endif /* _IKEV2_DRAIN_H */
