/* iked/ikev2_drain.c
 *
 * Runtime drain-redirect table (see ikev2_drain.h).
 *
 * A small fixed-size array of peer->gw entries.  Peers are matched by
 * address (AF_INET / AF_INET6); insert updates in place, replace frees
 * the old gw, clear removes.  Bounded by IKEV2_DRAIN_MAX so a hostile
 * admin CLI cannot grow memory without bound.  The table is not
 * thread-synchronized: it is mutated only from the admin/CLI event path
 * and read from the IKE_SA_INIT responder path, which in this daemon run
 * on the same single-threaded IKE loop (the crypto workers handle KDF,
 * not the SA dispatch).  See the note in crypto_workers.c.
 */

#include <config.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "racoon.h"
#include "ikev2_drain.h"

#define IKEV2_DRAIN_MAX 256

struct ikev2_drain_entry {
	int used;
	struct sockaddr_storage peer;	/* AF_INET / AF_INET6 */
	char *gw;			/* NUL-terminated redirect target */
};

static struct ikev2_drain_entry ikev2_drain_tbl[IKEV2_DRAIN_MAX];

/* Peer-key equality on the significant bytes.  The key is per-ADDRESS
 * (family + IP address), deliberately EXCLUDING the source port: the
 * admin CLI (ikedctl drain-sa) builds the peer via fill_index with
 * port 0, while the responder's ikev2_drain_lookup(remote) passes the
 * packet's real source sockaddr (port 500/4500/ephemeral, never 0).
 * Matching on the full sockaddr incl. port would make every CLI-set
 * drain impossible to hit in live IKE_SA_INIT (reviewer-verified
 * blocker).  This mirrors ikev2_redirect_pool_select, which also keys
 * on the address only. */
static int
entry_matches(const struct ikev2_drain_entry *e, const struct sockaddr *p)
{
	const struct sockaddr *sp = (const struct sockaddr *)&e->peer;

	if (sp->sa_family != p->sa_family)
		return 0;
	switch (p->sa_family) {
	case AF_INET:
		return memcmp(&((const struct sockaddr_in *)sp)->sin_addr,
			      &((const struct sockaddr_in *)p)->sin_addr,
			      sizeof(struct in_addr)) == 0;
	case AF_INET6:
		return memcmp(&((const struct sockaddr_in6 *)sp)->sin6_addr,
			      &((const struct sockaddr_in6 *)p)->sin6_addr,
			      sizeof(struct in6_addr)) == 0;
	default:
		return 0;
	}
}

int
ikev2_drain_set(const struct sockaddr *peer, const char *gw)
{
	struct ikev2_drain_entry *e, *free_e;
	size_t i;
	char *dup;

	if (!peer ||
	    (peer->sa_family != AF_INET && peer->sa_family != AF_INET6))
		return -1;
	dup = gw ? strdup(gw) : NULL;
	if (gw && !dup)
		return -1;

	/* existing entry -> update in place */
	for (i = 0; i < IKEV2_DRAIN_MAX; i++) {
		e = &ikev2_drain_tbl[i];
		if (e->used && entry_matches(e, peer)) {
			if (e->gw)
				free(e->gw);
			if (dup) {
				e->gw = dup;
			} else {
				e->used = 0;
				e->gw = NULL;
				memset(&e->peer, 0, sizeof(e->peer));
			}
			return 0;
		}
	}
	if (!dup)
		return 0;	/* clearing an absent entry is a no-op */
	/* else: add to a free slot */
	free_e = NULL;
	for (i = 0; i < IKEV2_DRAIN_MAX; i++) {
		e = &ikev2_drain_tbl[i];
		if (!e->used) {
			free_e = e;
			break;
		}
	}
	if (!free_e)
		return -1;	/* table full */
	memset(free_e, 0, sizeof(*free_e));
	memcpy(&free_e->peer, peer, peer->sa_family == AF_INET ?
	       sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	free_e->gw = dup;
	free_e->used = 1;
	return 0;
}

const char *
ikev2_drain_lookup(const struct sockaddr *peer)
{
	size_t i;

	if (!peer)
		return NULL;
	for (i = 0; i < IKEV2_DRAIN_MAX; i++)
		if (ikev2_drain_tbl[i].used &&
		    entry_matches(&ikev2_drain_tbl[i], peer))
			return ikev2_drain_tbl[i].gw;
	return NULL;
}

void
ikev2_drain_clear_all(void)
{
	size_t i;

	for (i = 0; i < IKEV2_DRAIN_MAX; i++) {
		struct ikev2_drain_entry *e = &ikev2_drain_tbl[i];
		if (e->gw)
			free(e->gw);
		memset(e, 0, sizeof(*e));
	}
}
