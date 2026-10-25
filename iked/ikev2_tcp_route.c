/*
 * RFC 9329: pick the IKE-over-TCP stream an outgoing IKE message rides.
 * Kept out of isakmp.c so tcpsrvtest can drive the exact production
 * selection with real struct ikev2_sa objects.
 */
#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "racoon.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_tcp_stream.h"
#include "ikev2_tcp_srv.h"
#include "ikev2_tcp_route.h"

/*
 * sa_tcp_encap: nonzero when the SA's remote has tcp_encap on (or there is
 * no SA yet, i.e. the pre-SA IKE_SA_INIT).  A UDP SA never rides a stream,
 * even if one exists to the same peer.
 *
 * An established SA first takes the stream bound to its own endpoints
 * (remote address + port, local address): with several clients behind one
 * NAT, only the port tells their streams apart.  sa->remote / sa->local are
 * struct sockaddr pointers.  Pass them as they are, not their addresses.
 * When no bound stream matches (pre-SA IKE_SA_INIT, or an SA whose remote
 * still carries the IKE port), fall back to the address-only lookup.
 */
struct tcp_stream *
ikev2_tcp_route(const struct ikev2_sa *sa, int sa_tcp_encap,
    const struct sockaddr *dest, const struct sockaddr *src)
{
	struct tcp_stream *ts = NULL;

	if (sa != NULL && !sa_tcp_encap)
		return NULL;
	if (sa != NULL && sa->remote != NULL && sa->local != NULL)
		ts = tcp_srv_find_bound(sa->remote, sa->local);
	if (ts == NULL && dest != NULL)
		ts = tcp_srv_find(dest, src);
	return ts;
}
