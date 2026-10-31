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
#include <errno.h>

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

/*
 * RFC 9329: the transmit decision + send-result contract, shared by
 * isakmp_try_tcp_send() and tcpsrvtest so the test drives the production
 * code rather than a copy.  Returns 0 when no stream applies (caller uses
 * UDP), 1 whenever a stream matched -- including when the send FAILED: a
 * tcp_encap peer's IKE never falls back to UDP.  *rp (if non-NULL) gets the
 * tcp_stream_send() result for logging and *tsp the stream (which, after a
 * fatal r<0, is already marked dead and must not be touched again beyond
 * reading its fields before the next event-loop pass).  On r<0 the stream is
 * retired with tcp_srv_teardown(), which only MARKS it dead: this function
 * may run inside that very stream's dispatch.
 */
int
ikev2_tcp_send(const struct ikev2_sa *sa, int sa_tcp_encap,
    const struct sockaddr *dest, const struct sockaddr *src,
    const unsigned char *pkt, size_t len, int *rp, struct tcp_stream **tsp)
{
	struct tcp_stream *ts;
	int r;

	if (pkt == NULL)
		return 0;
	ts = ikev2_tcp_route(sa, sa_tcp_encap, dest, src);
	if (ts == NULL)
		return 0;
	r = tcp_stream_send(ts, pkt, len);
	if (r < 0) {
		int e = errno;

		tcp_srv_teardown(ts);
		errno = e;
	}
	if (rp != NULL)
		*rp = r;
	if (tsp != NULL)
		*tsp = ts;
	return 1;
}
