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
#include "ike_conf.h"
#include "rc_net.h"
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
 * RFC 9329: is this IKE_SA's traffic TCP-bound?  Only when its remote
 * configuration exists and has tcp_encap on.  An SA without rmconf is NOT
 * tcp_encap (it must never be pulled onto a stream that happens to reach
 * the same peer).  The pre-SA IKE_SA_INIT (sa == NULL) is handled by
 * ikev2_tcp_route() itself, which ignores the flag when sa is NULL.
 */
int
ikev2_sa_tcp_encap(const struct ikev2_sa *sa)
{
	return sa != NULL && sa->rmconf != NULL &&
	    ikev2_tcp_encap(sa->rmconf) == RCT_BOOL_ON;
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

static void
rebind_dest(struct sockaddr **dp, const struct sockaddr *remote)
{
	struct sockaddr *n;

	if (*dp == NULL || (n = rcs_sadup(remote)) == NULL)
		return;
	rc_free(*dp);
	*dp = n;
}

/*
 * RFC 9329 s7 (MOBIKE / reconnect): a TCP-encapsulated peer that changed
 * its transport opens a NEW TCP connection and continues the IKE_SA on it.
 * When the peer address is unchanged but the message arrived on a
 * different live stream (new client source port), re-bind the responder
 * SA to that stream: its remote port is what ikev2_tcp_route()'s bound
 * lookup keys on, so without this replies keep going to the old (possibly
 * dead) stream or to whichever stream the address-only fallback finds
 * first.  An ADDRESS change is a real MOBIKE move and goes through
 * ikev2_mobike_apply(); an initiator's remote is the peer's IKE port,
 * not a stream port, so it is never re-bound here.  The child ESP is not
 * touched: over TCP it stays UDP-encapsulated on 4500/4500 (see
 * ikev2_mobike_natt).  Returns 1 when the SA was re-bound.
 */
int
ikev2_tcp_rebind(struct ikev2_sa *sa, const struct sockaddr *remote)
{
	struct sockaddr *n;

	if (sa == NULL || remote == NULL || sa->remote == NULL ||
	    sa->local == NULL || sa->is_initiator || !ikev2_sa_tcp_encap(sa))
		return 0;
	if (rcs_cmpsa_wop(remote, sa->remote) != 0)
		return 0;		/* address change: MOBIKE's job */
	if (rcs_cmpsa(remote, sa->remote) == 0)
		return 0;		/* same stream */
	if (tcp_srv_find_bound(remote, sa->local) == NULL)
		return 0;		/* not a live registered stream */
	if ((n = rcs_sadup(remote)) == NULL)
		return 0;
	rc_free(sa->remote);
	sa->remote = n;
	if (sa->transmit_info.packet || sa->transmit_info.frags)
		rebind_dest(&sa->transmit_info.dest, remote);
	if (sa->response_info.packet || sa->response_info.frags)
		rebind_dest(&sa->response_info.dest, remote);
	return 1;
}
