#ifndef _IKEV2_TCP_ROUTE_H_
#define _IKEV2_TCP_ROUTE_H_

struct ikev2_sa;
struct sockaddr;
struct tcp_stream;

/* RFC 9329: the stream an outgoing IKE message for `sa` must ride, or NULL
 * for UDP.  See ikev2_tcp_route.c. */
struct tcp_stream *ikev2_tcp_route(const struct ikev2_sa *sa,
    int sa_tcp_encap, const struct sockaddr *dest,
    const struct sockaddr *src);

#endif
