#ifndef _IKEV2_TCP_ROUTE_H_
#define _IKEV2_TCP_ROUTE_H_

#include <stddef.h>

struct ikev2_sa;
struct sockaddr;
struct tcp_stream;

/* RFC 9329: the stream an outgoing IKE message for `sa` must ride, or NULL
 * for UDP.  See ikev2_tcp_route.c. */
struct tcp_stream *ikev2_tcp_route(const struct ikev2_sa *sa,
    int sa_tcp_encap, const struct sockaddr *dest,
    const struct sockaddr *src);

/* RFC 9329: route + send + result contract (see ikev2_tcp_route.c).
 * 0 = no stream, use UDP; 1 = handled on TCP (even on failure). */
int ikev2_tcp_send(const struct ikev2_sa *sa, int sa_tcp_encap,
    const struct sockaddr *dest, const struct sockaddr *src,
    const unsigned char *pkt, size_t len, int *rp, struct tcp_stream **tsp);

#endif
