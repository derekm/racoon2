/* $Id$ */
/*
 * iked/ikev2_tcp_srv.h -- RFC 9329 TCP listener + stream registry.
 *
 * This is what the iked main loop drives.  One listener socket (IKE port)
 * plus the set of accepted tcp_stream connections are held here; the loop
 * asks which fds to wait on (read AND write) and hands the ready sets back
 * for processing.  It is deliberately separate from the UDP recvfrom path in
 * isakmp.c so the existing UDP handling stays untouched.
 *
 *   tcp_srv_open_listener()   - non-blocking SOCK_STREAM listener (IKE port)
 *   tcp_srv_accept_pending()  - accept every queued conn into a tcp_stream
 *   tcp_srv_fdset()           - build rfds/wfds (read + write readiness)
 *   tcp_srv_process()         - accept (listener ready), drain streams (read
 *                               ready), finish connects / flush (write ready)
 *
 * Lifecycle: an accepted stream is removed and closed on framing-fatal, peer
 * FIN, or a refused/failed connect (all surfaced as -1).  framing-fatal and
 * IKE-layer decisions are separated exactly as in ikev2_tcp_stream.c: a
 * short-IKE record is dropped, an IKE dispatch return is IKE bookkeeping, and
 * only a -1 closes the stream.  This module owns the stream objects it holds.
 *
 * The registry is a tasteless but deliberate design until the daemon wires
 * it: iked is single-threaded, so no locking is needed.
 */
#ifndef _IKEV2_TCP_SRV_H_
#define _IKEV2_TCP_SRV_H_

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include "vmbuf.h"
#include "ikev2_tcp_stream.h"

void tcp_srv_init(tcp_stream_dispatch dispatch, void *arg);
void tcp_srv_fini(void);

/* Create the non-blocking TCP listener on [local]addr.  RFC 9329's default
 * port is 4500 (IKEV2_TCP_PORT).  `port` is authoritative when non-zero;
 * when zero, the port already in `local` is kept (so a caller may bind to
 * 4500 explicitly, or pass a sockaddr already carrying the port).  Returns
 * the fd (owned by this module) or -1. */
int tcp_srv_open_listener(const struct sockaddr *local, int port);
int tcp_srv_listener_fd(void);

/* Accept every pending connection into a registered tcp_stream.  >=0 count. */
int tcp_srv_accept_pending(void);

/* Fill rfds (always) and wfds (streams with queued outbound bytes; a
 * connecting stream is parked and driven by the initiator path, not here).
 * May be NULL.  Returns max fd + 1. */
int tcp_srv_fdset(fd_set *rfds, fd_set *wfds);

/* Drive the registry with the ready sets from evloop_wait_rw: accept on a
 * ready listener, drain ready streams, flush write-ready streams, and tear
 * down a stream whose read/write returned fatal. */
void tcp_srv_process(const fd_set *rfds, const fd_set *wfds);

/* Number of live streams (for diagnostics/tests). */
int tcp_srv_count(void);

/* Find the registered stream whose peer == remote and local source == local
 * (address+port, family-exact).  NULL if none.  This is how the transmit path
 * routes a reply back onto the same TCP stream an IKE message arrived on. */
struct tcp_stream *tcp_srv_find(const struct sockaddr *remote,
				const struct sockaddr *local);

#endif /* _IKEV2_TCP_SRV_H_ */
