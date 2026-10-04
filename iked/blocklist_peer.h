/*
 * Optional libblocklist (blocklistd) glue for iked.
 * Stubs compile when --enable-blocklist is off.
 *
 * The action codes are iked-private on purpose: <blocklist.h> declares
 * BLOCKLIST_AUTH_OK etc. as enumerators, so a same-named #define here
 * would rewrite that enum and break the --enable-blocklist build.
 */
#ifndef IKED_BLOCKLIST_PEER_H
#define IKED_BLOCKLIST_PEER_H

#include <sys/types.h>
#include <sys/socket.h>

#define IKED_BL_AUTH_OK		0	/* -> BLOCKLIST_AUTH_OK (resets count) */
#define IKED_BL_AUTH_FAIL	1	/* -> BLOCKLIST_AUTH_FAIL (counts) */

void iked_blocklist_init(void);

/*
 * Report a peer.  fd is the iked UDP socket the datagram arrived on;
 * blocklistd getsockname()s it to match the [local] 500/4500 rule, so
 * it must be a real socket (fd < 0 => report is dropped locally).
 * AUTH_FAIL reports are rate-limited per source and globally.
 */
void iked_blocklist_peer(int action, int fd, const struct sockaddr *remote,
    const char *why);

#endif
