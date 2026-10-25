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
/* A failure seen before any round trip (pre-IKE_SA_INIT: short/malformed
 * datagram, zero IKEv1 cookie).  Its source address is unverified and
 * spoofable, so it is reported (as AUTH_FAIL) only with the separate
 * default-off "blocklist_prehandshake on;". */
#define IKED_BL_PREHS_FAIL	2

/* Reporting policy, from racoon2.conf interface { } (all default off):
 *   blocklist on;               report to blocklistd at all
 *   blocklist_log_only on;      log what would be reported, send nothing
 *   blocklist_prehandshake on;  also report IKED_BL_PREHS_FAIL
 * The RACOON2_BLOCKLIST environment variable can only LOWER it ("off" or
 * "log"), never enable reporting the config left off. */
struct iked_bl_cfg {
	int enable, log_only, prehandshake;
	const char *env;		/* RACOON2_BLOCKLIST or NULL */
};
#define IKED_BL_DROP	0
#define IKED_BL_LOG	1
#define IKED_BL_SEND	2
int iked_blocklist_decide(int action, const struct iked_bl_cfg *);

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
