/* Optional libblocklist glue. Stubs compile when --enable-blocklist is off. */
#ifndef IKED_BLOCKLIST_PEER_H
#define IKED_BLOCKLIST_PEER_H

#include <sys/socket.h>

#ifndef BLOCKLIST_AUTH_OK
#define BLOCKLIST_AUTH_OK		0
#define BLOCKLIST_AUTH_FAIL		1
#define BLOCKLIST_ABUSIVE_BEHAVIOR	2
#define BLOCKLIST_BAD_USER		3
#endif

void iked_blocklist_init(void);
void iked_blocklist_peer(int action, const struct sockaddr *sa, const char *why);

#endif
