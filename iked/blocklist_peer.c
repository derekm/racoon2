/*
 * Notify blocklistd about IKE scanners / AUTH failures.
 * Default build is a no-op; --enable-blocklist links -lblocklist.
 */
#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "blocklist_peer.h"

#ifdef HAVE_BLOCKLIST
#include <blocklist.h>

static struct blocklist *blstate;

void
iked_blocklist_init(void)
{
	if (blstate == NULL)
		blstate = blocklist_open();
}

void
iked_blocklist_peer(int action, const struct sockaddr *sa, const char *why)
{
	socklen_t slen;

	if (blstate == NULL)
		iked_blocklist_init();
	if (blstate == NULL || sa == NULL)
		return;
	switch (sa->sa_family) {
	case AF_INET:
		slen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		slen = sizeof(struct sockaddr_in6);
		break;
	default:
		return;
	}
	(void)blocklist_sa_r(blstate, action, -1, sa, slen,
	    why ? why : "iked");
}
#else
void
iked_blocklist_init(void)
{
}

void
iked_blocklist_peer(int action, const struct sockaddr *sa, const char *why)
{
	(void)action;
	(void)sa;
	(void)why;
}
#endif
