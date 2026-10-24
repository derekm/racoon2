/*
 * blocklistd reporting policy (pure; see blocklist_peer.h).  Kept apart
 * from blocklist_peer.c so it is built and unit-tested (blocklisttest)
 * in every configuration, with or without --enable-blocklist.
 */
#include <stddef.h>
#include <string.h>

#include "blocklist_peer.h"

int
iked_blocklist_decide(int action, const struct iked_bl_cfg *c)
{
	int log_only;

	if (c == NULL || !c->enable)
		return IKED_BL_DROP;
	if (c->env != NULL && strcmp(c->env, "off") == 0)
		return IKED_BL_DROP;
	log_only = c->log_only ||
	    (c->env != NULL && strcmp(c->env, "log") == 0);
	switch (action) {
	case IKED_BL_PREHS_FAIL:
		if (!c->prehandshake)
			return IKED_BL_DROP;
		break;
	case IKED_BL_AUTH_FAIL:
	case IKED_BL_AUTH_OK:
		break;
	default:
		return IKED_BL_DROP;
	}
	return log_only ? IKED_BL_LOG : IKED_BL_SEND;
}

