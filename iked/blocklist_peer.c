/*
 * Notify blocklistd about IKE scanners / AUTH failures.
 * Default build is a no-op; --enable-blocklist links -lblocklist.
 *
 * Scanner-only contract (doc/blocklist.md): callers report malformed
 * datagrams, zero IKEv1 initiator cookies and IKEv2 responder-side
 * AUTH verification results.  Never call this for INVALID_SYNTAX on a
 * live SA / rekey, QCD, window mismatch or DPD silence.
 *
 * Runtime switch (read once in iked_blocklist_init()):
 *   RACOON2_BLOCKLIST=off   never talk to blocklistd
 *   RACOON2_BLOCKLIST=log   log what would be reported, send nothing
 *   unset / anything else   report (default)
 */
#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "blocklist_peer.h"

#ifdef HAVE_BLOCKLIST
#include <blocklist.h>

#include "racoon.h"

/* AUTH_FAIL rate limits; override at build time with -D if needed. */
#ifndef IKED_BL_PEER_INTERVAL
#define IKED_BL_PEER_INTERVAL	10	/* s between reports per source */
#endif
#ifndef IKED_BL_GLOBAL_PER_SEC
#define IKED_BL_GLOBAL_PER_SEC	20	/* reports/s across all sources */
#endif
#define IKED_BL_SLOTS		256	/* per-source table, power of 2 */

enum { BL_MODE_ON, BL_MODE_LOG, BL_MODE_OFF };

struct bl_slot {
	int family;
	uint8_t addr[16];
	time_t last;
};

static struct blocklist *blstate;
static int bl_mode = -1;
static struct bl_slot bl_slots[IKED_BL_SLOTS];
static time_t bl_global_sec;
static unsigned int bl_global_cnt;
static unsigned long bl_suppressed;

static time_t
bl_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		return time(NULL);
	return ts.tv_sec;
}

void
iked_blocklist_init(void)
{
	const char *s;

	if (bl_mode == -1) {
		s = getenv("RACOON2_BLOCKLIST");
		if (s != NULL && strcmp(s, "off") == 0)
			bl_mode = BL_MODE_OFF;
		else if (s != NULL && strcmp(s, "log") == 0)
			bl_mode = BL_MODE_LOG;
		else
			bl_mode = BL_MODE_ON;
		plog(PLOG_INFO, PLOGLOC, NULL, "blocklist: mode %s\n",
		    bl_mode == BL_MODE_OFF ? "off" :
		    bl_mode == BL_MODE_LOG ? "log-only" : "on");
	}
	if (bl_mode == BL_MODE_ON && blstate == NULL)
		blstate = blocklist_open();
}

/*
 * Normalise to a plain v4/v6 address.  An IPv4-mapped IPv6 source is
 * reported as AF_INET so the nft ban lands in the v4 set the kernel
 * actually matches.
 */
static int
bl_normalise(const struct sockaddr *sa, struct sockaddr_storage *out,
    socklen_t *outlen, struct bl_slot *key)
{
	memset(out, 0, sizeof(*out));
	memset(key, 0, sizeof(*key));
	switch (sa->sa_family) {
	case AF_INET:
		memcpy(out, sa, sizeof(struct sockaddr_in));
		*outlen = sizeof(struct sockaddr_in);
		key->family = AF_INET;
		memcpy(key->addr, &((const struct sockaddr_in *)sa)->sin_addr, 4);
		return 0;
#ifdef INET6
	case AF_INET6: {
		const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;

		if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)) {
			struct sockaddr_in *s4 = (struct sockaddr_in *)out;

			s4->sin_family = AF_INET;
#ifdef HAVE_SA_LEN
			s4->sin_len = sizeof(*s4);
#endif
			s4->sin_port = s6->sin6_port;
			memcpy(&s4->sin_addr, &s6->sin6_addr.s6_addr[12], 4);
			*outlen = sizeof(struct sockaddr_in);
			key->family = AF_INET;
			memcpy(key->addr, &s4->sin_addr, 4);
			return 0;
		}
		memcpy(out, sa, sizeof(struct sockaddr_in6));
		*outlen = sizeof(struct sockaddr_in6);
		key->family = AF_INET6;
		memcpy(key->addr, &s6->sin6_addr, 16);
		return 0;
	}
#endif
	default:
		return -1;
	}
}

/* 1 = report now, 0 = suppressed by the per-source or global limit. */
static int
bl_allow(const struct bl_slot *key)
{
	uint32_t h = 2166136261u;
	struct bl_slot *s;
	time_t now;
	size_t i;

	for (i = 0; i < sizeof(key->addr); i++)
		h = (h ^ key->addr[i]) * 16777619u;
	h ^= (uint32_t)key->family;
	s = &bl_slots[h & (IKED_BL_SLOTS - 1)];

	now = bl_now();
	if (s->family == key->family &&
	    memcmp(s->addr, key->addr, sizeof(s->addr)) == 0 &&
	    now - s->last < IKED_BL_PEER_INTERVAL)
		return 0;

	if (now != bl_global_sec) {
		bl_global_sec = now;
		bl_global_cnt = 0;
	}
	if (bl_global_cnt >= IKED_BL_GLOBAL_PER_SEC)
		return 0;
	bl_global_cnt++;

	/* slot collisions just evict: worst case a source reports early */
	s->family = key->family;
	memcpy(s->addr, key->addr, sizeof(s->addr));
	s->last = now;
	return 1;
}

void
iked_blocklist_peer(int action, int fd, const struct sockaddr *sa,
    const char *why)
{
	struct sockaddr_storage ss;
	struct bl_slot key;
	socklen_t slen;
	int blaction;

	if (bl_mode == -1)
		iked_blocklist_init();
	if (bl_mode == BL_MODE_OFF || sa == NULL)
		return;
	if (bl_normalise(sa, &ss, &slen, &key) != 0)
		return;
	if (why == NULL)
		why = "iked";

	switch (action) {
	case IKED_BL_AUTH_FAIL:
		blaction = BLOCKLIST_AUTH_FAIL;
		if (!bl_allow(&key)) {
			if ((++bl_suppressed & 0x3ff) == 1)
				plog(PLOG_DEBUG, PLOGLOC, NULL,
				    "blocklist: rate-limited %s from %s "
				    "(%lu suppressed so far)\n", why,
				    rcs_sa2str((struct sockaddr *)&ss),
				    bl_suppressed);
			return;
		}
		break;
	case IKED_BL_AUTH_OK:
		blaction = BLOCKLIST_AUTH_OK;
		break;
	default:
		return;
	}

	if (fd < 0) {
		plog(PLOG_INTWARN, PLOGLOC, NULL,
		    "blocklist: no local socket for %s (%s); not reported\n",
		    rcs_sa2str((struct sockaddr *)&ss), why);
		return;
	}

	if (bl_mode == BL_MODE_LOG) {
		plog(PLOG_INFO, PLOGLOC, NULL,
		    "blocklist(log-only): would report %s %s fd=%d (%s)\n",
		    blaction == BLOCKLIST_AUTH_OK ? "AUTH_OK" : "AUTH_FAIL",
		    rcs_sa2str((struct sockaddr *)&ss), fd, why);
		return;
	}

	if (blstate == NULL)
		iked_blocklist_init();
	if (blstate == NULL)
		return;
	if (blocklist_sa_r(blstate, blaction, fd,
	    (const struct sockaddr *)&ss, slen, why) == -1)
		plog(PLOG_DEBUG, PLOGLOC, NULL,
		    "blocklist: notify blocklistd failed for %s (%s)\n",
		    rcs_sa2str((struct sockaddr *)&ss), why);
	else
		plog(PLOG_INFO, PLOGLOC, NULL,
		    "blocklist: reported %s %s (%s)\n",
		    blaction == BLOCKLIST_AUTH_OK ? "AUTH_OK" : "AUTH_FAIL",
		    rcs_sa2str((struct sockaddr *)&ss), why);
}
#else
void
iked_blocklist_init(void)
{
}

void
iked_blocklist_peer(int action, int fd, const struct sockaddr *sa,
    const char *why)
{
	(void)action;
	(void)fd;
	(void)sa;
	(void)why;
}
#endif
