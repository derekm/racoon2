/*
 * iked/eaplocal.c - hermetic test of the responder's EAP-remote decision
 * gate, ikev2_eap_remote().
 *
 * The responder trigger (iked/ikev2.c responder_ike_sa_auth_recv0) must
 * route an IDi-without-AUTH message to the EAP relay ONLY for an
 * EAP-configured remote; every other method (PSK, a signature method, or an
 * unspecified method) keeps the existing reject.  This test proves that
 * ikev2_eap_remote() implements exactly that fail-closed gate, using a real
 * ikev2_sa and a real rcf_remote whose kmp_auth_method is a real
 * rc_alglist:
 *
 *   1. RCT_ALG_EAP  -> 1 (route to EAP)
 *   2. RCT_ALG_PSK  -> 0 (keep the reject)
 *   3. NULL (unspecified) -> 0 (keep the reject)
 *   4. NULL sa / NULL rmconf -> 0 (no crash, still rejects)
 *
 * Returns 0 iff all pass.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "ikev2_eap.h"
#include <getopt.h>
#include "test_util.h"

TEST_MAIN_STUBS()

/* build a fresh rc_alglist with a single method */
static struct rc_alglist *
mkalg(rc_type t)
{
	struct rc_alglist *a = racoon_calloc(1, sizeof(*a));
	if (a)
		a->algtype = t;
	return a;
}

/* point an SA's rmconf at a fresh, calloc'd remote (with ikev2 sub) */
static struct rcf_remote *
mkrmconf(void)
{
	struct rcf_remote *rm =
		(struct rcf_remote *)racoon_calloc(1, sizeof(struct rcf_remote));
	if (!rm)
		return NULL;
	rm->ikev2 = (struct rcf_kmp *)racoon_calloc(1, sizeof(struct rcf_kmp));
	if (!rm->ikev2) {
		racoon_free(rm);
		return NULL;
	}
	return rm;
}

int
main(void)
{
	struct ikev2_sa *sa;
	struct rcf_remote *rm;
	struct rc_alglist *alg;
	int got, fails = 0;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;
	ikev2_sa_init();
	sched_init();

	/* ---- 1. RCT_ALG_EAP -> 1 (route to EAP) ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	rm = mkrmconf();
	alg = mkalg(RCT_ALG_EAP);
	if (!rm || !alg) return 2;
	rm->ikev2->kmp_auth_method = alg;
	sa->rmconf = rm;	/* direct: bypass set_rmconf accessor reads */
	got = ikev2_eap_remote(sa);
	if (got == 1)
		printf("eaplocal: PASS 1 EAP remote is EAP\n");
	else {
		printf("eaplocal: FAIL 1 EAP remote -> %d (want 1)\n", got);
		fails++;
	}
	sa->rmconf = NULL;	/* don't let dispose free our test remote */
	ikev2_dispose_sa(sa);
	racoon_free(alg);
	racoon_free(rm->ikev2);
	racoon_free(rm);

	/* ---- 2. RCT_ALG_PSK -> 0 (keep the reject) ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	rm = mkrmconf();
	alg = mkalg(RCT_ALG_PSK);
	if (!rm || !alg) return 2;
	rm->ikev2->kmp_auth_method = alg;
	sa->rmconf = rm;
	got = ikev2_eap_remote(sa);
	if (got == 0)
		printf("eaplocal: PASS 2 PSK remote is not EAP\n");
	else {
		printf("eaplocal: FAIL 2 PSK remote -> %d (want 0)\n", got);
		fails++;
	}
	sa->rmconf = NULL;
	ikev2_dispose_sa(sa);
	racoon_free(alg);
	racoon_free(rm->ikev2);
	racoon_free(rm);

	/* ---- 3. NULL method (unspecified) -> 0 ---- */
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	rm = mkrmconf();
	if (!rm) return 2;
	rm->ikev2->kmp_auth_method = NULL;
	sa->rmconf = rm;
	got = ikev2_eap_remote(sa);
	if (got == 0)
		printf("eaplocal: PASS 3 unspecified remote is not EAP\n");
	else {
		printf("eaplocal: FAIL 3 unspecified -> %d (want 0)\n", got);
		fails++;
	}
	sa->rmconf = NULL;
	ikev2_dispose_sa(sa);
	racoon_free(rm->ikev2);
	racoon_free(rm);

	/* ---- 4. NULL sa / NULL rmconf -> 0, no crash ---- */
	got = ikev2_eap_remote(NULL);
	if (got == 0)
		printf("eaplocal: PASS 4a NULL sa -> 0\n");
	else {
		printf("eaplocal: FAIL 4a NULL sa -> %d (want 0)\n", got);
		fails++;
	}
	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	sa->rmconf = NULL;
	got = ikev2_eap_remote(sa);
	if (got == 0)
		printf("eaplocal: PASS 4b NULL rmconf -> 0\n");
	else {
		printf("eaplocal: FAIL 4b NULL rmconf -> %d (want 0)\n", got);
		fails++;
	}
	ikev2_dispose_sa(sa);

	printf("eaplocal: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
