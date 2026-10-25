/*
 * blocklisttest: pin the blocklistd reporting policy.  Secure defaults:
 * nothing is reported unless racoon2.conf says "blocklist on;", the
 * spoofable pre-IKE_SA_INIT class needs its own opt-in, and the
 * RACOON2_BLOCKLIST environment variable can only lower the mode.
 */
#include <stdio.h>
#include "blocklist_peer.h"

static int fails;

static void
chk(int en, int lo, int ph, const char *env, int act, int want, int line)
{
	struct iked_bl_cfg c = { en, lo, ph, env };
	int got = iked_blocklist_decide(act, &c);

	if (got != want) {
		printf("FAIL line %d: en=%d lo=%d ph=%d env=%s act=%d "
		    "got %d want %d\n", line, en, lo, ph, env ? env : "-",
		    act, got, want);
		fails++;
	}
}
#define C(en, lo, ph, env, act, want) chk(en, lo, ph, env, act, want, __LINE__)

int
main(void)
{
	int a;

	if (iked_blocklist_decide(IKED_BL_AUTH_FAIL, NULL) != IKED_BL_DROP) {
		printf("FAIL: NULL cfg must drop\n");
		fails++;
	}
	/* default (all off): nothing, whatever the env says */
	for (a = IKED_BL_AUTH_OK; a <= IKED_BL_PREHS_FAIL; a++) {
		C(0, 0, 0, NULL, a, IKED_BL_DROP);
		C(0, 0, 0, "on", a, IKED_BL_DROP);
		C(0, 0, 0, "log", a, IKED_BL_DROP);
		C(0, 1, 1, NULL, a, IKED_BL_DROP);
	}
	/* enabled: post-SA_INIT results sent; pre-handshake still dropped */
	C(1, 0, 0, NULL, IKED_BL_AUTH_FAIL, IKED_BL_SEND);
	C(1, 0, 0, NULL, IKED_BL_AUTH_OK, IKED_BL_SEND);
	C(1, 0, 0, NULL, IKED_BL_PREHS_FAIL, IKED_BL_DROP);
	C(1, 1, 0, NULL, IKED_BL_PREHS_FAIL, IKED_BL_DROP);
	C(1, 0, 0, "log", IKED_BL_PREHS_FAIL, IKED_BL_DROP);
	/* pre-handshake opt-in */
	C(1, 0, 1, NULL, IKED_BL_PREHS_FAIL, IKED_BL_SEND);
	C(1, 1, 1, NULL, IKED_BL_PREHS_FAIL, IKED_BL_LOG);
	/* log-only via config or env */
	C(1, 1, 0, NULL, IKED_BL_AUTH_FAIL, IKED_BL_LOG);
	C(1, 0, 0, "log", IKED_BL_AUTH_FAIL, IKED_BL_LOG);
	/* env can only lower */
	C(1, 0, 1, "off", IKED_BL_AUTH_FAIL, IKED_BL_DROP);
	C(1, 0, 1, "off", IKED_BL_PREHS_FAIL, IKED_BL_DROP);
	C(1, 1, 0, "on", IKED_BL_AUTH_FAIL, IKED_BL_LOG);
	C(1, 0, 0, "bogus", IKED_BL_AUTH_FAIL, IKED_BL_SEND);
	/* unknown action */
	C(1, 0, 1, NULL, 99, IKED_BL_DROP);
	C(1, 0, 1, NULL, -1, IKED_BL_DROP);

	if (fails) {
		printf("blocklisttest: %d failure(s)\n", fails);
		return 1;
	}
	printf("blocklisttest: ok\n");
	return 0;
}
