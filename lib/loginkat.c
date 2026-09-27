/*
 * loginkat — Known-Answer Test for the spmd control-channel login MAC.
 *
 * The login handshake (ik ed/spmd shell) is:
 *   server sends:  220 <challenge>      (random hex, one per connection)
 *   client replies: LOGIN <h>           where h = hex(HMAC-SHA256(key=password,
 *                                       data=challenge)), password being the
 *                                       spmd interface secret hex string.
 * Both sides compute h through the SAME libracoon function
 * spmd_if_login_response(), so this test link against libracoon.la and checks
 * that function against pinned reference digests (computed independently
 * with Python hashlib, not from this code path).
 *
 * This replaces the historical SHA1(challenge || password) plain-digest
 * construction (length-extension-prone, unkeyed concatenation) with a keyed
 * MAC (F7).  The vectors below would all fail under the old code.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "racoon.h"
#include "if_spmd.h"

static int
check(const char *pw, const char *challenge, const char *expect)
{
	struct spmd_cid cid;
	int rc = 0;

	memset(&cid, 0, sizeof(cid));
	cid.password = (char *)pw;
	cid.challenge = (char *)challenge;

	if (spmd_if_login_response(&cid) < 0) {
		fprintf(stderr, "loginkat: spmd_if_login_response failed\n");
		return 1;
	}
	if (strcmp(cid.hash, expect) != 0) {
		fprintf(stderr,
		    "loginkat: MISMATCH\n  got     : %s\n  expected: %s\n",
		    cid.hash, expect);
		rc = 1;
	} else {
		printf("loginkat: PASS (%s)\n", cid.hash);
	}
	free(cid.hash);
	return rc;
}

int
main(int ac, char **av)
{
	int fail = 0;

	(void)ac; (void)av;
	plog_setmode(RCT_LOGMODE_NORMAL, NULL, "loginkat", 1, 1);

	/* v1: 64-hex password, 40-hex challenge */
	fail |= check(
	    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
	    "A1B2C3D4E5F60718293A0B1C2D3E4F5061728394",
	    "5E03268D8906FE71EEFA6D54DA3A68161496E44EC1F5AF857803DF4852D23881");

	/* v2: different password + 72-hex challenge */
	fail |= check(
	    "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
	    "00112233445566778899AABBCCDDEEFF00112233445566778899",
	    "3C83B4AB49FF7EE8FC73864160859D8C8774F7576981260EE633CD5099F13A8B");

	/* v3: short inputs */
	fail |= check(
	    "4B52574759354A624E5A4E",
	    "CAFEBABE",
	    "19020FF15CD00650C90F2A34ADF22752B5F112F6FACCA1A09858E0F4E15ECA24");

	if (fail) {
		printf("loginkat: FAIL\n");
		return 1;
	}
	printf("loginkat: ALL PASS\n");
	return 0;
}
