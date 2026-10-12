/*
 * test_ikev1_hardening.c -- unit tests for the peer-input hardening ported
 * from (or found while studying) rdratlos/racoon-ipsec-tools:
 *   - length-checked, constant-time payload compare (hashcmp.c), used by
 *     the IKEv1 HASH(1..4)/Phase-1 HASH and Quick Mode ID-echo checks;
 *   - Vendor ID matching never reads past a short VID payload (pre-auth);
 *   - draft NAT-T 00/01 (ESPINUDP_NON_IKE) is no longer recognized.
 * Buffers holding a "received" payload are malloc'ed at their exact
 * on-wire size, so an over-read is caught by ASan (Fedora ASan job).
 */
#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"
#include "isakmp.h"
#include "isakmp_var.h"
#include "isakmp_impl.h"
#include "crypto_impl.h"
#include "hashcmp.h"
#include "ikev1/vendorid.h"
#include "ikev1/ikev1_natt.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

/* exact-size payload: 4-byte generic header + body */
static struct isakmp_gen *
mkpl(const void *body, size_t blen, size_t claim)
{
	struct isakmp_gen *g = malloc(sizeof(*g) + blen);

	if (g == NULL)
		exit(1);
	memset(g, 0, sizeof(*g));
	g->len = htons((uint16_t)claim);
	if (blen)
		memcpy(g + 1, body, blen);
	return g;
}

static void
test_payload_body_cmp(void)
{
	unsigned char h[20], h2[20];
	struct isakmp_gen *g;

	memset(h, 0xa5, sizeof(h));
	memcpy(h2, h, sizeof(h2));

	g = mkpl(h, 20, 4 + 20);
	TEST_CHECK(ike_payload_body_cmp(h, 20, g) == 0);
	free(g);

	h2[19] ^= 1;
	g = mkpl(h2, 20, 4 + 20);
	TEST_CHECK(ike_payload_body_cmp(h, 20, g) == 1);
	free(g);

	/* B3: 4-byte HASH payload body vs a 20-byte PRF output */
	g = mkpl(h, 4, 4 + 4);
	TEST_CHECK(ike_payload_body_cmp(h, 20, g) == -1);
	free(g);

	/* longer than the PRF output is malformed too */
	g = mkpl(h, 20, 4 + 20);
	TEST_CHECK(ike_payload_body_cmp(h, 16, g) == -1);
	free(g);

	/* length field shorter than the generic header */
	g = mkpl(NULL, 0, 2);
	TEST_CHECK(ike_payload_body_cmp(h, 20, g) == -1);
	free(g);

	TEST_CHECK(ike_payload_body_cmp(h, 20, NULL) == -1);
}

static void
test_ct_equal(void)
{
	TEST_CHECK(ike_ct_equal("abcd", "abcd", 4));
	TEST_CHECK(!ike_ct_equal("abcd", "abce", 4));
	TEST_CHECK(ike_ct_equal("x", "y", 0));
}

static void
test_vendorid_short(void)
{
	rc_vchar_t *rfc = set_vendorid(VENDORID_NATT_RFC);
	struct isakmp_gen *g;

	TEST_CHECK(rfc != NULL && rfc->l == 16);
	if (rfc == NULL)
		return;

	g = mkpl(rfc->v, rfc->l, 4 + rfc->l);
	TEST_CHECK(check_vendorid(g) == VENDORID_NATT_RFC);
	free(g);

	/* B2: a VID payload carrying only the first 4 bytes of a known hash
	 * at the very end of the datagram: must not match, must not over-read */
	g = mkpl(rfc->v, 4, 4 + 4);
	TEST_CHECK(check_vendorid(g) == VENDORID_UNKNOWN);
	free(g);

	/* empty body */
	g = mkpl(NULL, 0, 4);
	TEST_CHECK(check_vendorid(g) == VENDORID_UNKNOWN);
	free(g);

	/* length field below the header size (would underflow vidlen) */
	g = mkpl(NULL, 0, 1);
	TEST_CHECK(check_vendorid(g) == VENDORID_UNKNOWN);
	free(g);

	rc_vfree(rfc);
}

int
main(int argc, char *argv[])
{
	(void)argc;

	test_init(argv[0]);
	eay_init();
	compute_vendorids();

	RUN_TEST(test_payload_body_cmp);
	RUN_TEST(test_ct_equal);
	RUN_TEST(test_vendorid_short);

	plog_clean();
	return test_exit_status();
}
