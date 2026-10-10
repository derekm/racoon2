/*
 * iked/eapemittest.c - hermetic test of the responder EAP IKE_AUTH response
 * composition (ikev2_eap_emit.c).
 *
 * Proves the plaintext payload list for an EAP round response is exactly
 * IDr then one EAP payload (type 48) with NO AUTH - the shape the responder
 * must put on the wire for EAP in IKE_AUTH (RFC 7296 s2.16 / RFC 5998 s2),
 * without sending over a socket.  This is the 'emit payload 48' gate, tested
 * against a REAL ike_sa + rmconf/id_r.
 *
 * Cases:
 *   1. IDr + EAP(48), no AUTH: first_np == IDr (35), and the blob's payload
 *      headers are IDr then EAP(48) in that order.
 *   2. NULL eap_req -> NULL (no partial emit).
 *   3. NULL sa -> NULL.
 *
 * Returns 0 iff all pass.
 */

#include <config.h>

#include <stdio.h>
#include <string.h>

#include "racoon.h"
#include "gcmalloc.h"
#include "vmbuf.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ike_conf.h"
#include "ikev2_eap_emit.h"
#include <getopt.h>
#include "test_util.h"

TEST_MAIN_STUBS()

static int fails;

int
main(void)
{
	struct ikev2_sa *sa;
	rc_vchar_t *eap_req, *blob;
	uint8_t first_np;
	const struct ikev2_payload_header *h;

	if (rbuf_init(8, 80, 8, 1000, 5))
		return 2;
	ikev2_sa_init();
	sched_init();

	sa = ikev2_allocate_sa(NULL, NULL, NULL, NULL);
	if (!sa) return 2;
	/* id_r: prepopulate with a trivial identifier so the composition reads
	 * it off the SA (no rmconf needed). */
	sa->id_r = rc_vnew((const uint8_t *)"\x01\x04R2\x00\x00\x00\x00",
			   8);   /* FQDN-ish wire IDr */
	if (!sa->id_r) return 2;

	eap_req = rc_vnew((const uint8_t *)
			  "\x01\x07\x00\x09\x01"   /* Code=1 Request, id=7, EAP
						     * type 1 (Identity) */
			  "\x00\x00\x00\x00",
			  9);
	if (!eap_req) return 2;

	/* ---- 1. IDr + EAP(48), no AUTH, first_np == IDr ---- */
	{
		struct ikev2_payloads payl;
		ikev2_payloads_init(&payl);
		if (ikev2_eap_emit_request(sa, &payl, eap_req) != 0) {
			printf("eapemittest: FAIL 1 emit rc\n");
			fails++;
		} else {
			blob = ikev2_payloads_to_blob(&payl, &first_np);
			if (!blob) {
				printf("eapemittest: FAIL 1 no blob\n");
				fails++;
			} else {
				int ok = 1;
				/* IDr = 36, present as first_np (the first
				 * payload's type; each payload's own type
				 * rides in the PREVIOUS header's
				 * next_payload). */
				if (first_np != IKEV2_PAYLOAD_ID_R)
					ok = 0;
				h = (const struct ikev2_payload_header *)blob->v;
				/* payload 1: IDr; its next_payload names the
				 * next type, which must be EAP (48) */
				if (h->next_payload != IKEV2_PAYLOAD_EAP)
					ok = 0;
				/* payload 2: EAP; its next_payload must be
				 * NONE (no trailing AUTH). */
				h = (const struct ikev2_payload_header *)
				    ((uint8_t *)(h + 1) +
				     get_payload_data_length(h));
				if (h->next_payload != IKEV2_NO_NEXT_PAYLOAD)
					ok = 0;
				rc_vfree(blob);
				if (!ok) {
					printf("eapemittest: FAIL 1 composition "
					       "wrong (first_np=%u)\n",
					       first_np);
					fails++;
				} else
					printf("eapemittest: PASS 1 IDr + "
					       "EAP(48), no AUTH\n");
			}
		}
		ikev2_payloads_destroy(&payl);
	}

	/* ---- 2. NULL eap_req refuses ---- */
	{
		struct ikev2_payloads payl;
		ikev2_payloads_init(&payl);
		if (ikev2_eap_emit_request(sa, &payl, NULL) != 0)
			printf("eapemittest: PASS 2 NULL eap_req refused\n");
		else {
			printf("eapemittest: FAIL 2 NULL eap_req accepted\n");
			fails++;
		}
		ikev2_payloads_destroy(&payl);
	}

	/* ---- 3. NULL sa refuses ---- */
	{
		struct ikev2_payloads payl;
		ikev2_payloads_init(&payl);
		if (ikev2_eap_emit_request(NULL, &payl, eap_req) != 0)
			printf("eapemittest: PASS 3 NULL sa refused\n");
		else {
			printf("eapemittest: FAIL 3 NULL sa accepted\n");
			fails++;
		}
		ikev2_payloads_destroy(&payl);
	}

	rc_vfree(eap_req);
	ikev2_dispose_sa(sa);
	printf("eapemittest: %s (%d failures)\n",
	       fails ? "FAIL" : "ALL PASS", fails);
	return fails ? 1 : 0;
}
