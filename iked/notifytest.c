/*
 * notifytest.c — RFC 7296 §2.7 receive classification of the core error /
 * collision notify types (the "deferred sub-items" of the IANA gap report).
 *
 * RFC 7296 §2.7 (and §1.7): error notifies are in the range 0–16383
 * (IKEV2_NOTIFYTYPE_ERROR_MAX); status notifies are 16384+.
 *  - An error notify received in a response means "the corresponding
 *    request has failed entirely": the caller (createchild_init_recv_notify /
 *    the generic notify path) must treat the request as failed — on a
 *    CREATE_CHILD_SA rekey that is ikev2_child_abort(), which clears a
 *    stuck rekey_inprogress and re-arms expiry.
 *  - A status notify must be ignored (except logged).
 *
 * This locks in the implemented behaviour for the deferred items:
 *   INVALID_SPI (11), INVALID_MESSAGE_ID (9), INVALID_SELECTORS (39),
 *   TEMPORARY_FAILURE (43), SINGLE_PAIR_REQUIRED (34)  — all error-type,
 *   so ikev2_process_notify must report them (non-zero -> request failed),
 *   and SET_WINDOW_SIZE (16385) — status-type, must be ignored (0).
 *
 * The classifier is ikev2_process_notify(); a NULL ike_sa is tolerated by
 * isakmp_log (it guards `if (ike_sa)`).  Send-side emission of 11/39/9/34
 * is deliberately NOT asserted here: those paths are not implemented yet,
 * and asserting an absence of behaviour is a non-test.
 *
 * Linked with the full iked object set (addtest_ikedsrc) so the real
 * classifier + notify_type_str are exercised, exactly as the other
 * full-link tests (test_ts_substitute, eaproundtest, ...) do.
 */
#include "config.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "racoon.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"
#include "ikev2_notify.h"

#include "test_util.h"

TEST_MAIN_STUBS()

static int fails = 0;

static void
ck(int ok, const char *what)
{
	if (!ok) {
		++fails;
		printf("FAIL: %s\n", what);
	} else {
		printf("ok: %s\n", what);
	}
}

/* build a Notify payload of the given type, protocol 0, no SPI/data. */
static struct ikev2_payload_header *
mk_notify(unsigned int type, size_t *outlen)
{
	struct ikev2payl_notify *n;
	size_t len = sizeof(*n);

	n = calloc(1, len);
	if (!n)
		return NULL;
	set_payload_header(&n->header, IKEV2_NO_NEXT_PAYLOAD, len);
	n->nh.protocol_id = 0;
	n->nh.spi_size = 0;
	put_uint16(&n->nh.notify_message_type, type);
	*outlen = len;
	return (struct ikev2_payload_header *)n;
}

int
main(int argc, char *argv[])
{
	struct ikev2_payload_header *p;
	size_t len;
	int rc;

	test_init(argv[0]);

	/*
	 * Error-type notifies: each must be reported (non-zero) so the
	 * CREATE_CHILD_SA request is treated as failed (RFC 7296 §2.7).
	 */
#define CK_ERROR(n_, N_)							\
	do {								\
		p = mk_notify(N_, &len);				\
		rc = ikev2_process_notify(NULL, p, 1);			\
		ck(rc != 0, #N_ " (" #n_ ") -> non-zero (error/request-failed)"); \
		free(p);						\
	} while (0)

	CK_ERROR(11, IKEV2_INVALID_SPI);
	CK_ERROR(9, IKEV2_INVALID_MESSAGE_ID);
	CK_ERROR(39, IKEV2_INVALID_SELECTORS);
	CK_ERROR(43, IKEV2_TEMPORARY_FAILURE);
	CK_ERROR(34, IKEV2_SINGLE_PAIR_REQUIRED);
	CK_ERROR(44, IKEV2_CHILD_SA_NOT_FOUND);

	/*
	 * Status-type notifies: must be ignored (0 -> caller continues).
	 * SET_WINDOW_SIZE (16385) is the deferred item; a raw 16384 (first
	 * status value, unrecognised) pins the boundary without touching an
	 * SA-requiring handler.
	 */
#define CK_STATUS(N_)							\
	do {								\
		p = mk_notify(N_, &len);				\
		rc = ikev2_process_notify(NULL, p, 1);			\
		ck(rc == 0, #N_ " -> 0 (status/ignored)");		\
		free(p);						\
	} while (0)

	CK_STATUS(IKEV2_SET_WINDOW_SIZE);		/* 16385, deferred */

	/*
	 * Error/status boundary: 16383 (IKEV2_NOTIFYTYPE_ERROR_MAX) is the
	 * last error type and is unhandled, so must report as error.  (16384
	 * is INITIAL_CONTACT, a handled status case that needs a real SA, so
	 * it is not exercised here — SET_WINDOW_SIZE above already pins the
	 * status side of the boundary.)
	 */
	p = mk_notify(IKEV2_NOTIFYTYPE_ERROR_MAX, &len);
	rc = ikev2_process_notify(NULL, p, 1);
	ck(rc != 0, "notify 16383 (ERROR_MAX) -> non-zero (error)");
	free(p);

	/*
	 * The notify->string table must name the just-added error types
	 * (log readability / diagnostics on the wire).
	 */
	ck(strcmp(ikev2_notify_type_str(IKEV2_CHILD_SA_NOT_FOUND),
		  "CHILD_SA_NOT_FOUND") == 0,
	   "notify_type_str(44) == CHILD_SA_NOT_FOUND");
	ck(strcmp(ikev2_notify_type_str(IKEV2_TEMPORARY_FAILURE),
		  "TEMPORARY_FAILURE") == 0,
	   "notify_type_str(43) == TEMPORARY_FAILURE");
	ck(strcmp(ikev2_notify_type_str(IKEV2_INVALID_SPI),
		  "INVALID_SPI") == 0,
	   "notify_type_str(11) == INVALID_SPI");
	ck(strcmp(ikev2_notify_type_str(IKEV2_SET_WINDOW_SIZE),
		  "SET_WINDOW_SIZE") == 0,
	   "notify_type_str(16385) == SET_WINDOW_SIZE");

	if (fails) {
		printf("notifytest: %d FAILURE(S)\n", fails);
		return 1;
	}
	printf("notifytest: all checks passed\n");
	return 0;
}
