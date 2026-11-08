/*
 * oakleytest.c -- IKEv1 oakley_do_decrypt empty-plaintext guard regression.
 *
 * oakley_do_decrypt() indexes new->u[new->l - 1] for the pad byte after
 * decryption.  If the provider returns a non-NULL empty plaintext
 * (new->l == 0), that read is one byte before the buffer.  IKEv2 guards
 * this at ikev2_decrypt.c and ikev2_frag.c; the IKEv1 site is guarded in
 * oakley.c (new->l == 0 || new->v == NULL before the pad read).
 *
 * A real block cipher never yields an empty plaintext, so the guard cannot
 * be reached with real backends.  This test injects an empty-returning
 * decrypt through the test seam alg_oakley_encdef_test_set_decrypt() and
 * asserts the guard rejects it (NULL).  If the guard is removed, the
 * function reads new->u[-1] and returns a trivially short buffer instead
 * of NULL, so the assertion goes red without relying on a crash.
 */
#include "config.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include "racoon.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "vmbuf.h"
#include "oakley.h"
#include "ikev1/algorithm.h"
#include "ikev1/handler.h"
#include "ikev1/remoteconf.h"

#include <getopt.h>

#include "test_util.h"

TEST_MAIN_STUBS()

/* Provider-shaped decrypt that returns a non-NULL, zero-length plaintext.
 * Allocates 1 byte so v is non-NULL on any allocator, then blanks l. */
static rc_vchar_t *
empty_decrypt(rc_vchar_t *buf, rc_vchar_t *key, rc_vchar_t *iv)
{
	rc_vchar_t *r;

	(void)buf; (void)key; (void)iv;
	if ((r = rc_vmalloc(1)) == NULL)
		return NULL;
	r->l = 0;
	return r;
}

int
main(int argc, char **argv)
{
	struct ph1handle ph1;
	struct isakmpsa approval;
	rc_vchar_t *msg = NULL, *ivdp = NULL, *ivep = NULL;
	int doi, blen;

	(void)argc;
	test_init(argv[0]);
	memset(&ph1, 0, sizeof(ph1));
	memset(&approval, 0, sizeof(approval));

	doi = alg_oakley_encdef_doi(RCT_ALG_AES128_CBC);
	blen = alg_oakley_encdef_blocklen(doi);
	if (doi == 0 || blen <= 0) {
		fprintf(stderr,
		    "AES128_CBC missing from the oakley table; skipping\n");
		return 0;	/* not a failure on tableless builds */
	}
	approval.enctype = doi;
	ph1.approval = &approval;
	ph1.key = rc_vmalloc(blen);
	msg = rc_vmalloc(sizeof(struct isakmp) + blen);
	ivdp = rc_vmalloc(blen);
	ivep = rc_vmalloc(blen);
	if (ph1.key == NULL || msg == NULL || ivdp == NULL || ivep == NULL)
		return 1;
	memset(msg->v, 0x40, msg->l);
	memset(ivdp->v, 0x11, ivdp->l);
	memset(ivep->v, 0, ivep->l);

	/* An empty plaintext must be rejected (NULL), never an OOB pad read.
	 * Removing the guard makes this return a short buffer -> red. */
	alg_oakley_encdef_test_set_decrypt(doi, empty_decrypt);
	TEST_CHECK(oakley_do_decrypt(&ph1, msg, ivdp, ivep) == NULL);

	rc_vfree(msg);
	rc_vfree(ivdp);
	rc_vfree(ivep);
	rc_vfree(ph1.key);
	return test_exit_status();
}
