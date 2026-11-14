/*
 * ikerekeyaddketest.c -- G03 / S5: the initiator IKE_SA-rekey ADDKE path
 * runs a CLASSICAL round after a NONE gap.
 *
 * RFC 9370 s2.2.2 allows ADDKE lists such as {ML-KEM-768, NONE, ECP-256}
 * (transform types 6..8 = {36, 0, 19}): two real rounds, the second one
 * classical.  The initiator IKE_SA-rekey completion used to hand the next
 * method straight to the ML-KEM keygen, so round 2 (19) failed and the
 * rekey died.
 *
 * This parks a real struct ikev2_rekey_init_recv_ctx on an IKE SA and
 * drives the REAL ikev2_rekey_ikesa_init_addke_complete() twice, playing
 * the responder with the real primitives:
 *   round 1: ML-KEM-768 encapsulation against our KEi(1) -> ct, SK(1);
 *   round 2: our KEi(2) must be an ECP-256 public value under method 19;
 *            the peer computes g^xy from it and returns its public value;
 *            SK(1)|SK(2) must equal exactly what the peer derived.
 * ikev2_packet_construct / ikev2_transmit are wrapped (link --wrap) to
 * capture the followup request instead of encrypting/sending it.
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
#include "ikev2_rekey_ctx.h"
#include "oakley.h"
#include "crypto_impl.h"
#include "ike_conf.h"

#include "test_util.h"

TEST_MAIN_STUBS()

#ifndef WITH_ADDKE
int
main(void)
{
	printf("ikerekeyaddketest: SKIP (built without WITH_ADDKE)\n");
	return 77;
}
#else

static int fails;

#define CK(cond, what) do {						\
	if (!(cond)) {							\
		++fails;						\
		printf("FAIL: %s (line %d)\n", (what), __LINE__);	\
	} else								\
		printf("ok: %s\n", (what));				\
} while (0)

/* captured followup request */
static int n_construct, n_transmit, cap_exch;
static unsigned int cap_group;
static rc_vchar_t *cap_pub;	/* KE payload body after the KE header */

rc_vchar_t *
__wrap_ikev2_packet_construct(int exch, int flags, uint32_t msgid,
    struct ikev2_sa *sa, struct ikev2_payloads *payl)
{
	int i;

	(void)flags; (void)msgid; (void)sa;
	++n_construct;
	cap_exch = exch;
	rc_vfree(cap_pub);
	cap_pub = NULL;
	cap_group = 0;
	for (i = 0; i < payl->num; i++) {
		rc_vchar_t *d = payl->payloads[i].data;

		if (payl->payloads[i].type == IKEV2_PAYLOAD_KE && d &&
		    d->l > sizeof(struct ikev2payl_ke_h)) {
			struct ikev2payl_ke_h *kh = (void *)d->v;

			cap_group = get_uint16(&kh->dh_group_id);
			cap_pub = rc_vnew(d->v + sizeof(*kh),
					  d->l - sizeof(*kh));
		}
	}
	return rc_vmalloc(28);
}

int
__wrap_ikev2_transmit(struct ikev2_sa *sa, rc_vchar_t *pkt)
{
	(void)sa;
	++n_transmit;
	rc_vfree(pkt);
	return 0;
}

static int
veq(const rc_vchar_t *a, const void *b, size_t l)
{
	return a && a->l == l && memcmp(a->v, b, l) == 0;
}

int
main(int argc, char **argv)
{
	struct ikev2_sa *old_sa, *new_sa;
	struct ikev2_isakmpsa *nsa;
	struct ikev2_rekey_init_recv_ctx *ctx;
	struct sockaddr_storage ls, rs;
	rc_vchar_t *pub0 = NULL, *ct = NULL, *ss1 = NULL;
	rc_vchar_t *ppub = NULL, *ppriv = NULL, *gxy = NULL;
	const struct dhgroup *dh19;
	unsigned char exp[256];

	(void)argc;
	test_init(argv[0]);
	/* what isakmp_init() does before any exchange: crypto providers +
	 * the DH group table (else every dhgroup has type 0) */
	sched_init();	/* the round arms the 10 s followup timer */
	if (eay_init() != 0 || oakley_dhinit() != 0) {
		printf("FAIL: crypto/DH init\n");
		return 1;
	}

	old_sa = calloc(1, sizeof(*old_sa));
	new_sa = calloc(1, sizeof(*new_sa));
	nsa = calloc(1, sizeof(*nsa));
	ctx = calloc(1, sizeof(*ctx));
	if (!old_sa || !new_sa || !nsa || !ctx)
		return 1;
	test_make_addr(&ls, AF_INET, "192.0.2.1", 500);
	test_make_addr(&rs, AF_INET, "192.0.2.2", 500);
	old_sa->local = (struct sockaddr *)&ls;
	old_sa->remote = (struct sockaddr *)&rs;
	old_sa->is_initiator = TRUE;
	old_sa->state = IKEV2_STATE_ESTABLISHED;
	old_sa->send_message_id = 5;
	IKEV2_CHILD_LIST_INIT(&old_sa->children);
	IKEV2_CHILD_LIST_INIT(&new_sa->children);

	/* types 6,7,8 = {ML-KEM-768, NONE, ECP-256} */
	nsa->addke = 36;
	nsa->addke_methods[0] = 36;
	nsa->addke_methods[1] = 0;
	nsa->addke_methods[2] = 19;
	nsa->addke_nrounds = 3;
	new_sa->negotiated_sa = nsa;

	/* the ctx exactly as ikev2_rekey_ikesa_init_recv parks it */
	ctx->old_sa = old_sa;
	ctx->new_sa = new_sa;
	ctx->addke_deferred = 1;
	ctx->addke_method = 36;
	ctx->addke_round = 0;
	ctx->addke_nrounds = ikev2_addke_dense_count(nsa->addke_methods,
						     nsa->addke_nrounds);
	ctx->addke_link = rc_vnew("L0", 2);
	CK(ctx->addke_nrounds == 2, "{36,NONE,19}: two dense rounds");
	CK(ikev2_addke_kex_keygen(&ctx->addke_kex, 36, &pub0) == 0 && pub0,
	   "round 1 (ML-KEM-768) keygen");
	old_sa->addke_rekey_init = ctx;
	old_sa->addke_rekey_pending = 1;

	/* responder, round 1: encapsulate against KEi(1) */
	CK(pub0 && ikev2_addke_mlkem_encap(36, pub0, &ct, &ss1) == 0 &&
	   ct && ss1 && ss1->l == 32, "peer ML-KEM-768 encapsulation");
	if (fails)
		goto out;

	CK(ikev2_rekey_ikesa_init_addke_complete(old_sa, ct,
	       (const uint8_t *)"L1", 2) == 0,
	   "round 1 completes and starts round 2 (was -1: ML-KEM keygen "
	   "of 19)");
	CK(n_construct == 1 && n_transmit == 1 &&
	   cap_exch == IKEV2EXCH_IKE_FOLLOWUP_KE,
	   "round 2 IKE_FOLLOWUP_KE request sent");
	CK(cap_group == 19, "KEi(2) names method 19 (ECP-256)");
	CK(cap_pub && cap_pub->l == 64,
	   "KEi(2) is a 64-octet ECP-256 public value");
	CK(ctx->addke_round == 1 && ctx->addke_method == 19 &&
	   ctx->addke_final == 0, "ctx advanced to round 2 (method 19)");
	CK(veq(ctx->addke_link, "L1", 2), "fresh responder link adopted");
	CK(veq(ctx->addke_sk, ss1->v, ss1->l), "SK(1) = ML-KEM secret");
	if (fails)
		goto out;

	/* responder, round 2: classical ECP-256 */
	dh19 = ikev2_addke_method_dhgroup(19);
	CK(dh19 != NULL, "group 19 resolves");
	if (!dh19)
		goto out;
	CK(oakley_dh_generate(dh19, &ppub, &ppriv) == 0 &&
	   oakley_dh_compute(dh19, ppub, ppriv, cap_pub, &gxy) == 0 && gxy,
	   "peer ECP-256 g^xy from KEi(2)");
	if (fails)
		goto out;
	CK(ikev2_rekey_ikesa_init_addke_complete(old_sa, ppub, NULL, 0) == 0,
	   "round 2 (classical) completes");
	CK(ctx->addke_final == 1, "last round reached");
	CK(n_construct == 1, "no third followup");
	if (ss1->l + gxy->l <= sizeof(exp)) {
		memcpy(exp, ss1->v, ss1->l);
		memcpy(exp + ss1->l, gxy->v, gxy->l);
		CK(veq(ctx->addke_sk, exp, ss1->l + gxy->l),
		   "SK = SK(1)|SK(2) equals what the peer derived");
	} else
		CK(0, "unexpected secret sizes");
	CK(ctx->addke_kex.kem == NULL && ctx->addke_kex.dh_priv == NULL,
	   "round key material consumed");

	/* derive refuses a mismatched classical value (fail closed) */
	{
		struct ikev2_addke_kex kx;
		rc_vchar_t *p = NULL, *ss = NULL, *bad = rc_vmalloc(10);

		memset(&kx, 0, sizeof(kx));
		CK(ikev2_addke_kex_keygen(&kx, 19, &p) == 0 && p,
		   "standalone ECP-256 keygen");
		CK(bad && ikev2_addke_kex_derive(&kx, bad, &ss) != 0 && !ss,
		   "short peer public value rejected");
		CK(kx.dh_priv == NULL && kx.dh_pub == NULL,
		   "state cleared after a failed derive");
		rc_vfree(p);
		rc_vfree(bad);
	}
out:
	if (old_sa->addke_rekey_timer)
		SCHED_KILL(old_sa->addke_rekey_timer);
	ikev2_addke_kex_clear(&ctx->addke_kex);
	rc_vfreez(ctx->addke_link);
	rc_vfreez(ctx->addke_sk);
	free(ctx);
	rc_vfree(pub0);
	rc_vfree(ct);
	rc_vfreez(ss1);
	rc_vfree(ppub);
	rc_vfreez(ppriv);
	rc_vfreez(gxy);
	rc_vfree(cap_pub);
	free(nsa);
	free(new_sa);
	free(old_sa);
	printf("ikerekeyaddketest: %s\n", fails ? "FAILED" : "OK");
	return fails ? 1 : 0;
}
#endif /* WITH_ADDKE */
