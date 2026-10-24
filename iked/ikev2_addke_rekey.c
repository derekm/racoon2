/* ikev2_addke_rekey.c — IKE-SA rekey responder final-round completion.
 *
 * ikev2_rekey_responder_addke_complete() lives here (not in ikev2_rekey.c)
 * with an injectable ops table, so addketest can drive its -1 / -2 / 0
 * return contract with a handful of fakes instead of the ~100-symbol iked
 * link closure.  Production installs the default ops (the real functions).
 */
#include "config.h"

#include <sys/types.h>
#include <sys/param.h>

#include "racoon.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_addke_rekey.h"

/* --- external deps arrive via the injected ops table (set by production
 * in ikev2_rekey.c, or by the test); no default ops here so addketest links
 * this unit without the ~100-symbol iked closure. --- */

static const struct ikev2_addke_rekey_ops *g_ops;	/* NULL until set */

void
ikev2_addke_rekey_set_ops(const struct ikev2_addke_rekey_ops *ops)
{
	g_ops = ops;
}

/*
 * The responder ctx lifetime helper is shared with ikev2_rekey.c (the round)
 * so the deferred ctx is completed here and freed here.
 */
void
ikev2_rekey_responder_ctx_free(struct ikev2_rekey_responder_ctx *ctx)
{
	if (ctx == NULL)
		return;
	if (ctx->local)
		rc_free(ctx->local);
	if (ctx->remote)
		rc_free(ctx->remote);
	if (ctx->parsed_sa)
		proplist_discard(ctx->parsed_sa);
	if (ctx->g_ir)
		rc_vfreez(ctx->g_ir);
	if (ctx->ke_r)
		rc_vfree(ctx->ke_r);
	if (ctx->pkt)
		rc_vfree(ctx->pkt);
	if (ctx->payl_inited)
		ikev2_payloads_destroy(&ctx->payl);
	rc_free(ctx);
}

int
ikev2_rekey_responder_addke_complete(struct ikev2_sa *old_sa,
				     rc_vchar_t *addke_sk,
				     rc_vchar_t *ct,
				     uint32_t followup_msgid,
				     unsigned int ke_method)
{
	const struct ikev2_addke_rekey_ops *ops = g_ops;
	struct ikev2_rekey_responder_ctx *ctx;
	struct ikev2_sa *new_sa;

	if (ops == NULL) {
		/* Missing-ops install is NOT an abort: don't touch the parked
		 * pin.  ikev2_rekey_abandon_parked and the followup timeout
		 * DEAD ctx->new_sa THROUGH that pin and clear it via dispose;
		 * detaching (or freeing) the ctx here would orphan new_sa in
		 * the SA list instead of failing closed. */
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "addke rekey complete: ops not installed\n");
		return -1;
	}

	ctx = (struct ikev2_rekey_responder_ctx *)old_sa->addke_rekey_complete;
	old_sa->addke_rekey_complete = NULL;

	if (!ctx || !ctx->new_sa) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "addke rekey complete: no parked ctx\n");
		/* complete() detached the ctx; release it via the injected
		 * ctx_free (production free, or the test's counting fake)
		 * rather than leaking it.  Timeout never sees a detached ctx. */
		if (ctx)
			ops->ctx_free(ctx);
		return -1;
	}
	new_sa = ctx->new_sa;

	ops->kill_timer(old_sa);
	old_sa->addke_rekey_pending = 0;

	/*
	 * Transmit the FINAL followup KEr BEFORE the irreversible establish
	 * (SKEYSEED + finish adopts children). A failed final send must NOT
	 * take the establish-then-kill path (fail would DEAD a new_sa that
	 * already owns children). On success the response cache is armed and
	 * then we derive keys + establish; the peer's next message-id is
	 * answered from the cache.
	 */
	{
		struct ikev2_payloads payl;
		struct ikev2payl_ke_h keh;
		rc_vchar_t *ker = 0;
		rc_vchar_t *pkt = 0;

		ikev2_payloads_init(&payl);
		memset(&keh, 0, sizeof(keh));
		keh.dh_group_id = htons((uint16_t)ke_method);
		ker = rc_vprepend(ct, &keh, sizeof(keh));
		if (!ker) {
			ikev2_payloads_destroy(&payl);
			goto fail;
		}
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ker, FALSE);
		/* rfc9370: the followup response echoes the INITIATOR's
		 * followup REQUEST message id (the responder's rekey ctx
		 * carries the CREATE_CHILD id, which differs once the
		 * followup runs as its own exchange). */
		pkt = ops->packet_construct(IKEV2EXCH_IKE_FOLLOWUP_KE,
					    (old_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0) |
					    IKEV2FLAG_RESPONSE,
					    followup_msgid, old_sa, &payl);
		rc_vfree(ker);
		if (!pkt) {
			ikev2_payloads_destroy(&payl);
			goto fail;
		}
		if (ops->transmit_response(old_sa, pkt, ctx->local,
					   ctx->remote) != 0) {
			rc_vfree(pkt);	/* failure: caller owns the packet */
			ikev2_payloads_destroy(&payl);
			goto fail;
		}
		ikev2_payloads_destroy(&payl);
	}

	if (ops->derive(new_sa, old_sa, ctx->g_ir, addke_sk) != 0)
		goto fail_after_send;
	rc_vfreez(old_sa->addke_rekey_sk);
	old_sa->addke_rekey_sk = NULL;
	old_sa->addke_rekey_round = 0;
	if (ops->establish(ctx) != 0)
		goto fail_after_send;
	/* success: the rekeyed SA is complete in its own right (already in
	 * the SA list via ikev2_create_sa); drop the deferred-rekey link so
	 * disposing the OLD SA cannot recurse into a live ESTABLISHED SA
	 * that owns children (ikev2_dispose_sa asserts the child list is
	 * empty).  Mirrors the initiator tail and the ADDKE timeout/abandon
	 * paths, which all clear old_sa->new_sa. */
	old_sa->new_sa = NULL;

	ops->ctx_free(ctx);
	return 0;

      fail:
	isakmp_log(old_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		   "failed completing ADDKE IKE-SA rekey\n");
	if (new_sa)
		ops->set_state(new_sa, IKEV2_STATE_DEAD);
	ops->ctx_free(ctx);
	/* round() earned this SK (final round) before complete(); drop it. */
	rc_vfreez(old_sa->addke_rekey_sk);
	old_sa->addke_rekey_sk = NULL;
	old_sa->new_sa = NULL;
	old_sa->rekey_inprogress = FALSE;
	return -1;

      fail_after_send:
	/* The final KEr was already transmitted and cached above: the peer
	 * holds the success signal. Do NOT report it failed (the caller maps
	 * -1 to STATE_NOT_FOUND, which would REPLACE the armed cache and tell
	 * the initiator to abandon a rekey it already believes completed).
	 * Tear down locally and return -2 so the caller abandons WITHOUT an
	 * error notify. */
	isakmp_log(old_sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		   "IKE-SA rekey KEr sent but local establish failed; "
		   "abandoning without notification\n");
	rc_vfreez(old_sa->addke_rekey_sk);
	old_sa->addke_rekey_sk = NULL;
	old_sa->addke_rekey_round = 0;
	if (new_sa)
		ops->set_state(new_sa, IKEV2_STATE_DEAD);
	ops->ctx_free(ctx);
	old_sa->new_sa = NULL;
	old_sa->rekey_inprogress = FALSE;
	return -2;
}

/*
 * One IKE-FOLLOWUP-KE round of the IKE-SA rekey (RFC 9370 s2.2.4):
 *   - non-final round: mint a fresh ADDITIONAL_KEY_EXCHANGE link, append
 *     this round's SK(1..n), transmit the response, and ONLY after a
 *     successful transmit atomically commit (SK + link + round advance);
 *   - final round: append the last SK(n) so complete() has SK(1..n); no
 *     response is transmitted here.
 * Returns 1 (non-final committed), 0 (final), -1 (pre-send failure), or
 * -2 (pre-send LOCAL send failure).  The SK is appended only on the
 * non-final path AFTER a successful transmit, never up front, so a
 * failed-send retransmit that re-enters cannot double-SK (ss1|ss2).
 */
int
ikev2_rekey_responder_addke_round(struct ikev2_sa *old_sa, rc_vchar_t *ss,
				  rc_vchar_t *ct, uint32_t msgid,
				  unsigned int ke_method)
{
	const struct ikev2_addke_rekey_ops *ops = g_ops;
	struct ikev2_rekey_responder_ctx *ctx;
	struct ikev2_sa *new_sa;
	int nrounds, round;
	unsigned int expect;

	if (ops == NULL)
		return -1;	/* missing-ops install; nothing to do */
	if (!old_sa || !ss || !ct)
		return -1;
	ctx = (struct ikev2_rekey_responder_ctx *)old_sa->addke_rekey_complete;
	new_sa = old_sa->new_sa;
	if (!new_sa || !new_sa->negotiated_sa)
		return -1;

	nrounds = new_sa->negotiated_sa->addke_nrounds;
	if (nrounds <= 0)
		nrounds = new_sa->negotiated_sa->addke != 0 ? 1 : 0;
	round = old_sa->addke_rekey_round;
	if (round < 0 || round >= nrounds || round >= 8)
		return -1;
	expect = new_sa->negotiated_sa->addke_methods[round];
	if (expect == 0)
		expect = (unsigned int)new_sa->negotiated_sa->addke;
	if (ke_method != expect) {
		isakmp_log(old_sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE-SA rekey followup method %u != round %d "
			   "method %u\n",
			   ke_method, round, expect);
		return -1;
	}

	/* Note: this round's SK is appended ONLY in the paths below, and
	 * for the non-final path only AFTER a successful transmit —
	 * appending up here would double-SK (ss1|ss2) if a failed send is
	 * retransmitted and this handler re-enters. */

	if (round + 1 < nrounds) {
		rc_vchar_t *new_link;
		struct ikev2_payloads payl;
		struct ikev2payl_ke_h keh;
		rc_vchar_t *ker = 0;
		rc_vchar_t *pkt = 0;
		rc_vchar_t *acc = NULL;

		new_link = ops->random_bytes(16);
		if (!new_link)
			return -1;
		ikev2_payloads_init(&payl);
		memset(&keh, 0, sizeof(keh));
		keh.dh_group_id = htons((uint16_t)ke_method);
		ker = rc_vprepend(ct, &keh, sizeof(keh));
		if (!ker) {
			ikev2_payloads_destroy(&payl);
			rc_vfree(new_link);
			return -1;
		}
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ker, FALSE);
		ikev2_payloads_push(&payl, IKEV2_PAYLOAD_NOTIFY,
				    ops->notify_payload(
				IKEV2_NOTIFY_PROTO_NONE, 0, 0,
				IKEV2_ADDITIONAL_KEY_EXCHANGE,
				new_link->v, new_link->l),
				    TRUE);
		/* Pre-allocate this round's SK(1..n) BEFORE the send so
		 * nothing that can fail (malloc) remains after a successful
		 * transmit.  Link + SK + round are then committed below as
		 * ONE atomic pointer-swing.  -2 therefore means only a
		 * PRE-SEND local send failure (window restore + re-entry is
		 * correct there); the caller restores the inbound window
		 * and sends NO error notify (a retransmit of this followup
		 * re-enters). */
		acc = rc_vmalloc((old_sa->addke_rekey_sk ?
				  old_sa->addke_rekey_sk->l : 0) + ss->l);
		if (!acc) {
			ikev2_payloads_destroy(&payl);
			rc_vfree(new_link);
			return -1;
		}
		if (old_sa->addke_rekey_sk)
			memcpy(acc->v, old_sa->addke_rekey_sk->v,
			       old_sa->addke_rekey_sk->l);
		memcpy((uint8_t *)acc->v + acc->l - ss->l, ss->v, ss->l);
		pkt = ops->packet_construct(
			IKEV2EXCH_IKE_FOLLOWUP_KE,
			(old_sa->is_initiator ? IKEV2FLAG_INITIATOR : 0) |
			IKEV2FLAG_RESPONSE,
			msgid, old_sa, &payl);
		rc_vfree(ker);
		if (!pkt) {
			ikev2_payloads_destroy(&payl);
			rc_vfree(new_link);
			rc_vfree(acc);
			return -1;
		}
		if (ops->transmit_response(old_sa, pkt, ctx->local,
					   ctx->remote) != 0) {
			ikev2_payloads_destroy(&payl);
			rc_vfree(pkt);	/* failure: caller owns the packet */
			rc_vfree(new_link);
			rc_vfree(acc);
			return -2;
		}
		ikev2_payloads_destroy(&payl);
		/* atomic commit after a successful transmit (no alloc here):
		 * SK + link + round swing together. */
		if (old_sa->addke_rekey_sk)
			rc_vfreez(old_sa->addke_rekey_sk);
		old_sa->addke_rekey_sk = acc;
		acc = NULL;
		rc_vfreez(old_sa->addke_rekey_link);
		old_sa->addke_rekey_link = new_link;
		new_link = NULL;
		old_sa->addke_rekey_round = round + 1;
		ops->kill_timer(old_sa);
		ops->arm_timer(old_sa);
		isakmp_log(old_sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
			   "IKE-SA rekey ADDKE round %d/%d done; minted "
			   "followup link\n",
			   round + 1, nrounds);
		return 1;
	}
	/* final round: no response is transmitted here; append the last
	 * SK(n) so the caller's complete() has SK(1..n). */
	{
		rc_vchar_t *acc;

		acc = rc_vmalloc((old_sa->addke_rekey_sk ?
				  old_sa->addke_rekey_sk->l : 0) + ss->l);
		if (!acc)
			return -1;
		if (old_sa->addke_rekey_sk) {
			memcpy(acc->v, old_sa->addke_rekey_sk->v,
			       old_sa->addke_rekey_sk->l);
			rc_vfreez(old_sa->addke_rekey_sk);
		}
		memcpy((uint8_t *)acc->v + acc->l - ss->l, ss->v, ss->l);
		old_sa->addke_rekey_sk = acc;
	}
	return 0;
}
