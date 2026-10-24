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
 * The responder ctx lifetime helpers are shared with ikev2_rekey.c (the
 * round) so the deferred ctx is created here and completed here.
 */
struct ikev2_rekey_responder_ctx *
ikev2_rekey_responder_ctx_new(struct ikev2_sa *old_sa)
{
	struct ikev2_rekey_responder_ctx *ctx;

	if ((ctx = rc_calloc(1, sizeof(*ctx))) == NULL)
		return NULL;
	ctx->old_sa = old_sa;
	return ctx;
}

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
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "addke rekey complete: ops not installed\n");
		return -1;
	}

	ctx = (struct ikev2_rekey_responder_ctx *)old_sa->addke_rekey_complete;
	old_sa->addke_rekey_complete = NULL;
	if (!ctx || !ctx->new_sa) {
		plog(PLOG_INTERR, PLOGLOC, 0,
		     "addke rekey complete: no parked ctx\n");
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
