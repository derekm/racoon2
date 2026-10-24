/* ikev2_addke_rekey.c/share — IKE-SA rekey responder completion core.
 *
 * The final-round completion of a responder-deferred ADDKE IKE-SA rekey is
 * kept in its own translation unit so the -1 / -2 return contract (a final
 * KEr already on the wire must NOT be answered with STATE_NOT_FOUND; only a
 * PRE-send failure may be) can be exercised in addketest with a handful of
 * injected ops instead of the ~100-symbol iked link closure that dragging in
 * ikev2_rekey.o would pull.
 */
#ifndef IKEV2_ADDKE_REKEY_H
#define IKEV2_ADDKE_REKEY_H

/* Does NOT include ikev2_impl.h: the includer (ikev2_addke_rekey.c,
 * ikev2_rekey.c) brings in racoon.h + ikev2_impl.h first; this header only
 * references their types (struct ikev2_sa, rc_vchar_t, struct ikev2_payloads). */

/* Deferred-responder context (moved here so complete() and the responder
 * round in ikev2_rekey.c share the same struct). */
struct ikev2_rekey_responder_ctx {
	struct ikev2_sa *old_sa;
	struct ikev2_sa *new_sa;
	int serial;		/* old_sa->serial_number, for liveness check */
	struct algdef *dhdef;
	uint32_t message_id;
	struct sockaddr *local;
	struct sockaddr *remote;
	struct ikev2_payloads payl;
	int payl_inited;
	struct prop_pair **parsed_sa;
	rc_vchar_t *g_ir;
	rc_vchar_t *ke_r;
	rc_vchar_t *pkt;
	int addke_deferred;	/* SKEYSEED pending the IKE_FOLLOWUP_KE */
};

/* Injectable dependencies of ikev2_rekey_responder_addke_complete.  The
 * production set_ops() wires these to the real iked functions; addketest
 * installs fakes to drive the -1 / -2 / 0 branches. */
struct ikev2_addke_rekey_ops {
	int (*transmit_response)(struct ikev2_sa *, rc_vchar_t *pkt,
				 struct sockaddr *local, struct sockaddr *remote);
	rc_vchar_t *(*packet_construct)(int exch, int flags, uint32_t msgid,
					struct ikev2_sa *,
					struct ikev2_payloads *);
	int (*derive)(struct ikev2_sa *new_sa, struct ikev2_sa *old_sa,
		      rc_vchar_t *g_ir, rc_vchar_t *sk);	/* rekey_skeyseed */
	int (*establish)(struct ikev2_rekey_responder_ctx *);	/* responder_finish */
	void (*ctx_free)(struct ikev2_rekey_responder_ctx *);
	void (*set_state)(struct ikev2_sa *, int);
	void (*kill_timer)(struct ikev2_sa *);
};

void ikev2_addke_rekey_set_ops(const struct ikev2_addke_rekey_ops *);

/* Responder ctx lifetime helpers (shared with ikev2_rekey.c round). */
struct ikev2_rekey_responder_ctx *
ikev2_rekey_responder_ctx_new(struct ikev2_sa *);
void ikev2_rekey_responder_ctx_free(struct ikev2_rekey_responder_ctx *);

/* The final-round completion; returns 0 success, -1 pre-send failure
 * (caller MAY answer STATE_NOT_FOUND), -2 post-send (KEr already on the
 * wire; caller must NOT answer STATE_NOT_FOUND). */
int ikev2_rekey_responder_addke_complete(struct ikev2_sa *old_sa,
					 rc_vchar_t *addke_sk,
					 rc_vchar_t *ct,
					 uint32_t followup_msgid,
					 unsigned int ke_method);

/* Backend-finalize the rekey (SKEYSEED already computed); shared by the
 * normal tail and the ADDKE deferred completion. Exported so the default ops
 * can bind establish() to it. */
int ikev2_rekey_responder_finish(struct ikev2_rekey_responder_ctx *);

#endif
