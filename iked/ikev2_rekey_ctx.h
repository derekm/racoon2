/*
 * ikev2_rekey_ctx.h -- the initiator IKE_SA-rekey receive context
 * (ikev2_rekey.c), exposed so a full-link unit test can park one on an
 * IKE SA and drive the real ikev2_rekey_ikesa_init_addke_complete().
 * Internal to iked; include after ikev2_impl.h.
 */
#ifndef IKEV2_REKEY_CTX_H
#define IKEV2_REKEY_CTX_H

struct ikev2_rekey_init_recv_ctx {
	struct ikev2_sa *old_sa;
	struct ikev2_sa *new_sa;
	int serial;	/* old_sa->serial_number, for liveness check */
	struct prop_pair **parsed_sa;
	rc_vchar_t *g_ir;
	/* RFC 9370 ADDKE (initiator IKE_SA-rekey): the rekeyed IKE_SA
	 * offered type-6, so SKEYSEED is deferred until the IKE_FOLLOWUP_KE
	 * response supplies SK(1).  g_ir (DH) and the followup response both
	 * arrive async; install only when both are present. */
	int addke_deferred;	/* defer SKEYSEED pending the followup */
	/* this round's key-exchange state: ML-KEM keypair or classical DH
	 * group + values (rounds may be classical, RFC 9370 s2.2.2) */
	struct ikev2_addke_kex addke_kex;
	int addke_method;	/* this round's ADDKE method id */
	int addke_round;	/* completed followup rounds */
	int addke_nrounds;	/* negotiated rounds (1 if legacy) */
	int addke_final;	/* last followup response decapsulated */
	rc_vchar_t *addke_link;	/* link echoed in N(16441) */
	uint32_t addke_followup_msgid;
	rc_vchar_t *addke_sk;	/* SK(1) once the followup response lands */
	int addke_g_ir_ready;	/* DH g_ir computed (async) */
};

#endif /* IKEV2_REKEY_CTX_H */
