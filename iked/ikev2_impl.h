/* $Id: ikev2_impl.h,v 1.73 2008/09/10 08:30:58 fukumoto Exp $ */

/*
 * Copyright (C) 2004-2005 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "nattraversal.h"
#include "addresspool.h"

#ifdef WITH_ADDKE
#include <openssl/evp.h>	/* EVP_PKEY in the ML-KEM prototypes */
struct dhgroup;		/* classical-DH ADDKE round state (oakley.h defs) */
#endif

#define	IKEV2_DEFAULT_RETRY	10
#define	IKEV2_DEFAULT_NEGOTIATION_TIMEOUT	600	/* ??? */
#define	IKEV2_DEFAULT_LIFETIME_TIME	86400	/* 1day */
#define	IKEV2_DEFAULT_LIFETIME_BYTE	0	/* no limit */
#define	IKEV2_DEFAULT_GRACE_PERIOD	0	/* infinite */
#define	IKEV2_DEFAULT_POLLING_INTERVAL	3600	/* 1hour */

#define	IKEV2_DEFAULT_IPSEC_LIFETIME_TIME	3600

#define	IKEV2_DEFAULT_LIFETIME_SOFT_FACTOR	0.8
#define	IKEV2_DEFAULT_LIFETIME_SOFT_JITTER	0.1
/*
 * Optional initiator CHILD rekey cap in seconds.  0 (default) = use
 * the configured soft lifetime.  A positive value applies only to
 * CP/road-warrior children (non-empty lease_list).  RFC 7296 3.3.5:
 * IKEv2 has no lifetime attribute.
 */
#define	IKEV2_CHILD_REKEY_FLOOR	0
extern int ikev2_child_rekey_floor;

extern double ikev2_lifetime_soft_factor;
extern double ikev2_lifetime_soft_jitter;

extern int ikev2_esp_tfc_padding_not_supported;

/* (draft-ietf-ipsec-esp-v3-09.txt)
   A minimum window size of 32 packets MUST be supported when 32-bit
   sequence numbers are employed; a window size of 64 is preferred and
   SHOULD be employed as the default.
*/
#ifndef IKEV2_IPSEC_WINDOW_SIZE
#define	IKEV2_IPSEC_WINDOW_SIZE	64
#endif

extern int ikev2_ipsec_window_size;

/*
 * (2.10) Nonces used in IKEv2
 * MUST be randomly chosen, MUST be at least 128 bits in size, and MUST
 * be at least half the key size of the negotiated prf.
 *
 * (3.9) The size of a Nonce MUST be between 16 and 256 octets inclusive.
 *
 */
/* so far, HMAC TIGER's 192bits output is the longest defined for prf */
/* thus 256 bits (32 octets) shall be adequate */
#define	IKEV2_DEFAULT_NONCE_SIZE		(256 / 8)

/* EAP remote-access auth: default RADIUS auth port (RFC 2865). */
#define	IKEV2_RADIUS_DEFAULT_PORT		1812

/* RFC 5723 session resumption: default ticket lifetime in seconds (RFC
 * 5723 s6.2 requires a finite lifetime; 24h matches the IKE_SA default). */
#define	IKEV2_DEFAULT_SESSION_RESUME_LIFETIME	86400

extern struct ikev2_payload_types {
	const char *name;
	size_t minimum_length;
} ikev2_payload_types[];

#define	IKEV2_PAYLOAD_TYPE_DEFINED(type_)	((type_) >= IKEV2_PAYLOAD_SA && (type_) <= IKEV2_PAYLOAD_ENCRYPTED_AND_AUTHENTICATED_FRAGMENT)
#define	IKEV2_PAYLOAD_TYPES(type_)	(ikev2_payload_types[(type_) - IKEV2_PAYLOAD_SA])
#define	IKEV2_PAYLOAD_NAME(type_)	(IKEV2_PAYLOAD_TYPE_DEFINED(type_) ? IKEV2_PAYLOAD_TYPES(type_).name : "unknown")

extern int ikev2_half_open_sa;

enum ikev2_state {
	IKEV2_STATE_IDLING = 0,
	IKEV2_STATE_INI_IKE_SA_INIT_SENT = 1,
	IKEV2_STATE_RES_IKE_SA_INIT_SENT = 2,
	IKEV2_STATE_INI_IKE_AUTH_SENT = 3,
	IKEV2_STATE_RES_IKE_AUTH_RCVD = 4,
	IKEV2_STATE_INI_IKE_AUTH_RCVD = 5,
	IKEV2_STATE_ESTABLISHED = 6,
	IKEV2_STATE_DYING = 7,
	IKEV2_STATE_DEAD = 8,
	IKEV2_STATE_RES_IKE_AUTH_EAP = 9
#ifdef WITH_INTERMEDIATE
	, IKEV2_STATE_INI_IKE_INTERMEDIATE_SENT = 10
#endif
	, IKEV2_STATE_RES_IKE_AUTH_EAP_FINAL = 11
	/* IKEV2_STATE_EAP  = 12 */

	/* RFC 5723 initiator: we sent IKE_SESSION_RESUME (exchange 38) with a
	 * stored ticket and await the unprotected Nr response. */
	, IKEV2_STATE_INI_IKE_SESSION_RESUME_SENT = 13

	/* IKEV2_STATE_ESTABLISHED_WAIT_INITIATOR, */
};

enum ikev2_child_state {
	IKEV2_CHILD_STATE_IDLING = 0,
	IKEV2_CHILD_STATE_GETSPI,
	IKEV2_CHILD_STATE_GETSPI_DONE,
	IKEV2_CHILD_STATE_WAIT_RESPONSE,
	IKEV2_CHILD_STATE_MATURE,
	IKEV2_CHILD_STATE_EXPIRED,	/* XXX STATE_DONE */
	IKEV2_CHILD_STATE_REQUEST_PENDING,
	IKEV2_CHILD_STATE_REQUEST_SENT,
	IKEV2_CHILD_STATE_NUM,

	IKEV2_CHILD_STATE_INVALID	/* to indicate invalid state */
};

#define	IKEV2_SA_LIST_HEAD		TAILQ_HEAD(ikev2_sa_list, ikev2_sa)
#define	IKEV2_SA_LIST_INIT(head_)	TAILQ_INIT(head_)
#define	IKEV2_SA_LIST_ENTRY		TAILQ_ENTRY(ikev2_sa)
#define	IKEV2_SA_LIST_FIRST(head_)	TAILQ_FIRST(head_)
#define	IKEV2_SA_LIST_NEXT(p_)		TAILQ_NEXT((p_), link)
#define	IKEV2_SA_LIST_END(p_)		((p_) == 0)
#define	IKEV2_SA_LIST_LINK(head_, p_)	TAILQ_INSERT_TAIL((head_), (p_), link)
#define	IKEV2_SA_LIST_REMOVE(head_, p_)	TAILQ_REMOVE((head_), (p_), link)

extern IKEV2_SA_LIST_HEAD ikev2_sa_list;

#define	IKEV2_CHILD_LIST_HEAD			TAILQ_HEAD(ikev2_child_sa_list, ikev2_child_sa)
#define	IKEV2_CHILD_LIST_INIT(head_)		TAILQ_INIT(head_)
#define	IKEV2_CHILD_LIST_EMPTY(head_)		TAILQ_EMPTY((head_))
#define	IKEV2_CHILD_LIST_ENTRY			TAILQ_ENTRY(ikev2_child_sa)
#define	IKEV2_CHILD_LIST_FIRST(head_)		TAILQ_FIRST((head_))
#define	IKEV2_CHILD_LIST_NEXT(p_)		TAILQ_NEXT((p_), link)
#define	IKEV2_CHILD_LIST_END(p_)		((p_) == 0)
#define	IKEV2_CHILD_LIST_LINK(head_, p_)	TAILQ_INSERT_TAIL((head_), (p_), link)
#define	IKEV2_CHILD_LIST_REMOVE(head_, p_)	TAILQ_REMOVE((head_), (p_), link)

struct ikev2_sa {
	isakmp_index_t index;

	int serial_number;

	int version;
	int is_initiator;	/* side */
	int is_rekeyed_sa;
	int childless_established;	/* RFC 6023: SA-less AUTH settled config */
	int peer_childless;	/* RFC 6023 s3: responder sent N(16418) in IKE_SA_INIT */
	int childless_advertised;	/* RFC 6023 s3: we sent N(16418) in our IKE_SA_INIT response */
	int childless_requested;	/* we sent a modified (SA-less) IKE_AUTH request */
	int grace_expired;	/* kmp_sa_grace_period ran out: delete, do not rekey */

	struct sockaddr *remote;
	struct sockaddr *local;

#ifdef ENABLE_NATT
    struct sockaddr *oa_i; /* These addresses can be used for checksum fixup */
    struct sockaddr *oa_r; /* if NAT address substitution has been performed (RFC 7296 2.23.1) */
#endif

	struct rcf_remote *rmconf;

	uint32_t send_message_id;	/* for sending request */
	int request_pending;	/* number of requests in progress */
	uint32_t recv_message_id;	/* for receiving request */

	int state;		/* enum STATE */

	/* int                      got_response;  */
	/* struct timeval   last_received_time; */

	struct ikev2_isakmpsa *negotiated_sa;	/* XXX approval */

	struct keyed_hash *prf;	/* negotiated prf */

	rc_vchar_t *n_i;	/* Ni */
	rc_vchar_t *n_r;	/* Nr */

	struct algdef *dh_choice;	/* to retry with different DH group */

	rc_vchar_t *dhpriv;	/* x    */
	rc_vchar_t *dhpub;	/* g^x  */
	rc_vchar_t *dhpub_p;	/* g^y  */

	rc_vchar_t *skeyseed;
	rc_vchar_t *sk_d;
	rc_vchar_t *sk_a_i;
	rc_vchar_t *sk_a_r;
	rc_vchar_t *sk_e_i;
	rc_vchar_t *sk_e_r;
	rc_vchar_t *sk_p_i;
	rc_vchar_t *sk_p_r;

	/* Legacy H1 fields: the PRE-update (gen-0) RECEIVE keys.  These were
	 * added to re-validate a retransmitted gen-0 IKE_INTERMEDIATE request
	 * via ICV, but that is dead for AEAD (RFC 5282: the tag is checked in
	 * decrypt, ikev2_check_icv() returns 0 unconditionally; and a
	 * retransmitted request is SKF-fragmented, failing decrypt with the
	 * current keys before any ICV path).  The working recovery is
	 * intermediate_replay[]: the responder caches the gen-0 RESPONSE and
	 * replays it verbatim on the cleartext outer msgid.  Retained only for
	 * cleanup symmetry. */
	rc_vchar_t *prev_sk_a_r;
	rc_vchar_t *prev_sk_e_r;

	rc_vchar_t *id_i;	/* IDi' */
	rc_vchar_t *id_r;	/* IDr' */
	rc_type	id_i_type;	/* RCT_IDT_* of the asserted IDi */
	rc_type	id_r_type;	/* RCT_IDT_* of the asserted IDr */

	rc_vchar_t *my_first_message;	/* for AUTH calculation */
	rc_vchar_t *peer_first_message;

	/* X.509-from-wire (feature-gap P1): raw CERT payload bytes of the
	 * peer's leaf certificate received in IKE_AUTH (RFC 7296 s3.6),
	 * captured from the first CERT payload.  Used (when the remote is
	 * configured cert_validate on) to build/validate the chain against
	 * ca_file and verify AUTH against the leaf pubkey, instead of the
	 * config-file pubkey pin.  NULL when no CERT payload was received. */
	rc_vchar_t *peer_cert;
	/* Additional X.509 CERT payloads after the leaf (RFC 7296 s3.6:
	 * intermediates).  Captured bounded; used only as an UNTRUSTED
	 * chain-building pool, and only with cert_intermediates on. */
#define IKEV2_PEER_CERT_EXTRA_MAX	4
	rc_vchar_t *peer_cert_extra[IKEV2_PEER_CERT_EXTRA_MAX];
	int peer_cert_nextra;

	struct encryptor *encryptor;
	struct authenticator *authenticator;

	/* pending_requests; *//* CREATE_CHILD_SA, INFORMATIONAL */
	IKEV2_CHILD_LIST_HEAD children;

	struct verified_info verified_info;	/* auth verification context */

	struct transmit_info transmit_info;
	struct transmit_info response_info;
	int resume_dirty;	/* window/response advanced since last dump; persist on next periodic tick */

	struct timeval due_time;	/* certificate expiration time */
	struct sched *expire_timer;
	struct sched *soft_expire_timer;
	int soft_expired;
	struct sched *polling_timer;
	size_t lifetime_byte;
	struct sched *grace_timer;

	int child_created;	/* count of child created */
	int rekey_inprogress;
	int rekey_duplicate;
	int rekey_duplicate_serial;
	struct ikev2_sa *new_sa;	/* rekeyed IKE_SA */

	/* RFC 9370 ADDKE (IKE-SA rekey): while this SA's rekey is waiting
	 * for its IKE_FOLLOWUP_KE exchange, the rekey response has been
	 * sent but SKEYSEED derivation is deferred. */
	int addke_rekey_pending;	/* IKE-rekey followup expected */
	int addke_rekey_round;		/* completed followup rounds */
	rc_vchar_t *addke_rekey_link;	/* link echoed in N(16441) */
	rc_vchar_t *addke_rekey_sk;	/* SK(1)|...|SK(n) once followups land */
	void *addke_rekey_complete;	/* parked rekey ctx (rekey.c) */
	void *addke_rekey_init;	/* initiator parked rekey ctx (rekey.c) */
	struct sched *addke_rekey_timer;

	/* RFC 9242 IKE_INTERMEDIATE on the INITIAL IKE_SA (RFC 9370 s2.2:
	 * extra key exchange rounds between IKE_SA_INIT and IKE_AUTH). Active
	 * only when 16438 was negotiated by BOTH peers and an ADDKE round is
	 * selected; each round updates SKEYSEED and the IntAuth chain is bound
	 * into IKE_AUTH. */
#ifdef WITH_INTERMEDIATE
	int intermediate_negotiated;	/* both peers sent N(16438) */
	int intermediate_rounds;	/* completed intermediate KE rounds */
	uint32_t intermediate_msgid;	/* msgid for the next intermediate */
	rc_vchar_t *intauth_i;		/* chained IntAuth_iN */
	rc_vchar_t *intauth_r;		/* chained IntAuth_rN */
	rc_vchar_t *intermediate_req;	/* current round's request content (IntAuth) */
	rc_vchar_t *intermediate_resp;	/* current round's response content (IntAuth) */
	void *intermediate_priv;	/* initiator ML-KEM priv (EVP_PKEY *) */
	/* RFC 9370 s2.2.1: IKE_INTERMEDIATE ADDKE rounds may carry a
	 * CLASSICAL KE method too (transform id from the shared DH
	 * registry, e.g. ECP256=19, CURVE25519=31, MODP2048=14) — the spec
	 * makes no classical/PQ distinction.  For a classical round both
	 * sides hold a DH keypair: generate ours (oakley_dh_generate),
	 * exchange public values in the KE payload, and each computes
	 * g^xy = oakley_dh_compute(dh, our_pub, our_priv, peer_pub).
	 * intermediate_dhgroup is NULL on an ML-KEM round (where
	 * intermediate_priv holds the KEM keypair).  Freed in
	 * ikev2_intermediate_clear(). */
	const struct dhgroup *intermediate_dhgroup;
	rc_vchar_t *intermediate_dh_priv;
	rc_vchar_t *intermediate_dh_pub;
	/* R1 (review): cached gen-0 IKE_INTERMEDIATE RESPONSE (full wire
	 * packet, already authenticated under the pre-update keys).  On a
	 * retransmitted gen-0 request the responder is on gen-1 and can no
	 * longer decrypt it, so it replays these exact bytes instead.
	 * Cleared via ikev2_intermediate_clear(). */
	rc_vchar_t *intermediate_replay;	/* gen-0 wire response to replay */
	rc_vchar_t **intermediate_replay_frags;	/* gen-0 SKF datagrams sent
						 * (fragment-list replay) */
	int intermediate_replay_nfrags;
	uint32_t intermediate_replay_msgid;	/* request msgid it answers */
	struct timeval intermediate_replay_sent;/* replay rate-limit */
#endif

	/* RFC 8784 PPK: set on a peer who negotiated N(USE_PPK) in IKE_SA_INIT
	 * (echoed by the responder that holds the PPK; confirmed by the
	 * initiator that received the echo).  Gates the SK_d/SK_pi/SK_pr
	 * re-derivation with the PPK in ikev2_compute_keys() -- and hence
	 * MUST be zero on any rekeyed/resumed SA (RFC 8784 §2: PPK
	 * is negotiated in IKE_SA_INIT and used only for the initial IKE SA;
	 * rekey is taken at the first opportunity).  peer_sent_use_ppk records that the PEER offered
	 * (responder view) or echoed (initiator view) N(USE_PPK);
	 * peer_ppk_identity_ok is confirmed when the peer's N(PPK_IDENTITY)
	 * matched our configured PPK_ID in IKE_AUTH. */
	int ppk_active;
	int peer_sent_use_ppk;
	int peer_ppk_identity_ok;
	int ppk_deferred;	/* PPK mix deferred past IKE_INTERMEDIATE rounds */

	/* RFC 7427: SIG_HASH_ALGORITHMS (16431) negotiation in IKE_SA_INIT.
	 * peer_sent_sig_hash_algos = the PEER offered the notify (a signal that
	 * it supports the Digital Signature AUTH method 14); sig_hash_algos_ds,
	 * set when this side echoes it back, makes an RSASIG seat send/verify
	 * AUTH method 14 (DS) with the RFC 7427 [len][AlgorithmIdentifier][sig]
	 * envelope instead of classic method 1 (SIGN_RSA_EMSA_PKCS1_SHA1, which
	 * OpenSSL >=3.5 refuses for signing). Only negotiated when BOTH sides
	 * offer it, so plain iked<->iked rows stay on method 1. */
	int peer_sent_sig_hash_algos;
	int sig_hash_algos_ds;

	/* RFC 7427 s3.2: prefer RSASSA-PSS (id-RSASSA-PSS AlgorithmIdentifier,
	 * salt = hash length) over RSASSA-PKCS1-v1_5 when signing AUTH method
	 * 14 as RSA, for peers that only accept PSS (PSS-only / HSM keys).
	 * Set from the remote's 'sig_hash_rsa_pss' config (default off ->
	 * PKCS1-v1_5, the historical behaviour). */
	int sig_hash_ds_pss;

	/* RFC 7427 s3.2: the hash-algorithm set the PEER offered in its 16431
	 * notification (bit i set => hash id i offered: 2=SHA2-256, 3=SHA2-384,
	 * 4=SHA2-512, 5=Identity/EdDSA).  Our AUTH method-14 signer (DS) picks
	 * the STRONGEST hash this side also supports from this mask (SHA-512 >
	 * 384 > 256), per the plan's signer-completeness item.  Privileged over
	 * the historical hardcoded SHA-256. */
	int peer_sig_hash_mask;

	int behind_nat;
	int peer_behind_nat;
	int crypto_pending;
	int eap_round_pending;	/* EAP worker round in flight (own pin, see
				   eap_round_pending reason in ikev2_eap_round.c) */
	int frag_supported;		/* IKEv2 fragmentation (RFC7383) */
	int mobike_supported;		/* RFC 4555 */
	int mobike_update;		/* UPDATE_SA_ADDRESSES seen */
	int peer_sent_redirect;		/* RFC 5685: initiator offered N(16406)
					 * in IKE_SA_INIT; responder MAY answer
					 * N(REDIRECT,<new gw>) instead of an SA */
	int redirect_rx;		/* RFC 5685 initiator: responder
					 * answered our IKE_SA_INIT with
					 * N(REDIRECT,<new gw>) instead of an
					 * SA; the echoed Ni was verified
					 * against ike_sa->n_i.  The intended
					 * IKE_SA must be aborted and re-run
					 * against the new gateway. */
	uint8_t redirect_gw_type;	/* RFC 5685 s9.2 GW Ident Type of the
					 * redirect target: 1=IPv4, 2=IPv6,
					 * 3=FQDN */
	rc_vchar_t *redirect_gw;	/* redirect target identity bytes
					 * (4/16 octets, or FQDN) from the
					 * responder's N(REDIRECT) */
	rc_vchar_t *redirect_ni;	/* the echoed Ni verbatim from the
					 * N(REDIRECT), matching ike_sa->n_i */
	int redirect_count;		/* RFC 5685 s7: redirects followed in
					 * the current loop-detect window */
	time_t redirect_window;		/* start of that window */
	int redirect_follow;		/* RFC 5685 initiator: a verified
					 * redirect was received and the
					 * IKE_SA_INIT is being re-run against
					 * redirect_gw; the builder attaches
					 * N(REDIRECTED_FROM) naming the
					 * original (redirecting) gateway */
	uint8_t redirected_from_type;	/* GW Ident Type of the redirecting
					 * gateway (1=IPv4, 2=IPv6) */
	rc_vchar_t *redirected_from;	/* identity bytes of the redirecting
					 * gateway (the peer that sent
					 * N(REDIRECT)), for REDIRECTED_FROM */
	int natd_report;			/* include NATD in next reply (RFC 4555 3.8) */
	uint8_t natd_src_hash[20];	/* verbatim NAT_DETECTION_SOURCE_IP */
	uint8_t natd_dst_hash[20];	/* verbatim NAT_DETECTION_DESTINATION_IP */
	uint8_t natd_init_src_hash[20];	/* INIT binding-report digests;
					 * RFC 4555 §3.8 replay baseline */
	uint8_t natd_init_dst_hash[20];	/* INIT binding-report digests */
	uint8_t natd_peer_prev_src[20];	/* last peer SRC digest (drift) */
	uint8_t natd_peer_prev_dst[20];	/* last peer DST digest (drift) */
	int natd_peer_seen;		/* peer digests recorded */
	int initial_contact_pending;	/* INITIAL_CONTACT seen; flush stale
					 * same-peer SA once we are ESTABLISHED
					 * (RFC 7296 §1.4.1: don't tear the old
					 * SA down inside the new exchange) */
	rc_vchar_t *cookie2_echo;	/* RFC 4555 COOKIE2 to copy into response */
	/* RFC 5723: set when the peer sent N(TICKET_REQUEST) (seen in this
	 * IKE_AUTH request or an initiated exchange).  When the remote
	 * enables session resumption, the responder answers a successful
	 * authentication with N(TICKET_LT_OPAQUE). */
	int ticket_requested;
	/* RFC 5723: set when this IKE_SA was established by a ticket
	 * (IKE_SESSION_RESUME / exchange 38), not by a full IKE_AUTH.  The
	 * initiator is already authenticated by the ticket, so the resumed
	 * IKE_AUTH must not re-run the PSK/sig/EAP method: its AUTH derives
	 * from the resumed SK_p and its IDs come from the ticket. */
	int resumed;
	/* RFC 5723 (INITIATOR) s4.3.2: the stored ticket was refused
	 * (N(TICKET_NACK)) or the IKE_SESSION_RESUME request went
	 * unanswered; this SA restarted with a full IKE_SA_INIT and must
	 * never present a ticket again (even one a failed store clear left
	 * on disk), so the fallback cannot loop. */
	int resume_declined;
	/* RFC 5723 (RESPONDER) s4.3.4: the original IKE SA's SPI_i/SPI_r
	 * recovered from the accepted ticket (u64 form, as the ticket
	 * serializes them).  After the resumed IKE_AUTH succeeds these
	 * identify the still-live "old" SA the client resumed from, which
	 * SHOULD be silently deleted (no DELETE informational) along with
	 * its children.  Zero when not resumed from a ticket, or when the
	 * old SA must not be touched. */
	uint64_t resume_old_spi_i;
	uint64_t resume_old_spi_r;
	/* RFC 5723 (INITIATOR): the responder-minted ticket received in
	 * N(TICKET_LT_OPAQUE) (4-octet BE lifetime || ticket) during this
	 * SA's initial IKE_AUTH.  Held while the SA lives so it can be
	 * presented on a later reconnect via exchange 38; the full
	 * from-ticket state (SK_d, SAr, IDs) is serialized to the resume
	 * store at SA disposal so a reconnect can resume after this SA is
	 * gone. */
	rc_vchar_t *resume_ticket;
	rc_vchar_t *cookie2_sent;	/* RFC 4555 COOKIE2 we put on a request */
	int cookie2_matched;
	rc_vchar_t *qcd_token_peer;	/* RFC 6290 token from peer (taker) */
#define	IKEV2_MAX_EXTRA_ADDR	8
	uint8_t extra_addr4[IKEV2_MAX_EXTRA_ADDR][4];
	int n_extra_addr4;
	uint8_t extra_addr6[IKEV2_MAX_EXTRA_ADDR][16];
	int n_extra_addr6;
	/* RFC 4555 §3.6/§3.7 responder-follow: when the current path
	 * dies, probe the next ADDITIONAL_* address with COOKIE2 before
	 * aborting.  Kernel SAs stay on the old address until the
	 * probe's COOKIE2 matches. */
	int mobike_alt_idx;
	int mobike_rr_pending;
	struct sockaddr *mobike_rr_prev;
	struct ikev2_frag_item *frag_chain;	/* Received fragments */
	struct sched *natk_timer;
#if 0	/* XXX for transport mode */
	struct sockaddr *privaddr_p;
#endif

	/* EAP remote-access auth (RFC 7296 s2.16 / RFC 5998): the responder
	 * proxy state and the derived MSK for an eap-configured remote that
	 * is authenticating.  eap_relay is the per-SE multi-round relay
	 * (ikev2_eap_relay.c) driven by the worker path; eap_msk is the
	 * 64-octet MSK extracted from the final Access-Accept, substituted
	 * for the shared secret in the AUTH computation (IKEV2_AUTH_SHARED_KEY
	 * arm).  Both NULL on a non-EAP SA.  eap_rid is the running RADIUS
	 * Identifier across rounds.  Owned: freed in ike_sa.c teardown. */
	void *eap_relay;	/* struct ikev2_eap_relay *, per-SE */
	rc_vchar_t *eap_msk;	/* 64-octet EAP MSK (MSCHAPv2 or TLS), AUTH seed */
	uint8_t eap_rid;	/* running RADIUS Identifier for EAP rounds */
	uint8_t eap_only;	/* peer sent N(EAP_ONLY_AUTHENTICATION) (16417)
				   in the first IKE_AUTH (RFC 5998 s3) */
	uint8_t eap_only_honored; /* responder omitted AUTH: the initiator
				   asked AND kmp_auth_method is eap-only;
				   the EAP method must then be RFC 5998 s4
				   safe and produce an MSK (ikev2_eap.c) */
	int eap_method;		/* last EAP Type the peer answered with
				   (> Nak); 0 until a method round */
	uint32_t eap_message_id;	/* msgid of the in-flight peer EAP-Response
					   IKE_AUTH, echoed in our EAP response */
	char *eap_user;		/* EAP Identity string (owned, NULL until known);
				   sent as RADIUS User-Name so the server can
				   match the account */
	uint8_t eap_last_peer_id;	/* Identifier byte of the last peer EAP
					   Response we proxied; RFC 3748 s4.2 the
					   EAP-Success we synthesize must echo it
					   (the server's own Success packet is
					   preferred when the Accept carries one) */
	rc_vchar_t *eap_sa_i2;	/* retained peer IKE_AUTH child offer (owned):
				   SAi2 / TSi / TSr payload bytes from the
				   first IKE_AUTH, held until the final RFC 5998
				   [AUTH]-only message completes the child.  NULL
				   unless an eap remote parked in EAP. */
	rc_vchar_t *eap_ts_i;
	rc_vchar_t *eap_ts_r;

	IKEV2_SA_LIST_ENTRY link;

	/* RFC 7296 §2.3 INVALID_MESSAGE_ID: when we receive a request whose
	 * Message ID is outside the (window-1) supported window we do NOT
	 * acknowledge it — we initiate our own INFORMATIONAL carrying
	 * N(INVALID_MESSAGE_ID, data=the 4-octet invalid id).  Sending is
	 * optional and MUST be rate limited; these track the last time we
	 * sent one so a storm of out-of-window requests cannot fan out an
	 * unbounded reply stream. */
	time_t invalid_msgid_last_sent;	/* time() of the last INVALID_MESSAGE_ID
					   we sent on this SA (0 = never) */
};

enum request_callback {
	REQUEST_CALLBACK_CONTINUE,
	REQUEST_CALLBACK_TRANSMIT_ERROR,
	REQUEST_CALLBACK_RESPONSE
};

/* negotiated parameters */
struct ikev2_child_param {
	int use_transport_mode;	/* IN */
	int esp_tfc_padding_not_supported;	/* IN */
	int single_pair_required;	/* OUT */
	int additional_ts_possible;	/* OUT */
	rc_vchar_t *ts_i;	/* OUT */
	rc_vchar_t *ts_r;	/* OUT */
	unsigned int notify_code;	/* OUT */

	/* support for CONFIG payload */
	rc_vchar_t *cfg_payload;	/* OUT */
	int cfg_application_version;
	int cfg_ip4_dns;
	int cfg_ip6_dns;
	int cfg_ip4_dhcp;
	int cfg_ip6_dhcp;
	int cfg_mip6_home_prefix;
	int cfg_supported_attributes;
	/* split-tunnel / split-DNS: requested-by-peer + configured-eligible */
	int cfg_ip4_subnet;		/* peer wants INTERNAL_IP4_SUBNET (13) */
	int cfg_ip6_subnet;		/* peer wants INTERNAL_IP6_SUBNET (15) */
	int cfg_dns_domain;		/* peer wants INTERNAL_DNS_DOMAIN (25) */
	int cfg_dnssec_ta;		/* peer wants INTERNAL_DNSSEC_TA (26) */
};

struct ikev2_child_sa {
	u_long child_id;	/* unique id of child_sa */

	int is_initiator;	/* whether this side initiated the child_sa negotiation */
	enum ikev2_child_state state;

	struct sockaddr *local;
	struct sockaddr *remote;

	uint32_t message_id;
	/* struct timeval           time; */

	struct sadb_request sadb_request;

	struct algdef *dhgrp;	/* chosen dh group */
	rc_vchar_t *dhpriv;
	rc_vchar_t *dhpub;	/* my dh public value */
	rc_vchar_t *g_ir;	/* computed DH secret */

	rc_vchar_t *n_i;
	rc_vchar_t *n_r;

	rc_vchar_t *ts_i;
	rc_vchar_t *ts_r;

	struct rcf_selector *selector;
	struct prop_pair **my_proposal;
	struct prop_pair *peer_proposal;
	struct rc_addrlist	*srclist;
	struct rc_addrlist	*dstlist;

	struct sched *timer;	/* expiration timer */

	IKEV2_CHILD_LIST_ENTRY link;
	struct ikev2_sa *parent;

	struct ikev2_child_param child_param;

	int rekey_inprogress;

	rc_type preceding_satype;	/* to specify rekeying sa */
	uint32_t preceding_spi;

	int rekey_duplicate;
	uint32_t rekey_duplicate_message_id;

	int delete_sent;

	/* RFC 7296 §3.3.2 / RFC 4303 §2.2.1 ESN: 1 when the negotiated child
	 * SA uses extended (64-bit) sequence numbers.  Set only after the
	 * ESN transform is matched (NULL-negotiation: transform is absent ->
	 * ESN no); carried into the kernel SA as SADB_X_SAFLAGS_ESN (FreeBSD/
	 * OpenBSD 0x400) or XFRM_STATE_ESN + XFRMA_REPLAY_ESN_VAL (Linux). */
	int esn;

	/* RFC 9370 ADDKE (stage 2): while this child is waiting for
	 * its IKE_FOLLOWUP_KE exchange, the CREATE_CHILD_SA response
	 * has been sent but the keymat/XFRM install is deferred. */
	int addke_pending;	/* followup exchange expected */
	int in_ike_auth;	/* child negotiated inside IKE_AUTH: no ADDKE (rfc9370 s2.2; type-6 is CREATE_CHILD only) */
	rc_vchar_t *addke_link;	/* link data echoed in N(16441) */
	rc_vchar_t *addke_sk;	/* additional shared secret SK(1) */
	unsigned int addke_method; /* negotiated ADDKE KE method id */
	uint32_t addke_followup_msgid; /* initiator: followup request msgid */
	/* RFC 9370 multi-round: ordered negotiated ADDKE methods plus the
	 * round cursor.  Rounds run in transform-type order; each round
	 * consumes one IKE_FOLLOWUP_KE exchange whose KE method must
	 * equal methods[round]. */
	unsigned int addke_methods[8];	/* ADDKE1..ADDKE7 + NONE, type order */
	int addke_nrounds;
	int addke_round;	/* next round to expect/perform */
	int addke_peer_offer;	/* the peer actually offered an ADDKE transform */
#ifdef WITH_ADDKE
	void *addke_priv;	/* initiator: ML-KEM private key (EVP_PKEY *)
				 * held until the followup response decaps */
	/* Classical-DH ADDKE round state (RFC 9370: rounds may carry any
	 * KE method, ML-KEM or classical).  A round is classical when its
	 * method id is a DH group (not 35/36/37); then we hold our own
	 * keypair + the group so the followup computes g^xy against the
	 * peer's public value, and the responder sends its public value as
	 * KEr instead of a KEM ciphertext. */
	const struct dhgroup *addke_dh;	/* group for the current classical round */
	rc_vchar_t *addke_dh_pub;	/* classical round: our public value */
	rc_vchar_t *addke_dh_priv;	/* classical round: our private value */
#endif

	/* for informational exchange */
	void (*callback) (enum request_callback, struct ikev2_child_sa *, void *);
	void *callback_param;
	uint32_t deleting_child_id;

	/* for address lease from pool */
	struct rcf_address_list_head	lease_list;

	/* config from peer */
	struct rcf_address_list_head	loan_list;
	unsigned long	internal_address_expiry;
	struct rcf_address_list_head	internal_ip4_addr;
	struct rcf_address_list_head	internal_ip4_dns;
	struct rcf_address_list_head	internal_ip4_nbns;
	struct rcf_address_list_head	internal_ip4_dhcp;
	struct rcf_address_list_head	internal_ip4_subnet;
	struct rcf_address_list_head	internal_ip6_addr;
	struct rcf_address_list_head	internal_ip6_dns;
	struct rcf_address_list_head	internal_ip6_dhcp;
	struct rcf_address_list_head	internal_ip6_subnet;
	rc_vchar_t	*peer_application_version;
	rc_vchar_t	*internal_dns_domain;
	rc_vchar_t	*internal_dnssec_ta;
};


/*
 * packet construction utilities
 */
struct ikev2_payload_info {
	unsigned int type;
	rc_vchar_t *data;
	int need_free;
};

struct ikev2_payloads {
	int num;
	struct ikev2_payload_info *payloads;
};

extern struct sadb_response_method ikev2_sadb_callback;

extern void ikev2_payloads_init(struct ikev2_payloads *);
extern void ikev2_payloads_push(struct ikev2_payloads *, int, rc_vchar_t *,
				int);
extern void ikev2_payloads_destroy(struct ikev2_payloads *);
extern rc_vchar_t *ikev2_payloads_to_blob(struct ikev2_payloads *, uint8_t *);
extern rc_vchar_t *ikev2_packet_construct(int, int, uint32_t,
					  struct ikev2_sa *,
					  struct ikev2_payloads *);

extern int ikev2_payload_type_is_critical(unsigned int);

extern void ikev2_update_message_id(struct ikev2_sa *, uint32_t, int);
extern int ikev2_transmit(struct ikev2_sa *, rc_vchar_t *);
extern int ikev2_transmit_response(struct ikev2_sa *, rc_vchar_t *,
				   struct sockaddr *, struct sockaddr *);

extern void ikev2_stop_retransmit(struct ikev2_sa *);

extern int ikev2_respond_null(struct ikev2_sa *, rc_vchar_t *,
			      struct sockaddr *, struct sockaddr *);
extern int ikev2_respond_error(struct ikev2_sa *, rc_vchar_t *,
			       struct sockaddr *, struct sockaddr *, unsigned int,
			       uint8_t *, int, unsigned int, void *, size_t);
extern int ikev2_respond_error_ip_allowed(struct ikev2_sa *, rc_vchar_t *,
					  struct sockaddr *, struct sockaddr *,
					  unsigned int);

extern void ikev2_poll(struct ikev2_sa *);
extern void ikev2_sa_start_polling_timer(struct ikev2_sa *);

extern int ikev2_check_spi_size(struct isakmp_domain *, int, int);
extern int ikev2_ts_addr_size(int);

extern void ikev2_set_state(struct ikev2_sa *, int);

extern void ikev2_responder_state1_send(struct ikev2_sa *,
					struct ikev2_child_sa *);
extern int ikev2_responder_childless_auth_send(struct ikev2_sa *,
					uint32_t message_id,
					rc_vchar_t *cfg_payload);

extern int ikev2_createchild_initiator_send(struct ikev2_sa *,
					    struct ikev2_child_sa *);
extern void ikev2_createchild_responder_recv(struct ikev2_sa *, rc_vchar_t *,
					     struct sockaddr *,
					     struct sockaddr *);
extern void ikev2_createchild_responder_send(struct ikev2_sa *,
					     struct ikev2_child_sa *);
extern void ikev2_createchild_initiator_recv(struct ikev2_sa *, rc_vchar_t *,
				     struct sockaddr *,
				     struct sockaddr *);

/* ADDKE1..ADDKE7 (RFC 9370 Transform Types 6..12) */
#define	IKEV2_ADDKE_MAX_ROUNDS	7
extern int ikev2_addke_collect_rounds(struct prop_pair *, unsigned int *,
				      int *, int *);

#ifdef WITH_ADDKE
extern void ikev2_followup_ke_recv(struct ikev2_sa *, rc_vchar_t *,
				   struct sockaddr *, struct sockaddr *);
extern int ikev2_addke_selectable(void);
extern int ikev2_addke_selftest(void);
extern int ikev2_addke_method_is_mlkem(unsigned int);
extern const struct dhgroup *ikev2_addke_method_dhgroup(unsigned int);
extern int ikev2_addke_round_keygen(struct ikev2_child_sa *,
				    unsigned int, rc_vchar_t **);
extern void ikev2_addke_round_state_clear(struct ikev2_child_sa *);
extern int ikev2_addke_mlkem_keygen(unsigned int, rc_vchar_t **,
				    EVP_PKEY **);
extern int ikev2_addke_mlkem_encap(unsigned int, rc_vchar_t *,
				   rc_vchar_t **, rc_vchar_t **);
extern int ikev2_addke_mlkem_decap(EVP_PKEY *, rc_vchar_t *,
				   rc_vchar_t **);
extern int ikev2_child_addke_install(struct ikev2_child_sa *);
extern void ikev2_child_addke_arm_timeout(struct ikev2_child_sa *);
extern int ikev2_rekey_responder_addke_round(struct ikev2_sa *,
					     rc_vchar_t *, rc_vchar_t *,
					     uint32_t, unsigned int);
extern int ikev2_rekey_responder_addke_complete(struct ikev2_sa *,
						rc_vchar_t *, rc_vchar_t *,
						uint32_t, unsigned int);
extern int ikev2_rekey_ikesa_init_addke_complete(struct ikev2_sa *,
						 rc_vchar_t *,
						 const uint8_t *, size_t);
extern uint32_t ikev2_rekey_ikesa_init_followup_msgid(struct ikev2_sa *);
extern void ikev2_rekey_abandon_parked(struct ikev2_sa *);
extern int ikev2_initiator_followup_send(struct ikev2_child_sa *,
					 rc_vchar_t *);
extern int ikev2_initiator_followup_complete(struct ikev2_child_sa *,
					     rc_vchar_t *);
#endif

extern int ikev2_noncecmp(rc_vchar_t *, rc_vchar_t *);
extern void ikev2_initiator_rekey_finalize(struct ikev2_sa *,
					   struct ikev2_child_sa *);

extern int ikev2_input(rc_vchar_t *, struct sockaddr *, struct sockaddr *);
extern void ikev2_initiate(struct isakmp_acquire_request *,
			   struct rcf_policy *,
			   struct rcf_selector *,
			   struct rcf_remote *);
extern struct ikev2_child_sa *ikev2_request_initiator_start(struct ikev2_sa *,
    void (*callback)(enum request_callback, struct ikev2_child_sa *, void *),
    void *);
extern void ikev2_informational_initiator_transmit(struct ikev2_sa *,
						   struct ikev2_child_sa *,
						   struct ikev2_payloads *);

extern void ikev2_info_init_notify_recv(struct ikev2_child_sa *, rc_vchar_t *);
extern void ikev2_info_init_delete_recv(struct ikev2_child_sa *, rc_vchar_t *);
extern void ikev2_informational_initiator_notify(struct ikev2_sa *,
						 struct ikev2_payloads *);
extern int ikev2_send_invalid_message_id(struct ikev2_sa *, uint32_t);
extern void ikev2_informational_initiator_delete(struct ikev2_sa *,
						 struct ikev2_payloads *);

extern int ikev2_send_initial_contact(struct ikev2_sa *);
#define IKEV2_MAX_FRAGS		64
#define IKEV2_MAX_ASSEMBLIES	4	/* concurrent msgid assemblies / SA */
#define IKEV2_FRAG_TIMEOUT	60	/* seconds; drop incomplete */
#define IKEV2_MAX_REASM		65535	/* RFC 7296 max IKE datagram */

struct ikev2_frag_item {
	uint32_t msgid;
	uint16_t total_fragments;
	int num_received;
	time_t timeout;
	struct ikev2_frag_item *next;
	rc_vchar_t *parts[IKEV2_MAX_FRAGS + 1]; /* 1-indexed */
	size_t total_data_len;
};

extern int ikev2_frag_send(struct ikev2_sa *, rc_vchar_t **,
			   rc_vchar_t ***, int *);
extern rc_vchar_t *ikev2_frag_recv(struct ikev2_sa *, rc_vchar_t *,
				    struct sockaddr *, struct sockaddr *);
extern void ikev2_frag_purge(struct ikev2_sa *);

extern void ikev2_sa_init(void);
#ifdef DEBUG
void ikev2_dump(void);
#endif
extern void ikev2_sa_insert(struct ikev2_sa *);
extern struct ikev2_sa *ikev2_find_sa(rc_vchar_t *);
extern struct ikev2_sa *ikev2_find_sa_by_addr(struct sockaddr *);
extern struct ikev2_sa *ikev2_find_sa_by_serial(int num);
extern struct ikev2_sa *ikev2_allocate_sa(isakmp_cookie_t *, struct sockaddr *,
					  struct sockaddr *,
					  struct rcf_remote *);
extern void ikev2_sa_copy_negotiated_state(struct ikev2_sa *, struct ikev2_sa *);
extern void ikev2_sa_repin_natd(struct ikev2_sa *);
extern struct ikev2_sa *ikev2_create_sa(isakmp_cookie_t *, struct sockaddr *,
					struct sockaddr *, struct rcf_remote *);
extern void ikev2_sa_stop_timer(struct ikev2_sa *);
void ikev2_sa_start_lifetime_timer(struct ikev2_sa *);
void ikev2_sa_arm_lifetime(struct ikev2_sa *, int);
void ikev2_sa_stop_grace_timer(struct ikev2_sa *);
extern void ikev2_sa_expire(struct ikev2_sa *, int);
extern void initiator_state1_send(struct ikev2_sa *,
    void *, struct sockaddr *);
extern void ikev2_sa_delete(struct ikev2_sa *);
extern void ikev2_dispose_sa(struct ikev2_sa *);
#ifdef WITH_INTERMEDIATE
extern void ikev2_intermediate_clear(struct ikev2_sa *);
extern void ikev2_intermediate_clear_replay(struct ikev2_sa *);
extern void initiator_ike_intermediate_send(struct ikev2_sa *);
extern void initiator_ike_intermediate_recv(struct ikev2_sa *,
    rc_vchar_t *, struct sockaddr *, struct sockaddr *);
extern void responder_ike_intermediate_recv(struct ikev2_sa *,
    rc_vchar_t *, struct sockaddr *, struct sockaddr *);
extern void ikev2_replay_intermediate_response(struct ikev2_sa *);
#endif
extern void ikev2_shutdown(void);
extern void ikev2_initial_contact(struct ikev2_sa *);
extern struct ikev2_child_sa *ikev2_create_child_initiator(struct ikev2_sa *);
extern int ikev2_create_child_responder(struct ikev2_sa *,
    struct sockaddr *, struct sockaddr *, uint32_t,
    struct ikev2_payload_header *, struct ikev2_payload_header *,
    struct ikev2_payload_header *, struct ikev2_payload_header *,
    rc_vchar_t *, rc_vchar_t *, struct ikev2_child_param *, int,
    unsigned int, struct ikev2_child_sa *);
void ikev2_mobike_apply(struct ikev2_sa *, struct sockaddr *,
    struct sockaddr *);
extern int ikev2_set_negotiated_sa(struct ikev2_sa *, struct ikev2_isakmpsa *);
extern void ikev2_set_rmconf(struct ikev2_sa *, struct rcf_remote *);
extern struct rc_idlist *ikev2_my_id_list(struct ikev2_sa *);

extern struct encryptor *ikev2_encryptor_new(unsigned int, size_t);
extern struct authenticator *ikev2_authenticator_new(unsigned int);
extern struct keyed_hash *ikev2_prf_new(unsigned int);

extern void ikev2_child_state_set(struct ikev2_child_sa *,
				  enum ikev2_child_state);
extern void ikev2_child_state_next(struct ikev2_child_sa *);

extern void ikev2_child_param_init(struct ikev2_child_param *);
extern void ikev2_child_param_destroy(struct ikev2_child_param *);

extern struct ikev2_child_sa *ikev2_create_child_sa(struct ikev2_sa *, int);
extern void ikev2_destroy_child_sa(struct ikev2_child_sa *);
extern void ikev2_insert_child(struct ikev2_sa *, struct ikev2_child_sa *);
extern void ikev2_remove_child(struct ikev2_child_sa *);
extern int ikev2_child_sa_is_member(struct ikev2_sa *, struct ikev2_child_sa *);
extern struct ikev2_child_sa *ikev2_find_child_sa_by_spi(struct ikev2_sa *,
							 unsigned int, uint32_t,
							 enum peer_mine);

extern int ikev2_child_childless_prepare(struct ikev2_child_sa *);
extern struct ikev2_child_sa *ikev2_choose_pending_child(struct ikev2_sa *,
							 int);
extern struct ikev2_child_sa *ikev2_find_child_sa(struct ikev2_sa *, int,
						  uint32_t);
extern struct ikev2_child_sa *ikev2_find_request(struct ikev2_sa *ike_sa,
						 uint32_t id);
extern void ikev2_wakeup_child_sa(struct ikev2_child_sa *);

extern void ikev2_update_child(struct ikev2_child_sa *,
			       struct ikev2_payload_header *,
			       struct ikev2_payload_header *,
			       struct ikev2_payload_header *,
			       struct ikev2_child_param *);

int ikev2_expired(struct sadb_request *, struct rcpfk_msg *);
void ikev2_child_delete(struct ikev2_child_sa *);
void ikev2_child_delete_inbound(struct ikev2_child_sa *);
void ikev2_child_delete_outbound(struct ikev2_child_sa *);

void ikev2_child_delete_ipsecsa(struct ikev2_child_sa *);
void ikev2_delete_sa(struct ikev2_child_sa *, int, struct sockaddr *,
		     struct sockaddr *, uint32_t);

void ikev2_abort(struct ikev2_sa *, int);
void ikev2_silently_delete_old_resumed_sa(struct ikev2_sa *, uint64_t,
					  uint64_t);
void ikev2_child_abort(struct ikev2_child_sa *, int);

extern int ikev2_child_getspi(struct ikev2_child_sa *);
extern int ikev2_child_getspi_response(struct sadb_request *, struct sockaddr *,
				       struct sockaddr *, unsigned int, uint32_t);

extern rc_vchar_t *ikev2_pack_proposal(struct prop_pair **);

rc_vchar_t *ikev2_encrypt(struct ikev2_sa *, rc_vchar_t *, rc_vchar_t *);

void ikev2_rekey_childsa(struct ikev2_child_sa *, rc_type, uint32_t);
void ikev2_rekey_ikesa_initiate(struct ikev2_sa *);
void ikev2_rekey_ikesa_responder(rc_vchar_t *, struct sockaddr *,
				 struct sockaddr *, struct ikev2_sa *,
				 struct ikev2_payload_header *,
				 struct ikev2payl_ke *,
				 struct ikev2_payload_header *);

int ikev2_check_payloads(rc_vchar_t *, int);
void ikev2_print_ts(struct ikev2_traffic_selector *);
int ikev2_check_ts_payload(struct ikev2_payload_header *);
int ikev2_check_icv(struct ikev2_sa *, rc_vchar_t *);
int ikev2_decrypt(struct ikev2_sa *, rc_vchar_t *);
int ikev2_decrypt_local(struct ikev2_sa *, rc_vchar_t *);

int ikev2_cookie_init(void);
rc_vchar_t *ikev2_cookie(struct sockaddr *, isakmp_cookie_t *);
void ikev2_cookie_refresh(void);
void ikev2_respond_with_cookie(rc_vchar_t *, struct sockaddr *,
			       struct sockaddr *);
void ikev2_retransmit_add_cookie(struct ikev2_sa *, struct ikev2payl_notify *);
int ikev2_check_request_cookie(rc_vchar_t *, struct sockaddr *,
			       struct sockaddr *);

extern rc_vchar_t *ikev2_auth_calculate(struct ikev2_sa *, int);
extern rc_vchar_t *ikev2_auth_calculate_method(struct ikev2_sa *, int, int);
extern void ikev2_verify(struct verified_info *);
extern int ikev2_auth_verify(struct ikev2_sa *, int, struct ikev2payl_auth *);
extern int ikev2_auth_method(struct ikev2_sa *);
extern int ikev2_auth_method_for_alg(struct ikev2_sa *, struct rc_alglist *);

rc_vchar_t *ikev2_notify_payload(int, uint8_t *, int, int, uint8_t *, size_t);
rc_vchar_t *ikev2_delete_payload(unsigned int, unsigned int, unsigned int, uint8_t *);

extern struct prop_pair **ikev2_parse_sa(struct isakmp_domain *,
					 struct ikev2_payload_header *);
extern rc_vchar_t *ikev2_construct_sa(struct ikev2_child_sa *);
extern rc_vchar_t *ikev2_construct_ts_i(struct ikev2_child_sa *);
extern rc_vchar_t *ikev2_construct_ts_r(struct ikev2_child_sa *);
extern rc_vchar_t *ikev2_construct_ts(int, uint32_t, uint32_t,
				   struct rc_addrlist *);
extern int ikev2_confirm_ts(struct ikev2_payload_header *,
			    struct ikev2_payload_header *,
			    struct rcf_selector *);
extern rc_vchar_t *ikev2_identifier(struct rc_idlist *);

extern int ikev2_compute_keys(struct ikev2_sa *);
extern int ikev2_ppk_apply(struct ikev2_sa *ike_sa);
extern void ikev2_destroy_secret(struct ikev2_sa *sa);

extern rc_vchar_t *ikev2_prf_plus(struct ikev2_sa *, rc_vchar_t *, rc_vchar_t *,
			       ssize_t);

extern struct prop_pair *ikev2_find_match(struct prop_pair **,
					  struct prop_pair **, enum peer_mine);

extern struct prop_pair *ikev2_get_transforms(struct isakmp_domain *, caddr_t,
					      struct isakmp_pl_p *);
extern int ikev2_compare_transforms(struct isakmp_domain *, struct prop_pair *,
				    struct prop_pair *);
struct prop_pair *ikev2_match_transforms(struct isakmp_domain *,
					 struct prop_pair *,
					 struct prop_pair *);
extern int ikev2_encr_is_aead(u_int16_t);	/* RFC 5282 AEAD (ENCR+ICV) id */
extern int ikev2_child_compare_transforms(struct isakmp_domain *,
					  struct prop_pair *,
					  struct prop_pair *);
/* struct prop_pair * ikev2_child_match_transforms(struct isakmp_domain *, struct prop_pair *, struct prop_pair *); */
extern struct prop_pair *ikev2_prop_find(struct prop_pair *, unsigned int);
extern struct algdef *ikev2_child_dhdef(struct prop_pair *,
					struct prop_pair *);

extern struct ikev2_isakmpsa *ikev2_find_match_ikesa(struct rcf_remote *,
						     struct prop_pair **,
						     isakmp_cookie_t *,
						     int);
extern const char *ikev2_state_str(int);
extern const char *ikev2_child_state_str(int);

uint32_t ikev2_request_id(struct ikev2_sa *);

/* XXX should be in nattraversal.h, need sorting */
int natt_create_natd(struct ikev2_sa *, struct ikev2_payloads *,
		     struct sockaddr *, struct sockaddr *);

/* CONFIG payload */
void ikev2_create_config_request(struct ikev2_child_sa *);
int ikev2_process_config_request(struct ikev2_sa *,
    struct ikev2_child_sa *, struct ikev2_payload_header *,
    struct ikev2_child_param *);
int ikev2_create_config_reply(struct ikev2_sa *,
    struct ikev2_child_sa *, struct ikev2_child_param *);
int ikev2_dns_domain_normalize(const uint8_t *, size_t, char *, size_t);
int ikev2_dns_domain_allowed(const char *, const char *);
int ikev2_process_config_reply(struct ikev2_sa *, struct ikev2_child_sa *,
    struct ikev2_payload_header *);
int ikev2_process_config_informational(struct ikev2_sa *,
    struct ikev2_payload_header *, struct ikev2_child_param *);

/* script hook */
void ikev2_script_hook(struct ikev2_sa *, int);
void ikev2_child_script_hook(struct ikev2_child_sa *, int);

void ikev2_timeout(struct transmit_info *);
void ikev2_verified(struct verified_info *);
void ikev2_sa_periodic_task(void);
void ikev2_migrate_script_hook(struct ikev2_sa *,
			       struct sockaddr *, struct sockaddr *,
			       struct sockaddr *, struct sockaddr *);

int ikev2_resume_save(struct ikev2_sa *);
void ikev2_resume_forget(struct ikev2_sa *);
void ikev2_resume_dump_all(void);
void ikev2_resume_load(void);

/* IKE_AUTH exchange surface, defined in ikev2_sa_auth.c. */
void initiator_ike_sa_auth_recv0(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void responder_ike_sa_auth_recv0(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void initiator_ike_sa_auth_cont(struct ikev2_sa *, int, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void responder_ike_sa_auth_cont(struct ikev2_sa *, int, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void initiator_ike_sa_auth_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void responder_ike_sa_auth_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void responder_ike_sa_auth_eap_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void responder_ike_sa_auth_eap_final_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);

/* RFC 4555 MOBIKE, defined in ikev2_mobike.c. */
void ikev2_mobike_apply(struct ikev2_sa *, struct sockaddr *, struct sockaddr *);
int ikev2_mobike_probe_next(struct ikev2_sa *);
int ikev2_natt_follow_mapping_event(struct ikev2_sa *, struct sockaddr *);
int ikev2_kernel_migrated(struct ikev2_sa *, struct sockaddr *,
    struct sockaddr *);
struct ikev2_child_sa *ikev2_find_child_by_inbound_spi(uint32_t, int);
struct sadb_resync_ent;
void ikev2_sadb_resync(const struct sadb_resync_ent *, size_t);

/* IKEv2 transmit / retransmit / msgid-window helpers, defined in
 * ikev2_transmit.c. */
int ikev2_check_message_ordering(struct ikev2_sa *, uint32_t, int,
    struct sockaddr *, struct sockaddr *);
int ikev2_retransmit_forced(struct ikev2_sa *, uint32_t, int);
int ikev2_check_icv_prev_gen(struct ikev2_sa *, rc_vchar_t *);

/* INFORMATIONAL / ESTABLISHED-state dispatch, defined in
 * ikev2_informational.c. */
void ikev2_established_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void ikev2_dying_recv(struct ikev2_sa *, rc_vchar_t *, struct sockaddr *,
    struct sockaddr *);
void ikev2_dead_recv(struct ikev2_sa *, rc_vchar_t *, struct sockaddr *,
    struct sockaddr *);

/* Cookie-echo and NAT-D-report builders, defined in ikev2.c but used by the
 * informational responder path. */
void ikev2_push_cookie2_echo(struct ikev2_sa *, struct ikev2_payloads *);
int ikev2_push_natd_report(struct ikev2_sa *, struct ikev2_payloads *);

/* IKE_SA_INIT exchange surface, defined in ikev2_sa_init.c. */
void ikev2_initiator_start(struct ikev2_sa *);
int ikev2_initiator_redirect_follow(struct ikev2_sa *, struct sockaddr *);
int ikev2_check_new_request(rc_vchar_t *, struct sockaddr *, struct sockaddr *);
void responder_state0_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void initiator_ike_sa_init_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);

int ikev2_spi_is_zero(isakmp_cookie_t *);

/* RFC 5723 session-resumption surface, defined in ikev2_session_resume.c. */
void ike_msg_resume_store_save_from_sa(struct ikev2_sa *);
void ike_msg_resume_store_drop(struct ikev2_sa *);
int ike_msg_session_resume_available(struct ikev2_sa *);
int ike_msg_resume_store_migrate(const struct sockaddr *oldgw,
				 const struct sockaddr *newgw);
void ike_msg_session_resume_fallback(struct ikev2_sa *, const char *);
void initiator_ike_session_resume_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void responder_ike_session_resume_recv(struct ikev2_sa *, rc_vchar_t *,
    struct sockaddr *, struct sockaddr *);
void ikev2_maybe_issue_ticket(struct ikev2_sa *, struct ikev2_payloads *);

/* Shared proposal->isakmpsa conversion used by several modules; defined in
 * ikev2.c. */
struct ikev2_isakmpsa *ikev2_proppair_to_isakmpsa(struct prop_pair *);
void ikev2_child_arm_expire(struct ikev2_child_sa *, time_t);

int ikev2_qcd_init(void);
rc_vchar_t *ikev2_qcd_token(isakmp_cookie_t *, isakmp_cookie_t *);
void ikev2_qcd_respond(rc_vchar_t *, struct sockaddr *, struct sockaddr *);
int ikev2_qcd_taker_recv(struct ikev2_sa *, rc_vchar_t *);

extern struct isakmp_domain ikev2_doi;
extern struct isakmp_domain ikev2_createchild_doi;
