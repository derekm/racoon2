/* $Id: ikev2_notify.h,v 1.5 2008/02/05 09:03:22 mk Exp $ */

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

int resp_state0_recv_notify(struct ikev2_sa *, rc_vchar_t *, struct sockaddr *,
			    struct sockaddr *, struct ikev2_payload_header *);
int init_ike_sa_init_recv_notify(struct ikev2_sa *, rc_vchar_t *,
				 struct sockaddr *, struct sockaddr *,
				 struct ikev2_payload_header *, int *);
int resp_ike_sa_auth_recv_notify(struct ikev2_sa *, rc_vchar_t *,
				 struct sockaddr *, struct sockaddr *,
				 struct ikev2_payload_header *,
				 struct ikev2_child_param *, int *);
int init_ike_sa_auth_recv_notify(struct ikev2_sa *, rc_vchar_t *,
				 struct sockaddr *, struct sockaddr *,
				 struct ikev2_payload_header *,
				 struct ikev2_child_param *, int *);

int createchild_init_recv_notify(struct ikev2_sa *,
				 struct ikev2_payload_header *,
				 struct ikev2_child_param *,
				 struct ikev2_child_sa *);
int createchild_resp_recv_notify(struct ikev2_sa *, rc_vchar_t *,
				 struct sockaddr *, struct sockaddr *,
				 struct ikev2_payload_header *,
				 struct ikev2_child_param *, int *,
				 uint32_t *);

int ikev2_process_notify(struct ikev2_sa *, struct ikev2_payload_header *, int);
int ikev2_auth_lifetime_parse(const struct ikev2payl_notify *, uint32_t *);
void ikev2_auth_lifetime_apply(struct ikev2_sa *, uint32_t);
#define	IKEV2_MA_SINGLE		0	/* normal single-round IKE_AUTH */
#define	IKEV2_MA_SECOND_ROUND	1	/* answer IDr+AUTH, await round 2 */
#define	IKEV2_MA_REFUSE		2	/* AUTHENTICATION_FAILED */
int ikev2_multi_auth_decide(int, int, int, int);
/* RFC 4739 initiator plan (ikev2_multi_auth_plan) */
#define	IKEV2_MAI_SINGLE	0	/* one round, no ANOTHER_AUTH_FOLLOWS */
#define	IKEV2_MAI_TWO_ROUNDS	1	/* flag round 1, then a PSK round 2 */
#define	IKEV2_MAI_REFUSE	2	/* policy needs 2 rounds, peer can't */
int ikev2_multi_auth_plan(int, int, int);
struct ikev2_payloads;
void ikev2_push_auth_lifetime(struct ikev2_sa *, struct ikev2_payloads *);
int ikev2_process_child_notify(struct ikev2payl_notify *,
		       struct ikev2_child_param *);

/* RFC 7427 s3.2: parse a peer's 16431 hash-algorithm list into
 * ike_sa->peer_sig_hash_mask (bit i => hash id i offered).  Called from the
 * initiator- and responder-view 16431 notify handlers. */
void ikev2_remember_sig_hashes(struct ikev2_sa *, struct ikev2payl_notify *);

/* RFC 8983: shared IP4_ALLOWED/IP6_ALLOWED emit after a lease-assigning
 * CFG_REPLY (childful IKE_AUTH + CREATE_CHILD_SA responder). */
void ikev2_push_ip_allowed(struct ikev2_sa *, struct ikev2_payloads *,
			   struct ikev2_child_sa *);
/* RFC 8983: emit the pool-supported IP*_ALLOWED notifies into an existing
 * payload list (used on the internal_address_failure / family-mismatch
 * path, where no CFG_REPLY is pushed). */
void ikev2_build_ip_allowed(struct ikev2_payloads *, struct ikev2_sa *);

void ikev2_respond_with_notify(rc_vchar_t *, struct sockaddr *, struct sockaddr *,
			       int, uint8_t *, int);
void ikev2_respond_redirect(rc_vchar_t *, struct sockaddr *, struct sockaddr *,
			    rc_vchar_t *, rc_vchar_t *);
/* RFC 5685 redirect pool resolver: pick the redirect target for this
 * peer's ADDRESS from redirect_to (single identity or comma-separated
 * pool) with stable per-address affinity.  Returns caller-freed vchar. */
rc_vchar_t *ikev2_redirect_resolve(struct rcf_remote *, struct sockaddr *);
/* RFC 5685 redirect pool select (pure, testable): pick the member of a
 * comma-separated pool for `remote`'s ADDRESS (family + addr bytes only;
 * port / padding are excluded).  Returns caller-freed vchar. */
rc_vchar_t *ikev2_redirect_pool_select(rc_vchar_t *, struct sockaddr *);
rc_vchar_t *ikev2_build_redirect_notify_data(rc_vchar_t *, rc_vchar_t *);
/* RFC 5685 s9.2: parse an N(REDIRECT)'s Notify DATA into the GW Ident
 * Type, gateway identity bytes, and the echoed Ni.  Returns 0 on
 * success (*gw / *ni caller-freed), -1 on a malformed payload. */
int ikev2_parse_redirect_notify_data(rc_vchar_t *, uint8_t *, rc_vchar_t **,
				     rc_vchar_t **);
/* RFC 5685 s9.3: build the REDIRECTED_FROM (16408) Notify DATA the
 * initiator sends in its re-sent IKE_SA_INIT to the new gateway,
 * carrying the ORIGINAL (redirecting) gateway's identity. */
rc_vchar_t *ikev2_build_redirected_from_data(uint8_t, rc_vchar_t *);
/* RFC 5685 s7 redirect-loop limit: returns 0 when one more redirect may
 * be followed (and counts it), -1 when more than max redirects arrived
 * within period seconds of the window start. */
int ikev2_redirect_loop_check(int *count, time_t *window, time_t now,
			      int max, int period);
/* RFC 5685 redirect follow: resolve a recorded redirect target into a
 * struct sockaddr (IPv4/IPv6 literal) for re-initiation.  Returns NULL
 * for FQDN (no resolver at this layer) or a malformed identity. */
struct sockaddr *ikev2_redirect_gw_sadup(uint8_t, rc_vchar_t *);
void ikev2_respond_with_notify_exch(rc_vchar_t *, struct sockaddr *,
				    struct sockaddr *, int, int, uint8_t *,
				    int);

const char *ikev2_notify_type_str(int);

/* DEL-reply / INVALID_SPI send on a Delete naming an SA we don't hold
 * (RFC 7296 §2.8.2).  Exported for the notifytest unit driver, which
 * exercises the send path with a crafted bogus-SPI Delete payload. */
void ikev2_process_delete(struct ikev2_sa *, struct ikev2_payload_header *,
			  struct ikev2_payloads *);
