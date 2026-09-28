/*
 * Copyright (C) 2004-2005 WIDE Project.
 * Copyright (C) 2026 the racoon2 project.
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

/*
 * RFC 9242 IKE_INTERMEDIATE helpers that must outlive ikev2.c.
 *
 * ikev2.c still owns the exchange (exch 43, IntAuth chain, ADDKE round).
 * This TU exists so SA dispose can release IntAuth / ML-KEM state without
 * pulling the 7.8k-line ikev2.c through the GitHub contents push path.
 */

#include "config.h"

#ifdef WITH_INTERMEDIATE

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>

#include "racoon.h"
#include "safefile.h"
#include "isakmp.h"
#include "ikev2.h"
#include "keyed_hash.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "ikev2_notify.h"
#include "nattraversal.h"
#include "var.h"

void
ikev2_intermediate_clear(struct ikev2_sa *sa)
{
	if (!sa)
		return;
	ikev2_intermediate_clear_replay(sa);
	rc_vfreez(sa->intauth_i);
	sa->intauth_i = 0;
	rc_vfreez(sa->intauth_r);
	sa->intauth_r = 0;
	rc_vfreez(sa->intermediate_req);
	sa->intermediate_req = 0;
	rc_vfreez(sa->intermediate_resp);
	sa->intermediate_resp = 0;
	/* H1: retained gen-0 receive keys (must not leak; set on responder SA
	 * that did an RFC 9242 key update). */
	rc_vfreez(sa->prev_sk_a_r);
	sa->prev_sk_a_r = 0;
	rc_vfreez(sa->prev_sk_e_r);
	sa->prev_sk_e_r = 0;
	if (sa->intermediate_priv) {
		EVP_PKEY_free((EVP_PKEY *)sa->intermediate_priv);
		sa->intermediate_priv = 0;
	}
}

/* Drop only the gen-0 response replay cache.  Called once IKE_AUTH is
 * accepted (the RFC 9242 window is over); unlike ikev2_intermediate_clear
 * it does NOT drop the retained prev-gen receive keys, which the classical
 * (non-AEAD) gen-rolled retransmit path ikev2_check_icv_prev_gen() still
 * needs until dispose. */
void
ikev2_intermediate_clear_replay(struct ikev2_sa *sa)
{
	if (!sa)
		return;
	rc_vfreez(sa->intermediate_replay);
	sa->intermediate_replay = 0;
	if (sa->intermediate_replay_frags) {
		int i;

		for (i = 0; i < sa->intermediate_replay_nfrags; i++)
			if (sa->intermediate_replay_frags[i])
				rc_vfree(sa->intermediate_replay_frags[i]);
		racoon_free(sa->intermediate_replay_frags);
		sa->intermediate_replay_frags = 0;
		sa->intermediate_replay_nfrags = 0;
	}
	sa->intermediate_replay_msgid = 0;
}

/* =========================================================================
 * RFC 9242 IKE_INTERMEDIATE exchange (moved from ikev2.c): handlers,
 * IntAuth chain, ADDKE-round finalize, and the gen-0 response replay.
 * ========================================================================= */

void
ikev2_replay_intermediate_response(struct ikev2_sa *ike_sa)
{
	struct timeval now, diff;
	int sock;

	if (!ike_sa || !ike_sa->intermediate_replay)
		return;

	gettimeofday(&now, 0);
	timersub(&now, &ike_sa->intermediate_replay_sent, &diff);
	if (diff.tv_sec < 1)
		return;

	sock = isakmp_find_socket(ike_sa->local);
	if (sock == -1)
		return;

	if (ike_sa->intermediate_replay_frags) {
		int i;

		/* The gen-0 response went out as SKF fragments: replay the
		 * EXACT datagrams.  Each carries its own RFC 3948 marker
		 * (baked by ikev2_frag_send), so per-fragment UDP survives
		 * a 576-MTU path, and the peer's reassembler feeds them by
		 * message_id and drops duplicates.  Fragments are the wire
		 * form; re-sending the pre-fragment whole as one datagram
		 * (or re-marking it) would be the 576 hole again. */
		for (i = 0; i < ike_sa->intermediate_replay_nfrags; i++) {
			if (!ike_sa->intermediate_replay_frags[i])
				continue;
			if (sendfromto(sock,
				       ike_sa->intermediate_replay_frags[i]->v,
				       ike_sa->intermediate_replay_frags[i]->l,
				       ike_sa->local, ike_sa->remote, 1) == -1)
				break;
		}
		ike_sa->intermediate_replay_sent = now;
		isakmp_log(ike_sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
			   "H1 replay: re-sent cached gen-0 IKE_INTERMEDIATE response (%d fragment datagrams)\n",
			   ike_sa->intermediate_replay_nfrags);
		return;
	}

#ifdef ENABLE_NATT
	/* A replayed response over UDP/4500 needs the RFC 3948 non-ESP
	 * marker, exactly like the other send paths.  Use a copy so the
	 * pristine gen-0 cache survives for further retransmits. */
	if (natt_check_udp_encap(ike_sa->remote, ike_sa->local) > 0) {
	    rc_vchar_t *mark = natt_set_non_esp_marker(
		rc_vdup(ike_sa->intermediate_replay));
	    if (!mark)
		return;
	    if (sendfromto(sock, mark->v, mark->l, ike_sa->local,
			   ike_sa->remote, 1) == -1) {
		rc_vfree(mark);
		return;
	    }
	    rc_vfree(mark);
	} else
#endif
	if (sendfromto(sock, ike_sa->intermediate_replay->v,
		       ike_sa->intermediate_replay->l,
		       ike_sa->local, ike_sa->remote, 1) == -1)
		return;

	ike_sa->intermediate_replay_sent = now;
	isakmp_log(ike_sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
		   "H1 replay: re-sent cached gen-0 IKE_INTERMEDIATE response (%zu bytes)\n",
		   ike_sa->intermediate_replay->l);
}
/* =========================================================================
 * RFC 9242 IKE_INTERMEDIATE + RFC 9370 s2.2/s3.5: ADDKE on the INITIAL
 * IKE_SA.  When 16438 (INTERMEDIATE_EXCHANGE_SUPPORTED) is negotiated AND
 * the IKE_SA proposal selected an ADDKE transform (type 6 = ADDKE1), the
 * peers run one or more IKE_INTERMEDIATE (exch 43) rounds between
 * IKE_SA_INIT and IKE_AUTH.  Each round carries a KE payload whose method
 * equals the negotiated ADDKE id; after the round both sides update
 * SKEYSEED(1)=prf(SK_d,SK(1)|Ni|Nr) then Sk_*=prf+(SKEYSEED(1),Ni|Nr|SPIi|SPIr)
 * (RFC 9370 s3.5) and chain the round's pre-encryption content into the
 * IntAuth PRF (RFC 9242 s3.3.2).  The final IntAuth_iN|IntAuth_rN|
 * IKE_AUTH_MID is appended to the AUTH octets in ikev2_auth.c.  Both the
 * initiator and the responder mirrors share the helpers below and the
 * shared serializer ikev2_payloads_to_blob() from ikev2_packet.c.
 * ========================================================================= */

/* concat up to 4 optional vchars (NULL-safe) into a new vchar. */
static rc_vchar_t *
intermediate_concat4(rc_vchar_t *p1, rc_vchar_t *p2, rc_vchar_t *p3,
		     rc_vchar_t *p4)
{
	rc_vchar_t *ps[4];
	rc_vchar_t *out;
	uint8_t *ptr;
	size_t l = 0;
	int i;

	ps[0] = p1; ps[1] = p2; ps[2] = p3; ps[3] = p4;
	for (i = 0; i < 4; ++i)
		if (ps[i])
			l += ps[i]->l;
	out = rc_vmalloc(l);
	if (!out)
		return 0;
	ptr = (uint8_t *)out->v;
	for (i = 0; i < 4; ++i) {
		if (!ps[i] || !ps[i]->l)
			continue;
		memcpy(ptr, ps[i]->v, ps[i]->l);
		ptr += ps[i]->l;
	}
	return out;
}

/* Serialize the INNER payload chain of a decrypted inbound packet (skipping
 * the leading Encrypted payload header) into IntAuth_P.  Byte-identical to
 * ikev2_payloads_to_blob() of what the sender encrypted. */
static rc_vchar_t *
intermediate_packet_inner_blob(rc_vchar_t *packet)
{
	struct ikev2_header *ikehdr;
	struct ikev2_payload_header *p;
	unsigned int type;
	rc_vchar_t *out;
	uint8_t *ptr, *base, *end;
	size_t msglen = 0;
	uint8_t head = IKEV2_NO_NEXT_PAYLOAD;
	uint8_t *prev_np = &head;
	int started = 0;

	if (!packet || packet->l < sizeof(*ikehdr))
		return 0;
	ikehdr = (struct ikev2_header *)packet->v;
	base = (uint8_t *)packet->v;
	end = base + packet->l;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	while (type != IKEV2_NO_NEXT_PAYLOAD) {
		uint32_t plen;

		if ((uint8_t *)p < base || (uint8_t *)p + sizeof(*p) > end)
			return 0;
		plen = get_payload_length(p);
		if (plen < sizeof(*p) || (uint8_t *)p + plen > end)
			return 0;
		if (!started && type == IKEV2_PAYLOAD_ENCRYPTED) {
			type = p->next_payload;
			p = (struct ikev2_payload_header *)((uint8_t *)p + plen);
			continue;
		}
		started = 1;
		msglen += plen;
		type = p->next_payload;
		p = (struct ikev2_payload_header *)((uint8_t *)p + plen);
	}
	if (!started || msglen == 0)
		return 0;
	out = rc_vmalloc(msglen);
	if (!out)
		return 0;
	ptr = (uint8_t *)out->v;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	started = 0;
	while (type != IKEV2_NO_NEXT_PAYLOAD) {
		uint32_t plen;

		if ((uint8_t *)p < base || (uint8_t *)p + sizeof(*p) > end)
			goto fail;
		plen = get_payload_length(p);
		if (plen < sizeof(*p) || (uint8_t *)p + plen > end)
			goto fail;
		if (!started && type == IKEV2_PAYLOAD_ENCRYPTED) {
			type = p->next_payload;
			p = (struct ikev2_payload_header *)((uint8_t *)p + plen);
			continue;
		}
		started = 1;
		*prev_np = type;
		prev_np = &(((struct ikev2_payload_header *)ptr)->next_payload);
		memcpy(ptr, p, plen);
		ptr += plen;
		type = p->next_payload;
		p = (struct ikev2_payload_header *)((uint8_t *)p + plen);
	}
	*prev_np = IKEV2_NO_NEXT_PAYLOAD;
	return out;
fail:
	rc_vfree(out);
	return 0;
}

/* RFC 9370 s3.5: SKEYSEED(1)=prf(SK_d,SK(1)|Ni|Nr) then recompute all
 * Sk_* = prf+(SKEYSEED(1),Ni|Nr|SPIi|SPIr) via ikev2_compute_keys.  SK_d is
 * read as its PRE-update value (the formula's SK_d(n-1)). */
static int
ikev2_intermediate_update_keys(struct ikev2_sa *sa, rc_vchar_t *sk_n)
{
	rc_vchar_t *data, *new_seed, *old_seed;

	if (!sa->sk_d || !sa->n_i || !sa->n_r || !sk_n)
		return -1;
	data = intermediate_concat4(sk_n, sa->n_i, sa->n_r, 0);
	if (!data)
		return -1;
	new_seed = keyed_hash(sa->prf, sa->sk_d, data);
	rc_vfree(data);
	if (!new_seed)
		return -1;
	/* H1: retain the current (PRE-update, gen-0) RECEIVE keys before the
	 * swap below destroys them (ikev2_compute_keys cleanses + frees the
	 * originals).  A retransmitted gen-0 IKE_INTERMEDIATE request must be
	 * able to validate ICV and be replayed from the response cache, or one
	 * lost intermediate response kills the SA. */
	rc_vfreez(sa->prev_sk_a_r); sa->prev_sk_a_r = 0;
	rc_vfreez(sa->prev_sk_e_r); sa->prev_sk_e_r = 0;
	if (sa->sk_a_r)
		sa->prev_sk_a_r = rc_vdup(sa->sk_a_r);
	if (sa->sk_e_r)
		sa->prev_sk_e_r = rc_vdup(sa->sk_e_r);
	/* RFC 9370 s3.5 / RFC 9242 s3.3: the SKEYSEED generation swap must be
	 * all-or-nothing.  Hold the old generation until ikev2_compute_keys
	 * succeeds so a mid-derivation failure never leaves the NEW SKEYSEED
	 * paired with the OLD SK_* children (the caller aborts the SA on a
	 * non-zero return, but the descriptor must stay internally consistent
	 * up to that abort). */
	old_seed = sa->skeyseed;
	sa->skeyseed = new_seed;
	if (ikev2_compute_keys(sa) != 0) {
		rc_vfreez(sa->skeyseed);
		sa->skeyseed = old_seed;
		return -1;
	}
	rc_vfree(old_seed);
	return 0;
}

/* RFC 9242 s3.3.2: chain one round's content into IntAuth_i ('i') or
 * IntAuth_r ('r'), keyed by the CURRENT sk_p (the pre-update generation for
 * this round: INIT keys for round 1).  Must be called BEFORE
 * ikev2_intermediate_update_keys, which installs the next generation.  The
 * result is a keyed PRF value and must NEVER be logged. */
static void
ikev2_intermediate_chain_intauth(struct ikev2_sa *sa, int dir,
				 rc_vchar_t *content)
{
	rc_vchar_t *key, *prev, *data, *h;
	rc_vchar_t **chain;

	if (!content) {
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "IntAuth chain dir=%c no-content\n", dir);
		return;
	}
	chain = (dir == 'i') ? &sa->intauth_i : &sa->intauth_r;
	key = (dir == 'i') ? sa->sk_p_i : sa->sk_p_r;
	prev = *chain;
	if (!key) {
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "IntAuth chain dir=%c no-key sk_p_%c=NULL\n",
			   dir, dir);
		return;
	}
	data = intermediate_concat4(prev, content, 0, 0);
	if (!data)
		return;
	h = keyed_hash(sa->prf, key, data);
	rc_vfree(data);
	if (!h)
		return;
	rc_vfreez(*chain);
	*chain = h;
	TRACE((PLOGLOC, "IKE_INTERMEDIATE IntAuth_%c updated\n",
	       dir == 'i' ? 'i' : 'r'));
}

/* RFC 9242 s3.3.2 IntAuth_A: the outer IKE header + the Encrypted payload's
 * generic header.  Reconstructed deterministically so BOTH the sender and a
 * peer receiving the (fragmented) message reproduce identical bytes: the
 * header's next_payload is normalized to ENCRYPTED and its Length to the
 * Adjusted Length (|IntAuth_A| + |IntAuth_P|); the Encrypted generic header's
 * Payload Length is the Adjusted Payload Length (|IntAuth_P| + 4).  IV, ICV,
 * Padding and Pad Length are NOT counted.  This is exact for any IKE cipher;
 * an AEAD (AES-GCM) IKE cipher is still required for the initial-IKE_SA ADDKE
 * path so the intermediate messages are authenticated (IntAuth_A requires an
 * encryption ICV). */
static rc_vchar_t *
intermediate_content_a(struct ikev2_sa *sa, struct ikev2_header *hdr,
		       size_t inner_len, uint8_t first_inner_type)
{
	static const size_t hdr_len = sizeof(struct ikev2_header);
	size_t iv_len, tag_len;
	uint32_t enc_len;
	rc_vchar_t *c;
	uint8_t *p;

	iv_len = sa->encryptor ? encryptor_iv_length(sa->encryptor) : 0;
	tag_len = sa->encryptor ? encryptor_icv_length(sa->encryptor) : 0;
	/* RFC 9242 s3.3.2: the IntAuth prf uses ADJUSTED length fields --
	 * the IKE Header Length (Adjusted Length) = |IntAuth_A| + |IntAuth_P|
	 * and the Encrypted generic Payload Length (Adjusted Payload Length)
	 * = |IntAuth_P| + 4.  IV, Integrity Checksum Data, Padding and Pad
	 * Length are NOT counted (the peer's configured/actual iv+tag+pad
	 * must NOT leak into the prf input).  So:
	 *   enc_len (Enc generic, adjusted) = 4 + inner_len
	 *   header Length (adjusted)        = hdr_len + enc_len
	 * OLD code counted iv+tag+pad-len (4+iv+inner+1+tag), which makes
	 * every IntAuth_A differ from a standards-correct peer (iOS) by the
	 * IV+ICV+pad bytes -> IKE_AUTH 'authentication failure'.  Self-
	 * consistent between two racoon2 peers, so the iked<->iked matrix
	 * could not catch it. */
	enc_len = sizeof(struct ikev2_payload_header) + (uint32_t)inner_len;
	/* Debug (non-secret): reconstruction inputs so a byte-diff against
	 * the peer's signed IntAuth_A can pin the divergence.  Only lengths /
	 * header bytes, never key material. */
	isakmp_log(sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
		   "IntAuth_A recon hdr.next=%u hdr.len=%u -> norm enc_len=%u "
		   "iv=%zu tag=%zu inner=%zu\n",
		   (unsigned)hdr->next_payload,
		   (unsigned)get_uint32((uint8_t *)hdr + 24),
		   (unsigned)enc_len, iv_len, tag_len, inner_len);
	c = rc_vmalloc(hdr_len + sizeof(struct ikev2_payload_header));
	if (!c)
		return 0;
	p = (uint8_t *)c->v;
	memcpy(p, hdr, hdr_len);
	/* normalize the header next_payload (byte offset 16 is next_payload,
	 * byte 0 is the first octet of the initiator SPI -- do not touch it) */
	((struct ikev2_header *)p)->next_payload = IKEV2_PAYLOAD_ENCRYPTED;
	/* IKE header Length field is bytes 24-27: the UNfragmented full size */
	put_uint32(p + 24, (uint32_t)(hdr_len + enc_len));
	p += hdr_len;
	/* Encrypted payload generic header.  RFC 9242 s3.3.2: the reassembled
	 * header's RESERVED octet should be taken from the FIRST fragment's
	 * Encrypted Fragment header.  We zero it here (p[1]=0) -- a stated
	 * assumption that holds for every current peer (Critical bit C=0 and
	 * RESERVED=0 on the wire, incl. iOS).  Length is the ADJUSTED
	 * |IntAuth_P|+4 (IV/ICV/pad excluded). */
	p[0] = first_inner_type;
	p[1] = 0;
	put_uint16(p + 2, (uint16_t)enc_len);
	/* Debug (non-secret): the reconstructed IntAuth_A chunk (IKE header +
	 * Encrypted generic header) is complete only now -- dump after the Enc
	 * generic header above.  Public wire bytes; first 32 cover both SPIs +
	 * the two headers' next/len, printed with the adjusted lengths.  Never
	 * key material. */
	{
		char hxb[96];
		int _i, _n = c->l < 32 ? (int)c->l : 32;
		for (_i = 0; _i < _n; _i++)
			snprintf(&hxb[_i * 2], 3, "%02x", ((u_char *)c->v)[_i]);
		hxb[_i * 2] = '\0';
		isakmp_log(sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
			   "IntAuth_A recon[%zu] enc_len=%u enc_next=%u hx=%s\n",
			   c->l, enc_len, first_inner_type, hxb);
	}
	return c;
}

/* Build a KE payload whose method field carries the negotiated ADDKE id. */
static rc_vchar_t *
intermediate_ke_payload(uint32_t method, rc_vchar_t *body)
{
	struct ikev2payl_ke_h kh;

	kh.dh_group_id = htons((uint16_t)method);
	kh.reserved = 0;
	return rc_vprepend(body, &kh, sizeof(kh));
}

/* extract the raw body of a KE payload (after its 4-byte method header) */
static rc_vchar_t *
intermediate_ke_body(struct ikev2payl_ke *ke)
{
	uint32_t l;
	uint8_t *p;

	if (!ke)
		return 0;
	l = get_payload_length(&ke->header);
	if (l <= sizeof(struct ikev2_payload_header)
	    + sizeof(struct ikev2payl_ke_h))
		return 0;
	p = (uint8_t *)ke + sizeof(struct ikev2_payload_header)
		+ sizeof(struct ikev2payl_ke_h);
	return rc_vnew(p, l - sizeof(struct ikev2_payload_header)
		       - sizeof(struct ikev2payl_ke_h));
}

/* Shared bounded walker used by BOTH intermediate mirrors: find the KE
 * payload in a decrypted/reassembled IKE_INTERMEDIATE message.  Every step
 * is bounds-checked against packet->l, so a malformed/reassembled inner
 * chain cannot run off the buffer (returns NULL instead of crashing). */
static struct ikev2payl_ke *
intermediate_find_ke(rc_vchar_t *packet)
{
	struct ikev2_header *ikehdr = (struct ikev2_header *)packet->v;
	struct ikev2_payload_header *p;
	uint8_t *end, *base;
	unsigned int type;

	if (packet->l < sizeof(*ikehdr))
		return NULL;
	base = (uint8_t *)packet->v;
	end = base + packet->l;
	p = (struct ikev2_payload_header *)(ikehdr + 1);
	type = ikehdr->next_payload;
	while (type != IKEV2_NO_NEXT_PAYLOAD) {
		uint32_t plen;

		if ((uint8_t *)p < base || (uint8_t *)p + sizeof(*p) > end)
			return NULL;
		plen = get_payload_length(p);
		if (type == IKEV2_PAYLOAD_ENCRYPTED) {
			/* decrypted-inline content follows the enc header */
		} else if (type == IKEV2_PAYLOAD_KE) {
			if (plen < sizeof(*p) ||
			    (uint8_t *)p + plen > end)
				return NULL;
			return (struct ikev2payl_ke *)p;
		}
		if (plen < sizeof(*p) || (uint8_t *)p + plen > end)
			return NULL;
		type = p->next_payload;
		p = (struct ikev2_payload_header *)((uint8_t *)p + plen);
	}
	return NULL;
}

/* both sides have completed round N: chain both IntAuth derivations from the
 * held request/response contents.  Called BEFORE ikev2_intermediate_update_keys
 * so sa->sk_p_i/r still hold this round's pre-update generation, which is the
 * generation RFC 9242 s3.3.2 keys IntAuth for round N. */
static void
intermediate_finish_round(struct ikev2_sa *sa)
{
	/* fingerprint lengths only — do not print SKEYSEED / IntAuth */
	TRACE((PLOGLOC,
	       "IKE_INTERMEDIATE round done reqlen=%zu resplen=%zu\n",
	       sa->intermediate_req ? sa->intermediate_req->l : 0,
	       sa->intermediate_resp ? sa->intermediate_resp->l : 0));
	/* non-secret marker a matrix case asserts: both sides completing the
	 * round (with the ESP child coming up = AUTH+IntAuth verified = the
	 * RFC 9370 s3.5 SKEYSEED(1) genuinely matched) is the proof; the raw
	 * SKEYSEED/IntAuth bytes are deliberately NOT logged. */
	isakmp_log(sa, 0, 0, 0, PLOG_INFO, PLOGLOC,
		   "IKE_INTERMEDIATE ADDKE round complete reqlen=%zu resplen=%zu\n",
		   sa->intermediate_req ? sa->intermediate_req->l : 0,
		   sa->intermediate_resp ? sa->intermediate_resp->l : 0);
	sa->intermediate_rounds++;
	ikev2_intermediate_chain_intauth(sa, 'i', sa->intermediate_req);
	ikev2_intermediate_chain_intauth(sa, 'r', sa->intermediate_resp);
	/* NOTE: sa->intauth_i / sa->intauth_r are keyed PRF values
	 * (sk_p-keyed MACs, RFC 9242 s3.3.2) and must NEVER be logged.  The
	 * public transcript they cover is sa->intermediate_req/resp, freed
	 * below. */
	/* rc_vfreez is BY VALUE and, in -DDEBUG builds, does NOT clear the
	 * caller's pointer (the var->v=NULL is #ifndef DEBUG).  If we do not
	 * null the fields here, a later graceful dispose (the rekey reaper /
	 * ikev2_dispose_sa -> ikev2_intermediate_clear) re-frees the dangling
	 * pointer -> double-free -> SIGSEGV.  Own the release explicitly. */
	rc_vfreez(sa->intermediate_req);
	sa->intermediate_req = 0;
	rc_vfreez(sa->intermediate_resp);
	sa->intermediate_resp = 0;
}

/* --------------------------------------------------------------- initiator
 * send the current IKE_INTERMEDIATE request round. */
void
initiator_ike_intermediate_send(struct ikev2_sa *sa)
{
	struct ikev2_payloads payl;
	rc_vchar_t *pub = 0, *ke = 0, *pkt = 0, *cA = 0, *content = 0;
	rc_vchar_t *inner = 0;
	EVP_PKEY *priv = 0;
	uint32_t method;

	if (!sa->intermediate_negotiated || !sa->negotiated_sa ||
	    sa->negotiated_sa->addke == 0) {
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "IKE_INTERMEDIATE: no negotiated ADDKE method\n");
		ikev2_abort(sa, ECONNREFUSED);
		return;
	}
	if (!sa->encryptor || encryptor_icv_length(sa->encryptor) <= 0) {
		isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE_INTERMEDIATE: IntAuth_A requires an AEAD IKE cipher\n");
		ikev2_abort(sa, ECONNREFUSED);
		return;
	}
	method = sa->negotiated_sa->addke;
	if (ikev2_addke_mlkem_keygen(method, &pub, &priv) != 0) {
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "IKE_INTERMEDIATE: ML-KEM keygen failed\n");
		ikev2_abort(sa, ECONNREFUSED);
		return;
	}
	ke = intermediate_ke_payload(method, pub);
	pub = 0;
	if (!ke) {
		EVP_PKEY_free(priv);
		ikev2_abort(sa, ECONNREFUSED);
		return;
	}
	if (sa->intermediate_priv)
		EVP_PKEY_free((EVP_PKEY *)sa->intermediate_priv);
	sa->intermediate_priv = priv;

	ikev2_payloads_init(&payl);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, ke, FALSE);
	ke = 0;		/* owned by payl now */
	inner = ikev2_payloads_to_blob(&payl, 0);
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_INTERMEDIATE,
				     IKEV2FLAG_INITIATOR,
				     sa->intermediate_msgid, sa, &payl);
	if (!pkt)
		goto fail;
	cA = intermediate_content_a(sa, (struct ikev2_header *)pkt->v,
				    inner ? inner->l : 0, IKEV2_PAYLOAD_KE);
	content = intermediate_concat4(cA, inner, 0, 0);
	rc_vfree(cA);
	if (!content)
		goto fail;
	rc_vfreez(sa->intermediate_req);
	sa->intermediate_req = content;
	content = 0;

	/* Set the awaiting-response state FIRST: ikev2_set_state() tears down
	 * transmit_info (stop_retransmit) on every transition, which would
	 * kill the request's retransmit timer armed by ikev2_transmit()
	 * below as soon as it was created.  Ordering the state before the
	 * send lets the retransmit timer survive, so a lost intermediate
	 * response is retransmitted and the responder replays its cached
	 * gen-0 response (review R1). */
	ikev2_set_state(sa, IKEV2_STATE_INI_IKE_INTERMEDIATE_SENT);
	if (ikev2_transmit(sa, pkt) != 0)
		goto fail;
	pkt = 0;
	ikev2_payloads_destroy(&payl);
	rc_vfree(inner);
	return;

fail:
	ikev2_payloads_destroy(&payl);
	if (pkt)
		rc_vfree(pkt);
	if (ke)
		rc_vfree(ke);
	if (content)
		rc_vfree(content);
	if (inner)
		rc_vfree(inner);
	isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
		   "failed to send IKE_INTERMEDIATE\n");
	ikev2_abort(sa, ECONNREFUSED);
}

/* initiator state IKEV2_STATE_INI_IKE_INTERMEDIATE_SENT: an
 * IKE_INTERMEDIATE response carrying KEr(n) has arrived. */
void
initiator_ike_intermediate_recv(struct ikev2_sa *sa, rc_vchar_t *packet,
				struct sockaddr *local, struct sockaddr *remote)
{
	struct ikev2_header *ikehdr = (struct ikev2_header *)packet->v;
	struct ikev2payl_ke *ke = 0;
	rc_vchar_t *body = 0, *ss = 0, *cA = 0, *ib = 0, *resp = 0;

	(void)local; (void)remote;
	if (!sa->intermediate_negotiated || !sa->negotiated_sa ||
	    sa->negotiated_sa->addke == 0) {
		isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE_INTERMEDIATE: unexpected response\n");
		ikev2_abort(sa, ECONNREFUSED);
		return;
	}
	if (!(ikehdr->flags & IKEV2FLAG_RESPONSE)) {
		isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE_INTERMEDIATE: expected a response\n");
		ikev2_abort(sa, ECONNREFUSED);
		return;
	}
	/* Robustness: an ICV-valid response for a different exchange type
	 * arriving while we await the intermediate response is a stale
	 * retransmit (e.g. a delayed IKE_SA_INIT response).  Ignore it rather
	 * than kill the SA -- RFC 7296 does not require aborting on a
	 * last-arrived exchange (F1). */
	if (ikehdr->exchange_type != IKEV2EXCH_IKE_INTERMEDIATE) {
		isakmp_log(sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
			   "IKE_INTERMEDIATE: ignoring stale exch %d response\n",
			   ikehdr->exchange_type);
		return;
	}
	if (get_uint32(&ikehdr->message_id) != sa->intermediate_msgid) {
		/* Late/retransmitted response for an already-consumed round, or
		 * a stale message with a lower id.  Drop, don't abort (F1). */
		isakmp_log(sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
			   "IKE_INTERMEDIATE: stale/dup msgid %u (expected %u), dropping\n",
			   get_uint32(&ikehdr->message_id),
			   sa->intermediate_msgid);
		return;
	}

	ke = intermediate_find_ke(packet);
	if (!ke)
		goto malformed;
	if (ntohs(ke->ke_h.dh_group_id) != sa->negotiated_sa->addke) {
		isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE_INTERMEDIATE: round KE method %u != negotiated %u\n",
			   ntohs(ke->ke_h.dh_group_id), sa->negotiated_sa->addke);
		goto malformed;
	}
	body = intermediate_ke_body(ke);
	if (!body)
		goto malformed;
	if (!sa->intermediate_priv) {
		/* Duplicate of the response we already consumed this round
		 * (the shared secret was obtained and intermediate_priv freed).
		 * Idempotent -- ignore it, the SA survives (F1). */
		isakmp_log(sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
			   "IKE_INTERMEDIATE: duplicate response, ignoring\n");
		rc_vfree(body);
		return;
	}
	if (ikev2_addke_mlkem_decap((EVP_PKEY *)sa->intermediate_priv,
				    body, &ss) != 0) {
		rc_vfree(body);
		isakmp_log(sa, 0, 0, 0, PLOG_INTERR, PLOGLOC,
			   "IKE_INTERMEDIATE: ML-KEM decap failed\n");
		goto abort;
	}
	rc_vfree(body);
	if (sa->intermediate_priv) {
		EVP_PKEY_free((EVP_PKEY *)sa->intermediate_priv);
		sa->intermediate_priv = 0;
	}

	/* hold the RESPONSE content (IntAuth_r chunk) */
	ib = intermediate_packet_inner_blob(packet);
	if (!ib)
		goto malformed;
	cA = intermediate_content_a(sa, (struct ikev2_header *)packet->v,
				    ib->l, IKEV2_PAYLOAD_KE);
	resp = intermediate_concat4(cA, ib, 0, 0);
	rc_vfree(cA);
	rc_vfree(ib);
	rc_vfreez(sa->intermediate_resp);
	sa->intermediate_resp = resp;
	resp = 0;

	/* RFC 9242 s3.3: IntAuth for this round is keyed by the PRE-update sk_p
	 * (the intermediate messages are protected with keys from the previous
	 * generation).  Chain BOTH directions BEFORE the key update; the post-
	 * update sk_p applies to the exchanges that FOLLOW the intermediate. */
	intermediate_finish_round(sa);
	if (ikev2_intermediate_update_keys(sa, ss) != 0) {
		rc_vfree(ss);
		goto abort;
	}
	rc_vfree(ss);

	/* only ADDKE1 (one round) is implemented here */
	ikev2_set_state(sa, IKEV2_STATE_INI_IKE_AUTH_SENT);
	ikev2_update_message_id(sa, sa->intermediate_msgid, TRUE);
	initiator_state1_send(sa, 0, sa->remote);
	return;

malformed:
	isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
		   "IKE_INTERMEDIATE response malformed\n");
	ikev2_abort(sa, ECONNREFUSED);
	return;
abort:
	ikev2_abort(sa, ECONNREFUSED);
}

/* --------------------------------------------------------------- responder
 * an IKE_INTERMEDIATE request (KEi(n)) reached the responder's post-INIT
 * state.  Encapsulate, reply KEr(n), update the keys and IntAuth chains,
 * and stay in the post-INIT state awaiting the next intermediate or AUTH. */
void
responder_ike_intermediate_recv(struct ikev2_sa *sa, rc_vchar_t *packet,
				struct sockaddr *src, struct sockaddr *dst)
{
	struct ikev2_header *ikehdr = (struct ikev2_header *)packet->v;
	struct ikev2payl_ke *ke = 0;
	rc_vchar_t *body = 0, *ct = 0, *ss = 0, *kep = 0, *pkt = 0;
	rc_vchar_t *cA = 0, *cAreq = 0, *iblob = 0, *req = 0, *resp = 0;
	rc_vchar_t *inner = 0;
	struct ikev2_payloads payl;
	uint32_t rmsgid;

	if (!sa->intermediate_negotiated || !sa->negotiated_sa ||
	    sa->negotiated_sa->addke == 0) {
		isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE_INTERMEDIATE: not negotiated, dropping\n");
		goto drop;
	}
	if (!sa->encryptor || encryptor_icv_length(sa->encryptor) <= 0) {
		isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE_INTERMEDIATE: IntAuth_A requires an AEAD IKE cipher\n");
		goto drop;
	}
	if (ikehdr->flags & IKEV2FLAG_RESPONSE) {
		isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE_INTERMEDIATE: unexpected response\n");
		goto drop;
	}
	rmsgid = get_uint32(&ikehdr->message_id);

	ke = intermediate_find_ke(packet);
	isakmp_log(sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
		   "responder-inter walked ke=%p\n", (void *)ke);
	if (!ke || (uint32_t)ntohs(ke->ke_h.dh_group_id) != sa->negotiated_sa->addke)
		goto drop;
	body = intermediate_ke_body(ke);
	isakmp_log(sa, 0, 0, 0, PLOG_DEBUG, PLOGLOC,
		   "responder-inter ke_body=%p addke=%u\n", (void *)body,
		   sa->negotiated_sa->addke);
	if (!body)
		goto drop;

	/* hold the REQUEST content (IntAuth_i chunk) */
	iblob = intermediate_packet_inner_blob(packet);
	if (!iblob)
		goto drop;
	cAreq = intermediate_content_a(sa, (struct ikev2_header *)packet->v,
				       iblob->l, IKEV2_PAYLOAD_KE);
	req = intermediate_concat4(cAreq, iblob, 0, 0);
	rc_vfree(cAreq);
	rc_vfree(iblob);
	rc_vfreez(sa->intermediate_req);
	sa->intermediate_req = req;
	req = 0;

	if (ikev2_addke_mlkem_encap(sa->negotiated_sa->addke, body,
				    &ct, &ss) != 0) {
		rc_vfree(body);
		goto drop;
	}
	rc_vfree(body);
	kep = intermediate_ke_payload(sa->negotiated_sa->addke, ct);
	ct = 0;
	if (!kep)
		goto drop;

	ikev2_payloads_init(&payl);
	ikev2_payloads_push(&payl, IKEV2_PAYLOAD_KE, kep, FALSE);
	kep = 0;
	inner = ikev2_payloads_to_blob(&payl, 0);
	pkt = ikev2_packet_construct(IKEV2EXCH_IKE_INTERMEDIATE,
				     IKEV2FLAG_RESPONSE, rmsgid, sa, &payl);
	if (!pkt)
		goto drop2;
	cA = intermediate_content_a(sa, (struct ikev2_header *)pkt->v,
				    inner ? inner->l : 0, IKEV2_PAYLOAD_KE);
	resp = intermediate_concat4(cA, inner, 0, 0);
	rc_vfree(cA);
	rc_vfreez(sa->intermediate_resp);
	sa->intermediate_resp = resp;
	resp = 0;

	/* R1: cache the gen-0 IKE_INTERMEDIATE response (full wire packet,
	 * already authenticated under the pre-update keys) BEFORE
	 * ikev2_transmit_response() fragments-and-consumes pkt.  A peer that
	 * lost a fragment retransmits the gen-0 request, which we can no
	 * longer decrypt once the keys advance to gen-1; ikev2_input() then
	 * replays these exact bytes (the peer is still on gen-0 and can
	 * authenticate them). */
	rc_vfreez(sa->intermediate_replay);
	sa->intermediate_replay = rc_vdup(pkt);
	sa->intermediate_replay_msgid = rmsgid;
	gettimeofday(&sa->intermediate_replay_sent, 0);

	if (ikev2_transmit_response(sa, pkt, src, dst) != 0)
		goto drop2;
	pkt = 0;
	/* If the response went out fragmented, the wire form is the SKF
	 * datagram list now cached in response_info.  Own a private copy
	 * for the gen-0 replay cache (response_info is reused by later
	 * exchanges), so a 576-MTU retransmit replays per-fragment UDP --
	 * the pre-fragment whole cannot be re-fragmented under gen-1 keys
	 * nor carried as one datagram. */
	{
		int fi;

		if (sa->intermediate_replay_frags) {
			for (fi = 0; fi < sa->intermediate_replay_nfrags; fi++)
				if (sa->intermediate_replay_frags[fi])
					rc_vfree(sa->intermediate_replay_frags[fi]);
			racoon_free(sa->intermediate_replay_frags);
			sa->intermediate_replay_frags = 0;
			sa->intermediate_replay_nfrags = 0;
		}
		if (sa->response_info.frags &&
		    sa->response_info.nfrags > 0) {
			sa->intermediate_replay_frags = racoon_calloc(
			    (size_t)sa->response_info.nfrags,
			    sizeof(rc_vchar_t *));
			if (sa->intermediate_replay_frags) {
				for (fi = 0; fi < sa->response_info.nfrags; fi++)
					sa->intermediate_replay_frags[fi] =
					    rc_vdup(sa->response_info.frags[fi]);
				sa->intermediate_replay_nfrags =
				    sa->response_info.nfrags;
			}
		}
	}
	ikev2_payloads_destroy(&payl);
	rc_vfree(inner);
	inner = 0;

	/* IntAuth for this round is keyed by the PRE-update sk_p (RFC 9242
	 * s3.3: intermediate messages use the previous key generation).  Chain
	 * both directions BEFORE the key update; the response itself was sent
	 * immediately above, still encrypted with the pre-update IKE keys. */
	intermediate_finish_round(sa);
	if (ikev2_intermediate_update_keys(sa, ss) != 0) {
		rc_vfree(ss);
		/* The response was already sent (still gen-0).  Failing the
		 * key update here MUST close the SA: leaving it up would
		 * desync it (peer advances to gen-1 on the response it
		 * already holds while we stay on gen-0, and recv_message_id
		 * was never advanced, so a retransmit would be re-processed
		 * as a brand-new round).  Fail closed, never drop. */
		isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
			   "IKE_INTERMEDIATE: responder key update failed, aborting\n");
		ikev2_abort(sa, ECONNREFUSED);
		return;
	}
	rc_vfree(ss);
	/* RFC 9242 s3.2: AUTH msgid = last intermediate + 1.  The responder
	 * accepted the intermediate (recv_message_id == rmsgid); advance it so
	 * the IKE_AUTH request (rmsgid+1) is not dropped as unordered. */
	ikev2_update_message_id(sa, rmsgid, FALSE);
	return;

drop2:
	ikev2_payloads_destroy(&payl);
	if (pkt)
		rc_vfree(pkt);
	if (inner)
		rc_vfree(inner);
drop:
	if (ss)
		rc_vfree(ss);
	if (ct)
		rc_vfree(ct);
	if (kep)
		rc_vfree(kep);
	isakmp_log(sa, 0, 0, 0, PLOG_PROTOERR, PLOGLOC,
		   "IKE_INTERMEDIATE: responder round failed\n");
}

#endif /* WITH_INTERMEDIATE */
