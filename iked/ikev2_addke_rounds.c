/*
 * Copyright (c) 2026
 *	Yasuyuki Goda and the racoon2 project.
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * RFC 9370 s2.2.1/s2.2.2: derive the additional key exchange rounds from
 * a negotiated (selected) proposal.
 *
 * Kept free of crypto and daemon state so it is compiled into iked
 * regardless of WITH_ADDKE and linked straight into addketest.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

#include "racoon.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "ikev2.h"
#include "ikev2_impl.h"

/*
 * Walk ADDKE1..ADDKE7 (Transform Types 6..12) of the selected proposal
 * in Transform Type order and record one round per type whose chosen
 * Transform ID is not NONE (0):
 *
 *   - "If the responder selects NONE for some ADDKE Transform Types ...
 *     then any corresponding additional key exchanges MUST NOT take
 *     place" -- NONE is not a round.
 *   - "the responder's choice MUST NOT contain duplicated algorithms
 *     (those with an identical Transform ID and attributes), except for
 *     the Transform ID of NONE" -- a repeated Transform ID is reported
 *     as an error so the responder refuses (NO_PROPOSAL_CHOSEN) and the
 *     initiator treats the exchange as failed.  No ADDKE method in the
 *     IANA registry defines transform attributes, so equal IDs are equal
 *     algorithms.
 *
 * methods[] receives up to IKEV2_ADDKE_MAX_ROUNDS entries; *nrounds the
 * number of real rounds; *offered (optional) whether any ADDKE type was
 * present at all, NONE included.  Returns 0, or -1 on a duplicated
 * choice (methods/nrounds then describe the rounds up to the duplicate
 * and must not be used).
 */
int
ikev2_addke_collect_rounds(struct prop_pair *proposal,
			   unsigned int *methods, int *nrounds, int *offered)
{
	int type, n = 0, i;

	*nrounds = 0;
	if (offered)
		*offered = 0;
	for (i = 0; i < IKEV2_ADDKE_MAX_ROUNDS; ++i)
		methods[i] = 0;
	if (proposal == NULL)
		return 0;
	for (type = IKEV2TRANSFORM_TYPE_ADDKE;
	     type < IKEV2TRANSFORM_TYPE_ADDKE + IKEV2_ADDKE_MAX_ROUNDS;
	     ++type) {
		struct prop_pair *p;

		for (p = proposal->tnext; p; p = p->next) {
			struct ikev2transform *t =
			    (struct ikev2transform *)p->trns;
			unsigned int id;

			if (t == NULL || t->transform_type != (unsigned)type)
				continue;
			/* first transform of this type is the choice */
			if (offered)
				*offered = 1;
			id = get_uint16(&t->transform_id);
			if (id == IKEV2TRANSF_ADDKE_NONE)
				break;
			for (i = 0; i < n; ++i) {
				if (methods[i] == id) {
					*nrounds = n;
					return -1;
				}
			}
			methods[n++] = id;
			break;
		}
	}
	*nrounds = n;
	return 0;
}

/*
 * Dense-slot helpers over the type-indexed negotiated ADDKE method list.
 *
 * addke_methods[] on a negotiated isakmpsa is keyed by TYPE (slot r =
 * transform type IKEV2TRANSFORM_TYPE_ADDKE + r); addke_nrounds is the
 * highest occupied slot + 1, so NONE (0) rounds leave exposed "gaps" in
 * the middle (e.g. an offer of ADDKE1=mlkem768, ADDKE2=NONE, ADDKE3=
 * mlkem1024 is {36, 0, 19} with addke_nrounds 3).  The wire emitter and
 * the storage are correct and iterate the slots, skipping 0; only the
 * ROUND-DRIVING consumers (which walk real rounds one at a time) must
 * collapse the array to its non-NONE entries.  These two helpers provide
 * that dense view: a dense round index counts the real (non-NONE) types,
 * and ikev2_addke_dense_slot() maps it back to the type slot (for
 * re-emitting a type-specific transform if ever needed) and its method.
 */

/* Number of real (non-NONE) additional key-exchange rounds described by a
 * type-indexed methods[0..nslots).  A NONE transform is not a round
 * (RFC 9370 s2.2.1), so it is not counted. */
int
ikev2_addke_dense_count(const unsigned int *methods, int nslots)
{
	int i, n = 0;

	for (i = 0; i < nslots; ++i)
		if (methods[i] != 0)
			++n;
	return n;
}

/* Map a DENSE round index (0-based over the real non-NONE rounds) to the
 * type-indexed slot that carries it.  On success returns 0 and, if non-NULL,
 * stores the type offset in *slot (transform_type == IKEV2TRANSFORM_TYPE_ADDKE
 * + *slot) and the method in *method.  Returns -1 when rounds is out of range
 * (fewer than rounds non-NONE slots); *slot/*method are then untouched. */
int
ikev2_addke_dense_slot(const unsigned int *methods, int nslots, int rounds,
		       int *slot, unsigned int *method)
{
	int i, n = 0;

	for (i = 0; i < nslots; ++i) {
		if (methods[i] == 0)
			continue;
		if (n == rounds) {
			if (slot)
				*slot = i;
			if (method)
				*method = methods[i];
			return 0;
		}
		++n;
	}
	return -1;
}
