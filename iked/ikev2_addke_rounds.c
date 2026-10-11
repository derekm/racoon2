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
