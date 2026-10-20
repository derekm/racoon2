/*
 * Copyright (C) 2026 Derek P. Moore.
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
 * libFuzzer harness: IKEv1 (KAME/ipsec-tools) pre-authentication parsing.
 * isakmp_parse() walks the generic payload chain; every Vendor ID payload
 * then goes through check_vendorid() (the short-VID over-read fixed in
 * 4528ad9), every HASH payload through ike_payload_body_cmp() (the short
 * HASH over-read fixed in 060d321), and every SA payload through
 * get_proppair() (proposal/transform walk).  The ISAKMP header length is
 * patched to the input length unless bit0 of the first byte is set.
 */
#include "config.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "isakmp.h"
#include "isakmp_impl.h"
#include "isakmp_var.h"
#include "ikev1_impl.h"
#include "ikev1/ipsec_doi.h"
#include "oakley.h"
#include "sockmisc.h"
#include "handler.h"
#include "proposal.h"
#include "crypto_impl.h"
#include "hashcmp.h"
#include "vendorid.h"
#include "fuzz_common.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_init("fuzz_ikev1_parse");
	if (eay_init() != 0)
		abort();
	compute_vendorids();
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint8_t mine[32];
	rc_vchar_t *msg, *pl, *sa;
	struct isakmp_parse_t *p;
	uint8_t flags;

	if (size < 1 || size > 65536)
		return 0;
	flags = data[0];
	data++; size--;
	if (size < sizeof(struct isakmp))
		return 0;
	msg = rc_vmalloc(size);
	if (msg == NULL)
		return 0;
	memcpy(msg->v, data, size);
	if (!(flags & 1))
		put_uint32(&((struct isakmp *)msg->v)->len, (uint32_t)size);
	pl = isakmp_parse(msg);
	if (pl != NULL) {
		for (p = (struct isakmp_parse_t *)pl->v;
		     p->type != ISAKMP_NPTYPE_NONE; p++) {
			switch (p->type) {
			case ISAKMP_NPTYPE_VID:
				(void)check_vendorid(p->ptr);
				break;
			case ISAKMP_NPTYPE_HASH:
				(void)ike_payload_body_cmp(mine,
				    (flags >> 1) & 31, p->ptr);
				break;
			case ISAKMP_NPTYPE_SA:
				/* the payload alone, as ipsecdoi_checkph1proposal sees it */
				sa = rc_vmalloc(p->len);
				if (sa == NULL)
					break;
				memcpy(sa->v, p->ptr, p->len);
				{
					struct prop_pair **pair;

					pair = get_proppair(sa, IPSECDOI_TYPE_PH1);
					if (pair != NULL)
						free_proppair(pair);
				}
				rc_vfree(sa);
				break;
			}
		}
		rc_vfree(pl);
	}
	rc_vfree(msg);
	return 0;
}
