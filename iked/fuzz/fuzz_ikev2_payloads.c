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
 * libFuzzer harness: IKEv2 payload-chain validation, the first parser an
 * unauthenticated datagram reaches (ikev2_check_payloads: header length,
 * payload lengths, NONCE/NOTIFY/DELETE/TS/CONFIG/SKF bodies).
 * First input byte: bit0 = before_decrypt, bit1 = keep the header length
 * field as given (else it is patched to the real length, so the walk is
 * reached instead of the cheap length-mismatch exit).
 */
#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>

#include "racoon.h"
#include "var.h"
#include "plog.h"
#include "sockmisc.h"
#include "isakmp.h"
#include "ikev2.h"
#include "isakmp_impl.h"
#include "ikev2_impl.h"
#include "fuzz_common.h"

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_init("fuzz_ikev2_payloads");
	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	rc_vchar_t *pkt;
	uint8_t flags;

	if (size < 1 || size > 65536)
		return 0;
	flags = data[0];
	data++; size--;
	pkt = rc_vmalloc(size);
	if (pkt == NULL)
		return 0;
	memcpy(pkt->v, data, size);
	if (!(flags & 2) && size >= sizeof(struct ikev2_header))
		put_uint32(&((struct ikev2_header *)pkt->v)->length, (uint32_t)size);
	(void)ikev2_check_payloads(pkt, flags & 1);
	rc_vfree(pkt);
	return 0;
}
