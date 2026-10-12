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
 * Length-checked, constant-time comparison of peer-supplied crypto
 * material (IKEv1 HASH(n), ID echo, NAT-D, COOKIE2, RSA verify).
 * Idea from rdratlos/racoon-ipsec-tools 5339c11 (CRYPTO_memcmp for hash,
 * cookie, signature and NAT-D compares); the length check before compare
 * closes a short-HASH-payload over-read found in both trees.  No code
 * was copied.
 */
#include "config.h"

#include <sys/types.h>
#include <string.h>
#include <openssl/crypto.h>

#include <stdint.h>
#include <netinet/in.h>

#include "isakmp.h"
#include "hashcmp.h"

int
ike_ct_equal(const void *a, const void *b, size_t len)
{
	if (len == 0)
		return 1;
	return CRYPTO_memcmp(a, b, len) == 0;
}

int
ike_payload_body_cmp(const void *mine, size_t mine_len,
    const struct isakmp_gen *gen)
{
	size_t plen;

	if (gen == NULL)
		return -1;
	{
		const uint8_t *l = (const uint8_t *)&gen->len;

		plen = ((size_t)l[0] << 8) | l[1];
	}
	if (plen < sizeof(*gen) || plen - sizeof(*gen) != mine_len)
		return -1;
	return ike_ct_equal(mine, gen + 1, mine_len) ? 0 : 1;
}
