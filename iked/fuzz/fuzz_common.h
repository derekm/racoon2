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
/* shared set-up for the libFuzzer harnesses (iked/fuzz, --enable-fuzz) */
#ifndef __FUZZ_COMMON_H__
#define __FUZZ_COMMON_H__
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "rbuf.h"
#include "plog.h"
#include "test_util.h"

/* the globals and trace stubs main.o normally provides */
TEST_MAIN_STUBS()

static void
fuzz_init(const char *ident)
{
	if (rbuf_init(8, 80, 8, 1000, 5) != 0) {
		fprintf(stderr, "rbuf_init failed\n");
		abort();
	}
	/* NORMAL: protocol errors are logged, the per-payload DEBUG dumps
	 * (which would dominate the run time) are not */
	plog_setmode(RCT_LOGMODE_NORMAL, "/dev/null", ident, FALSE, FALSE);
}
#endif
