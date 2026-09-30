/* $Id$ */
/*
 * IKEv2 Configuration payload attribute walker unit test (same shape
 * as fragtest: check_PROGRAM, TAP-style printf + exit status).
 *
 * Exercises ikev2cfg_attr_len() — the single bounds-clamped advance
 * shared by every CFG attribute walker in ikev2_config.c (the
 * reviewer P2: the three walkers historically advanced with bare
 * `bytes -= TOTALLENGTH(attr)` guarded only by an assert() that
 * compiles out under -DNDEBUG, so a peer-controlled length field
 * underflowed size_t and walked OOB).  The test drives the helper with
 * the daemon's exact loop shape:
 *
 *     for (; bytes > 0 && (adv = ikev2cfg_attr_len(attr, bytes)) > 0;
 *          bytes -= adv, attr = IKEV2CFG_ATTR_NEXT(attr))
 *
 * proving malformed/truncated payloads stop the walk cleanly and never
 * read past the end.
 *
 * The struct (ikev2.h) and macros are provided by ikev2cfg_walk.c,
 * which is linked into this test; get_uint16/put_uint16 are stubbed
 * here like fragtest.c does (they normally come from isakmp.o).
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isakmp.h"
#include "ikev2.h"
#include "ikev2cfg_walk.h"

uint16_t
get_uint16(const void *ptr)
{
	const uint8_t *p = ptr;

	return ((uint16_t)p[0] << 8)
		+ ((uint16_t)p[1] << 0);
}

void
put_uint16(void *ptr, uint32_t value)
{
	uint8_t *p = ptr;

	p[0] = (value >> 8) & 0xff;
	p[1] = (value >> 0) & 0xff;
}

static int failed = 0;

#define CHECK(cond_)							\
	do {								\
		if (cond_)						\
			printf("ok   - %s\n", #cond_);		\
		else {							\
			printf("FAIL - %s (line %d)\n", #cond_, __LINE__); \
			failed = 1;					\
		}							\
	} while (0)

/* build an attribute chain in a caller buffer; returns bytes used */
static size_t
build_attr(uint8_t *buf, uint16_t type, uint16_t len)
{
	put_uint16(buf, type);
	put_uint16(buf + 2, len);
	memset(buf + 4, 0x5a, len);
	return (size_t)4 + len;
}

/* walk a chain with the daemon's exact loop shape; returns attrs consumed
 * and sets *finalbytes to bytes remaining after the loop */
static size_t
walk_chain(const uint8_t *buf, size_t buflen, size_t *finalbytes)
{
	struct ikev2cfg_attrib *attr = (struct ikev2cfg_attrib *)(uintptr_t)buf;
	size_t bytes = buflen;
	size_t adv = 0;
	size_t n = 0;

	for (; bytes > 0 && (adv = ikev2cfg_attr_len(attr, bytes)) > 0;
	     bytes -= adv, attr = IKEV2CFG_ATTR_NEXT(attr))
		n++;

	if (finalbytes)
		*finalbytes = bytes;
	return n;
}

int
main(void)
{
	uint8_t		buf[4096];
	size_t		used;
	size_t		bytes_after;
	size_t		n;

	memset(buf, 0, sizeof(buf));	/* silence FALSE maybe-uninitialized:
					 * walk_chain(buf, 0) never derefs */

	printf("# ikev2cfg_attr_len unit test\n");

	/* 1. empty payload: nothing to walk */
	n = walk_chain(buf, 0, &bytes_after);
	CHECK(n == 0);
	CHECK(bytes_after == 0);

	/* 2. truncated header (1-3 bytes remain): walker must stop */
	n = walk_chain(buf, 1, &bytes_after);
	CHECK(n == 0);
	CHECK(bytes_after == 1);
	n = walk_chain(buf, 3, &bytes_after);
	CHECK(n == 0);
	CHECK(bytes_after == 3);

	/* 3. single well-formed attribute (type 1, value len 4) */
	used = build_attr(buf, 1, 4);
	n = walk_chain(buf, used, &bytes_after);
	CHECK(n == 1);
	CHECK(bytes_after == 0);

	/* 4. zero-length value attribute (charon CPRQ: type 1, len 0) */
	used = build_attr(buf, 1, 0);
	n = walk_chain(buf, used, &bytes_after);
	CHECK(n == 1);
	CHECK(bytes_after == 0);

	/* 5. length field overruns remaining payload (the underflow class) */
	/* write only the 4-byte header — do not extend past the buffer */
	put_uint16(buf, 1);
	put_uint16(buf + 2, 0xFFFF);
	n = walk_chain(buf, 6, &bytes_after);	/* header says 65539, 6 remain */
	CHECK(n == 0);
	CHECK(bytes_after == 6);	/* must NOT have wrapped to huge */

	/* 6. value length extends just past the payload */
	used = build_attr(buf, 3, 16);
	n = walk_chain(buf, used - 1, &bytes_after); /* 19 of 20 remain */
	CHECK(n == 0);
	CHECK(bytes_after == 19);

	/* 7. two valid attrs then a truncated tail: walks 2, stops clean */
	used = 0;
	used += build_attr(buf + used, 1, 4);
	used += build_attr(buf + used, 3, 2);
	used += 2;			/* +2 garbage: truncated next header */
	n = walk_chain(buf, used, &bytes_after);
	CHECK(n == 2);
	CHECK(bytes_after == 2);	/* the 2 garbage bytes stop the walk */

	/* 8. exact-fit tail: last attribute consumes the final bytes */
	used = 0;
	used += build_attr(buf, 1, 4);
	n = walk_chain(buf, used, &bytes_after);
	CHECK(n == 1);
	CHECK(bytes_after == 0);

	/* 9. fuzz: walker never reads past the payload on any input */
	{
		size_t	i;
		for (i = 0; i < sizeof(buf); i++)
			buf[i] = (uint8_t)(i * 7 + 13);

		for (i = 0; i < 64; i++) {
			const size_t sz = i;
			struct ikev2cfg_attrib *attr =
			    (struct ikev2cfg_attrib *)(uintptr_t)buf;
			size_t bytes = sz;
			size_t adv = 0;
			unsigned int iters = 0;

			for (; bytes > 0 &&
			       (adv = ikev2cfg_attr_len(attr, bytes)) > 0;
			     bytes -= adv,
			       attr = IKEV2CFG_ATTR_NEXT(attr)) {
				/* consumed attr must stay in-bounds */
				CHECK((const uint8_t *)(void *)attr >= buf &&
				      (size_t)((const uint8_t *)(void *)attr - buf) < sz);
				CHECK(adv >= 4);
				CHECK(adv <= sz);
				if (++iters > 4096)
					break;	/* runaway guard */
			}
			CHECK(iters <= 4096);
		}
	}

	printf("# %s\n", failed ? "FAILED" : "all green");
	return failed ? 1 : 0;
}
