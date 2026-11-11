/*
 * vmbuf_test — unit (known-answer) test for the lib/vmbuf.c + lib/rbuf.c
 * hardening set (VB-01..VB-05).
 *
 * None of the helpers here require ADDKE; it links only vmbuf.o + rbuf.o
 * and drives the public rc_v* / rbuf_* API directly.  It is the in-tree
 * red-capable regression suite that previously did not exist: under the
 * UNFIXED code it fails/crashes on the wrap, zero-size and sign paths;
 * under the fixed code it is fully green.
 *
 * Coverage:
 *   VB-01 rc_vprepend / rc_vconcat / rc_vmem2str reject a length add that
 *         wraps past SIZE_MAX and leave the original unchanged; normal,
 *         empty and boundary inputs still succeed.
 *   VB-02 rc_vmalloc(0) = non-NULL empty (l == 0); rc_vrealloc(ptr,0)
 *         shrinks to a valid empty vmbuf without NULL/dangling; 
 *         rc_vreallocf(ptr,0) consumes the original bytes and yields a
 *         valid empty vmbuf (no glibc double free); positive->zero and
 *         zero->positive; realloc failure preserves the original for
 *         rc_vrealloc and consumes it for rc_vreallocf.
 *   VB-03 the scratch ring rinses a reused slot's prior (possibly secret)
 *         bytes via a non-elidable wipe (vmbuf_cleanse) + heavy slot
 *         reuse stays clean under the sanitizer.
 *   VB-04 rc_vconcat is safe for a compliant-but-overlapping slice caller
 *         (snapshot before the relocating rc_vrealloc / memmove) and keeps
 *         normal non-alias output equal to dest followed by data.
 *   VB-05 rc_vmemcmp keeps the correct ordering sign when the length
 *         difference exceeds INT_MAX, plus equal/unequal/empty; rc_vmem2str
 *         returns NULL (not a crash) when the scratch allocation fails.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/resource.h>

#include "vmbuf.h"
#include "rbuf.h"

static int nchecks = 0;
static int nfails = 0;

#define CHECK(cond)							\
	do {								\
		nchecks++;						\
		if (!(cond)) {						\
			printf("FAIL %s:%d: %s\n",			\
			    __FILE__, __LINE__, #cond);			\
			nfails++;					\
		}							\
	} while (0)

static void
check_bytes(const char *label, const rc_vchar_t *b, const void *expected, size_t n)
{
	if (b == NULL || b->l != n || memcmp(b->v, expected, n) != 0) {
		printf("FAIL %s:%d: %s (l=%lu want=%lu)\n",
		    __FILE__, __LINE__, label,
		    b ? (unsigned long)b->l : (unsigned long)-1,
		    (unsigned long)n);
		nfails++;
	}
	nchecks++;
}

/* ---------- VB-01 : wrap past SIZE_MAX must be rejected ---------- */

static void
test_prepend_rejects_wrap(void)
{
	static unsigned char dummy[16] = { 0 };
	rc_vchar_t buf;
	rc_vchar_t *r;

	buf.l = (size_t)-1 - 8;		/* near SIZE_MAX */
	buf.v = dummy;
	r = rc_vprepend(&buf, dummy, 16);	/* orig_l + 16 wraps */
	CHECK(r == NULL);
	CHECK(buf.l == (size_t)-1 - 8);
	CHECK(buf.v == dummy);
}

static void
test_concat_rejects_wrap(void)
{
	static unsigned char dummy[16] = { 0 };
	rc_vchar_t buf;
	rc_vchar_t *r;

	buf.l = (size_t)-1 - 8;
	buf.v = dummy;
	r = rc_vconcat(&buf, dummy, 16);
	CHECK(r == NULL);		/* reject, not a wrapping realloc */
	CHECK(buf.l == (size_t)-1 - 8);
	CHECK(buf.v == dummy);
}

static void
test_mem2str_rejects_wrap(void)
{
	static unsigned char dummy[8] = { 0 };
	rc_vchar_t src;

	src.l = (size_t)-1;		/* 1 + SIZE_MAX wraps to 0 */
	src.v = dummy;
	CHECK(rc_vmem2str(&src) == NULL);
}

static void
test_prepend_normal(void)
{
	static char out[32];
	rc_vchar_t buf;

	buf.l = 3; buf.v = (void *)"abc";
	rc_vchar_t *r = rc_vprepend(&buf, "XY", 2);
	CHECK(r != NULL);
	if (r) {
		memcpy(out, r->v, r->l);
		out[r->l] = 0;
		CHECK(r->l == 5);
		CHECK(strcmp(out, "XYabc") == 0);
		rc_vfree(r);
	}

	/* empty original still succeeds: prepend onto l == 0 */
	buf.l = 0; buf.v = (void *)"";
	r = rc_vprepend(&buf, "Z", 1);
	CHECK(r != NULL && r->l == 1);
	if (r) {
		memcpy(out, r->v, r->l);
		out[r->l] = 0;
		CHECK(strcmp(out, "Z") == 0);
		rc_vfree(r);
	}
}

static void
test_concat_normal(void)
{
	static char out[32];
	rc_vchar_t *b;

	/* normal non-alias output = dest followed by data */
	b = rc_vmalloc(3);
	CHECK(b != NULL);
	if (b) {
		memcpy(b->v, "abc", 3);
		b = rc_vconcat(b, "de", 2);
		CHECK(b != NULL && b->l == 5);
		if (b) {
			memcpy(out, b->v, b->l);
			out[b->l] = 0;
			CHECK(strcmp(out, "abcde") == 0);
		}
		rc_vfree(b);
	}

	/* boundary: concat onto an empty (l == 0) heap vmbuf still succeeds —
	 * an ordinary non-wrapping grow, not a mis-rejection of the wrap. */
	{
		rc_vchar_t *bb = rc_vmalloc(0);
		CHECK(bb != NULL);
		if (bb) {
			bb = rc_vconcat(bb, "xy", 2);
			CHECK(bb != NULL && bb->l == 2 &&
			    memcmp(bb->v, "xy", 2) == 0);
			rc_vfree(bb);
		}
	}
}

static void
test_mem2str_normal(void)
{
	static const char hello[] = "hello";
	const char *s;
	rc_vchar_t src;

	src.l = 5; src.v = (void *)hello;
	s = rc_vmem2str(&src);
	CHECK(s != NULL && strcmp(s, "hello") == 0);

	/* empty string still works */
	src.l = 0; src.v = (void *)"";
	s = rc_vmem2str(&src);
	CHECK(s != NULL && s[0] == '\0');
}

/* ---------- VB-04 : contained-overlap (aliasing) rc_vconcat ---------- */

static void
test_concat_overlap(void)
{
	char out[16];
	rc_vchar_t *b;

	/* data aliases dest->v (self-append): rc_vconcat must snapshot the
	 * source before the relocating rc_vrealloc, else a moved buffer
	 * leaves the self-slice pointing at freed memory (VB-04). */
	b = rc_vnew("abcdef", 6);
	CHECK(b != NULL);
	if (!b)
		return;
	b = rc_vconcat(b, (const char *)b->v, b->l);	/* data == dest->v */
	CHECK(b != NULL && b->l == 12);
	if (b) {
		memcpy(out, b->v, b->l);
		out[b->l] = 0;
		CHECK(strcmp(out, "abcdefabcdef") == 0);

		/* mid-buffer slice: data = dest->v + 3, len 3 */
		b = rc_vconcat(b, (const char *)b->v + 3, 3);
		CHECK(b != NULL && b->l == 15);
		if (b) {
			memcpy(out, b->v, b->l);
			out[b->l] = 0;
			CHECK(strncmp(out + 12, "def", 3) == 0);
		}
	}
	if (b)
		rc_vfree(b);
}

/* ---------- VB-02 : zero-size / empty-buffer semantics ---------- */

static void
test_vmalloc_zero(void)
{
	rc_vchar_t *b = rc_vmalloc(0);

	CHECK(b != NULL);
	if (b) {
		CHECK(b->l == 0);
		rc_vfree(b);
	}
}

static void
test_vrealloc_zero(void)
{
	rc_vchar_t *b = rc_vnew("abcdef", 6);
	rc_vchar_t *r;

	CHECK(b != NULL && b->l == 6);
	r = rc_vrealloc(b, 0);
	CHECK(r == b);			/* shrink to empty, NOT NULL */
	CHECK(r != NULL && r->l == 0);
	CHECK(r == NULL || r->v != NULL);	/* non-NULL empty slot */
	if (r)
		rc_vfree(r);

	/* zero -> positive */
	b = rc_vmalloc(0);
	r = rc_vrealloc(b, 8);
	CHECK(r != NULL && r->l == 8);
	if (r)
		rc_vfree(r);
}

static void
test_vreallocf_zero(void)
{
	rc_vchar_t *b = rc_vnew("abcdef", 6);

	/* must consume the original bytes and yield a valid empty vmbuf;
	 * UNFIXED code triggers a glibc "double free" abort here. */
	b = rc_vreallocf(b, 0);
	CHECK(b != NULL && b->l == 0);
	CHECK(b == NULL || b->v != NULL);	/* non-NULL empty slot */
	if (b)
		rc_vfree(b);
}

/* Below, the two realloc/scratch-failure tests force rc_malloc/rc_realloc
 * to fail by capping RLIMIT_AS.  That is fine for the plain build, but it
 * conflicts with ASan (which reserves a huge shadow address space), so the
 * sanitizer run injects -DVMBUF_TEST_NO_RLIMIT to skip them while still
 * covering the zero-size and cleanse paths that ASan is used to prove. */
#ifndef VMBUF_TEST_NO_RLIMIT

static void
test_realloc_failure_semantics(void)
{
	struct rlimit rl;
	rc_vchar_t *b;
	rc_vchar_t *r;
	void *origv;
	size_t orgl;

	/* Force rc_realloc (= realloc) to fail for a huge non-zero size by
	 * capping the address space.  rc_vrealloc must PRESERVE the
	 * original; rc_vreallocf must CONSUME (free) it. */
	rl.rlim_cur = rl.rlim_max = (1UL << 30);	/* 1 GiB AS cap */
	(void)setrlimit(RLIMIT_AS, &rl);

	b = rc_vnew("abcdef", 6);
	origv = b->v; orgl = b->l;
	r = rc_vrealloc(b, (1ULL << 40));	/* 1 TiB: realloc fails */
	CHECK(r == NULL);
	CHECK(b->v == origv);		/* preserved */
	CHECK(b->l == orgl);
	rc_vfree(b);

	b = rc_vnew("abcdef", 6);
	r = rc_vreallocf(b, (1ULL << 40));
	CHECK(r == NULL);		/* consumed; do not free b again */
}

#endif /* VMBUF_TEST_NO_RLIMIT */

/* ---------- VB-05 : rc_vmemcmp sign across INT_MAX ---------- */

static void
test_memcmp(void)
{
	static unsigned char a[128], b[128];
	const size_t BIG = (1ULL << 34);	/* 17 GiB: diff > INT_MAX */

	/* equal */
	memset(a, 'x', sizeof(a));
	memset(b, 'x', sizeof(b));
	rc_vchar_t s1, s2;
	s1.l = 64; s1.v = a;
	s2.l = 64; s2.v = a;
	CHECK(rc_vmemcmp(&s1, &s2) == 0);

	/* unequal in the common prefix */
	b[5] = 'y';			/* s2 > s1 at byte 5 */
	s1.l = 64; s1.v = a;
	s2.l = 64; s2.v = b;
	CHECK(rc_vmemcmp(&s1, &s2) < 0);
	CHECK(rc_vmemcmp(&s2, &s1) > 0);
	b[5] = 'x';

	/* empty */
	s1.l = 0; s1.v = a;
	s2.l = 0; s2.v = b;
	CHECK(rc_vmemcmp(&s1, &s2) == 0);
	s2.l = 5; s2.v = b;
	CHECK(rc_vmemcmp(&s1, &s2) < 0);	/* empty < non-empty */
	CHECK(rc_vmemcmp(&s2, &s1) > 0);

	/* equal common prefix, length difference > INT_MAX: the ordering
	 * sign must NOT wrap/negate (UNFIXED: (int)(l1-l2) wraps negative) */
	s1.l = BIG; s1.v = a;
	s2.l = 100; s2.v = a;
	CHECK(rc_vmemcmp(&s1, &s2) > 0);
	CHECK(rc_vmemcmp(&s2, &s1) < 0);
}

#ifndef VMBUF_TEST_NO_RLIMIT

static void
test_mem2str_oom(void)
{
	static unsigned char dummy[8] = { 0 };
	struct rlimit rl;
	rc_vchar_t src;
	const char *s;

	/* request a scratch bigger than the (capped) address space so
	 * rbuf_getvb -> rc_vmalloc fails; rc_vmem2str must return NULL
	 * and NOT dereference the NULL scratch (UNFIXED: SEGV). */
	src.l = (300ULL << 20);		/* 300 MB */
	src.v = dummy;
	rl.rlim_cur = rl.rlim_max = (256ULL << 20);	/* 256 MiB AS cap */
	(void)setrlimit(RLIMIT_AS, &rl);

	s = rc_vmem2str(&src);
	CHECK(s == NULL);
}

#endif /* VMBUF_TEST_NO_RLIMIT */

/* ---------- VB-03 : non-elidable rinse + scratch-slot reuse ---------- */

/* Linked with -Wl,--wrap=vmbuf_cleanse so every vmbuf_cleanse call in the
 * linked vmbuf.lo/rbuf.lo lands here and increments this counter.  The
 * scratch-reuse test asserts the counter advances when rbuf_getvb reuses a
 * ring slot, i.e. it FAILS if the rinse call site is ever deleted. */
static int s_cleanse_count;
void __real_vmbuf_cleanse(rc_vchar_t *);
void __wrap_vmbuf_cleanse(rc_vchar_t *v)
{
	s_cleanse_count++;
	__real_vmbuf_cleanse(v);
}

static void
test_cleanse(void)
{
	static const unsigned char pat[] = "S3CR3T-S3CR3T";
	rc_vchar_t *b = rc_vnew(pat, sizeof(pat) - 1);
	int allzero = 1, i;

	CHECK(b != NULL);
	if (!b)
		return;
	vmbuf_cleanse(b);
	for (i = 0; i < (int)b->l; i++)
		if (b->u[i] != 0)
			allzero = 0;
	CHECK(allzero);
	rc_vfree(b);
}

static void
test_scratch_reuse(void)
{
	static unsigned char payload[64];
	rc_vchar_t src;
	const char *s;
	int before, i;

	memset(payload, 0x5a, sizeof(payload));	/* stand-in "secret" */
	src.l = sizeof(payload);
	src.v = payload;
	/* warm all 8 ring slots (allocated lazily), so the next round of
	 * rbuf_getvb calls REUSES (and must rinse) prior slot bytes. */
	for (i = 0; i < 8; i++) {
		s = rc_vmem2str(&src);
		if (s == NULL) {
			CHECK(0);
			return;
		}
	}
	before = s_cleanse_count;
	/* rotate through the ring again: every reuse must rinse the prior
	 * (secret-like) bytes before freeing.  If rbuf_getvb ever stops
	 * calling vmbuf_cleanse, s_cleanse_count stops advancing -> FAIL. */
	for (i = 0; i < 16; i++) {
		s = rc_vmem2str(&src);
		if (s == NULL) {
			CHECK(0);
			return;
		}
	}
	CHECK(s_cleanse_count > before);
	CHECK(1);	/* 8-slot ring reused ~2x; no crash / double-free */
}

int
main(int ac, char **av)
{
	(void)ac; (void)av;

	/* initialize the scratch ring (vbuf slots allocated lazily) so
	 * rc_vmem2str can run; no addke/libracoon needed. */
	if (rbuf_init(0, 0, 0, 0, 8) == -1) {
		printf("FAIL: rbuf_init failed\n");
		return 1;
	}

	/* normal / empty / boundary first (RLIMIT_AS still unlimited) */
	test_mem2str_normal();
	test_prepend_normal();
	test_concat_normal();
	test_concat_overlap();
	test_memcmp();
	test_vmalloc_zero();
	test_vrealloc_zero();
	test_vreallocf_zero();
	test_cleanse();
	test_scratch_reuse();

	/* wrap-rejections (must see NULL, original untouched) */
	test_prepend_rejects_wrap();
	test_concat_rejects_wrap();
	test_mem2str_rejects_wrap();

	/* realloc-failure semantics + scratch-OOM (these lower RLIMIT_AS,
	 * so run them after the normal-input tests; skipped in the ASan
	 * build via VMBUF_TEST_NO_RLIMIT) */
#ifndef VMBUF_TEST_NO_RLIMIT
	test_mem2str_oom();
	test_realloc_failure_semantics();
#endif

	if (nfails) {
		printf("vmbuf_test: %d/%d checks FAILED\n", nfails, nchecks);
		return 1;
	}
	printf("vmbuf_test: ALL PASS (%d checks)\n", nchecks);
	return 0;
}
