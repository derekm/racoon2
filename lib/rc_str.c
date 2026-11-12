
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "racoon.h"

/*
 * rc_str.c - string concatenation and ${\...} / $[\...] macro expansion.
 *
 * == rc_strzcat contract ==
 * Appends srclen bytes of src onto the NUL-terminated buffer owned by
 * (*buf,*buflen), growing the buffer (via rc_realloc) whenever the current
 * capacity is insufficient, and updating *buflen to the new capacity.
 *   - src must be a NUL-terminated string; srclen is the number of source
 *     bytes used to size the destination (not the NUL terminator).
 *   - when *buflen != 0, *buf must name a valid owned NUL-terminated buffer
 *     that the caller will release.
 *   - an append input (src) must NOT alias the destination's *buf (strlcat
 *     overlapping-source and realloc-same-pointer are both undefined).
 * Success/failure contract: on success the caller owns a valid
 * NUL-terminated result with capacity *buflen; on allocation failure *buf
 * is left untouched and *buflen is NOT advanced to claim a capacity that
 * was not actually allocated.  When srclen == 0 and no buffer exists yet
 * (*buflen == 0) a real owned empty NUL-terminated buffer (capacity 1) is
 * established, so the caller always owns a valid empty string rather than
 * an uninitialized pointer.
 *
 * == rc_strex contract ==
 * Expands the special strings in src into a freshly allocated dst.
 * Return values (per the original header):
 *   -1 fatal error - typically no memory, OR the per-call expansion work /
 *      output-size budget (see RC_STREX_* below) was exceeded: a
 *      self/mutual reference or runaway growth terminates here instead of
 *      hanging or exhausting the allocator.  The budget is generous enough
 *      that any legitimate finite nested/cross-type expansion (including
 *      deep nesting and nested environment references) still succeeds.
 *   -2 src was invalid format (parenthesis mismatch).
 *   -3 string to be expanded was not defined.
 * The outer loop runs the ${...} pass to completion, THEN the $[...] pass:
 * $[...] output that introduces ${...} stays literal; ${...} output that
 * introduces $[...] is expanded by the subsequent pass; nested
 * $[A] -> $[B] chains resolve within the same pass.  (This asymmetry is
 * intentional and preserved here.)
 * On ANY failure *dst is left untouched; on success the caller owns a valid
 * NUL-terminated result (the expanded text, which is empty only if the
 * input was empty or expanded entirely to empty values).  A no-macro input
 * like "plain text" is returned unchanged.
 */

/*
 * Per-call expansion budgets (SX-04): bound the total number of macro
 * substitutions and the total size of accumulated output within a single
 * rc_strex() call, so a self/mutual reference or runaway growth returns -1
 * (fatal) instead of hanging or dying in the allocator.  A legitimate
 * finite expansion (even deeply nested / cross-type) needs nowhere near
 * these limits; an infinite cycle triples past them almost immediately.
 */
#define RC_STREX_MAX_SUBST	100000	/* max ${...}/$[...] substitutions/call */
#define RC_STREX_MAX_OUT	(1 << 20) /* max bytes of accumulated output */

/*
 * Reason a getval() callback returned NULL, so rc_strex() can tell "fatal /
 * out of memory" apart from "name not defined":
 *   0 = success (or no failure recorded),
 *  -1 = allocation failure inside the getter (fatal),
 *  -3 = the requested name/symbol is genuinely undefined.
 * It is config-time state: rc_strex() is not re-entered from within a
 * getter (getters never expand again), and configuration parsing is
 * single-threaded, so a file-scope flag is safe.
 */
static int strex_getval_err = 0;

static char *strex_setval(char *, size_t);
static char *strex_env(char *, size_t);

struct strex_t {
	const char *begin;
	const char *end;
	char *(*getval)(char *, size_t);
} strex[] = {
	{ "${", "}", strex_setval, },
	{ "$[", "]", strex_env, },
};

/*
 * it will stringwise concatinate src to *buf like strcat(3).
 * the difference is that it will reallocate the buffer
 * when the size of the buffer is not enough for the result.
 * new size will be set to *buflen.  srclen is the size of the string
 * to be copied, then it will append a NULL at the end of the result.
 */
int
rc_strzcat(char **buf, size_t *buflen, char *src, size_t srclen)
{
	char *new;
	size_t dstlen;

	/*
	 * srclen == 0: append nothing, but the caller must still own a valid
	 * NUL-terminated empty result (never an uninitialized pointer / stale
	 * length).  If a buffer already exists, leave it; otherwise establish
	 * a valid owned empty string so a getter for an empty VALUE can
	 * return a well-formed "" rather than garbage.  An empty NAME is not
	 * given a value here - the getters reject it (e.g. getenv("") is NULL
	 * and maps to -3 undefined) at rc_strex.
	 */
	if (srclen == 0) {
		if (*buflen == 0) {
			/* *buf is not trustworthy when *buflen == 0 - the caller
			 * may have passed an uninitialized pointer (e.g. an empty
			 * ${...} or $[...] name); null it so rc_realloc allocates
			 * fresh instead of relocating garbage (SX review). */
			*buf = NULL;
			if ((new = rc_realloc(*buf, 1)) == NULL)
				return -1;
			new[0] = '\0';
			*buf = new;
			*buflen = 1;
		}
		return 0;
	}

	/* if *buflen == 0, then it will allocate a memory against *src. */
	if (*buflen == 0) {
		*buf = NULL;	/* make sure *buf */
		dstlen = 0;
	} else
		dstlen = strlen(*buf);

	/* overflow guard on dstlen += srclen (SX-01) */
	if (srclen > SIZE_MAX - dstlen)
		return -1;
	dstlen += srclen;
	if (dstlen == SIZE_MAX)	/* dstlen + 1 would wrap */
		return -1;

	if (dstlen + 1 > *buflen) {
		/* buflen is only changed when a new buffer is actually
		 * allocated; move the update to AFTER the successful
		 * rc_realloc so *buflen never claims a capacity that does
		 * not exist (SX-01). */
		if ((new = rc_realloc(*buf, dstlen + 1)) == NULL)
			return -1;
		if (*buf == NULL)
			new[0] = '\0';	/* initialize */
		*buf = new;
		*buflen = dstlen + 1;
	}

	strlcat(*buf, src, *buflen);
	(*buf)[dstlen] = '\0';

	return 0;
}

static char *
strex_setval(char *str, size_t len)
{
	extern struct rcf_setval *rcf_setval_head;
	struct rcf_setval *n;
	char *buf = NULL;
	size_t buflen = 0;

	for (n = rcf_setval_head; n; n = n->next) {
		if (strncmp(n->sym->v, str, len) == 0 && n->sym->l == len) {
			if (rc_strzcat(&buf, &buflen, n->val->v, n->val->l)) {
				strex_getval_err = -1;
				return NULL;
			}
			strex_getval_err = 0;
			return buf;
		}
	}

	/* name not defined (empty name included, unless an empty-symbol
	 * setval matched above) */
	strex_getval_err = -3;
	return NULL;
}

static char *
strex_env(char *str, size_t len)
{
	char *res;
	/* defense-in-depth: init so getenv(buf) is safe even if rc_strzcat
	 * ever fails to populate an empty result */
	char *buf = NULL;
	size_t buflen = 0;

	if (rc_strzcat(&buf, &buflen, str, len)) {
		strex_getval_err = -1;
		return NULL;
	}
	res = getenv(buf);
	rc_free(buf);
	if (res == NULL) {
		strex_getval_err = -3;
		return NULL;
	}
	buflen = 0;
	buf = NULL;
	if (rc_strzcat(&buf, &buflen, res, strlen(res))) {
		strex_getval_err = -1;
		return NULL;
	}

	strex_getval_err = 0;
	return buf;
}

/*
 * it expands the special strings in src, allocates a memory for dst,
 * and stores it to dst.  the processing of the special strings are
 * defined by struct strex[].
 *
 * return value:
 *   -1: fatal error.  typically no memory, or the expansion budget
 *       (RC_STREX_MAX_SUBST / RC_STREX_MAX_OUT) was exceeded.
 *   -2: src was invalid format.  i.e. parenthesis mismatching.
 *   -3: string to be expanded was not defined.
 */
int
rc_strex(char *src, char **dst)
{
	char *mid, *res;
	char *vs, *ve, *vv;
	size_t reslen;
	struct strex_t *st;
	size_t i;
	unsigned long nsub = 0;	/* macro substitutions performed (SX-04) */
	size_t outtotal = 0;	/* total bytes of accumulated output (SX-04) */

	if ((mid = strdup(src)) == NULL)
		return -1;
	strex_getval_err = 0;

	for (i = 0; i < sizeof(strex)/sizeof(strex[0]); i++) {
		st = &strex[i];
		for (;;) {
			res = NULL;
			reslen = 0;
			vs = ve = mid;
			while ((ve = strstr(vs, st->begin)) != NULL) {
				/* copy the prepended data */
				if (ve - vs != 0 &&
				    rc_strzcat(&res, &reslen, vs,
					(size_t)(ve - vs))) {
					rc_free(res);
					rc_free(mid);
					return -1;
				}
				vs = ve + strlen(st->begin);
				if ((ve = strstr(vs, st->end)) == NULL) {
					rc_free(res);
					rc_free(mid);
					return -2;	/* invalid format */
				}
				/* expansion work budget (SX-04): a self/mutual
				 * reference or runaway substitution count
				 * terminates here instead of spinning. */
				if (++nsub > RC_STREX_MAX_SUBST) {
					rc_free(res);
					rc_free(mid);
					return -1;
				}
				/* copy the expanded data */
				if ((vv = (st->getval)(vs,
					(size_t)(ve - vs))) == NULL) {
					int err = strex_getval_err;
					strex_getval_err = 0;
					rc_free(res);
					rc_free(mid);
					if (err == -1)
						return -1; /* fatal / OOM */
					return -3; /* string not defined */
				}
				/* copy the appended data */
				if (rc_strzcat(&res, &reslen, vv, strlen(vv))) {
					rc_free(vv);
					rc_free(res);
					rc_free(mid);
					return -1;
				}
				outtotal += strlen(vv);
				/* output-size budget (SX-04) */
				if (outtotal > RC_STREX_MAX_OUT) {
					rc_free(vv);
					rc_free(res);
					rc_free(mid);
					return -1;
				}
				rc_free(vv);
				vs = ve + strlen(st->end);
			}
			if (vs == mid && ve == NULL) {
				/* nothing to be done */
				res = mid;
				break;
			}
			/* copy the rest */
			if (rc_strzcat(&res, &reslen, vs,
			    strlen(mid) - (vs - mid))) {
				rc_free(res);
				rc_free(mid);
				return -1;
			}
			outtotal += strlen(mid) - (vs - mid);
			if (outtotal > RC_STREX_MAX_OUT) {
				rc_free(res);
				rc_free(mid);
				return -1;
			}
			rc_free(mid);
			mid = res;
		}
	}

	*dst = res;

	return 0;
}
