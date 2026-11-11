/*	$KAME: vmbuf.c,v 1.11 2001/11/26 16:54:29 sakane Exp $	*/

/*
 * Copyright (C) 2004 WIDE Project.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "rc_malloc.h"
#include "vmbuf.h"
#include "rbuf.h"

rc_vchar_t *
rc_vmalloc(size_t size)
{
	rc_vchar_t *var;
	caddr_t v;

	if ((var = (rc_vchar_t *)rc_malloc(sizeof(*var))) == NULL)
		return NULL;

	var->l = size;
	if (size == 0) {
		/* A zero-length buffer is a VALID empty vmbuf (l == 0).
		 * Guarantee a non-NULL v slot regardless of how the libc
		 * allocator treats a 0-size request (glibc is non-NULL, but
		 * other allocators may return NULL). */
		v = (caddr_t)rc_calloc(1, 1);
		if (v == NULL) {
			rc_free(var);
			return NULL;
		}
		var->v = v;
		return var;
	}
	var->v = (caddr_t)rc_calloc(1, size);
	if (var->v == NULL) {
		rc_free(var);
		return NULL;
	}

	return var;
}

/*
 * Resizes vmbuf.
 * If ptr is not NULL, ptr->v will be reallocated.  ptr itself is not reallocated.
 * If ptr is NULL, it is equivalent to rc_vmalloc(size).
 *
 * Returns ptr if ptr was not NULL.  If ptr was NULL, returns new vmbuf.
 * If reallocate fails, ptr does not change, and returns NULL
 */
rc_vchar_t *
rc_vrealloc(rc_vchar_t *ptr, size_t size)
{
	caddr_t v;

	if (ptr != NULL) {
		if (size == 0) {
			/* Valid shrink to an empty (l == 0) vmbuf, returned
			 * non-NULL.  Do NOT relay realloc(p, 0): its result is
			 * implementation-defined (glibc frees p and may return
			 * NULL, which we must not mistake for OOM), and we must
			 * not free the bytes twice.  Establish the non-NULL
			 * 1-byte empty slot BEFORE releasing the old bytes so
			 * that on allocation failure ptr is left unchanged and
			 * its original bytes intact (the failure contract
			 * below: "If reallocate fails, ptr does not change"). */
			if ((v = (caddr_t)rc_calloc(1, 1)) == NULL)
				return NULL;	/* ptr unchanged, original intact */
			if (ptr->v)
				rc_free(ptr->v);
			ptr->v = v;
			ptr->l = 0;
			return ptr;
		}
		if ((v = (caddr_t)rc_realloc(ptr->v, size)) == NULL)
			return NULL;
		if (size > ptr->l)
			memset(v + ptr->l, 0, size - ptr->l);
		ptr->v = v;
		ptr->l = size;
	} else {
		if ((ptr = rc_vmalloc(size)) == NULL)
			return NULL;
	}

	return ptr;
}

/*
 * Resizes vmbuf.
 * If ptr is not NULL, ptr->v will be reallocated.  ptr itself is not reallocated.
 * If ptr is NULL, it is equivalent to rc_vmalloc(size).
 *
 * Returns ptr if ptr was not NULL.  If ptr was NULL, returns new vmbuf.
 * if reallocate fails, ptr is deallocated using rc_vfree(), then returns NULL
 */
rc_vchar_t *
rc_vreallocf(rc_vchar_t *ptr, size_t size)
{
	caddr_t v;

	if (ptr != NULL) {
		if (size == 0) {
			/* Valid shrink to an empty (l == 0) vmbuf: consume the
			 * old bytes once and return ptr non-NULL.  Never relay
			 * realloc(p, 0) — glibc frees p and may return NULL,
			 * which would lead us to rc_vfree() the already-freed
			 * bytes (double free).  Establish the non-NULL 1-byte
			 * empty slot FIRST, so that on allocation failure we
			 * still consume the original (the contract below:
			 * "if reallocate fails, ptr is deallocated"). */
			if ((v = (caddr_t)rc_calloc(1, 1)) == NULL) {
				rc_vfree(ptr);	/* consumes the original on OOM */
				return NULL;
			}
			if (ptr->v)
				rc_free(ptr->v);
			ptr->v = v;
			ptr->l = 0;
			return ptr;
		}
		if ((v = (caddr_t)rc_realloc(ptr->v, size)) == NULL) {
			rc_vfree(ptr);	/* consumes the original on OOM */
			return NULL;
		}
		if (size > ptr->l)
			memset(v + ptr->l, 0, size - ptr->l);
		ptr->v = v;
		ptr->l = size;
	} else {
		if ((ptr = rc_vmalloc(size)) == NULL)
			return NULL;
	}

	return ptr;
}

void
rc_vfree(rc_vchar_t *var)
{
	if (var == NULL)
		return;

	if (var->v)
		rc_free(var->v);

	rc_free(var);

	return;
}

/*
 * Zeroing and free.
 */
void
rc_vfreez(rc_vchar_t *var)
{
	if (var == NULL)
		return;

	if (var->v) {
		/* Always cleanse key material, debug builds included (L3):
		 * a -DDEBUG build must not leave secret bytes in freed heap
		 * beyond the first scratch use. */
		memset(var->v, 0, var->l);
		rc_free(var->v);
	}

	/* note: rc_vfreez is by-value and CANNOT null the caller's pointer;
	 * callers that keep the reference after freeing must null it
	 * themselves (callers null it themselves, e.g. ikev2_cleanse_key_gen). */
	var->v = NULL;
	var->l = 0;
	rc_free(var);

	return;
}

/*
 * Rinse a vmbuf's contents with a non-elidable wipe so that secret bytes
 * (e.g. an rc_vmem2str'd privkey / psk / radius-secret) cannot persist in
 * memory that will be reused — the rbuf scratch ring reuses slots via
 * rc_vfree (rbuf.c).  A plain memset(0) may be optimized away for a buffer
 * that is about to be freed, so the wipe writes through a volatile pointer
 * the compiler cannot elide (portable fallback for explicit_bzero).
 */
void
vmbuf_cleanse(rc_vchar_t *var)
{
	volatile unsigned char *p;
	size_t i;

	if (var == NULL || var->v == NULL || var->l == 0)
		return;
	p = (volatile unsigned char *)var->v;
	for (i = 0; i < var->l; i++)
		p[i] = 0;
}

rc_vchar_t *
rc_vdup(const rc_vchar_t *src)
{
	rc_vchar_t *new;

	if ((new = rc_vmalloc(src->l)) == NULL)
		return NULL;

	memcpy(new->v, src->v, src->l);

	return new;
}

int
rc_vmemcmp(const rc_vchar_t *s1, const rc_vchar_t *s2)
{
	unsigned char *p1, *p2;
	size_t n;

	n = s1->l < s2->l ? s1->l : s2->l;
	if (n != 0) {
		p1 = (unsigned char *)s1->v;
		p2 = (unsigned char *)s2->v;
		do {
			if (*p1++ != *p2++)
				return (*--p1 - *--p2);
		} while (--n != 0);
	}
	if (s1->l > s2->l)
		return 1;
	if (s1->l < s2->l)
		return -1;
	return 0;
}

/*
 * assumed that "src" must be a printable string.
 */
const char *
rc_vmem2str(const rc_vchar_t *src)
{
	rc_vchar_t *buf;

	/* The +1 for the NUL terminator must not wrap past SIZE_MAX
	 * (src->l == SIZE_MAX would wrap to 0). */
	if (src->l == (size_t)-1)
		return NULL;
	buf = rbuf_getvb(1 + src->l);
	/* The scratch allocation can fail: return NULL instead of
	 * dereferencing a NULL buffer (VB-05). */
	if (buf == NULL)
		return NULL;
	memcpy(buf->v, src->v, src->l);
	buf->s[src->l] = '\0';

	return buf->v;
}

/*
 * copy a null terminated string to a allocated vmbuf.
 */
rc_vchar_t *
rc_str2vmem(const char *src)
{
	rc_vchar_t *dst;
	size_t len;

	len = strlen(src);
	if ((dst = rc_vmalloc(len)) == NULL)
		return NULL;
	memcpy(dst->v, src, len);

	return dst;
}

rc_vchar_t *
rc_vnew(const void *ptr, size_t len)
{
	rc_vchar_t	* buf;

	buf = rc_vmalloc(len);
	if (buf == NULL)
		return NULL;

	memcpy(buf->v, ptr, len);
	return buf;
}

rc_vchar_t *
rc_vprepend(const rc_vchar_t *buf, const void * ptr, size_t len)
{
	rc_vchar_t	* newv;
	size_t orig_l;

	if (buf == NULL)
		return NULL;
	orig_l = buf->l;
	/* Reject a length add that would wrap past SIZE_MAX, before the
	 * allocation/copy; the original buffer is left untouched. */
	if (len > (size_t)-1 - orig_l)
		return NULL;
	newv = rc_vmalloc(orig_l + len);
	if (newv == NULL)
		return NULL;
	memcpy(newv->v, ptr, len);
	memcpy(newv->u + len, buf->v, buf->l);
	return newv;
}

/*
 * concat data to dest vmbuf
 * resizes dest, then copies data to tail of buf
 * returns new dest if success
 * if fail, dest does not change, and returns 0
 *
 * NOTE (VB-04): `data` must not alias, or point into, `dest->v`.  As a
 * defensive guard for a future compliant-but-overlapping slice caller, if
 * `data` does lie within dest->v we snapshot it to a temp BEFORE the
 * relocating rc_vrealloc (which may move dest->v and invalidate `data`),
 * then copy from the snapshot; otherwise a memmove is used for the copy.
 * Normal non-alias output is unchanged: dest followed by data.
 */
rc_vchar_t *
rc_vconcat(rc_vchar_t *dest, const void *data, size_t len)
{
	size_t orig_l;
	int overlap;
	rc_vchar_t *snap;

	orig_l = dest->l;
	/* Reject a length add that would wrap past SIZE_MAX, before the
	 * relocating rc_vrealloc; dest is left untouched. */
	if (len > (size_t)-1 - orig_l)
		return 0;

	overlap = ((const char *)data >= (const char *)dest->v &&
		   (const char *)data < (const char *)dest->v + orig_l);
	if (overlap) {
		snap = rc_vnew(data, len);
		if (snap == NULL)
			return NULL;
		dest = rc_vrealloc(dest, orig_l + len);
		if (!dest) {
			rc_vfree(snap);
			return 0;
		}
		memcpy(dest->u + orig_l, snap->v, len);
		rc_vfree(snap);
	} else {
		dest = rc_vrealloc(dest, orig_l + len);
		if (! dest)
			return 0;
		memmove(dest->u + orig_l, data, len);
	}
	return dest;
}

