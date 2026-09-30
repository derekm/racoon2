/*
 * $Id$
 *
 * Bounds-checked walk over the IKEv2 Configuration payload attribute
 * chain (RFC 7296 s3.15.1).  Shared by every CFG attribute walker so
 * the advance logic lives in one place and is unit-testable (reviewer
 * P2: the three walkers in ikev2_config.c previously advanced with
 * bare `bytes -= TOTALLENGTH(attr)` guarded only by an assert() that
 * compiles out under -DNDEBUG, so a peer length could underflow the
 * size_t and walk OOB).
 */

#ifndef IKEV2CFG_WALK_H_
#define IKEV2CFG_WALK_H_

#include <sys/types.h>

struct ikev2cfg_attrib;

/*
 * Return the total wire length (header + value) of the attribute at
 * *attr provided it fits wholly within *bytes, else 0.  Use it in the
 * walk condition and consume a non-zero return in the stride so the
 * walker only advances over an in-bounds attribute; 0 means stop.
 */
size_t ikev2cfg_attr_len(const struct ikev2cfg_attrib *attr, size_t bytes);

#endif /* IKEV2CFG_WALK_H_ */
