/*
 * bounds-checked IKEv2 Configuration payload attribute walker
 *
 * After the reviewer P2: the three CFG attribute walkers in
 * ikev2_config.c historically advanced with bare logic:
 *
 *     bytes -= IKEV2CFG_ATTR_TOTALLENGTH(attr),
 *     attr  = IKEV2CFG_ATTR_NEXT(attr)
 *
 * guarded only by an assert() (compiled out under -DNDEBUG).  A
 * peer-controlled attribute whose length field overruns the payload
 * underflows the size_t and walks out of bounds.  All walkers now
 * validate each attribute with this single helper before the advance
 * arithmetic runs: an attribute is consumed only when its header AND
 * its full T-L-V length fit within the remaining payload.
 */

#include <sys/types.h>
#include <stdint.h>

#include "isakmp.h"
#include "ikev2.h"

/* the IKEd TU normally gets this from isakmp_impl.h; declare it here so
 * the file also compiles standalone in cfgwalktest (where the test
 * provides the stub), matching fragtest's self-containment */
extern uint16_t get_uint16(const void *);

/*
 * Return the total wire length (4-byte header + value length) that a
 * well-formed attribute at *attr would occupy, provided it fits wholly
 * within the remaining *bytes of the payload; otherwise return 0.
 *
 * A caller uses this in the walk condition:
 *
 *     bytes > 0 && (adv = ikev2cfg_attr_len(attr, bytes)) > 0
 *
 * and advances with adv in the stride, so the pointer only moves when
 * the attribute was validated in-bounds.  A 0 return means the walker
 * MUST stop: only part of the header remains, or the declared value
 * length overruns the payload.
 */
size_t
ikev2cfg_attr_len(const struct ikev2cfg_attrib *attr, size_t bytes)
{
	size_t total;

	if (bytes < sizeof(struct ikev2cfg_attrib))
		return 0;

	total = IKEV2CFG_ATTR_TOTALLENGTH(attr);
	if (total > bytes)
		return 0;

	return total;
}
