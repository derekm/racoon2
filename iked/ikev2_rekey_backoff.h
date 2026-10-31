/*
 * Bounded backoff for a Child SA rekey the peer rejected (e.g.
 * NO_PROPOSAL_CHOSEN, RFC 7296 s1.3.3/s2.8).  The old Child SA stays in
 * use until its hard lifetime; a fresh soft EXPIRE from the kernel (one
 * per SA direction) must not start another identical CREATE_CHILD_SA at
 * once.  Retries are timer-driven: 30, 60, 120, 240, 240 ... seconds.
 */
#ifndef IKEV2_REKEY_BACKOFF_H
#define IKEV2_REKEY_BACKOFF_H

#include <time.h>

#define IKEV2_REKEY_BACKOFF_BASE	30
#define IKEV2_REKEY_BACKOFF_MAX		240

time_t ikev2_rekey_backoff_delay(unsigned int failures);
time_t ikev2_rekey_note_failure(unsigned int *failures, time_t *not_before,
    time_t now);
int ikev2_rekey_deferred(time_t not_before, time_t now);

#endif
