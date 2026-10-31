/* See ikev2_rekey_backoff.h. */
#include "ikev2_rekey_backoff.h"

time_t
ikev2_rekey_backoff_delay(unsigned int failures)
{
	time_t d = IKEV2_REKEY_BACKOFF_BASE;

	while (failures > 1 && d < IKEV2_REKEY_BACKOFF_MAX) {
		d *= 2;
		failures--;
	}
	return d > IKEV2_REKEY_BACKOFF_MAX ? IKEV2_REKEY_BACKOFF_MAX : d;
}

/* Record one rejected rekey; returns the delay before the next attempt. */
time_t
ikev2_rekey_note_failure(unsigned int *failures, time_t *not_before,
    time_t now)
{
	time_t d;

	if (*failures < 1000)
		(*failures)++;
	d = ikev2_rekey_backoff_delay(*failures);
	*not_before = now + d;
	return d;
}

/* Nonzero: a soft EXPIRE now must not start a rekey (backoff pending). */
int
ikev2_rekey_deferred(time_t not_before, time_t now)
{
	return not_before != 0 && now < not_before;
}
