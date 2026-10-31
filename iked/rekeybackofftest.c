/* Unit test: bounded Child SA rekey backoff (ikev2_rekey_backoff.c). */
#include <stdio.h>
#include <stdlib.h>
#include "ikev2_rekey_backoff.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", \
	__FILE__, __LINE__, #c); fails++; } } while (0)

int
main(void)
{
	unsigned int n = 0;
	time_t nb = 0, now = 1000, d;

	CHECK(!ikev2_rekey_deferred(0, now));	/* never failed */
	CHECK(ikev2_rekey_backoff_delay(1) == 30);
	CHECK(ikev2_rekey_backoff_delay(2) == 60);
	CHECK(ikev2_rekey_backoff_delay(3) == 120);
	CHECK(ikev2_rekey_backoff_delay(4) == 240);
	CHECK(ikev2_rekey_backoff_delay(50) == 240);
	CHECK(ikev2_rekey_backoff_delay(~0u) == 240);

	/* the observed loop: rejection, then soft EXPIRE of the outbound SA
	 * 1 s later and of the inbound SA 2 s later; neither may rekey. */
	d = ikev2_rekey_note_failure(&n, &nb, now);
	CHECK(n == 1 && d == 30 && nb == now + 30);
	CHECK(ikev2_rekey_deferred(nb, now + 1));
	CHECK(ikev2_rekey_deferred(nb, now + 2));
	CHECK(ikev2_rekey_deferred(nb, now + 29));
	CHECK(!ikev2_rekey_deferred(nb, now + 30));	/* timer retry */
	d = ikev2_rekey_note_failure(&n, &nb, now + 30);
	CHECK(n == 2 && d == 60 && nb == now + 90);
	for (int i = 0; i < 2000; i++)
		d = ikev2_rekey_note_failure(&n, &nb, now);
	CHECK(d == 240 && n == 1000);
	if (fails)
		return 1;
	printf("rekeybackofftest: ok\n");
	return 0;
}
