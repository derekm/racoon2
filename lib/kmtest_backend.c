/* Distinct automake object so kmtest does not share if_userspace.$(OBJEXT)
 * with libracoon.la (libtool vs non-libtool). */
#include "if_userspace.c"

/* same TU as the backend: let kmtest observe the live-SPI table */
int kmtest_live_spis(void);
int
kmtest_live_spis(void)
{
	return n_live_spi;
}
