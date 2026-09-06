/* Distinct automake object so kmtest does not share if_userspace.$(OBJEXT)
 * with libracoon.la (libtool vs non-libtool). */
#include "if_userspace.c"
