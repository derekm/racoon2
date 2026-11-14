#!/bin/sh
# Automake test wrapper for lib/sample: sample takes a config file as its
# argument, and the harness runs tests with none. The config path is
# injected by AM_TESTS_ENVIRONMENT (abs_top_srcdir so VPATH builds work).
#
# With ENABLE_SECURE the parser only opens a config file owned by the
# running uid (rc_safefile).  A checkout owned by another user (e.g. synced
# into a BSD VM and tested as root) would make 'sample' fail for a reason
# unrelated to the code under test, so parse a private copy owned by us.
conf=$(mktemp "${TMPDIR:-/tmp}/r2-sample.XXXXXX") || exit 99
if ! cat "$R2_SAMPLE_CONF" > "$conf"; then
	rm -f "$conf"
	exit 99
fi
"$1" "$conf"
rc=$?
rm -f "$conf"
exit $rc
