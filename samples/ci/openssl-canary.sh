#!/bin/sh
# samples/ci/openssl-canary.sh [build-dir]
#
# OpenSSL deprecation canary.  Compiles iked sources with every deprecated
# OpenSSL API hidden (-DOPENSSL_NO_DEPRECATED, API compat pinned to 3.0) so
# code that would stop building on OpenSSL 4.0 is seen early.
#   - CLEAN list: files that already build this way; any regression there
#     FAILS (-Werror=deprecated-declarations, -Werror=implicit-function-
#     declaration).  Grow the list as files are cleaned; never shrink it.
#   - every other iked/lib .c file: count of errors/deprecation warnings,
#     reported as a tracker line ("CANARY backlog <file> <n>"), not gating.
# Run from a configured tree (config.h present).  OPENSSL_CFLAGS may point
# at another OpenSSL (e.g. -I/opt/openssl-master/include).
set -u
B=${1:-.}
cd "$B" || exit 2
CLEAN="iked/hashcmp.c iked/authenticator.c iked/ikev2_addke.c iked/ikev2_eap.c"
TOP=$(pwd)
FLAGS="-fsyntax-only -DHAVE_CONFIG_H -I$TOP -I$TOP/lib -I$TOP/iked -I$TOP/iked/ikev1 ${OPENSSL_CFLAGS:-} \
	-DOPENSSL_NO_DEPRECATED -DOPENSSL_API_COMPAT=0x30000000L \
	-Werror=deprecated-declarations -Werror=implicit-function-declaration"
rc=0
for f in $CLEAN; do
	# shellcheck disable=SC2086
	if (cd "$(dirname "$f")" && ${CC:-cc} $FLAGS "$(basename "$f")") > /tmp/canary.$$ 2>&1; then
		echo "CANARY clean $f"
	else
		echo "CANARY FAIL $f regressed to deprecated/removed OpenSSL API:"
		head -20 /tmp/canary.$$; rc=1
	fi
done
total=0
for f in iked/*.c iked/ikev1/*.c lib/*.c; do
	case " $CLEAN " in *" $f "*) continue ;; esac
	# shellcheck disable=SC2086
	n=$(cd "$(dirname "$f")" && ${CC:-cc} $FLAGS "$(basename "$f")" 2>&1 | grep -cE 'error:|deprecated' || true)
	[ "${n:-0}" -gt 0 ] && echo "CANARY backlog $f $n" && total=$((total + n))
done
echo "CANARY backlog total $total (not gating)"
rm -f /tmp/canary.$$
exit $rc
