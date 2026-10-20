#!/bin/sh
# sh-lint.sh [repo-root] -- syntax-check every tracked shell script against
# the interpreter its shebang names, so a `#!/bin/sh` script cannot carry
# bash-only syntax (process substitution, [[ ]], arrays ...) unnoticed.
#   #!/bin/sh       -> dash -n (or sh -n); a POSIX-only parser catches bashisms
#   #!.../bash      -> bash -n
#   *.sh, no shebang -> treated as sh (sourced fragments such as kinds/*.sh)
# When shellcheck is installed it also runs at severity "error" with the
# matching dialect.  Exit 1 on any finding.
ROOT=${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
cd "$ROOT" || exit 2
if command -v dash >/dev/null 2>&1; then SHN=dash; else SHN=sh; fi
SC=; command -v shellcheck >/dev/null 2>&1 && SC=shellcheck
bad=0; n=0
for f in $(git ls-files); do
	[ -f "$f" ] || continue
	l=$(head -n 1 "$f" 2>/dev/null)
	case $l in
	'#!/bin/sh'*|'#! /bin/sh'*|'#!/usr/bin/env sh'*) d=sh ;;
	'#!'*bash*) d=bash ;;
	'#!'*) continue ;;
	*) case $f in *.sh) d=sh ;; *) continue ;; esac ;;
	esac
	n=$((n + 1))
	if [ "$d" = sh ]; then
		$SHN -n "$f" 2>/tmp/sh-lint.$$ || { echo "sh-lint: $f: not POSIX sh ($SHN -n):"; cat /tmp/sh-lint.$$; bad=1; }
	else
		bash -n "$f" 2>/tmp/sh-lint.$$ || { echo "sh-lint: $f: bash -n failed:"; cat /tmp/sh-lint.$$; bad=1; }
	fi
	if [ -n "$SC" ]; then
		$SC -S error -s "$d" "$f" >/tmp/sh-lint.$$ 2>&1 || { echo "sh-lint: $f: shellcheck -S error:"; cat /tmp/sh-lint.$$; bad=1; }
	fi
done
rm -f /tmp/sh-lint.$$
echo "sh-lint: $n scripts checked ($SHN -n${SC:+, shellcheck -S error}): $([ $bad = 0 ] && echo clean || echo FAIL)"
exit $bad
