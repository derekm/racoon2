#!/bin/sh
# Reproducible WSL Linux matrix. Cases are rows in cases.tsv.
#   wsl.exe -d Ubuntu -u root -- bash samples/linux-matrix/run.sh
#   ./run.sh --cases 'unit|admin-empty'
# IKE rows with a numeric workers cell stop racoon2-iked, flush leftover
# SPD, restart racoon2-spmd (IKE-bypass cache), spawn iked -F with
# RACOON2_CRYPTO_WORKERS, restore after the case.
# Does not enable racoon2.target.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$HERE/lib.sh"
. "$HERE/kinds/unit.sh"
. "$HERE/kinds/admin.sh"
. "$HERE/kinds/ikev2.sh"
. "$HERE/kinds/ikev1.sh"
. "$HERE/kinds/i2ike.sh"
. "$HERE/kinds/i2ikesa.sh"
. "$HERE/kinds/i2iinit.sh"
. "$HERE/kinds/i2iinit_drop.sh"
. "$HERE/kinds/i2iinit_nointermediate.sh"

FILTER=
REBUILD=
R2_SRC=${R2_SRC:-/home/derek/src/racoon2}

crstrip() { printf '%s' "$1" | tr -d '\r'; }

usage() {
	cat <<EOF
usage: run.sh [--cases REGEX] [--rebuild BUILD] [--src DIR] [--prefix DIR]
builds.tsv names: xfrm (Linux default), pfkey, xfrm-addke (RFC 9370 PQC)
cases.tsv kinds: unit admin ikev2 ikev1 i2ike
cases.tsv gate: rows with gate=addke run ONLY when ADDKE is available (see
                 R2_ADDKE below); they are auto-skipped otherwise so the PQC
                 matrix does not run on an OpenSSL 3.0/Ubuntu build.
env: R2_ADDKE=yes|auto  force the ADDKE gate (default auto: detect WITH_ADDKE
     in the installed iked).  CI sets it explicitly per target: yes for
     Fedora 44 (OpenSSL 3.5), unset/auto for Ubuntu (OpenSSL 3.0).
EOF
}

while [ $# -gt 0 ]; do
	case $1 in
	--cases) FILTER=$2; shift 2 ;;
	--rebuild) REBUILD=$2; shift 2 ;;
	--src) R2_SRC=$2; shift 2 ;;
	--prefix) PREFIX=$2; ETC=$PREFIX/etc/racoon2; SBIN=$PREFIX/sbin; shift 2 ;;
	-h|--help) usage; exit 0 ;;
	*) usage; exit 2 ;;
	esac
done
export R2_SRC PREFIX ETC SBIN

# RFC 9370 ADDKE availability gate (env/configure-specific).
# R2_ADDKE=yes|no forces; 'auto'/unset detects WITH_ADDKE in the installed iked
# (the followup symbol is compiled in only under WITH_ADDKE, i.e. OpenSSL 3.5 /
# Fedora 44).  This is what keeps the PQC matrix off the OpenSSL 3.0 Ubuntu
# build and on Fedora.
addke_ok() {
	case ${R2_ADDKE:-auto} in
	yes) return 0 ;;
	no)  return 1 ;;
	esac
	[ -x "$SBIN/iked" ] && grep -q ikev2_followup_ke_recv "$SBIN/iked" 2>/dev/null && return 0
	# Autoconf writes `/* #undef WITH_ADDKE */` when the feature is off.
	# A bare grep of the token is a false-positive on Ubuntu OpenSSL 3.0
	# and lets i2ikesa-addke / i2iinit-addke run (and fail) in CI.
	[ -f "$R2_SRC/iked/config.h" ] &&
		grep -qE '^[[:space:]]*#define[[:space:]]+WITH_ADDKE([[:space:]]|$)' \
			"$R2_SRC/iked/config.h" 2>/dev/null
}


rebuild() {
	b=$1
	args=
	while IFS="$(printf '\t')" read -r name cargs; do
		name=$(crstrip "$name")
		cargs=$(crstrip "$cargs")
		case $name in ''|\#*) continue ;; esac
		if [ "$name" = "$b" ]; then
			args=$cargs
			break
		fi
	done < "$HERE/builds.tsv"
	[ -d "$R2_SRC" ] || die "no src $R2_SRC" || return 1
	(
		cd "$R2_SRC" || exit 1
		if [ ! -f Makefile ]; then
			autoreconf -fi
			# shellcheck disable=SC2086
			./configure --prefix="$PREFIX" $args
		fi
		make -j2
		make install
	)
}

if [ -n "$REBUILD" ]; then
	rebuild "$REBUILD" || exit 1
fi

pass=0
fail=0
skip=0
trap iked_restore EXIT
while IFS="$(printf '\t')" read -r name kind expect workers note gate || [ -n "$name" ]; do
	name=$(crstrip "$name")
	kind=$(crstrip "$kind")
	expect=$(crstrip "$expect")
	workers=$(crstrip "$workers")
	note=$(crstrip "$note")
	gate=$(crstrip "$gate")
	case $name in ''|\#*) continue ;; esac
	if [ -n "$FILTER" ]; then
		echo "$name $kind" | grep -Eq "$FILTER" || continue
	fi
	if [ "$expect" = skip ]; then
		log "SKIP $name ($note)"
		skip=$((skip + 1))
		continue
	fi
	if [ "$gate" = addke ] && ! addke_ok; then
		log "SKIP $name (ADDKE gate off: R2_ADDKE=${R2_ADDKE:-auto})"
		skip=$((skip + 1))
		continue
	fi
	case $workers in -|'') R2_WORKERS= ;; *) R2_WORKERS=$workers ;; esac
	export R2_WORKERS
	log "=== $name ($kind) workers=${R2_WORKERS:-live} ==="
	R2_CASE_FAIL=0
	if kind_$kind "$name"; then
		st=0
	else
		st=$?
	fi
	if [ "$R2_CASE_FAIL" != 0 ] || [ "$st" -ne 0 ]; then
		log "FAIL $name"
		fail=$((fail + 1))
	else
		log "PASS $name"
		pass=$((pass + 1))
	fi
	iked_restore
	name=
done < "$HERE/cases.tsv"

log "pass=$pass fail=$fail skip=$skip"
[ "$fail" -eq 0 ]
