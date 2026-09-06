#!/bin/sh
# Reproducible WSL Linux matrix. Cases are rows in cases.tsv.
#   wsl.exe -d Ubuntu -u root -- bash samples/linux-matrix/run.sh
#   ./run.sh --cases 'unit|admin-empty'
# IKE rows with a workers cell stop racoon2-iked only, spawn iked -F
# with RACOON2_CRYPTO_WORKERS, restore after the case.
# Does not enable racoon2.target. Does not stop racoon2-spmd.
set -u
HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
. "$HERE/lib.sh"
. "$HERE/kinds/unit.sh"
. "$HERE/kinds/admin.sh"
. "$HERE/kinds/ikev2.sh"
. "$HERE/kinds/ikev1.sh"

FILTER=
REBUILD=
R2_SRC=${R2_SRC:-/home/derek/src/racoon2}

usage() {
	cat <<EOF
usage: run.sh [--cases REGEX] [--rebuild BUILD] [--src DIR] [--prefix DIR]
builds.tsv names: xfrm (Linux default), pfkey
cases.tsv kinds: unit admin ikev2 ikev1
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

rebuild() {
	b=$1
	args=
	while IFS='	' read -r name cargs; do
		case $name in ''|\#*) continue ;; esac
		if [ "$name" = "$b" ]; then
			args=$cargs
			break
		fi
	done < "$HERE/builds.tsv"
	[ -d "$R2_SRC" ] || die "no src $R2_SRC"
	cd "$R2_SRC" || die "cd $R2_SRC"
	if [ ! -f Makefile ]; then
		autoreconf -fi
		./configure --prefix="$PREFIX" $args
	fi
	make -j2
	make install
}

if [ -n "$REBUILD" ]; then
	rebuild "$REBUILD" || exit 1
fi

pass=0
fail=0
skip=0
trap iked_restore EXIT
while IFS='	' read -r name kind expect workers note; do
	case $name in ''|\#*) continue ;; esac
	if [ -n "$FILTER" ]; then
		echo "$name $kind" | grep -Eq "$FILTER" || continue
	fi
	if [ "$expect" = skip ]; then
		log "SKIP $name ($note)"
		skip=$((skip + 1))
		continue
	fi
	case $workers in -|'') R2_WORKERS= ;; *) R2_WORKERS=$workers ;; esac
	export R2_WORKERS
	log "=== $name ($kind) workers=${R2_WORKERS:-live} ==="
	if kind_$kind "$name"; then
		log "PASS $name"
		pass=$((pass + 1))
	else
		log "FAIL $name"
		fail=$((fail + 1))
	fi
	iked_restore
done < "$HERE/cases.tsv"

log "pass=$pass fail=$fail skip=$skip"
[ "$fail" -eq 0 ]
