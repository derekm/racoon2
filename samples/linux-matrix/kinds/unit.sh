#!/bin/sh
# kinds/unit.sh — in-tree check_PROGRAMS. $1 = case name.
kind_unit() {
	name=$1
	src=${R2_SRC:-/home/derek/src/racoon2}
	case $name in
	kmtest)
		make -C "$src/lib" kmtest
		"$src/lib/kmtest"
		;;
	eaytest)
		make -C "$src/iked" eaytest
		"$src/iked/eaytest"
		;;
	ndcppkats)
		# NDcPP v3.0e crypto KATs (A9/A10/B1/B3-B6).  The KAT prints one
		# "KAT <cell>: PASS|FAIL <evidence>" line per cell on stdout,
		# which the runner captures into the matrix log; the report
		# generator later maps KAT lines to CPL cells.
		make -C "$src/iked" ndcppkats
		"$src/iked/ndcppkats"
		;;
	evlooptest)
		make -C "$src/iked" evlooptest
		"$src/iked/evlooptest"
		;;
	workerstest)
		make -C "$src/iked" workerstest
		"$src/iked/workerstest"
		;;
	xfrm-natt-oa)
		make -C "$src/lib" xfrmnatt
		"$src/lib/xfrmnatt"
		;;
	xfrm-tmpl-family)
		make -C "$src/lib" xfrmtmpl
		"$src/lib/xfrmtmpl"
		;;
	*)
		die "unknown unit case $name"
		return 1
		;;
	esac
}
