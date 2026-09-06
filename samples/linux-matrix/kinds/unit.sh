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
	evlooptest)
		make -C "$src/iked" evlooptest
		"$src/iked/evlooptest"
		;;
	workerstest)
		make -C "$src/iked" workerstest
		"$src/iked/workerstest"
		;;
	*)
		die "unknown unit case $name"
		return 1
		;;
	esac
}
