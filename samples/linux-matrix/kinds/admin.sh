#!/bin/sh
# kinds/admin.sh — ikedctl against a running iked. $1 = case name.
kind_admin() {
	name=$1
	require_root || return 1
	iked_listening || { die "iked not on :500"; return 1; }
	ctl="$SBIN/ikedctl"
	[ -x "$ctl" ] || { die "no $ctl"; return 1; }

	case $name in
	admin-empty)
		out=$($ctl show-sa isakmp) || { die "show-sa isakmp rc=$?"; return 1; }
		echo "$out" | grep -q Destination || { die "no show-sa header"; return 1; }
		if $ctl show-sa esp; then
			die "show-sa esp should be ENOTSUP"
			return 1
		fi
		if $ctl vpn-connect 10.99.99.99; then
			die "vpn-connect 10.99.99.99 should be ENOENT"
			return 1
		fi
		;;
	*)
		die "unknown admin case $name"
		return 1
		;;
	esac
}
