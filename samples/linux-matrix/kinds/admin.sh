#!/bin/sh
# kinds/admin.sh — ikedctl against a running iked. $1 = case name.
kind_admin() {
	name=$1
	require_root || return 1
	# admin-case rows test the persistent iked (ikedctl against the live
	# service), so ensure it is listening first.  A prior shard row may
	# have stopped/started :500 (ephemeral R2_WORKERS path or systemd
	# restore), and the very first row of a shard can race the service
	# coming up.  Bring the unit up and wait, mirroring iked_restore().
	if ! iked_listening; then
		systemctl start "$IKED_UNIT" 2>/dev/null || true
		i=0
		while ! iked_listening; do
			i=$((i + 1))
			[ "$i" -gt 20 ] && break
			sleep 1
		done
	fi
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
