#!/bin/sh
# kinds/admin.sh — ikedctl against a running iked. $1 = case name.
#
# On a systemd host (the box, Ubuntu CI) the row exercises the persistent
# iked service on :500.  Where there is no live iked and no systemd to
# start one (the Fedora PQC container ships no units), the row brings up
# its own spmd + iked in a private netns with a dedicated admin socket and
# runs the SAME assertions against that daemon.  ikedctl only needs an
# iked behind an admin socket; nothing in the checks depends on systemd,
# so the row runs everywhere instead of being skipped.

admin_ephemeral_down() {
	pkill -9 -f "$C/" 2>/dev/null || true
	ip netns del "$NSR" 2>/dev/null || true
	rm -f "$SPMIF_R" "$SOCK_R"
	rm -rf "$PRIVRES_R"
}

admin_ephemeral_up() {
	row_ns "$1"
	[ -x "$SBIN/iked" ] && [ -x "$SBIN/spmd" ] || { die "no $SBIN/iked or spmd"; return 1; }
	[ -f "$ETC/spmd.pwd" ] || { die "no $ETC/spmd.pwd"; return 1; }
	[ -f "$ETC/psk/macos.psk" ] || { die "no $ETC/psk/macos.psk"; return 1; }
	admin_ephemeral_down
	rm -rf "$D" "$C"; mkdir -p "$D" "$C" "$PRIVRES_R"
	ip netns add "$NSR" || { die "ip netns add $NSR"; return 1; }
	ip netns exec "$NSR" ip link set lo up
	ip netns exec "$NSR" ip addr add 192.0.13.1/32 dev lo
	cat > "$C/admin.conf" <<CONF
interface {
	ike { "192.0.13.1"; };
	spmd { unix "$SPMIF_R"; };
	spmd_password "$ETC/spmd.pwd";
};
resolver { resolver off; };
remote matrix_admin {
	acceptable_kmp { ikev2; };
	ikev2 {
		passive on;
		my_id fqdn "racoon2-matrix";
		peers_id fqdn "r2init-matrix";
		peers_ipaddr "192.0.13.2";
		kmp_enc_alg { aes256_cbc; };
		kmp_prf_alg { hmac_sha2_256; };
		kmp_hash_alg { hmac_sha2_256; };
		kmp_dh_group { ecp256; };
		kmp_auth_method { psk; };
		pre_shared_key "$ETC/psk/macos.psk";
	};
	selector_index sel_in;
};
selector sel_out {
	direction outbound;
	src "192.0.13.1"; dst "192.0.13.2";
	policy_index pol;
};
selector sel_in {
	direction inbound;
	dst "192.0.13.1"; src "192.0.13.2";
	policy_index pol;
};
policy pol {
	action auto_ipsec;
	remote_index matrix_admin;
	ipsec_mode transport;
	ipsec_index { ipsec_e; };
	ipsec_level require;
	peers_sa_ipaddr "192.0.13.2";
	my_sa_ipaddr "192.0.13.1";
};
ipsec ipsec_e {
	ipsec_sa_lifetime_time 300 sec;
	sa_index esp_e;
};
sa esp_e {
	sa_protocol esp;
	esp_enc_alg { aes_gcm; };
	esp_auth_alg { non_auth; };
};
CONF
	( ip netns exec "$NSR" "$SBIN/spmd" -F -f "$C/admin.conf" ) >"$D/spmd.log" 2>&1 &
	i=0; until [ -S "$SPMIF_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	[ -S "$SPMIF_R" ] || { die "ephemeral spmd did not come up"; cat "$D/spmd.log"; return 1; }
	( ip netns exec "$NSR" env RACOON2_ADMIN_SOCK="$SOCK_R" RACOON2_RESUME_DIR="$PRIVRES_R" \
	    "$SBIN/iked" -F -f "$C/admin.conf" -D 0x0001 -l "$D/iked.log" ) >"$D/iked.out" 2>&1 &
	i=0; until [ -S "$SOCK_R" ] || [ "$i" -ge 15 ]; do sleep 1; i=$((i+1)); done
	[ -S "$SOCK_R" ] || { die "ephemeral iked admin socket $SOCK_R did not appear"; tail -20 "$D/iked.log" "$D/iked.out" 2>/dev/null; return 1; }
	ip netns exec "$NSR" ss -ulnp 2>/dev/null | grep -q '192.0.13.1:500 ' || { die "ephemeral iked not on 192.0.13.1:500"; return 1; }
	log "admin: no live iked/systemd here; testing an ephemeral iked in netns $NSR via $SOCK_R"
	return 0
}

kind_admin() {
	name=$1
	require_root || return 1
	ctl="$SBIN/ikedctl"
	[ -x "$ctl" ] || { die "no $ctl"; return 1; }
	_eph=0
	# admin-case rows test the persistent iked (ikedctl against the live
	# service), so ensure it is listening first.  A prior shard row may
	# have stopped/started :500 (ephemeral R2_WORKERS path or systemd
	# restore), and the very first row of a shard can race the service
	# coming up.  Bring the unit up and wait, mirroring iked_restore().
	if ! iked_listening; then
		if systemctl is-system-running >/dev/null 2>&1 || \
		   [ -d /run/systemd/system ]; then
			systemctl start "$IKED_UNIT" 2>/dev/null || true
			i=0
			while ! iked_listening; do
				i=$((i + 1))
				[ "$i" -gt 20 ] && break
				sleep 1
			done
			iked_listening || { die "iked not on :500"; return 1; }
		else
			admin_ephemeral_up "$name" || { admin_ephemeral_down; return 1; }
			_eph=1
			ctl="$SBIN/ikedctl -s $SOCK_R"
		fi
	fi

	_rc=0
	case $name in
	admin-empty)
		if ! out=$($ctl show-sa isakmp); then
			die "show-sa isakmp rc=$?"; _rc=1
		elif ! echo "$out" | grep -q Destination; then
			die "no show-sa header"; _rc=1
		elif $ctl show-sa esp; then
			die "show-sa esp should be ENOTSUP"; _rc=1
		elif $ctl vpn-connect 10.99.99.99; then
			die "vpn-connect 10.99.99.99 should be ENOENT"; _rc=1
		fi
		;;
	*)
		die "unknown admin case $name"
		_rc=1
		;;
	esac
	[ "$_eph" -eq 1 ] && admin_ephemeral_down
	return $_rc
}
