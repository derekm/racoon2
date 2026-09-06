#!/bin/sh
# kinds/ikev2.sh — strongSwan netns vs live racoon2 (r2_xfrm_e2e.sh).
# One charon at a time. Workers cell: stop racoon2-iked only, not spmd.
kind_ikev2() {
	name=$1
	require_root || return 1
	detect_rip || return 1
	[ -f "$ETC/psk/macos.psk" ] || { log "FAIL: no $ETC/psk/macos.psk"; return 1; }
	charon_reset
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH_H" 2>/dev/null || true
	netns_up
	systemctl stop strongswan-starter.service 2>/dev/null || true
	ip xfrm state flush || true
	ip xfrm policy flush || true
	ip netns exec "$NS" ip xfrm state flush || true
	ip netns exec "$NS" ip xfrm policy flush || true
	# spmd caches IKE UDP bypass in-process. Kernel flush without a
	# restart skips reinstall → IKE_AUTH hits the tunnel SPD.
	systemctl restart racoon2-spmd 2>/dev/null || true
	sleep 1
	iked_apply_workers || return 1

	# ICMP to the host's eth0 addr from the veth often fails (local-dest);
	# IKE UDP still delivers. Gate on HIP only.
	if ! ip netns exec "$NS" ping -c 1 -W 2 "$HIP" >/dev/null; then
		log "FAIL: netns ping $HIP"
		return 1
	fi

	pskhex=$(xxd -p -c 256 "$ETC/psk/macos.psk" | tr -d '\n')
	cat >/etc/ipsec.conf <<EOF
config setup
	uniqueids=no
	charondebug="ike 1, knl 1"

conn r2macos
	keyexchange=ikev2
	ike=aes256-sha256-modp2048!
	esp=aes128gcm16!
	left=$CIP
	leftid=@macos.client
	leftsubnet=$CIP/32
	right=$RIP
	rightid=@racoon2.wsl
	rightsubnet=$RIP/32
	authby=secret
	auto=add
	type=tunnel
	ikelifetime=1h
	keylife=1h
	keyingtries=1
EOF
	cat >/etc/ipsec.secrets <<EOF
@macos.client @racoon2.wsl : PSK 0x${pskhex}
EOF
	chmod 600 /etc/ipsec.secrets

	ip netns exec "$NS" ipsec start
	sleep 2
	# ipsec up can hang after the Child SA is already in; ping is the gate.
	timeout 25 ip netns exec "$NS" ipsec up r2macos || true
	sleep 2
	if ! ip netns exec "$NS" ping -c 3 -W 2 "$RIP"; then
		log "FAIL: inner ping"
		charon_reset
		return 1
	fi
	ip xfrm state | grep -q 'aead rfc4106(gcm(aes))' || {
		log "FAIL: no GCM SAD"
		charon_reset
		return 1
	}

	show=$("$SBIN/ikedctl" show-sa isakmp) || {
		log "FAIL: show-sa"
		charon_reset
		return 1
	}
	echo "$show" | grep -q "$CIP" || {
		log "FAIL: show-sa missing $CIP"
		charon_reset
		return 1
	}
	"$SBIN/ikedctl" vpn-disconnect "$CIP" || {
		log "FAIL: vpn-disconnect"
		charon_reset
		return 1
	}
	show2=$("$SBIN/ikedctl" show-sa isakmp) || {
		log "FAIL: show-sa after disconnect"
		charon_reset
		return 1
	}
	if echo "$show2" | grep -q "$CIP"; then
		log "FAIL: SA still listed after vpn-disconnect"
		charon_reset
		return 1
	fi
	iked_listening || {
		log "FAIL: iked died after vpn-disconnect"
		charon_reset
		return 1
	}

	charon_reset
}
