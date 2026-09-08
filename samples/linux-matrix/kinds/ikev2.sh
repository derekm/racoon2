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
	# decapped tunnel traffic arrives on eth3 with src 192.0.2.2, which
	# does not reverse-route via eth3 — rp_filter would drop it. The
	# IKEv1 harness sets this; ikev2 needs it once the ping is a real
	# ESP proof.
	echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter
	echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter
	echo 0 > /proc/sys/net/ipv4/conf/"$VETH_H"/rp_filter
	systemctl stop strongswan-starter.service 2>/dev/null || true
	ip netns exec "$NS" ip xfrm state flush || true
	ip netns exec "$NS" ip xfrm policy flush || true
	iked_apply_workers || return 1

	# ICMP to the host's eth0 addr from the veth often fails (local-dest);
	# IKE UDP still delivers. Gate on HIP only.
	if ! ip netns exec "$NS" ping -c 1 -W 2 "$HIP" >/dev/null; then
		log "FAIL: netns ping $HIP"
		return 1
	fi

	# kill non-tunnel ICMP from the client: with no ESP SA a ping to RIP
	# dies (the DROP matches iif r2h); through the tunnel the decapped
	# reply path bypasses this rule — the inner ping is then a REAL ESP
	# proof. Cleaned up by charon_reset.
	iptables -t raw -C PREROUTING -i "$VETH_H" -s "${CIP}/32" -p icmp -j DROP 2>/dev/null ||
		iptables -t raw -A PREROUTING -i "$VETH_H" -s "${CIP}/32" -p icmp -j DROP

	# the in-SPD matches plain IKE UDP (XfrmInTmplMismatch) before
	# iked sees it. Same-port allow rows; 500<->4500 float is
	# installed by spmd_ike_bypass (RFC 3947), not here.
	for p in 500 4500; do
		ip xfrm policy add src "${CIP}/32" dst "${RIP}/32" proto udp \
			sport "$p" dport "$p" dir in  ptype main action allow 2>/dev/null || true
		ip xfrm policy add src "${RIP}/32" dst "${CIP}/32" proto udp \
			sport "$p" dport "$p" dir out ptype main action allow 2>/dev/null || true
	done

	# ESP proposal selection: case name suffix drives the strongSwan
	# esp= line -- -s384 -> aes256-sha384!, -s512 -> aes256-sha512!,
	# default stays aes128gcm16!
	STRONG_ESP=aes128gcm16!
	EXPECT_AUTH=
	FRAG=
	MOBIKE=
	case "$name" in
	*-s384) STRONG_ESP='aes256-sha384!'; EXPECT_AUTH='auth-trunc hmac(sha384).* 192$' ;;
	*-s512) STRONG_ESP='aes256-sha512!'; EXPECT_AUTH='auth-trunc hmac(sha512).* 256$' ;;
	*-g8)  STRONG_ESP='aes128gcm8!';  EXPECT_AUTH='aead rfc4106(gcm(aes)).* 64$' ;;
	*-g12) STRONG_ESP='aes128gcm12!'; EXPECT_AUTH='aead rfc4106(gcm(aes)).* 96$' ;;
	*-frag) FRAG='fragmentation=yes' ;;
	*-mobike) MOBIKE='mobike=yes' ;;
	esac
	pskhex=$(xxd -p -c 256 "$ETC/psk/macos.psk" | tr -d '\n')
	mkdir -p /etc/strongswan.d/charon
	cat >/etc/strongswan.d/charon/bypass-lan.conf <<'EOF'
charon {
	plugins {
		bypass-lan {
			load = no
		}
	}
}
EOF
	# strongSwan sends its own TS (no CP request); racoon2 remote still
	# needs the pool for Apple clients — present but unused here.
	cat >/etc/ipsec.conf <<EOF
config setup
	uniqueids=no
	charondebug="ike 1, knl 1"

conn r2macos
	keyexchange=ikev2
	ike=aes256-sha256-modp2048!
	esp=$STRONG_ESP
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
	$FRAG
	$MOBIKE
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
	# NB: no inner-ping gate on the netns rows — charon-in-netns cannot
	# install its side of the SAs on these kernels (mirrored WSL2 and
	# GH-hosted; manual netns xfrm adds work, so it is charon's netlink
	# path that fails, not the tree). The netns rows prove negotiation +
	# the responder SAD/SPD with exact auth/trunc content.
	if [ -n "$EXPECT_AUTH" ]; then
		ip xfrm state | grep -q "$EXPECT_AUTH" || {
			log "FAIL: SAD missing $EXPECT_AUTH"
			ip xfrm state | grep -E 'auth|aead' | head -6
			charon_reset
			return 1
		}
	else
		ip xfrm state | grep -q 'aead rfc4106(gcm(aes))' || {
			log "FAIL: no GCM SAD"
			charon_reset
			return 1
		}
	fi

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
