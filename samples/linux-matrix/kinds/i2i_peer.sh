#!/bin/sh
# kinds/i2i_peer.sh — peer-backend swap for the i2i-family kinds.
# The i2i kinds default to iked<->iked.  A `-charon` name suffix (or
# R2_PEER_I=charon) runs the SAME kind with a strongSwan charon initiator
# (RFC 9370 ADDKE ke1_mlkem768 + RFC 9242 IKE_INTERMEDIATE) in the
# initiator netns; the responder stays the iked SUT.  This is the interop
# row: charon 6.0.7 (ml plugin) and a WITH_ADDKE iked derive the same
# ML-KEM-768 key material across two independent implementations — the ESP
# child landing proves SK(1) matched (AUTH+IntAuth verify).  iked default
# paths in the kinds stay untouched.
# New -charon rows ship gate=box until a container counted-gate PASS.
# Requires strongSwan 6.0.x + the `ml` plugin on the run host (box:
# libstrongswan-ml.so; mlkem768/ML_KEM_768 in libstrongswan.so.0).

I2I_CHARON_ID=charon-i2i
I2I_CHARON_BIN=${I2I_CHARON_BIN:-/usr/libexec/strongswan/charon}
I2I_SWANCTL_BIN=${I2I_SWANCTL_BIN:-/usr/bin/swanctl}
I2I_CHARON_VDIR=${I2I_CHARON_VDIR:-/etc/strongswan/swanctl/conf.d}

# i2i_peer <name> — peer backend for a case: charon when the name carries a
# -charon suffix (or R2_PEER_I=charon globally), else iked.
i2i_peer() {
	case "$1" in
	*-charon) echo charon ;;
	*)        echo "${R2_PEER_I:-iked}" ;;
	esac
}

# i2i_peer_resp_id <peer> — the responder's peers_id for this initiator id.
i2i_peer_resp_id() {
	if [ "$1" = charon ]; then echo "$I2I_CHARON_ID"; else echo "r2init-matrix"; fi
}

# i2i_peer_i_conf <C> <HI> <HR> <name> <peer> — write a swanctl conn for a
# charon initiator; the iked initiator conf stays inline in the kind.  PSK
# hex is read from the existing matrix psk file (never printed, never
# committed); the conf file is removed by i2i_peer_i_cleanup.
i2i_peer_i_conf() {
	_C=$1 _HI=$2 _HR=$3 _name=$4 _peer=$5
	[ "$_peer" = charon ] || return 0
	I2I_CHARON_CONF="$I2I_CHARON_VDIR/r2-${_name}.conf"
	mkdir -p "$I2I_CHARON_VDIR" || return 1
	_pskhex=$(psk_file_hex "$ETC/psk/macos.psk") || { log "FAIL: charon psk hex"; return 1; }
	cat > "$I2I_CHARON_CONF" <<EOF
connections {
	$_name {
		version = 2
		rekey_time = 0s
		proposals = aes256gcm16-prfsha256-ecp256-ke1_mlkem768
		local_addrs = $_HI
		remote_addrs = $_HR
		local {
			id = $I2I_CHARON_ID
			auth = psk
		}
		remote {
			id = racoon2-matrix
			auth = psk
		}
		children {
			ch {
				local_ts = $_HI/32
				remote_ts = $_HR/32
				esp_proposals = aes128gcm16
				rekey_time = 0s
			}
		}
	}
}
secrets {
	ike-$_name {
		secret = "0x$_pskhex"
	}
}
EOF
	return 0
}

# i2i_peer_i_start <D> <NSI> <peer> <name> — spawn the charon initiator in
# its netns (stderr to $D/charon-init.log).  iked spawn stays in the kind.
i2i_peer_i_start() {
	_D=$1 _NSI=$2 _peer=$3 _name=$4
	[ "$_peer" = charon ] || return 0
	( ip netns exec "$_NSI" "$I2I_CHARON_BIN" --debug-ike 3 --debug-knl 1 \
	    --debug-cfg 2 --debug-mgr 2 --debug-net 1 ) >"$_D/charon-init.log" 2>&1 &
	sleep 2
	return 0
}

# i2i_peer_i_trigger <D> <NSI> <peer> <name> — load conns + initiate.  The
# iked trigger (ikedctl establish-sa) stays inline in the kind.
i2i_peer_i_trigger() {
	_D=$1 _NSI=$2 _peer=$3 _name=$4
	[ "$_peer" = charon ] || return 0
	( ip netns exec "$_NSI" "$I2I_SWANCTL_BIN" --load-all --debug 2 ) >"$_D/swanctl-load.log" 2>&1
	( ip netns exec "$_NSI" "$I2I_SWANCTL_BIN" --initiate --child ch --debug 2 ) >"$_D/swanctl-init.log" 2>&1
	return 0
}

# i2i_peer_i_evidence <D> <peer> — this initiator completed its ADDKE side:
# iked logs round-complete; charon selected KE1_ML_KEM_768 and reached
# ESTABLISHED (the ESP child landing elsewhere in the kind proves SK(1)).
i2i_peer_i_evidence() {
	_D=$1 _peer=$2
	if [ "$_peer" = charon ]; then
		grep -q 'KE1_ML_KEM_768' "$_D/charon-init.log" 2>/dev/null &&
		grep -q 'state change: CONNECTING => ESTABLISHED' "$_D/charon-init.log" 2>/dev/null
		return $?
	fi
	grep -q 'IKE_INTERMEDIATE ADDKE round complete' "$_D/init-iked.log" 2>/dev/null
}

# i2i_peer_i_diag <D> <peer> — charon-side failure tail for the FAIL dump.
i2i_peer_i_diag() {
	_D=$1 _peer=$2
	[ "$_peer" = charon ] || return 0
	grep -E 'selected proposal|KE1_ML_KEM_768|state change|not acceptable|no proposal|received proposals' \
		"$_D/charon-init.log" 2>/dev/null | tail -8
}

# i2i_peer_i_cleanup <peer> — stop the charon initiator, drop its swanctl
# conn file.  iked cleanup stays in the kind.
i2i_peer_i_cleanup() {
	_peer=$1
	[ "$_peer" = charon ] || return 0
	killall -9 charon 2>/dev/null || true
	rm -f /var/run/charon.pid /var/run/charon.ctl
	rm -f "${I2I_CHARON_CONF:-/nonexistent}"
	return 0
}
